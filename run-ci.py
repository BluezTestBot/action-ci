#!/usr/bin/env python3
import os
import sys
import argparse
import logging
import subprocess
import configparser
import requests
import re
import smtplib
import email.utils
from github import Github
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# Globals
logger = None
config = None

github_repo = None
github_pr = None
github_commits = None

pw_sid = None
pw_series = None

src_dir = None

test_suite = {}

PW_BASE_URL = "https://patchwork.kernel.org/api/1.1"

EMAIL_MESSAGE = '''
This is automated email and please do not reply to this email!

Dear submitter,

Thank you for submitting the patches to the linux bluetooth mailing list.
While we are preparing for reviewing the patches, we found the following
issue/warning.

Test Result:
{}

Outputs:
{}


---
Regards,
Linux Bluetooth
'''

def requests_url(url):
    """ Helper function to requests WEB API GET with URL """

    resp = requests.get(url)
    if resp.status_code != 200:
        raise requests.HTTPError("GET {}".format(resp.status_code))

    return resp

def patchwork_get_series(sid):
    """ Get series detail from patchwork """

    url = PW_BASE_URL + "/series/" + sid
    req = requests_url(url)

    return req.json()

def patchwork_get_sid(pr_title):
    """
    Parse PR title prefix and get PatchWork Series ID
    PR Title Prefix = "[PW_S_ID:<series_id>] XXXXX"
    """

    try:
        sid = re.search(r'^\[PW_SID:([0-9]+)\]', pr_title).group(1)
    except AttributeError:
        logging.error("Unable to find the series_id from title %s" % pr_title)
        sid = None

    return sid

def patchwork_get_patch_detail_title(title):
    """
    Use :title to find a matching patch in series and get the detail
    """

    for patch in pw_series['patches']:
        if (patch['name'].find(title) != -1):
            logger.debug("Found matching patch title in the series")
            req = requests_url(patch['url'])
            return req.json()
        logger.debug("No matching patch title found")

    logger.error("Cannot find a matching patch from PatchWork series")

def github_pr_post_comment(name, status, output=None):
    """ Post message to PR page """

    comment = "**" + name + ": " + status + "**\n\n"
    if output:
        comment += "Output:\n"
        comment += "```\n"
        comment += output
        comment += "\n```\n"

    github_pr.create_issue_comment(comment)

def run_cmd(*args, cwd=None):
    """ Run command and return return code, stdout and stderr """

    cmd = []
    cmd.extend(args)
    cmd_str = "{}".format(" ".join(str(w) for w in cmd))
    logger.info("CMD: %s" % cmd_str)

    stdout = ""
    try:
        proc = subprocess.Popen(cmd,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                bufsize=1,
                                universal_newlines=True,
                                cwd=cwd)
    except OSError as e:
        logger.error("ERROR: failed to run cmd: %s" % e)
        return (-1, None, None)

    for line in proc.stdout:
        logger.debug(line.rstrip('\n'))
        stdout += line

    # stdout is consumed in previous line. so, communicate() returns empty
    _ignore, stderr = proc.communicate()

    logger.debug(">> STDERR\n{}".format(stderr))

    return (proc.returncode, stdout, stderr)

def config_enable(config, name):
    """
    Check "enable" in config[name].
    Return False if it is specifed otherwise True
    """

    if name in config:
        if 'enable' in config[name]:
            if config[name]['enable'] == 'no':
                logger.info("config." + name + " is disabled")
                return False

    logger.info("config." + name + " is enabled")
    return True

def send_email(sender, receiver, msg):
    """ Send email """

    email_cfg = config['email']

    if 'EMAIL_TOKEN' not in os.environ:
        logging.warning("missing EMAIL_TOKEN. Skip sending email")
        return

    try:
        session = smtplib.SMTP(email_cfg['server'], int(email_cfg['port']))
        session.ehlo()
        if 'starttls' not in email_cfg or email_cfg['starttls'] == 'yes':
            session.starttls()
        session.ehlo()
        session.login(sender, os.environ['EMAIL_TOKEN'])
        session.sendmail(sender, receiver, msg.as_string())
        logging.info("Successfully sent email")
    except Exception as e:
        logging.error("Exception: {}".format(e))
    finally:
        session.quit()

    logging.info("Sending email done")


def compose_email(test_name, test_result, title, submitter, msgid):
    """
    Compose and send email
    """

    logger.debug("Compose Email")
    email_cfg = config['email']
    sender = email_cfg['user']

    add_reply_to = False

    receivers = []
    if 'only-maintainers' in email_cfg and email_cfg['only-maintainers'] == 'yes':
        # Send only to the addresses in the 'maintainers'
        maintainers = "".join(email_cfg['maintainers'].splitlines()).split(",")
        receivers.extend(maintainers)
    else:
        # Send to default-to address and submitter
        receivers.append(email_cfg['default-to'])
        receivers.append(submitter)

        add_reply_to = True

    # Create message
    msg = MIMEMultipart()
    msg['From'] = sender
    msg['To'] = ", ".join(receivers)
    msg['Subject'] = "RE: " + title

    # In case to use default-to address, set Reply-To to mailing list in case
    # submitter reply to the result email.
    if add_reply_to:
        msg['Reply-To'] = email_cfg['default-to']

    # Message Header
    msg.add_header('In-Reply-To', msgid)
    msg.add_header('References', msgid)

    body = EMAIL_MESSAGE.format(test_name + " Failed", test_result)
    logger.debug("Message Body: %s" % body)
    msg.attach(MIMEText(body, 'plain'))

    logger.debug("Mail Message: {}".format(msg))

    # Send email
    send_email(sender, receivers, msg)


class CiBase:
    """
    Base class for CI Tests.
    """
    name = None
    enable = True

    result_type = "success"
    result_msg = ""

    def error(self, msg):
        self.result_type = "error"
        self.result_msg = msg
        raise EndTest

    def skip(self, msg):
        self.result_type = "skipped"
        self.result_msg = msg
        raise EndTest

    def add_failure(self, msg):
        self.result_type = "failure"
        if not self.result_msg:
            self.result_msg = msg
        else:
            self.result_msg += "\n\n" + msg


class CheckPatch(CiBase):
    name = "checkpatch"
    # private context used for own reference
    context = []

    checkpatch_pl = '/usr/bin/checkpatch.pl'

    def run(self):
        logger.debug("##### Run CheckPatch Test #####")

        self.enable = config_enable(config, self.name)
        self.config()

        # Check if it is disabled.
        if self.enable == False:
            self.skip("Disabled in configuration")

        for commit in github_commits:
            output = self.run_checkpatch(commit.sha)
            if output != None:
                msg = "{}\n{}".format(commit.commit.message.splitlines()[0],
                                      output)
                self.add_failure(msg)

                # Save commit and output in :context for later reference
                self.context.append({"commit": commit, "output": output})

        if self.result_type == "failure":
            self.notify_failure()

    def config(self):
        """
        Config the test cases.
        """
        logger.debug("Parser configuration")

        if self.name in config:
            if 'bin_path' in config[self.name]:
                self.checkpatch_pl = config[self.name]['bin_path']
        logger.debug("checkpatch_pl = %s" % self.checkpatch_pl)

    def notify_failure(self):
        """
        Notify failure to submitter
        """

        logger.debug("Notify failure")

        # There might be more than one failure in the series and the result
        # is in :context array
        for test_result in self.context:
            commit = test_result['commit']
            result = test_result['output']
            commit_title = commit.commit.message.splitlines()[0]
            patch = patchwork_get_patch_detail_title(commit_title)

            compose_email(self.name, result, patch['name'],
                          patch['submitter']['email'], patch['msgid'])

    def run_checkpatch(self, sha):
        """
        Run checkpatch script with commit sha.
        On success, it returns None.
        On failure, it returns the stderr output string
        """

        output = None
        logger.info("Commit SHA: %s" % sha)

        diff = subprocess.Popen(('git', 'show', '--format=email', sha),
                                stdout=subprocess.PIPE)
        try:
            subprocess.check_output((self.checkpatch_pl, '--no-tree', '-'),
                                    stdin=diff.stdout,
                                    stderr=subprocess.STDOUT,
                                    shell=True)
        except subprocess.CalledProcessError as ex:
            output = ex.output.decode("utf-8")
            logger.error("checkpatch returned error/warning")
            logger.error("output: %s" % output)

        return output


class CheckGitLint(CiBase):
    name = "checkgitlint"
    # private context used for own reference
    context = []

    gitlint_config = '/.gitlint'

    def run(self):
        logger.debug("##### Run CheckGitLint Test #####")

        self.enable = config_enable(config, self.name)
        self.config()

        # Check if it is disabled.
        if self.enable == False:
            self.skip("Disabled in configuration")

        for commit in github_commits:
            output = self.run_checkgitlint(commit.sha)
            if output != None:
                msg = "{}\n{}".format(commit.commit.message.splitlines()[0],
                                      output)
                self.add_failure(msg)

                # Save commit and output in :context
                self.context.append({"commit": commit, "output": output})

        if self.result_type == "failure":
            self.notify_failure()

    def config(self):
        """
        Config the test cases.
        """
        logger.debug("Parser configuration")

        if self.name in config:
            if 'config_path' in config[self.name]:
                self.gitlint_config = config[self.name]['config_path']
        logger.debug("gitlint_config = %s" % self.gitlint_config)

    def notify_failure(self):
        """
        Notify failure to submitter
        """

        logger.debug("Notify failure")

        # There might be more than one failure in the series and the result
        # is in :context array
        for test_result in self.context:
            commit = test_result['commit']
            result = test_result['output']
            commit_title = commit.commit.message.splitlines()[0]
            patch = patchwork_get_patch_detail_title(commit_title)

            compose_email(self.name, result, patch['name'],
                          patch['submitter']['email'], patch['msgid'])

    def run_checkgitlint(self, sha):
        """
        Run checkpatch script with commit sha.
        On success, it returns None.
        On failure, it returns the stderr output string
        """

        output = None
        logger.info("Commit SHA: %s" % sha)

        commit = subprocess.Popen(('git', 'log', '-1', '--pretty=%B', sha),
                                  stdout=subprocess.PIPE)
        try:
            subprocess.check_output(('gitlint', '-C', self.gitlint_config),
                                    stdin=commit.stdout,
                                    stderr=subprocess.STDOUT,
                                    shell=True)
        except subprocess.CalledProcessError as ex:
            output = ex.output.decode("utf-8")
            logger.error("gitlint returned error/warning")
            logger.error("output: %s" % output)

        return output


class CheckBuild(CiBase):
    name = "checkbuild"
    # private context used for own reference
    context = None

    def run(self):
        logger.debug("##### Run CheckBuild Test #####")

        self.enable = config_enable(config, self.name)

        self.config()

        # Check if it is disabled.
        if self.enable == False:
            self.skip("Disabled in configuration")

        # bootstrap-configure
        (ret, stdout, stderr) = run_cmd("./bootstrap-configure",
                                        "--enable-external-ell",
                                        cwd=src_dir)
        if ret:
            self.add_failure(stderr)
            self.notify_failure()
            raise EndTest

        # make
        (ret, stdout, stderr) = run_cmd("make", cwd=src_dir)
        if ret:
            self.add_failure(stderr)
            self.notify_failure()
            raise EndTest

    def config(self):
        """
        Configure the test cases.
        """
        # Set Reference to patchwork series
        self.context = pw_series

    def notify_failure(self):
        """
        Notify failure to submitter
        """

        logger.debug("Notify failure")

        patch = self.context['patches'][0]

        compose_email(self.name, self.result_msg, self.context['name'],
                      self.context['submitter']['email'], patch['msgid'])


class MakeCheck(CiBase):
    name = "makecheck"
    # private context used for own reference
    context = None

    def run(self):
        logger.debug("##### Run MakeCheck Test #####")

        self.enable = config_enable(config, self.name)

        self.config()

        # Check if it is disabled.
        if self.enable == False:
            self.skip("Disabled in configuration")

        # Only run if "checkbuild" success
        if test_suite["checkbuild"].result_type != "success":
            logger.info("Checkbuild is not success. skip this test")
            self.skip("checkbuild not success")
            raise EndTest

        # Run make check. Assume the code is already configuared and problem
        # to build.
        (ret, stdout, stderr) = run_cmd("make", "check", cwd=src_dir)
        if ret:
            self.add_failure(stderr)
            self.notify_failure()
            raise EndTest

    def config(self):
        """
        Configure the test cases.
        """
        # Set Reference to patchwork series
        self.context = pw_series


    def notify_failure(self):
        """
        Notify failure to submitter
        """

        logger.debug("Notify failure")

        patch = self.context['patches'][0]

        compose_email(self.name, self.result_msg, self.context['name'],
                      self.context['submitter']['email'], patch['msgid'])


class EndTest(Exception):
    """
    End of Test
    """


def run_ci(args):
    """
    Run CI tests and returns the number of failed tests
    """

    global test_suite

    num_fails = 0

    if args.show_test_list:
        for testcase in CiBase.__subclasses__():
            print(testcase.name)
        return 0

    # Run tests
    for testcase in CiBase.__subclasses__():
        test = testcase()

        test_suite[test.name] = test

        try:
            test.run()
        except EndTest:
            logger.debug("Test Ended")

        logger.info("Process test result for " + test.name)

        if test.result_type == "failure":
            num_fails += 1

        logger.info(test.name + " result: " + test.result_type)
        logger.debug("Post message to github: " + test.result_msg)
        github_pr_post_comment(test.name, test.result_type, test.result_msg)

    return num_fails

def init_github(repo, pr_num):
    """
    Initialize github object
    """

    global github_repo
    global github_pr
    global github_commits
    global pw_sid
    global pw_series

    github_repo = Github(os.environ['GITHUB_TOKEN']).get_repo(repo)
    github_pr = github_repo.get_pull(pr_num)
    github_commits = github_pr.get_commits()

    pw_sid = patchwork_get_sid(github_pr.title)
    pw_series = patchwork_get_series(pw_sid)

def init_logging(verbose):
    """
    Initialize the logger and default level is INFO or DEBUG if @verbose
    is True
    """

    global logger

    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    if verbose:
        logger.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s:%(levelname)-8s:%(message)s')
    ch.setFormatter(formatter)

    logger.addHandler(ch)

    logger.info("Logger is initialized: level=%s",
                 logging.getLevelName(logger.getEffectiveLevel()))

def init_config(config_file, verbose=False):
    """
    Read @config_file and initialize the values if necessary
    """

    global config

    config = configparser.ConfigParser()

    config_full_path = os.path.abspath(config_file)
    if not os.path.exists(config_full_path):
        raise FileNotFoundError

    logger.info("Loading config file: %s" % config_full_path)
    config.read(config_full_path)

    # Display current config settings
    if verbose == True:
        for section in config.sections():
            logger.debug("[%s]" % section)
            for (key, val) in config.items(section):
                logger.debug("   %s : %s" % (key, val))

def parse_args():

    parser = argparse.ArgumentParser(
        description="Check patch style in the pull request")
    parser.add_argument('-c', '--config-file', default='config.ini',
                        help='Configuration file')
    parser.add_argument('-l', '--show-test-list', action='store_true',
                        help='List supported CI tests')
    parser.add_argument('-p', '--pr-num', required=True, type=int,
                        help='Pull request number')
    parser.add_argument('-r', '--repo', required=True,
                        help='Github repo in :owner/:repo')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Display debugging info')

    return parser.parse_args()

def main():

    global src_dir

    args = parse_args()

    init_logging(args.verbose)

    init_config(args.config_file, args.verbose)

    init_github(args.repo, args.pr_num)

    # Assume that the current dir is the top source path
    src_dir = os.path.abspath(os.path.curdir)

    # Run CI tests
    try:
        num_fails = run_ci(args)
    except BaseException:

        # Just for debugging purpose, post the result to the github comments
        # TODO: github_commnet()
        raise

    sys.exit(num_fails)

if __name__ == "__main__":
    main()

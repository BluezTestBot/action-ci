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
import shutil
import email.utils
import pathlib
import tarfile
import time
from enum import Enum
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

base_dir = None
src_dir = None
src2_dir = None
ell_dir = None
dist_dir = None

test_suite = {}

PW_BASE_URL = "https://patchwork.kernel.org/api/1.1"

EMAIL_MESSAGE = '''This is automated email and please do not reply to this email!

Dear submitter,

Thank you for submitting the patches to the linux bluetooth mailing list.
This is a CI test results with your patch series:
PW Link:{}

---Test result---

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

GITHUB_COMMENT = '''**{display_name}**
Test ID: {name}
Desc: {desc}
Duration: {elapsed:.2f} seconds
**Result: {status}**


'''

GITHUB_COMMENT_OUTPUT = '''Output:
```
{output}
```
'''

def github_pr_post_comment(test):
    """ Post message to PR page """

    comment = GITHUB_COMMENT.format(name=test.name,
                                    display_name=test.display_name,
                                    desc=test.desc,
                                    status=test.verdict.name,
                                    elapsed=test.elapsed())
    if test.output:
        output = GITHUB_COMMENT_OUTPUT.format(output=test.output)
        comment += output

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

def get_receivers(submitter):
    """
    Get list of receivers
    """

    logger.debug("Get Receivers list")
    email_cfg = config['email']

    receivers = []
    if 'only-maintainers' in email_cfg and email_cfg['only-maintainers'] == 'yes':
        # Send only to the addresses in the 'maintainers'
        maintainers = "".join(email_cfg['maintainers'].splitlines()).split(",")
        receivers.extend(maintainers)
    else:
        # Send to default-to address and submitter
        receivers.append(email_cfg['default-to'])
        receivers.append(submitter)

    return receivers

def get_sender():
    """
    Get Sender from configuration
    """
    email_cfg = config['email']
    return email_cfg['user']

def get_default_to():
    """
    Get Default address which is a mailing list address
    """
    email_cfg = config['email']
    return email_cfg['default-to']

def is_maintainer_only():
    """
    Return True if it is configured to send maintainer-only
    """
    email_cfg = config['email']

    if 'only-maintainers' in email_cfg and email_cfg['only-maintainers'] == 'yes':
        return True

    return False

def compose_email(title, body, submitter, msgid):
    """
    Compose and send email
    """

    receivers = get_receivers(submitter)
    sender = get_sender()

    # Create message
    msg = MIMEMultipart()
    msg['From'] = sender
    msg['To'] = ", ".join(receivers)
    msg['Subject'] = "RE: " + title

    # In case to use default-to address, set Reply-To to mailing list in case
    # submitter reply to the result email.
    if not is_maintainer_only():
        msg['Reply-To'] = get_default_to()

    # Message Header
    msg.add_header('In-Reply-To', msgid)
    msg.add_header('References', msgid)

    logger.debug("Message Body: %s" % body)
    msg.attach(MIMEText(body, 'plain'))

    logger.debug("Mail Message: {}".format(msg))

    # Send email
    send_email(sender, receivers, msg)

def is_workflow_patch(commit):
    """
    If the message contains a word "workflow", then return True.
    This is basically to prevent the workflow patch for github from running
    checkpath and gitlint tests.
    """
    if commit.commit.message.find("workflow:") >= 0:
        return True

    return False

class Verdict(Enum):
    PENDING = 0
    PASS = 1
    FAIL = 2
    ERROR = 3
    SKIP = 4


class CiBase:
    """
    Base class for CI Tests.
    """
    name = None
    display_name = None
    desc = None
    enable = True
    start_time = 0
    end_time = 0

    verdict = Verdict.PENDING
    output = ""

    def success(self):
        self.end_timer()
        self.verdict = Verdict.PASS

    def error(self, msg):
        self.verdict = Verdict.ERROR
        self.output = msg
        self.end_timer()
        raise EndTest

    def skip(self, msg):
        self.verdict = Verdict.SKIP
        self.output = msg
        self.end_timer()
        raise EndTest

    def add_failure(self, msg):
        self.verdict = Verdict.FAIL
        if not self.output:
            self.output = msg
        else:
            self.output += "\n" + msg

    def add_failure_end_test(self, msg):
        self.add_failure(msg)
        self.end_timer()
        raise EndTest

    def start_timer(self):
        self.start_time = time.time()

    def end_timer(self):
        self.end_time = time.time()

    def elapsed(self):
        if self.start_time == 0:
            return 0
        if self.end_time == 0:
            self.end_timer()
        return self.end_time - self.start_time


class CheckPatch(CiBase):
    name = "checkpatch"
    display_name = "CheckPatch"
    desc = "Run checkpatch.pl script with rule in .checkpatch.conf"

    checkpatch_pl = '/usr/bin/checkpatch.pl'

    def config(self):
        """
        Config the test cases.
        """
        logger.debug("Parser configuration")

        if self.name in config:
            if 'bin_path' in config[self.name]:
                self.checkpatch_pl = config[self.name]['bin_path']
        logger.debug("checkpatch_pl = %s" % self.checkpatch_pl)

    def run(self):
        logger.debug("##### Run CheckPatch Test #####")
        self.start_timer()

        self.enable = config_enable(config, self.name)
        self.config()

        # Check if it is disabled.
        if self.enable == False:
            self.skip("Disabled in configuration")

        for commit in github_commits:
            # Skip test if the patch is workflow path
            if is_workflow_patch(commit):
                logger.info("Skip workflow patch")
                continue

            output = self.run_checkpatch(commit.sha)
            if output != None:
                msg = "{}\n{}".format(commit.commit.message.splitlines()[0],
                                      output)
                self.add_failure(msg)

        if self.verdict != Verdict.FAIL:
            self.success()

    def run_checkpatch(self, sha):
        """
        Run checkpatch script with commit sha.
        On success, it returns None.
        On failure, it returns the stderr output string
        """

        output = None
        logger.info("Commit SHA: %s" % sha)

        diff = subprocess.Popen(('git', 'show', '--format=email', sha),
                                stdout=subprocess.PIPE,
                                cwd=src_dir)
        try:
            subprocess.check_output((self.checkpatch_pl, '--no-tree', '-'),
                                    stdin=diff.stdout,
                                    stderr=subprocess.STDOUT,
                                    shell=True,
                                    cwd=src_dir)
        except subprocess.CalledProcessError as ex:
            output = ex.output.decode("utf-8")
            logger.error("checkpatch returned error/warning")
            logger.error("output: %s" % output)

        return output


class GitLint(CiBase):
    name = "gitlint"
    display_name = "GitLint"
    desc = "Run gitlint with rule in .gitlint"

    gitlint_config = '/.gitlint'

    def config(self):
        """
        Config the test cases.
        """
        logger.debug("Parser configuration")

        if self.name in config:
            if 'config_path' in config[self.name]:
                self.gitlint_config = config[self.name]['config_path']
        logger.debug("gitlint_config = %s" % self.gitlint_config)

    def run(self):
        logger.debug("##### Run Gitlint Test #####")
        self.start_timer()

        self.enable = config_enable(config, self.name)
        self.config()

        # Check if it is disabled.
        if self.enable == False:
            self.skip("Disabled in configuration")

        for commit in github_commits:
            # Skip test if the patch is workflow path
            if is_workflow_patch(commit):
                logger.info("Skip workflow patch")
                continue

            output = self.run_gitlint(commit.sha)
            if output != None:
                msg = "{}\n{}".format(commit.commit.message.splitlines()[0],
                                      output)
                self.add_failure(msg)

        if self.verdict != Verdict.FAIL:
            self.success()

    def run_gitlint(self, sha):
        """
        Run checkpatch script with commit sha.
        On success, it returns None.
        On failure, it returns the stderr output string
        """

        output = None
        logger.info("Commit SHA: %s" % sha)

        commit = subprocess.Popen(('git', 'log', '-1', '--pretty=%B', sha),
                                  stdout=subprocess.PIPE,
                                  cwd=src_dir)
        try:
            subprocess.check_output(('gitlint', '-C', self.gitlint_config),
                                    stdin=commit.stdout,
                                    stderr=subprocess.STDOUT,
                                    shell=True,
                                    cwd=src_dir)
        except subprocess.CalledProcessError as ex:
            output = ex.output.decode("utf-8")
            logger.error("gitlint returned error/warning")
            logger.error("output: %s" % output)

        return output


class BuildSetup_ell(CiBase):
    name = "setupell"
    display_name = "Prep - Setup ELL"
    desc = "Clone, build, and install ELL"

    def config(self):
        """
        Configure the test case
        """
        pass

    def run(self):
        logger.debug("##### Run Build: Setup ELL #####")
        self.start_timer()

        # Run only if build is enabled
        self.enable = config_enable(config, "build")
        if self.enable == False:
            self.skip("Build is disabled")

        self.config()

        # bootstrap-configure
        (ret, stdout, stderr) = run_cmd("./bootstrap-configure", cwd=ell_dir)
        if ret:
            self.add_failure_end_test(stderr)

        # make
        (ret, stdout, stderr) = run_cmd("make", cwd=ell_dir)
        if ret:
            self.add_failure_end_test(stderr)

        # install
        (ret, stdout, stderr) = run_cmd("make", "install", cwd=ell_dir)
        if ret:
            self.add_failure_end_test(stderr)

        self.success()


class BuildPrep(CiBase):
    name = "buildprep"
    display_name = "Build - Prep"
    desc = "Prepare environment for build"

    def config(self):
        """
        Config the test case
        """
        pass

    def run(self):
        logger.debug("##### Run Build: Prep #####")
        self.start_timer()

        self.config()

        # Duplicate the src for 2nd build test case
        shutil.copytree(src_dir, src2_dir)
        logger.debug("Duplicate src_dir to src2_dir")

        self.success()


class Build(CiBase):
    name = "build"
    display_name = "Build - Configure"
    desc = "Configure the BlueZ source tree"

    def config(self):
        """
        Configure the test cases.
        """
        pass

    def run(self):
        logger.debug("##### Run Build Test #####")
        self.start_timer()

        self.enable = config_enable(config, self.name)

        self.config()

        # Check if it is disabled.
        if self.enable == False:
            self.skip("Disabled in configuration")

        # bootstrap-configure
        (ret, stdout, stderr) = run_cmd("./bootstrap-configure",
                                        cwd=src_dir)
        if ret:
            self.add_failure_end_test(stderr)

        # At this point, consider test passed here
        self.success()


class BuildMake(CiBase):
    name = "buildmake"
    display_name = "Build - Make"
    desc = "Build the BlueZ source tree"

    def config(self):
        """
        Configure the test cases.
        """
        pass

    def run(self):
        logger.debug("##### Run Build Make Test #####")
        self.start_timer()

        self.enable = config_enable(config, 'build')

        self.config()

        # Check if it is disabled.
        if self.enable == False:
            self.skip("Disabled in configuration")

        # Only run if "checkbuild" success
        if test_suite["build"].verdict != Verdict.PASS:
            logger.info("build test did not pass. skip this test")
            self.skip("build test did not pass")

        # make
        (ret, stdout, stderr) = run_cmd("make", cwd=src_dir)
        if ret:
            self.add_failure_end_test(stderr)

        # At this point, consider test passed here
        self.success()


class MakeCheck(CiBase):
    name = "makecheck"
    display_name = "Make Check"
    desc = "Run \'make check\'"

    def config(self):
        """
        Configure the test cases.
        """
        pass

    def run(self):
        logger.debug("##### Run MakeCheck Test #####")
        self.start_timer()

        self.enable = config_enable(config, self.name)

        self.config()

        # Check if it is disabled.
        if self.enable == False:
            self.skip("Disabled in configuration")

        # Only run if "checkbuild" success
        if test_suite["build"].verdict != Verdict.PASS:
            logger.info("build test is not success. skip this test")
            self.skip("build test is not success")

        # Run make check. Assume the code is already configuared and problem
        # to build.
        (ret, stdout, stderr) = run_cmd("make", "check", cwd=src_dir)
        if ret:
            self.add_failure_end_test(stderr)

        # At this point, consider test passed here
        self.success()


class MakeDist(CiBase):
    name = "makedist"
    display_name = "Make Dist"
    desc = "Run \'make dist\' and build the distribution tarball"

    def config(self):
        """
        Configure the test cases
        """
        pass

    def run(self):
        logger.debug("##### Run MakeDist Test #####")

        global dist_dir

        self.start_timer()

        self.enable = config_enable(config, self.name)

        self.config()

        # Check if it is disabled.
        if self.enable == False:
            self.skip("Disabled in configuration")

        # Only run if "checkbuild" success
        if test_suite["build"].verdict != Verdict.PASS:
            logger.info("build test is not success. skip this test")
            self.skip("build test is not success")

        # Actual test starts:

        # 'make dist' that generates the tarball
        (ret, stdout, stderr) = run_cmd("make", "dist", cwd=src_dir)
        if ret:
            self.add_failure_end_test(stderr)

        # Find tarball
        bluez_tarball_file = self.find_tarball(src_dir)
        if bluez_tarball_file is None:
            self.add_failure_end_test("Unable to find tarball: %s" % src_dir)

        bluez_tarball_file_path = os.path.join(src_dir, bluez_tarball_file)
        if not os.path.exists(bluez_tarball_file_path):
            logger.error("Unable to find BlueZ tarball: %s" %
                                                        bluez_tarball_file_path)
            self.add_failure_end_test("Unable to find BlueZ tarball file")
        logger.debug("BlueZ tarball file path: %s" % bluez_tarball_file_path)

        # Extract tarball
        tf = tarfile.open(bluez_tarball_file_path)
        tf.extractall(path=src_dir)

        # Remove .tar.xz from the file name
        bluez_extract_folder = os.path.splitext(os.path.splitext(
                                                    bluez_tarball_file)[0])[0]
        dist_dir = os.path.join(src_dir, bluez_extract_folder)
        logger.debug("BlueZ tarball extracted to %s" % dist_dir)

        # Extra check
        if not os.path.exists(os.path.join(dist_dir, 'configure')):
            logger.error("Unable to find configure file")
            self.add_failure_end_test("Unable to find configure file")

        # At this point, consider test passed here
        self.success()

    def find_tarball(self, src_dir):
        """
        Find the bluez tarball from the src_dir and return full path, otherwise
        return None
        """
        tarball_file = None

        for fp in pathlib.Path(src_dir).rglob('bluez-*.tar.xz'):
            if fp is not None:
                tarball_file = fp
                break

        logger.debug("BlueZ tarball file: %s" % tarball_file)

        return tarball_file


class MakeDistConfig(CiBase):
    name = "makedistconfig"
    display_name = "Make Dist - Configure"
    desc = "Configure the source from distribution tarball"

    def config(self):
        """
        Configure the test cases
        """
        pass

    def run(self):
        logger.debug("##### Run MakeDist Configure Test #####")
        self.start_timer()

        self.enable = config_enable(config, 'makedist')

        self.config()

        # Check if it is disabled.
        if self.enable == False:
            self.skip("Disabled in configuration")

        # Only run if "build_extell" success
        if test_suite["makedist"].verdict != Verdict.PASS:
            logger.info("makedist test did not pass. skip this test")
            self.skip("makedist test did not pass")

        # Only run if "checkbuild" success
        if test_suite["build"].verdict != Verdict.PASS:
            logger.info("build test is not success. skip this test")
            self.skip("build test is not success")

        # Actual test starts:

        # Configure
        (ret, stdout, stderr) = run_cmd("./configure", cwd=dist_dir)
        if ret:
            self.add_failure_end_test(stderr)

        # At this point, consider test passed here
        self.success()


class MakeDistMake(CiBase):
    name = "makedistmake"
    display_name = "Make Dist - Make"
    desc = "Build the source from distribution tarball"

    def config(self):
        """
        Configure the test cases
        """
        pass

    def run(self):
        logger.debug("##### Run MakeDist Make Test #####")
        self.start_timer()

        self.enable = config_enable(config, 'makedist')

        self.config()

        # Check if it is disabled.
        if self.enable == False:
            self.skip("Disabled in configuration")

        # Only run if "build_extell" success
        if test_suite["makedist"].verdict != Verdict.PASS:
            logger.info("makedist test did not pass. skip this test")
            self.skip("makedist test did not pass")

        # Only run if "checkbuild" success
        if test_suite["build"].verdict != Verdict.PASS:
            logger.info("build test is not success. skip this test")
            self.skip("build test is not success")

        # Actual test starts:

        # make
        (ret, stdout, stderr) = run_cmd("make", cwd=dist_dir)
        if ret:
            self.add_failure_end_test(stderr)

        # At this point, consider test passed here
        self.success()


class BuildExtEll(CiBase):
    name = "build_extell"
    display_name = "Build w/ext ELL - Configure"
    desc = "Configure BlueZ source with \'--enable-external-ell\' configuration"

    def config(self):
        """
        Configure the test cases.
        """
        pass

    def run(self):
        logger.debug("##### Run Build w/exteranl ell - configure Test #####")
        self.start_timer()

        self.enable = config_enable(config, self.name)

        self.config()

        # Check if it is disabled.
        if self.enable == False:
            self.skip("Disabled in configuration")

        # bootstrap-configure
        (ret, stdout, stderr) = run_cmd("./bootstrap-configure",
                                        "--enable-external-ell",
                                        cwd=src2_dir)
        if ret:
            self.add_failure_end_test(stderr)

        # At this point, consider test passed here
        self.success()


class BuildExtEllMake(CiBase):
    name = "build_extell_make"
    display_name = "Build w/ext ELL - Make"
    desc = "Build BlueZ source with \'--enable-external-ell\' configuration"

    def config(self):
        """
        Configure the test cases.
        """
        pass

    def run(self):
        logger.debug("##### Run Build w/exteranl ell - make Test #####")
        self.start_timer()

        self.enable = config_enable(config, 'build_extell')

        self.config()

        # Check if it is disabled.
        if self.enable == False:
            self.skip("Disabled in configuration")

        # Only run if "build_extell" success
        if test_suite["build_extell"].verdict != Verdict.PASS:
            logger.info("build_extell test did not pass. skip this test")
            self.skip("build_extell test did not pass")

        # make
        (ret, stdout, stderr) = run_cmd("make", cwd=src2_dir)
        if ret:
            self.add_failure_end_test(stderr)

        # At this point, consider test passed here
        self.success()


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

        if test.verdict == Verdict.FAIL:
            num_fails += 1

        logger.info(test.name + " result: " + test.verdict.name)
        logger.debug("Post message to github: " + test.output)
        github_pr_post_comment(test)

    return num_fails

TEST_REPORT_PASS = '''##############################
Test: {} - PASS
Desc: {}

'''

TEST_REPORT_FAIL = '''##############################
Test: {} - {}
Desc: {}
Output:
{}

'''

ONELINE_RESULT = '''{test:<30}{result:<10}{elapsed:.2f} seconds\n'''

def report_ci():
    """
    Generate CI result report and send email
    """

    results = "Details\n"
    summary = "Test Summary:\n"

    for test_name, test in test_suite.items():
        if test.verdict == Verdict.PASS:
            results += TEST_REPORT_PASS.format(test.display_name,
                                               test.desc)
            summary += ONELINE_RESULT.format(test=test.display_name,
                                             result='PASS',
                                             elapsed=test.elapsed())
        if test.verdict == Verdict.FAIL:
            results += TEST_REPORT_FAIL.format(test.display_name,
                                               "FAIL",
                                               test.desc,
                                               test.output)
            summary += ONELINE_RESULT.format(test=test.display_name,
                                             result='FAIL',
                                             elapsed=test.elapsed())
        if test.verdict == Verdict.ERROR:
            results += TEST_REPORT_FAIL.format(test.display_name,
                                               "ERROR",
                                               test.desc,
                                               test.output)
            summary += ONELINE_RESULT.format(test=test.display_name,
                                             result='ERROR',
                                             elapsed=test.elapsed())
        if test.verdict == Verdict.SKIP:
            results += TEST_REPORT_FAIL.format(test.display_name,
                                               "SKIPPED",
                                               test.desc,
                                               test.output)
            summary += ONELINE_RESULT.format(test=test.display_name,
                                             result='ERROR',
                                             elapsed=test.elapsed())

    body = EMAIL_MESSAGE.format(pw_series["web_url"], summary + '\n' + results)

    patch = pw_series['patches'][0]

    # Compose email and send
    compose_email(pw_series['name'], body, pw_series['submitter']['email'], patch['msgid'])

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
                        help='Display supported CI tests')
    parser.add_argument('-p', '--pr-num', required=True, type=int,
                        help='Pull request number')
    parser.add_argument('-r', '--repo', required=True,
                        help='Github repo in :owner/:repo')
    parser.add_argument('-s', '--src_path', required=True,
                        help="Path to the BlueZ source")
    parser.add_argument('-e', '--ell-path', default='ell',
                        help='Path to ELL source')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Display debugging info')

    return parser.parse_args()

def main():

    global src_dir, src2_dir, ell_dir, base_dir

    args = parse_args()

    init_logging(args.verbose)

    init_config(args.config_file, args.verbose)

    init_github(args.repo, args.pr_num)

    # Assume that the current dir is the top base path
    base_dir = os.path.abspath(os.path.curdir)
    src_dir = args.src_path
    src2_dir = src_dir + "2"
    ell_dir = args.ell_path

    # Fetch commits in the tree for checkpath and gitlint
    logger.debug("Fetch %d commits in the tree" % github_pr.commits)
    pr_commits = github_pr.commits + 1
    (ret, stdout, stderr) = run_cmd("git", "fetch", "--depth=%d" % pr_commits,
                                    cwd=src_dir)
    if ret:
        logger.error("Failed to fetch the PR commits. error=%s" % stderr)
    else:
        logger.debug("output>>\n%s" % stdout)

    # Run CI tests
    try:
        num_fails = run_ci(args)
    except BaseException:

        # Just for debugging purpose, post the result to the github comments
        # TODO: github_commnet()
        raise

    # Generate email and report
    report_ci()

    sys.exit(num_fails)

if __name__ == "__main__":
    main()

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
pw_series_patch_1 = None

base_dir = None
src_dir = None
src2_dir = None
src3_dir = None
src4_dir = None
src5_dir = None
ell_dir = None

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

def requests_post(url, headers, content):
    """ Helper function to post data to URL """

    resp = requests.post(url, content, headers=headers)
    if resp.status_code != 201:
        raise requests.HTTPError("POST {}".format(resp.status_code))

    return resp

def patchwork_get_series(sid):
    """ Get series detail from patchwork """

    url = PW_BASE_URL + "/series/" + sid
    req = requests_url(url)

    return req.json()

def patchwork_get_patch(patch_id: str):
    """ Get patch detsil from patchwork """

    url = PW_BASE_URL + "/patches/" + patch_id
    req = requests_url(url)

    return req.json()

def patchwork_save_patch(patch, filename):
    """ Save patch to file and return the file path """

    patch_mbox = requests_url(patch["mbox"])

    with open(filename, "wb") as file:
        file.write(patch_mbox.content)

    return filename

def patchwork_save_patch_msg(patch, filename):
    """ Save patch commit message to file and return the file path """

    with open(filename, "wb") as file:
        file.write(bytes(patch['name'], 'utf-8'))
        file.write(b"\n\n")
        file.write(bytes(patch['content'], 'utf-8'))

    return filename

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

def patchwork_post_checks(url, state, target_url, context, description):
    """
    Post checks(test results) to the patchwork site(url)
    """

    logger.debug("URL: %s" % url)

    headers = {}
    if 'PATCHWORK_TOKEN' in os.environ:
        token = os.environ['PATCHWORK_TOKEN']
        headers['Authorization'] = f'Token {token}'

    content = {
        'user': 104215,
        'state': state,
        'target_url': target_url,
        'context': context,
        'description': description
    }

    logger.debug("Content: %s" % content)

    req = requests_post(url, headers, content)

    return req.json()

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

def git_config_add_safe_dir(path):
    """
    Add @path to the safe.directory in git config
    """

    (ret, stdout, stderr) = run_cmd("git", "config", "--global", "--add", "safe.directory", path, cwd=path)
    if ret:
        logger.error("Failed to add %s to safe.directory" % path)
    else:
        logger.debug("%s is added to safe.directory" % path)

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

def config_submit_pw(config, name):
    """
    Check "submit_pw" in config[name]
    Return True if it is specified and value is "yes"
    """

    if name in config:
        if 'submit_pw' in config[name]:
            if config[name]['submit_pw'] == 'yes':
                logger.info("config." + name + ".submit_pw is enabled")
                return True

    logger.info("config." + name + ".submit_pw is disabled")
    return False

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
    WARNING = 5


def patchwork_state(verdict):
    """
    Convert verdict to patchwork state
    """
    if verdict == Verdict.PASS:
        return 1
    if verdict == Verdict.WARNING:
        return 2
    if verdict == Verdict.FAIL:
        return 3

    return 0


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
    submit_pw = False

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

    def warning(self, msg):
        self.verdict = Verdict.WARNING
        self.output = msg
        self.end_timer()

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

    def submit_result(self, patch, verdict, description, url=None, name=None):
        """
        Submit the result to Patchwork
        """

        if self.submit_pw == False:
            logger.info("Submitting PW is disabled. Skipped")
            return

        if url == None:
            url = github_pr.html_url

        if name == None:
            name = self.name

        logger.debug("Submitting the result to Patchwork")
        pw_output = patchwork_post_checks(patch['checks'],
                                          patchwork_state(verdict),
                                          url,
                                          name,
                                          description)
        logger.debug("Submit result\n%s" % pw_output)


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

        self.enable = config_enable(config, self.name)
        self.submit_pw = config_submit_pw(config, self.name)

        if self.name in config:
            if 'bin_path' in config[self.name]:
                self.checkpatch_pl = config[self.name]['bin_path']

            logger.debug("checkpatch_pl = %s" % self.checkpatch_pl)

    def run(self):
        logger.debug("##### Run CheckPatch Test #####")
        self.start_timer()

        self.config()

        # Check if it is disabled.
        if self.enable == False:
            self.submit_result(pw_series_patch_1, Verdict.SKIP,
                               "CheckPatch SKIP(Disabled)")
            self.skip("Disabled in configuration")

        # Use patches from patchwork
        for patch_item in pw_series['patches']:
            logger.debug("patch id: %s" % patch_item['id'])

            patch = patchwork_get_patch(str(patch_item["id"]))

            # Run checkpatch
            (output, error) = self.run_checkpatch(patch)

            # Failed / Warning
            if error != None:
                msg = "{}\n{}".format(patch['name'], error)
                if error.find("WARNING:") != -1:
                    if error.find("ERROR:") != -1:
                        self.submit_result(patch, Verdict.FAIL, msg)
                    else:
                        self.submit_result(patch, Verdict.WARNING, msg)
                else:
                    self.submit_result(patch, Verdict.FAIL, msg)

                self.add_failure(msg)
                continue

            # Warning in output
            if output.find("WARNING:") != -1:
                self.submit_result(patch, Verdict.WARNING, output)
                continue

            # Success
            self.submit_result(patch, Verdict.PASS, "Checkpatch PASS")

        # Overall status
        if self.verdict != Verdict.FAIL:
            self.success()

    def run_checkpatch(self, patch):
        """
        Run checkpatch script with patch from the patchwork.
        It saves to file first and run checkpatch with the saved patch file.

        On success, it returns None.
        On failure, it returns the stderr output string
        """

        output = None
        error = None

        # Save the patch content to file
        filename = os.path.join(src_dir, str(patch['id']) + ".patch")
        logger.debug("Save patch: %s" % filename)
        patch_file = patchwork_save_patch(patch, filename)

        try:
            output = subprocess.check_output((self.checkpatch_pl, '--no-tree',
                                                                patch_file),
                                    stderr=subprocess.STDOUT,
                                    cwd=src_dir)
            output = output.decode("utf-8")

        except subprocess.CalledProcessError as ex:
            error = ex.output.decode("utf-8")
            logger.error("checkpatch.pl returned with error")
            logger.error("output: %s" % error)

        return (output, error)


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

        self.enable = config_enable(config, self.name)
        self.submit_pw = config_submit_pw(config, self.name)

        if self.name in config:
            if 'config_path' in config[self.name]:
                self.gitlint_config = config[self.name]['config_path']

            logger.debug("gitlint_config = %s" % self.gitlint_config)

    def run(self):
        logger.debug("##### Run Gitlint v2 Test #####")
        self.start_timer()

        self.config()

        # Check if it is disabled.
        if self.enable == False:
            self.submit_result(pw_series_patch_1, Verdict.SKIP,
                               "Gitlint SKIP(Disabled)")
            self.skip("Disabled in configuration")

        # Use patches from patchwork
        for patch_item in pw_series['patches']:
            logger.debug("patch_id: %s" % patch_item['id'])

            patch = patchwork_get_patch(str(patch_item['id']))

            # Run gitlint
            output = self.run_gitlint(patch)

            # Failed
            if output != None:
                msg = "{}\n{}".format(patch['name'], output)
                self.submit_result(patch, Verdict.FAIL, msg)
                self.add_failure(msg)
                continue

            # Success
            self.submit_result(patch, Verdict.PASS, "Gitlint PASS")

        # Overall status
        if self.verdict != Verdict.FAIL:
            self.success()

    def run_gitlint(self, patch):
        """
        Run checkpatch script with patch from the patchwork.
        It saves the commit message to the file first and run gitlint with it.

        On success, it returns None.
        On failure, it returns the stderr output string
        """

        output = None

        # Save the patch commit message to file
        filename = os.path.join(src_dir, str(patch['id']) + ".commit_msg")
        logger.debug("Save commit msg: %s" % filename)
        commit_msg_file = patchwork_save_patch_msg(patch, filename)

        try:
            subprocess.check_output(('gitlint', '-C', self.gitlint_config,
                                        "--msg-filename", commit_msg_file),
                                    stderr=subprocess.STDOUT,
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
        logger.debug("Parser configuration")

        self.enable = config_enable(config, "build")
        self.submit_pw = config_submit_pw(config, "build")

    def run(self):
        logger.debug("##### Run Build: Setup ELL #####")
        self.start_timer()

        self.config()

        # Run only if build is enabled
        if self.enable == False:
            self.submit_result(pw_series_patch_1, Verdict.SKIP,
                               "Setup ELL SKIP(Disabled)")
            self.skip("Build is disabled")

        # bootstrap-configure
        (ret, stdout, stderr) = run_cmd("./bootstrap-configure", cwd=ell_dir)
        if ret:
            self.submit_result(pw_series_patch_1, Verdict.FAIL,
                               "Setup ELL - Configuration FAIL: " + stderr)
            self.add_failure_end_test(stderr)

        # make
        (ret, stdout, stderr) = run_cmd("make", cwd=ell_dir)
        if ret:
            self.submit_result(pw_series_patch_1, Verdict.FAIL,
                               "Setup ELL - make FAIL: " + stderr)
            self.add_failure_end_test(stderr)

        # install
        (ret, stdout, stderr) = run_cmd("make", "install", cwd=ell_dir)
        if ret:
            self.submit_result(pw_series_patch_1, Verdict.FAIL,
                               "Setup ELL - make install FAIL: " + stderr)
            self.add_failure_end_test(stderr)

        self.submit_result(pw_series_patch_1, Verdict.PASS, "Setup ELL PASS")
        self.success()


class BuildPrep(CiBase):
    name = "buildprep"
    display_name = "Build - Prep"
    desc = "Prepare environment for build"

    def config(self):
        """
        Config the test case
        """
        logger.debug("Parser configuration")

        self.enable = config_enable(config, "build")
        self.submit_pw = config_submit_pw(config, "build")

    def run(self):
        logger.debug("##### Run Build: Prep #####")
        self.start_timer()

        self.config()

        # Duplicate the src for 2nd build test case
        shutil.copytree(src_dir, src2_dir)
        git_config_add_safe_dir(src2_dir)
        logger.debug("Duplicate src_dir to src2_dir")

        # Duplicate the src for 2nd build test case
        shutil.copytree(src_dir, src3_dir)
        git_config_add_safe_dir(src3_dir)
        logger.debug("Duplicate src_dir to src3_dir")

        # Duplicate the src for make check with valgrind
        shutil.copytree(src_dir, src4_dir)
        git_config_add_safe_dir(src4_dir)
        logger.debug("Duplicate src_dir to src4_dir")

        # Duplicate the src for scan-build
        shutil.copytree(src_dir, src5_dir)
        git_config_add_safe_dir(src5_dir)
        logger.debug("Duplicate src_dir to src5_dir")

        self.submit_result(pw_series_patch_1, Verdict.PASS, "Build Prep PASS")
        self.success()


class Build(CiBase):
    name = "build"
    display_name = "Build - Configure"
    desc = "Configure the BlueZ source tree"

    def config(self):
        """
        Configure the test cases.
        """
        logger.debug("Parser configuration")

        self.enable = config_enable(config, self.name)
        self.submit_pw = config_submit_pw(config, self.name)

    def run(self):
        logger.debug("##### Run Build Test #####")
        self.start_timer()

        self.config()

        # Check if it is disabled.
        if self.enable == False:
            self.submit_result(pw_series_patch_1, Verdict.SKIP,
                               "Build SKIP(Disabled)")
            self.skip("Disabled in configuration")

        # bootstrap-configure
        (ret, stdout, stderr) = run_cmd("./bootstrap-configure",
                                        cwd=src_dir)
        if ret:
            self.submit_result(pw_series_patch_1, Verdict.FAIL,
                               "Build Configuration FAIL: " + stderr)
            self.add_failure_end_test(stderr)

        # At this point, consider test passed here
        self.submit_result(pw_series_patch_1, Verdict.PASS,
                           "Build Configuration PASS")
        self.success()


class BuildMake(CiBase):
    name = "buildmake"
    display_name = "Build - Make"
    desc = "Build the BlueZ source tree"

    def config(self):
        """
        Configure the test cases.
        """
        logger.debug("Parser configuration")

        self.enable = config_enable(config, self.name)
        self.submit_pw = config_submit_pw(config, self.name)

    def run(self):
        logger.debug("##### Run Build Make Test #####")
        self.start_timer()

        self.config()

        # Check if it is disabled.
        if self.enable == False:
            self.submit_result(pw_series_patch_1, Verdict.SKIP,
                               "Make SKIP(Disabled)")
            self.skip("Disabled in configuration")

        # Only run if "checkbuild" success
        if test_suite["build"].verdict != Verdict.PASS:
            logger.info("build test did not pass. skip this test")
            self.submit_result(pw_series_patch_1, Verdict.SKIP,
                               "Make SKIP")
            self.skip("build test did not pass")

        # make
        (ret, stdout, stderr) = run_cmd("make", cwd=src_dir)
        if ret:
            self.submit_result(pw_series_patch_1, Verdict.FAIL,
                               "Make FAIL: " + stderr)
            self.add_failure_end_test(stderr)

        # At this point, consider test passed here
        self.submit_result(pw_series_patch_1, Verdict.PASS, "Make PASS")
        self.success()


class MakeCheck(CiBase):
    name = "makecheck"
    display_name = "Make Check"
    desc = "Run \'make check\'"

    def config(self):
        """
        Configure the test cases.
        """
        logger.debug("Parser configuration")

        self.enable = config_enable(config, self.name)
        self.submit_pw = config_submit_pw(config, self.name)

    def run(self):
        logger.debug("##### Run MakeCheck Test #####")
        self.start_timer()

        self.config()

        # Check if it is disabled.
        if self.enable == False:
            self.submit_result(pw_series_patch_1, Verdict.SKIP,
                               "Make Check SKIP(Disabled)")
            self.skip("Disabled in configuration")

        # Only run if "checkbuild" success
        if test_suite["build"].verdict != Verdict.PASS:
            logger.info("build test is not success. skip this test")
            self.submit_result(pw_series_patch_1, Verdict.SKIP,
                               "Make SKIP")
            self.skip("build test is not success")

        # Run make check. Assume the code is already configuared and problem
        # to build.
        (ret, stdout, stderr) = run_cmd("make", "check", cwd=src_dir)
        if ret:
            self.submit_result(pw_series_patch_1, Verdict.FAIL,
                               "Make Check FAIL: " + stderr)
            self.add_failure_end_test(stderr)

        # At this point, consider test passed here
        self.submit_result(pw_series_patch_1, Verdict.PASS, "Make Check PASS")
        self.success()

class MakeCheckValgrind(CiBase):
    name = "makecheckvalgrind"
    display_name = "Make Check w/Valgrind"
    desc = "Run \'make check\' with Valgrind"

    def config(self):
        """
        Configure the test cases.
        """
        logger.debug("Parser configuration")

        self.enable = config_enable(config, self.name)
        self.submit_pw = config_submit_pw(config, self.name)

    def run(self):
        logger.debug("##### Run MakeCheck w/ Valgrind Test #####")
        self.start_timer()

        self.config()

        # Check if it is disabled.
        if self.enable == False:
            self.submit_result(pw_series_patch_1, Verdict.SKIP,
                               "Make Check Valgrind SKIP(Disabled)")
            self.skip("Disabled in configuration")

        # Only run if "checkbuild" success
        if test_suite["build"].verdict != Verdict.PASS:
            logger.info("build test is not success. skip this test")
            self.submit_result(pw_series_patch_1, Verdict.SKIP,
                               "Make SKIP")
            self.skip("build test is not success")

        # bootstrap-configure without lsan and asan enabled
        (ret, stdout, stderr) = run_cmd("./bootstrap-configure",
                                        "--disable-lsan", "--disable-asan",
                                        cwd=src4_dir)
        if ret:
            self.submit_result(pw_series_patch_1, Verdict.FAIL,
                               "Build Configuration FAIL: " + stderr)
            self.add_failure_end_test(stderr)

        # make
        (ret, stdout, stderr) = run_cmd("make", cwd=src4_dir)
        if ret:
            self.submit_result(pw_series_patch_1, Verdict.FAIL,
                               "Make FAIL: " + stderr)
            self.add_failure_end_test(stderr)

        # Run make check. Assume the code is already configuared and problem
        # to build.
        (ret, stdout, stderr) = run_cmd("make", "check", cwd=src4_dir)
        if ret:
            self.submit_result(pw_series_patch_1, Verdict.FAIL,
                               "Make Check FAIL: " + stderr)
            self.add_failure_end_test(stderr)

        # At this point, consider test passed here
        self.submit_result(pw_series_patch_1, Verdict.PASS, "Make Check PASS")
        self.success()


class MakeDistcheck(CiBase):
    name = "makedistcheck"
    display_name = "Make Distcheck"
    desc = "Run distcheck to check the distribution"

    def config(self):
        """
        Configure the test cases
        """
        logger.debug("Parser configuration")

        self.enable = config_enable(config, self.name)
        self.submit_pw = config_submit_pw(config, self.name)

    def run(self):
        logger.debug("##### Run Make Distcheck Test #####")
        self.start_timer()

        self.config()

        # Check if it is disabled.
        if self.enable == False:
            self.submit_result(pw_series_patch_1, Verdict.SKIP,
                             "Make Distcheck SKIP(Disabled)")
            self.skip("Disabled in configuration")

        # Actual test starts:
        # Configure
        (ret, stdout, stderr) = run_cmd("./bootstrap-configure",
                                        "--disable-asan", "--disable-lsan",
                                        "--disable-ubsan", "--disable-android",
                                        cwd=src_dir)
        if ret:
            self.submit_result(pw_series_patch_1, Verdict.FAIL,
                               "Make Distcheck Configure FAIL: " + stderr)
            self.add_failure_end_test(stderr)

        # Make distcheck
        (ret, stdout, stderr) = run_cmd("fakeroot", "make", "distcheck",
                                        cwd=src_dir)
        if ret:
            self.submit_result(pw_series_patch_1, Verdict.FAIL,
                               "Make Distcheck Make FAIL: " + stderr)
            self.add_failure_end_test(stderr)

        # At this point, consider test passed here
        self.submit_result(pw_series_patch_1, Verdict.PASS,
                           "Make Distcheck PASS")
        self.success()


class BuildExtEll(CiBase):
    name = "build_extell"
    display_name = "Build w/ext ELL - Configure"
    desc = "Configure BlueZ source with \'--enable-external-ell\' configuration"

    def config(self):
        """
        Configure the test cases.
        """
        logger.debug("Parser configuration")

        self.enable = config_enable(config, self.name)
        self.submit_pw = config_submit_pw(config, self.name)

    def run(self):
        logger.debug("##### Run Build w/exteranl ell - configure Test #####")
        self.start_timer()

        self.config()

        # Check if it is disabled.
        if self.enable == False:
            self.submit_result(pw_series_patch_1, Verdict.SKIP,
                               "Build External ELL SKIP(Disabled)")
            self.skip("Disabled in configuration")

        # bootstrap-configure
        (ret, stdout, stderr) = run_cmd("./bootstrap-configure",
                                        "--disable-asan", "--disable-lsan",
                                        "--disable-ubsan", "--disable-android",
                                        "--enable-external-ell",
                                        cwd=src2_dir)
        if ret:
            self.submit_result(pw_series_patch_1, Verdict.FAIL,
                               "Build External ELL FAIL: " + stderr)
            self.add_failure_end_test(stderr)

        # At this point, consider test passed here
        self.submit_result(pw_series_patch_1, Verdict.PASS,
                           "Build External ELL PASS")
        self.success()


class BuildExtEllMake(CiBase):
    name = "build_extell_make"
    display_name = "Build w/ext ELL - Make"
    desc = "Build BlueZ source with \'--enable-external-ell\' configuration"

    def config(self):
        """
        Configure the test cases.
        """
        logger.debug("Parser configuration")

        self.enable = config_enable(config, 'build_extell')
        self.submit_pw = config_submit_pw(config, 'build_extell')

    def run(self):
        logger.debug("##### Run Build w/exteranl ell - make Test #####")
        self.start_timer()

        self.config()

        # Check if it is disabled.
        if self.enable == False:
            self.submit_result(pw_series_patch_1, Verdict.SKIP,
                              "Build With External ELL SKIP(Disabled)")
            self.skip("Disabled in configuration")

        # Only run if "build_extell" success
        if test_suite["build_extell"].verdict != Verdict.PASS:
            logger.info("build_extell test did not pass. skip this test")
            self.submit_result(pw_series_patch_1, Verdict.SKIP,
                             "Build With External ELL SKIP")
            self.skip("build_extell test did not pass")

        # make
        (ret, stdout, stderr) = run_cmd("make", cwd=src2_dir)
        if ret:
            self.submit_result(pw_series_patch_1, Verdict.FAIL,
                               "Build Make with External ELL FAIL: " + stderr)
            self.add_failure_end_test(stderr)

        # At this point, consider test passed here
        self.submit_result(pw_series_patch_1, Verdict.PASS,
                           "Build Make with External ELL PASS")
        self.success()


class IncrementalBuild(CiBase):
    name = "incremental_build"
    display_name = "Incremental Build with patches"
    desc = "Incremental build per patch in the series"

    def config(self):
        """
        Configure the test cases
        """
        logger.debug("Parser configuration")

        self.enable = config_enable(config, 'incremental_build')
        self.submit_pw = config_submit_pw(config, 'incremental_build')

    def run(self):
        logger.debug("##### Run Incremental Build Test #####")
        self.start_timer()

        self.config()

        # Check if it is disabled.
        if self.enable == False:
            self.submit_result(pw_series_patch_1, Verdict.SKIP,
                               "Incremental Build SKIP(Disabled)")
            self.skip("Disabled in configuration")

        # Only run if "checkbuild" success
        if test_suite["build"].verdict != Verdict.PASS:
            logger.info("build test is not success. skip this test")
            self.submit_result(pw_series_patch_1, Verdict.SKIP,
                               "Incremental Build SKIP(Build Fail)")
            self.skip("Build failed")

        # If there is only one patch, no need to run and just return success
        if github_pr.commits == 1:
            logger.debug("Only 1 patch and no need to run here")
            self.success()
            return

        # Make the source base to workflow branch
        (ret, stdout, stderr) = run_cmd("git", "checkout", "origin/workflow",
                                        cwd=src3_dir)

        # Get the patch from the series, apply it and build.
        for patch_item in pw_series['patches']:
            logger.debug("patch id: %s" % patch_item['id'])
            logger.debug("patch name: %s" % patch_item['name'])

            patch = patchwork_get_patch(str(patch_item["id"]))

            # Apply patch
            (output, error) = self.apply_patch(patch)
            if error != None:
                msg = "{}\n{}".format(patch['name'], error)
                self.submit_result(patch, Verdict.FAIL,
                                   "Applying Patch FAIL: " + error)
                self.add_failure_end_test(msg)
            logger.debug("Patch applied")


            # Configure
            (ret, stdout, stderr) = run_cmd("./bootstrap-configure",
                                            "--disable-asan", "--disable-lsan",
                                            "--disable-ubsan",
                                            "--disable-android", cwd=src3_dir)
            if ret:
                self.submit_result(patch, Verdict.FAIL,
                                   "Build Configuration FAIL: " + stderr)
                self.add_failure_end_test(stderr)

            # Make
            (ret, stdout, stderr) = run_cmd("make", cwd=src3_dir)
            if ret:
                self.submit_result(patch, Verdict.FAIL,
                                   "Make FAIL: " + stderr)
                self.add_failure_end_test(stderr)

            # Clean
            (ret, stdout, stderr) = run_cmd("make", "distclean",
                                            cwd=src3_dir)
            if ret:
                self.submit_result(patch, Verdict.FAIL,
                                   "Make Clean FAIL: " + stderr)
                self.add_failure_end_test(stderr)

        # All patch passed the build test
        self.submit_result(pw_series_patch_1, Verdict.PASS, "Pass")
        self.success()

    def apply_patch(self, patch):
        """
        Save the patch and apply to the source tree
        """

        output = None
        error = None

        # Save the patch content to file
        filename = os.path.join(src3_dir, str(patch['id']) + ".patch")
        logger.debug("Save patch: %s" % filename)
        patch_file = patchwork_save_patch(patch, filename)

        try:
            output = subprocess.check_output(('git', 'am', patch_file),
                                             stderr=subprocess.STDOUT,
                                             cwd=src3_dir)
            output = output.decode("utf-8")

        except subprocess.CalledProcessError as ex:
            error = ex.output.decode("utf-8")
            logger.error("git am returned with error")
            logger.error("output: %s" % error)

        return (output, error)


SCAN_BUILD_NOTE = '''*****************************************************************************
The bugs reported by the scan-build may or may not be caused by your patches.
Please check the list and fix the bugs if they are caused by your patch.
*****************************************************************************
'''

class ScanBuild(CiBase):
    name = "scan_build"
    display_name = "Scan Build"
    desc = "Run Scan Build with patches"

    def config(self):
        """
        Configure the test cases
        """
        logger.debug("Parser configuration")

        self.enable = config_enable(config, self.name)
        self.submit_pw = config_submit_pw(config, self.name)

    def run(self):
        logger.debug("##### Run Scan Build Test #####")
        self.start_timer()

        self.config()

        # Check if it is disabled.
        if self.enable == False:
            self.submit_result(pw_series_patch_1, Verdict.SKIP,
                               "Scan Build SKIP(Disabled)")
            self.skip("Disabled in configuration")

        # Only run if "checkbuild" success
        if test_suite["build"].verdict != Verdict.PASS:
            logger.info("build test is not success. skip this test")
            self.submit_result(pw_series_patch_1, Verdict.SKIP,
                               "Scan Build SKIP(Build Fail)")
            self.skip("Build failed")

        # Create the branch to come back later
        (ret, stdout, stderr) = run_cmd("git", "checkout", "-b", "patched",
                                        cwd=src5_dir)
        if ret:
            self.submit_result(pw_series_patch_1, Verdict.FAIL,
                               "checkout patched branch FAIL: " + stderr)
            self.add_failure_end_test(stderr)

        # Make the source base to workflow branch
        (ret, stdout, stderr) = run_cmd("git", "checkout", "origin/workflow",
                                        cwd=src5_dir)
        if ret:
            self.submit_result(pw_series_patch_1, Verdict.FAIL,
                               "Checkout origin/workflow FAIL: " + stderr)
            self.add_failure_end_test(stderr)

        # Configure the build once
        (ret, stdout, stderr) = run_cmd("./bootstrap-configure",
                                        "--disable-asan", "--disable-lsan",
                                        "--disable-ubsan", "--disable-android",
                                        cwd=src5_dir)
        if ret:
            self.submit_result(pw_series_patch_1, Verdict.FAIL,
                               "Build Configuration FAIL: " + stderr)
            self.add_failure_end_test(stderr)

        # Make the baseline before running with patches
        (ret, stdout, stderr) = run_cmd("scan-build", "make", cwd=src5_dir)
        if ret:
            self.submit_result(pw_series_patch_1, Verdict.FAIL,
                               "Scan Build FAIL: " + stderr)
            self.add_failure_end_test(stderr)

        # Checkout to the patched source
        (ret, stdout, stderr) = run_cmd("git", "checkout", "patched",
                                        cwd=src5_dir)
        if ret:
            self.submit_result(pw_series_patch_1, Verdict.FAIL,
                               "Checkout to Patched source FAIL: " + stderr)
            self.add_failure_end_test(stderr)

        # Run scan build again with patched source
        (ret, stdout, stderr) = run_cmd("scan-build", "make", cwd=src5_dir)
        if ret:
            self.submit_result(pw_series_patch_1, Verdict.FAIL,
                               "Scan Build w/patched FAIL: " + stderr)
            self.add_failure_end_test(stderr)

        # Process the result
        # If stderr is not empty, some bugs are found. consider it warning
        # instead of failure since it may not caused by the patch.
        if stderr != "":
            # Add warning
            self.submit_result(pw_series_patch_1, Verdict.WARNING,
                               "Scan-Build: " + stderr)
            self.warning(SCAN_BUILD_NOTE + stderr)
            return

        self.submit_result(pw_series_patch_1, Verdict.PASS, "Pass")
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

def all_test_passed():
    """
    Return True if all test passed, otherwise return False
    """

    for test_name, test in test_suite.items():
        if test.verdict != Verdict.PASS:
            return False

    return True

def report_ci():
    """
    Generate CI result report and send email
    """

    results = ""
    summary = "Test Summary:\n"

    if all_test_passed() == False:
        results = "Details\n"

    for test_name, test in test_suite.items():
        if test.verdict == Verdict.PASS:
            # No need to add result of passed tests to simplify the email
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
                                             result='SKIPPED',
                                             elapsed=test.elapsed())
        if test.verdict == Verdict.WARNING:
            results += TEST_REPORT_FAIL.format(test.display_name,
                                               "WARNING",
                                               test.desc,
                                               test.output)
            summary += ONELINE_RESULT.format(test=test.display_name,
                                             result='WARNING',
                                             elapsed=test.elapsed())

    body = EMAIL_MESSAGE.format(pw_series["web_url"], summary + '\n' + results)

    patch = pw_series['patches'][0]

    if config_enable(config, 'email'):
        # Compose email and send
        compose_email(pw_series['name'], body, pw_series['submitter']['email'],
                      patch['msgid'])
    else:
        logger.info("Email is disabled. Skip sending email")
        logger.debug("Message Body:\n%s" % body)

def init_github(repo, pr_num):
    """
    Initialize github object
    """

    global github_repo
    global github_pr
    global github_commits
    global pw_sid
    global pw_series
    global pw_series_patch_1

    github_repo = Github(os.environ['GITHUB_TOKEN']).get_repo(repo)
    github_pr = github_repo.get_pull(pr_num)
    github_commits = github_pr.get_commits()

    pw_sid = patchwork_get_sid(github_pr.title)
    pw_series = patchwork_get_series(pw_sid)
    pw_series_patch_1 = patchwork_get_patch(str(pw_series['patches'][0]['id']))

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

    global src_dir, src2_dir, src3_dir, src4_dir, src5_dir, ell_dir, base_dir

    args = parse_args()

    init_logging(args.verbose)

    init_config(args.config_file, args.verbose)

    init_github(args.repo, args.pr_num)

    # Assume that the current dir is the top base path
    base_dir = os.path.abspath(os.path.curdir)
    src_dir = args.src_path
    src2_dir = src_dir + "2"
    src3_dir = src_dir + "3"
    src4_dir = src_dir + "4"
    src5_dir = src_dir + "5"
    ell_dir = args.ell_path

    # Add source dir to git safe dir
    git_config_add_safe_dir(src_dir)

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

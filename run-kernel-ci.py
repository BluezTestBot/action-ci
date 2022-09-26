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
import time
from enum import Enum
from github import Github
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

# Globals
logger = None
config = None

github_repo = None
github_pr = None
github_commits = None

pw_sid = None
pw_series = None
pw_series_patch_1 = None

src_dir = None
src2_dir = None
bluez_dir = None
output_dir = None

test_suite = {}

# Test Runner Context
test_runner_context = None

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
        logger.error("Unable to find the series_id from title %s" % pr_title)
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

    logger.debug("Send email with result")

    if 'EMAIL_TOKEN' not in os.environ:
        logger.warning("missing EMAIL_TOKEN. Skip sending email")
        return

    logger.debug("EMAIL TOKEN is set in Environment")

    try:
        session = smtplib.SMTP(email_cfg['server'], int(email_cfg['port']))
        logger.debug("SMTP session is created")
        session.ehlo()
        if 'starttls' not in email_cfg or email_cfg['starttls'] == 'yes':
            session.starttls()
            logger.debug("SMTP TLS is set")
        session.ehlo()
        session.login(sender, os.environ['EMAIL_TOKEN'])
        logger.debug("SMTP EMAIL_TOKEN is set")
        session.sendmail(sender, receiver, msg.as_string())
        logger.info("Successfully sent email")
    except Exception as e:
        logger.error("Exception: {}".format(e))
    finally:
        session.quit()

    logger.info("Sending email done")

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

def compose_email(title, body, submitter, msgid, attachments=[]):
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

    # Attachment
    # logger.debug("Attachment count=%d" % len(attachments))
    # for logfile in attachments:
    #     logfile_base = os.path.basename(logfile)
    #     with open(logfile, "rb") as f:
    #         part = MIMEApplication(f.read(), Name=logfile_base)
    #     part['Content-Disposition'] = 'attachment; filename="%s"' % logfile_base
    #     msg.attach(part)
    #     logger.debug("Attached file: %s(%s)" % (logfile, logfile_base))

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

    def add_success(self, msg):
        self.verdict = Verdict.PASS
        if not self.output:
            self.output = msg
        else:
            self.output += "\n" + msg
        self.end_timer()

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
        self.end_timer()

    def add_failure_end_test(self, msg):
        self.add_failure(msg)
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
    ignore = None
    checkpatch_cmd = []

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

            if 'ignore' in config[self.name]:
                self.ignore = config[self.name]['ignore']
            logger.debug("checkpatch ignore: %s" % self.ignore)

        logger.debug("checkpatch_pl = %s" % self.checkpatch_pl)

        self.checkpatch_cmd.append(self.checkpatch_pl)
        self.checkpatch_cmd.append('--show-types')

        if self.ignore != None:
            self.checkpatch_cmd.append('--ignore')
            self.checkpatch_cmd.append(self.ignore)

    def run(self):
        logger.debug("##### Run CheckPatch Test #####")
        self.start_timer()

        self.config()

        # Check if it is disabled.
        if self.enable == False:
            self.submit_result(pw_series_patch_1, Verdict.SKIP,
                               "CheckPatch SKIP(Disabled)")
            self.skip("Disabled in configuration")

        for patch_item in pw_series['patches']:
            logger.debug("patch id: %s" % patch_item['id'])

            patch = patchwork_get_patch(str(patch_item['id']))

            # Run checkpatch
            (output, error) = self.run_checkpatch(patch)

            # Failed / Warning
            if error != None:
                msg = "{}\{}".format(patch['name'], error)
                if error.find("WARNING: ") != -1:
                    if error.find("ERROR: ") != -1:
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

        copied_cmd = self.checkpatch_cmd.copy()
        copied_cmd.append(patch_file)

        logger.debug("CMD: %s" % copied_cmd)

        try:
            output = subprocess.check_output(copied_cmd,
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
        logger.debug("##### Run Gitlint Test #####")
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


class SubjectPrefix(CiBase):
    name = "subjectprefix"
    display_name = "SubjectPrefix"
    desc = "Check subject contains \"Bluetooth\" prefix"

    def config(self):
        """
        Config the test cases.
        """
        logger.debug("Parser configuration")

        self.enable = config_enable(config, self.name)
        self.submit_pw = config_submit_pw(config, self.name)

    def run(self):
        logger.debug("##### Run SubjectPrefix Test #####")
        self.start_timer()

        self.config()

        # Check if it is disabled.
        if self.enable == False:
            self.submit_result(pw_series_patch_1, Verdict.SKIP,
                               "SubjectPrefix SKIP(Disabled)")
            self.skip("Disabled in configuration")

        for patch_item in pw_series['patches']:
            logger.debug("patch id: %s" % patch_item['id'])

            patch = patchwork_get_patch(str(patch_item['id']))

            # Check if the name contains "Bluetooth: "
            s = patch['name'].find('Bluetooth: ')
            if s < 0:
                # No Bluetooth prefix found. Instead of failing it,
                # set the result to WARNING just enough to get an
                # attention
                msg = "\"Bluetooth: \" is not specified in the subject"
                self.submit_result(patch, Verdict.FAIL, msg)
                self.add_failure(msg)
                continue

            self.submit_result(patch, Verdict.PASS, "PASS")

        # Overall status
        if self.verdict != Verdict.FAIL:
            self.success()


class BuildKernel(CiBase):
    name = "buildkernel"
    display_name = "BuildKernel"
    desc = "Build Kernel with minimal configuration supports Bluetooth"

    build_config = "/bluetooth_build.config"
    simple_build = False

    def config(self):
        """
        Configure the test cases.
        """
        logger.debug("Parser configuration")

        self.enable = config_enable(config, self.name)
        self.submit_pw = config_submit_pw(config, self.name)

        if self.name in config:
            if 'config_path' in config[self.name]:
                self.build_config = config[self.name]['config_path']
            if 'simple_build' in config[self.name]:
                if config[self.name]['simple_build'] == 'yes':
                    logger.info("config.simple_build" + " is enabled")
                    self.simple_build = True
        logger.debug("build_config = %s" % self.build_config)

    def run(self):
        logger.debug("##### Run BuildKernel Test #####")
        self.start_timer()

        self.config()

        # Check if it is disabled.
        if self.enable == False:
            self.submit_result(pw_series_patch_1, Verdict.SKIP,
                               "Build Kernel SKIP(Disabled)")
            self.skip("Disabled in configuration")

        # Copy bluetooth build config
        logger.info("Copy config file: %s" % self.build_config)
        (ret, stdout, stderr) = run_cmd("cp", self.build_config, ".config",
                                        cwd=src_dir)
        if ret:
            self.submit_result(pw_series_patch_1, Verdict.FAIL,
                               "Build Kernel Copy Config FAIL: " + stderr)
            self.add_failure_end_test(stderr)

        # Update .config
        logger.info("Run make olddepconfig")
        (ret, stdout, stderr) = run_cmd("make", "olddefconfig", cwd=src_dir)
        if ret:
            self.submit_result(pw_series_patch_1, Verdict.FAIL,
                               "Build Kernel Make olddefconfig FAIL: " + stderr)
            self.add_failure_end_test(stderr)

        # make
        if self.simple_build:
            (ret, stdout, stderr) = run_cmd("make", "-j2", "W=1", "net/bluetooth/",
                                            cwd=src_dir)
            if ret:
                self.submit_result(pw_series_patch_1, Verdict.FAIL,
                                   "Build Kernel make FAIL: " + stderr)
                self.add_failure_end_test(stderr)

            (ret, stdout, stderr) = run_cmd("make", "-j2", "W=1", "drivers/bluetooth/",
                                            cwd=src_dir)
            if ret:
                self.submit_result(pw_series_patch_1, Verdict.FAIL,
                                   "Build Kernel make FAIL: " + stderr)
                self.add_failure_end_test(stderr)
        else:
            # full build
            (ret, stdout, stderr) = run_cmd("make", "-j2", cwd=src_dir)
            if ret:
                self.submit_result(pw_series_patch_1, Verdict.FAIL,
                                   "Build Kernel make FAIL: " + stderr)
                self.add_failure_end_test(stderr)

        # At this point, consider test passed here
        self.submit_result(pw_series_patch_1, Verdict.PASS, "Build Kernel PASS")
        self.success()


class BuildKernel32(CiBase):
    name = "buildkernel32"
    display_name = "BuildKernel32"
    desc = "Build 32bit Kernel with minimal configuration supports Bluetooth"

    build_config = "/bluetooth_build.config"
    simple_build = False

    def config(self):
        """
        Configure the test cases.
        """
        logger.debug("Parser configuration")

        self.enable = config_enable(config, self.name)
        self.submit_pw = config_submit_pw(config, self.name)

        if self.name in config:
            if 'config_path' in config[self.name]:
                self.build_config = config[self.name]['config_path']
            if 'simple_build' in config[self.name]:
                if config[self.name]['simple_build'] == 'yes':
                    logger.info("config.simple_build" + " is enabled")
                    self.simple_build = True
        logger.debug("build_config = %s" % self.build_config)

    def run(self):
        logger.debug("##### Run BuildKernel32 Test #####")
        self.start_timer()

        self.config()

        # Check if it is disabled.
        if self.enable == False:
            self.submit_result(pw_series_patch_1, Verdict.SKIP,
                               "Build Kernel32 SKIP(Disabled)")
            self.skip("Disabled in configuration")

        # Copy bluetooth build config
        logger.info("Copy config file: %s" % self.build_config)
        (ret, stdout, stderr) = run_cmd("cp", self.build_config, ".config",
                                        cwd=src_dir)
        if ret:
            self.submit_result(pw_series_patch_1, Verdict.FAIL,
                               "Build Kernel32 Copy Config FAIL: " + stderr)
            self.add_failure_end_test(stderr)

        # Update .config
        logger.info("Run make ARCH=i386 olddepconfig")
        (ret, stdout, stderr) = run_cmd("make", "ARCH=i386", "olddefconfig", cwd=src_dir)
        if ret:
            self.submit_result(pw_series_patch_1, Verdict.FAIL,
                               "Build Kernel32 Make olddefconfig FAIL: " + stderr)
            self.add_failure_end_test(stderr)

        # make
        if self.simple_build:
            (ret, stdout, stderr) = run_cmd("make", "ARCH=i386", "-j2", "W=1", "net/bluetooth/",
                                            cwd=src_dir)
            if ret:
                self.submit_result(pw_series_patch_1, Verdict.FAIL,
                                   "Build Kernel32 make FAIL: " + stderr)
                self.add_failure_end_test(stderr)

            (ret, stdout, stderr) = run_cmd("make", "ARCH=i386", "-j2", "W=1", "drivers/bluetooth/",
                                            cwd=src_dir)
            if ret:
                self.submit_result(pw_series_patch_1, Verdict.FAIL,
                                   "Build Kernel32 make FAIL: " + stderr)
                self.add_failure_end_test(stderr)
        else:
            # full build
            (ret, stdout, stderr) = run_cmd("make", "ARCH=i386", "-j2", cwd=src_dir)
            if ret:
                self.submit_result(pw_series_patch_1, Verdict.FAIL,
                                   "Build Kernel32 make FAIL: " + stderr)
                self.add_failure_end_test(stderr)

        # At this point, consider test passed here
        self.submit_result(pw_series_patch_1, Verdict.PASS, "Build Kernel32 PASS")
        self.success()


class IncrementalBuild(CiBase):
    name = "incremental_build"
    display_name = "Incremental Build with patches"
    desc = "Incremental build per patch in the series"

    simple_build = False

    def config(self):
        """
        Configure the test cases.
        """
        logger.debug("Parser configuration")

        self.enable = config_enable(config, self.name)
        self.submit_pw = config_submit_pw(config, self.name)

        if self.name in config:
            if 'config_path' in config[self.name]:
                self.build_config = config[self.name]['config_path']
            if 'simple_build' in config[self.name]:
                if config[self.name]['simple_build'] == 'yes':
                    logger.info("config.simple_build" + " is enabled")
                    self.simple_build = True
        logger.debug("build_config = %s" % self.build_config)

    def run(self):
        logger.debug("##### Run IncrementalBuild Test #####")
        self.start_timer()

        self.config()

        # Check if it is disabled.
        if self.enable == False:
            self.submit_result(pw_series_patch_1, Verdict.SKIP,
                               "Incremental Build Kernel SKIP(Disabled)")
            self.skip("Disabled in configuration")

        # Run only if "BuildKernel" success
        if test_suite["buildkernel"].verdict != Verdict.PASS:
            logger.info("buildkernel test is not success. skip this test")
            self.submit_result(pw_series_patch_1, Verdict.SKIP,
                                "Incremental Build Kernel SKIP(Build Fail)")
            self.skip("buildkernel failed")

        # If there is only one patch, no need to run and just return success
        if github_pr.commits == 1:
            logger.debug("Only 1 patch and no need to run here again")
            self.success()
            return

        # Set the source to the base workflow branch
        (ret, stdout, stderr) = run_cmd("git", "fetch", "--depth=2", "origin",
                                        "workflow", cwd=src2_dir)
        if ret:
            msg = "Error: \n"
            if stderr != None:
                msg += "{}".format(stderr)
            self.add_failure_end_test(msg)

        (ret, stdout, stderr) = run_cmd("git", "checkout", "origin/workflow",
                                        cwd=src2_dir)
        if ret:
            msg = "Error: \n"
            if stderr != None:
                msg += "{}".format(stderr)
            self.add_failure_end_test(msg)

        # Get the patch from the series, apply it and build.
        for patch_item in pw_series['patches']:
            logger.debug("patch id: %s" % patch_item['id'])

            patch = patchwork_get_patch(str(patch_item['id']))

            # Apply patch
            (output, error) = self.apply_patch(patch, src2_dir)
            if error != None:
                msg = "{}\n{}".format(patch['name'], error)
                self.submit_result(patch, Verdict.FAIL,
                                   "Applying patch FAIL: " + error)
                self.add_failure_end_test(msg)
            logger.debug("Patch Applied")

            # Copy bluetooth build config
            logger.info("Copy config file: %s" % self.build_config)
            (ret, stdout, stderr) = run_cmd("cp", self.build_config, ".config",
                                            cwd=src2_dir)
            if ret:
                self.submit_result(pw_series_patch_1, Verdict.FAIL,
                                   "Build Kernel Copy Config FAIL: " + stderr)
                self.add_failure_end_test(stderr)

            # Update .config
            logger.info("Run make olddefconfig")
            (ret, stdout, stderr) = run_cmd("make", "olddefconfig", cwd=src2_dir)
            if ret:
                self.submit_result(pw_series_patch_1, Verdict.FAIL,
                                   "Make olddefconfig FAIL: " + stderr)
                self.add_failure_end_test(stderr)

            # make
            if self.simple_build:
                (ret, stdout, stderr) = run_cmd("make", "-j2", "W=1", "net/bluetooth/",
                                                cwd=src2_dir)
                if ret:
                    self.submit_result(pw_series_patch_1, Verdict.FAIL,
                                       "Build Kernel make FAIL: " + stderr)
                    self.add_failure_end_test(stderr)

                (ret, stdout, stderr) = run_cmd("make", "-j2", "W=1", "drivers/bluetooth/",
                                                cwd=src2_dir)
                if ret:
                    self.submit_result(pw_series_patch_1, Verdict.FAIL,
                                       "Build Kernel make FAIL: " + stderr)
                    self.add_failure_end_test(stderr)
            else:
                # full build
                (ret, stdout, stderr) = run_cmd("make", "-j2", cwd=src2_dir)
                if ret:
                    self.submit_result(pw_series_patch_1, Verdict.FAIL,
                                       "Build Kernel make FAIL: " + stderr)
                    self.add_failure_end_test(stderr)

        # All patches passed the build test
        self.submit_result(pw_series_patch_1, Verdict.PASS, "Pass")
        self.success()

    def apply_patch(self, patch, target_dir):
        """
        Save the patch and apply to the source tree
        """

        output = None
        error = None

        # Save the patch to file
        filename = os.path.join(target_dir, str(patch['id']) + ".patch")
        logger.debug("Save patch: %s" % filename)
        patch_file = patchwork_save_patch(patch, filename)

        try:
            output = subprocess.check_output(('git', 'am', patch_file),
                                             stderr=subprocess.STDOUT,
                                             cwd=target_dir)
            output = output.decode("utf-8")
        except subprocess.CalledProcessError as ex:
            error = ex.output.decode("utf-8")
            logger.error("git am returned with error")
            logger.error("output: %s" % error)

        return (output, error)


class TestRunnerSetup(CiBase):
    name = "testrunnersetup"
    display_name = "TestRunner: Setup"
    desc = "Setup environment for running Test Runner"

    test_list = []
    runner = None
    kernel_img = None
    result_logs = []

    def config(self):
        """
        Configure the test cases.
        """
        logger.debug("Parser configuration")

        self.enable = config_enable(config, self.name)
        self.submit_pw = config_submit_pw(config, self.name)

        default_test_list = ["bnep-tester",
                             "iso-tester",
                             "l2cap-tester",
                             "mgmt-tester",
                             "rfcomm-tester",
                             "sco-tester",
                             "ioctl-tester",
                             "smp-tester",
                             "userchan-tester"]

        if self.name in config:
            if 'test_list' in config[self.name]:
                self.test_list = "".join(config[self.name]['test_list'].splitlines()).split(",")
            else:
                self.test_list = default_test_list
        logger.debug("test list = %s" % self.test_list)

    def build_bluez(self):
        """
        Build BlueZ and return the path of test-runner otherwiase None
        """
        logger.debug("Build BlueZ Source")

        # Configure BlueZ
        logger.info("Configure the BlueZ source")
        (ret, stdout, stderr) = run_cmd("./bootstrap-configure",
                                        "--disable-lsan", "--disable-asan",
                                        cwd=bluez_dir)
        if ret:
            logger.error("Unable to configure the bluez")
            return None

        # make
        logger.info("Run make")
        (ret, stdout, stderr) = run_cmd("make", "-j2", cwd=bluez_dir)
        if ret:
            logger.error("Unable to build bluez")
            return None

        tester_path = os.path.join(bluez_dir, "tools/test-runner")
        if not os.path.exists(tester_path):
            logger.error("Unable to find the test-runner binary")
            return None

        logger.debug("test-runner path: %s" % tester_path)
        return tester_path

    def build_kernel(self):
        """
        Build Bluetooth-Next with tester.config and return the path of
        kernel image file otherwise None
        """
        logger.debug("Build Bluetooth-Next Source with tester config")

        # Default tester config
        # TODO: Pick up from the BlueZ Source doc/tester.config
        build_config = "/tester.config"

        # Copy bluetooth build config
        logger.info("Copy tester config file: %s" % build_config)
        (ret, stdout, stderr) = run_cmd("cp", build_config, ".config",
                                        cwd=src_dir)
        if ret:
            logger.error("Unable to copy config file")
            return None

        # Update .config
        logger.info("Run make olddefconfig")
        (ret, stdout, stderr) = run_cmd("make", "olddefconfig", cwd=src_dir)
        if ret:
            logger.error("Unable to run make olddefconfig")
            return None

        # make
        (ret, stdout, stderr) = run_cmd("make", "-j2", cwd=src_dir)
        if ret:
            logger.error("Unable to make the image")
            return None

        # Retrun image file
        bzimage_path = os.path.join(src_dir, "arch/x86/boot/bzImage")
        if not os.path.exists(bzimage_path):
            logger.error("Unable to find bzImage from: %s" % bzimage_path)
            return None

        logger.debug("bzImage file from: %s" % bzimage_path)
        return bzimage_path

    def run(self):
        logger.debug("##### Run TestRunner Setup #####")
        self.start_timer()

        global test_runner_context

        self.config()

        # Check if it is disabled.
        if self.enable == False:
            self.submit_result(pw_series_patch_1, Verdict.SKIP,
                               "Test Runner Setup SKIP(Disabled)")
            self.skip("Disabled in configuration")

        # Build BlueZ
        self.runner = self.build_bluez()
        if self.runner == None:
            self.submit_result(pw_series_patch_1, Verdict.FAIL,
                               "Test Runner Setup BlueZ FAIL")
            self.add_failure_end_test("Unable to build BlueZ source")

        # Build Kernel image for tester
        self.kernel_img = self.build_kernel()
        if self.kernel_img == None:
            self.submit_result(pw_series_patch_1, Verdict.FAIL,
                               "Test Runner Setup Build Kernel FAIL")
            self.add_failure_end_test("Unable to build Kernel image for tester")

        # At this point, consider test passed here
        test_runner_context = self
        self.submit_result(pw_series_patch_1, Verdict.PASS,
                           "Test Runner Setup PASS")
        self.success()


class TestRunner(CiBase):
    name = "testrunner"
    display_name = "TestRunner: "
    desc = "Run test-runner with "
    tester = None
    test_summary = None

    def __init__(self, tester="default"):
        """
        Init test object for tester
        """
        self.tester = tester
        self.name = self.name + tester
        self.display_name = self.display_name + tester
        self.desc = self.desc + tester

    def config(self):
        """
        Configure the test cases.
        """
        logger.debug("Parser configuration")

        # Use the config from the testrunnersetup
        self.submit_pw = config_submit_pw(config, "testrunnersetup")

    def save_result_log(self, log):
        """
        Save the test result(log) to the file
        """

        logfile_path = os.path.join(output_dir, self.tester + ".log")
        logger.debug("Save the result to the file: %s" % logfile_path)
        with open(logfile_path, 'w') as output_file:
            output_file.write(log)

        # Save the logfile path to the context for later use (attachment)
        test_runner_context.result_logs.append(logfile_path)

    def parse_result(self, results):
        """
        Parse the result line generated by the tester and returns the dict
        with total, passed, failed, not run, otherwise None.
        """

        regex = r"^Total:\s+(?P<total>\d+)\,\s+Passed:\s+(?P<passed>\d+)\s+\(.+\%\)\,\s+Failed:\s+(?P<failed>\d+)\,\s+Not\s+Run:\s+(?P<notrun>\d+)"
        matches = re.search(regex, results)
        if not matches:
            logger.error("Unable to parse the result line: %s" % results)
            return None

        logger.debug(matches.groupdict().items())
        return matches.groupdict()

    def run(self):
        logger.debug("##### Run TestRunner - %s #####" % self.tester)
        self.start_timer()

        self.config()

        # Check if testrunner is ready
        if test_runner_context == None:
            logger.debug("Test Runner is Not Ready. Skip testing %s" % self.tester)
            self.submit_result(pw_series_patch_1, Verdict.SKIP,
                               "Test Runner SKIP(Not Ready)")
            self.skip("Test Runner is Not Ready")

        # Get Tester Path
        tester_path = os.path.join(bluez_dir, "tools", self.tester)
        if not os.path.exists(tester_path):
            self.submit_result(pw_series_patch_1, Verdict.FAIL,
                               "Test Runner FAIL(No Tester Found)")
            self.add_failure_end_test("Unable to find tester: %s" % tester_path)

        # Running Tester
        (ret, stdout, stderr) = run_cmd(test_runner_context.runner, "-k", test_runner_context.kernel_img, "--", tester_path)
        if ret:
            logger.error("Failed to run tester: ret: %d" % ret)
            self.submit_result(pw_series_patch_1, Verdict.FAIL,
                               "Test Runner " + self.name + " FAIL: " + stderr)
            self.add_failure_end_test("Failed to run tester")

        # Remove terminal color macro
        stdout_clean = re.sub(r"\x1B\[\d?\;?\d+m", "", stdout)

        # Save the result to the log file
        self.save_result_log(stdout_clean)

        check_fail = False
        failed_tc = []

        # verdict result
        for line in stdout_clean.splitlines():
            if re.search(r"^Total: ", line):
                self.test_summary = line

                result = self.parse_result(line)
                if result["failed"] != "0":
                    logger.error("Some test failed - Return failure")
                    self.submit_result(pw_series_patch_1, Verdict.FAIL, line)
                    self.add_failure(line)

                    # Adding Failed test cases
                    if len(failed_tc):
                        self.add_failure("\nFailed Test Cases")
                        for tc in failed_tc:
                            self.add_failure(tc)

                    # No need to check failure
                    check_fail = False
                    return

                self.submit_result(pw_series_patch_1, Verdict.PASS, line)
                self.add_success(line)
                return

            if re.search(r"^Test Summary", line):
                logger.debug("Start to check failure in the line")
                check_fail = True

            if check_fail and re.search(r"Failed", line):
                logger.debug("Found a failed test case")
                failed_tc.append(line)

            if check_fail and re.search(r"Timed out", line):
                logger.debug("Found a failed test case: Timed out")
                failed_tc.append(line)

        self.add_failure("No test result found")


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

        # skip for test runner class
        if testcase.__name__ == "TestRunner":
            logger.debug("Skip for test runner class for now")
            break

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

    if test_runner_context:
        logger.debug("Running for tester")
        for tester in test_runner_context.test_list:
            logger.debug("running tester: %s" % tester)
            test = TestRunner(tester)
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

TEST_REPORT =  '''##############################
Test: {} - {} - {:.2f} seconds
{}
{}

'''

ONELINE_RESULT = '''{test:<30}{result:<10}{elapsed:.2f} seconds\n'''

def all_test_passed():
    """
    Return True if all tests passed, otherwise return False
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
            results += TEST_REPORT.format(test.display_name, "FAIL",
                                          test.elapsed(),
                                          test.desc,
                                          test.output)
            summary += ONELINE_RESULT.format(test=test.display_name,
                                             result='FAIL',
                                             elapsed=test.elapsed())
        if test.verdict == Verdict.ERROR:
            results += TEST_REPORT.format(test.display_name, "ERROR",
                                          test.elapsed(),
                                          test.desc,
                                          test.output)
            summary += ONELINE_RESULT.format(test=test.display_name,
                                             result='ERROR',
                                             elapsed=test.elapsed())
        if test.verdict == Verdict.SKIP:
            results += TEST_REPORT.format(test.display_name, "SKIPPED",
                                          test.elapsed(),
                                          test.desc,
                                          test.output)
            summary += ONELINE_RESULT.format(test=test.display_name,
                                             result='ERROR',
                                             elapsed=test.elapsed())

    body = EMAIL_MESSAGE.format(pw_series["web_url"], summary + '\n' + results)

    patch = pw_series['patches'][0]

    if config_enable(config, 'email'):
        # Compose email and send
        compose_email(pw_series['name'], body, pw_series['submitter']['email'],
                      patch['msgid'], test_runner_context.result_logs)
    else:
        logger.info("Email is disabled. Skip sending it")
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
    parser.add_argument('-s', '--src-path', required=True,
                        help='Path of bluetooth kernel source')
    parser.add_argument('-b', '--bluez-path', required=True,
                        help='Path of bluez source')
    parser.add_argument('-o', '--output-path', required=True,
                        help='Path for tester outputs')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Display debugging info')

    return parser.parse_args()

def main():

    global src_dir, src2_dir, bluez_dir, output_dir

    args = parse_args()

    init_logging(args.verbose)

    init_config(args.config_file, args.verbose)

    init_github(args.repo, args.pr_num)

    src_dir = args.src_path
    src2_dir = src_dir + "2"

    # Duplicate the src for 2nd build test case
    shutil.copytree(src_dir, src2_dir)
    logger.debug("Duplicate src_dir to src2_dir")

    bluez_dir = args.bluez_path
    output_dir = os.path.abspath(args.output_path)
    if not os.path.exists(output_dir):
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        logger.debug("Created outputdirectory: %s" % output_dir)

    logger.debug("Fetch commits in the tree: %d commits" % github_pr.commits)
    pr_commits = github_pr.commits
    logger.debug("Expand the commits in PR to the src: %d" % pr_commits)
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

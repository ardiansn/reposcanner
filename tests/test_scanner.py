"""End-to-end tests for soc_repo_scanner.py (standard library only).

Each test runs the script as a subprocess inside a TemporaryDirectory, so nothing is
left behind. PATH is limited to a private bin folder holding only `git` and, when a
test needs one, a fake `gitleaks`, so results do not depend on the scanners
installed on the machine.
"""
import glob
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

SCRIPT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "soc_repo_scanner.py")

# Synthetic secret, built at runtime so the source never contains a real-looking token
SYNTHETIC_SECRET_VALUE = "dummy_test_" + "secret_999"
SYNTHETIC_SECRET_LINE = "api_key = '" + SYNTHETIC_SECRET_VALUE + "'\n"

# Fake gitleaks: writes a report with one finding, or fails without writing one
FAKE_GITLEAKS_FINDING = """
import json, sys
report = sys.argv[sys.argv.index("--report-path") + 1]
with open(report, "w") as f:
    json.dump([{"RuleID": "generic-api-key", "File": "synthetic.txt"}], f)
sys.exit(1)
"""
FAKE_GITLEAKS_FAILURE = """
import sys
sys.stderr.write("synthetic gitleaks failure\\n")
sys.exit(2)
"""


class ScannerCliTest(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        self.cwd = os.path.join(self.tmp, "work")
        self.target = os.path.join(self.tmp, "target")
        self.bin = os.path.join(self.tmp, "bin")
        for path in (self.cwd, self.target, self.bin):
            os.makedirs(path)
        git = shutil.which("git")
        if git:
            os.symlink(git, os.path.join(self.bin, "git"))

    def tearDown(self):
        self._tmp.cleanup()

    def write_target(self, content):
        with open(os.path.join(self.target, "config.txt"), "w", encoding="utf-8") as f:
            f.write(content)

    def add_fake_tool(self, name, body):
        path = os.path.join(self.bin, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write("#!" + sys.executable + "\n" + body)
        os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)

    def run_scanner(self, *args):
        env = dict(os.environ, PATH=self.bin)
        return subprocess.run(
            [sys.executable, SCRIPT] + list(args),
            cwd=self.cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=120,
        )

    def assert_exit(self, result, expected):
        self.assertEqual(result.returncode, expected,
                         f"exit {result.returncode}, expected {expected}\n"
                         f"--- stdout ---\n{result.stdout}\n--- stderr ---\n{result.stderr}")

    # 1
    def test_default_run_with_finding_exits_0_and_writes_report(self):
        self.write_target(SYNTHETIC_SECRET_LINE)
        result = self.run_scanner("--local", self.target)
        self.assert_exit(result, 0)
        logs = glob.glob(os.path.join(self.cwd, "log", "soc_repo_scanner-local_target-*.log"))
        self.assertEqual(len(logs), 1)
        with open(logs[0], encoding="utf-8") as f:
            self.assertIn(SYNTHETIC_SECRET_VALUE, f.read())

    # 2
    def test_fail_on_findings_clean_directory_exits_0(self):
        self.write_target("nothing sensitive here\n")
        result = self.run_scanner("--local", self.target, "--fail-on-findings")
        self.assert_exit(result, 0)

    # 3
    def test_fail_on_findings_with_finding_exits_1(self):
        self.write_target(SYNTHETIC_SECRET_LINE)
        result = self.run_scanner("--local", self.target, "--fail-on-findings")
        self.assert_exit(result, 1)

    # 4
    def test_strict_missing_local_path_exits_3(self):
        result = self.run_scanner("--local", os.path.join(self.tmp, "missing"), "--strict")
        self.assert_exit(result, 3)

    # 5
    def test_default_missing_local_path_exits_0(self):
        result = self.run_scanner("--local", os.path.join(self.tmp, "missing"))
        self.assert_exit(result, 0)

    # 6
    def test_output_dir_receives_reports_and_no_cwd_log(self):
        self.write_target(SYNTHETIC_SECRET_LINE)
        self.add_fake_tool("gitleaks", FAKE_GITLEAKS_FINDING)
        out = os.path.join(self.tmp, "reports", "nested")
        result = self.run_scanner("--local", self.target, "--output-dir", out)
        self.assert_exit(result, 0)
        self.assertEqual(len(glob.glob(os.path.join(out, "soc_repo_scanner-*.log"))), 1)
        self.assertEqual(len(glob.glob(os.path.join(out, "gitleaks-report-*.json"))), 1)
        self.assertFalse(os.path.exists(os.path.join(self.cwd, "log")))

    # 7
    def test_invalid_flag_exits_2(self):
        result = self.run_scanner("--local", self.target, "--no-such-flag")
        self.assert_exit(result, 2)

    # Additional coverage for scanner results and precedence

    def test_fail_on_findings_counts_gitleaks_results(self):
        self.write_target("nothing sensitive here\n")
        self.add_fake_tool("gitleaks", FAKE_GITLEAKS_FINDING)
        result = self.run_scanner("--local", self.target, "--fail-on-findings")
        self.assert_exit(result, 1)

    def test_strict_scanner_failure_exits_3(self):
        self.write_target("nothing sensitive here\n")
        self.add_fake_tool("gitleaks", FAKE_GITLEAKS_FAILURE)
        result = self.run_scanner("--local", self.target, "--strict")
        self.assert_exit(result, 3)

    def test_strict_error_takes_precedence_over_findings(self):
        self.write_target(SYNTHETIC_SECRET_LINE)
        self.add_fake_tool("gitleaks", FAKE_GITLEAKS_FAILURE)
        result = self.run_scanner("--local", self.target, "--strict", "--fail-on-findings")
        self.assert_exit(result, 3)

    def test_strict_and_fail_on_findings_clean_run_exits_0(self):
        self.write_target("nothing sensitive here\n")
        result = self.run_scanner("--local", self.target, "--strict", "--fail-on-findings")
        self.assert_exit(result, 0)

    def test_strict_unwritable_output_dir_exits_3(self):
        self.write_target("nothing sensitive here\n")
        blocker = os.path.join(self.tmp, "not-a-dir")
        with open(blocker, "w") as f:
            f.write("file in the way\n")
        result = self.run_scanner("--local", self.target, "--strict", "--output-dir", blocker)
        self.assert_exit(result, 3)

    def test_output_dir_inside_target_is_not_scanned(self):
        self.write_target("nothing sensitive here\n")
        out = os.path.join(self.target, "reports")
        os.makedirs(out)
        with open(os.path.join(out, "old.log"), "w", encoding="utf-8") as f:
            f.write(SYNTHETIC_SECRET_LINE)
        result = self.run_scanner("--local", self.target, "--output-dir", out, "--fail-on-findings")
        self.assert_exit(result, 0)


if __name__ == "__main__":
    unittest.main()

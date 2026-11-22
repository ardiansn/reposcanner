"""Tests for soc_repo_scanner.py (standard library only).

Each CLI test runs the script as a subprocess inside a TemporaryDirectory, so nothing
is left behind. PATH is limited to a private bin folder holding only `git` and, when a
test needs them, fake `gitleaks` / `trufflehog` scripts, so results do not depend on
the scanners installed on the machine.
"""
import glob
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

SCRIPT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "soc_repo_scanner.py")

# Synthetic secrets, built at runtime so the source never contains a real-looking token
SYNTHETIC_SECRET_VALUE = "dummy_test_" + "secret_999"
SYNTHETIC_SECRET_LINE = "api_key = '" + SYNTHETIC_SECRET_VALUE + "'\n"
OTHER_SECRET_VALUE = "other_test_" + "value_12345"
OTHER_SECRET_LINE = "password = '" + OTHER_SECRET_VALUE + "'\n"
FIXTURE_FILE = os.path.join("fixtures", "sample.txt")

# Fake gitleaks: reports one finding in <source>/fixtures/sample.txt, or fails without a report
FAKE_GITLEAKS_FINDING = """
import json, os, sys
report = sys.argv[sys.argv.index("--report-path") + 1]
source = sys.argv[sys.argv.index("--source") + 1]
secret = "dummy_test_" + "secret_999"
finding = {"RuleID": "generic-api-key", "File": os.path.join(source, "fixtures", "sample.txt"),
           "StartLine": 7, "Commit": "", "Match": "api_key = " + secret, "Secret": secret,
           "Line": "    api_key = " + secret + "  # copied by some versions"}
with open(report, "w") as f:
    json.dump([finding], f)
sys.exit(1)
"""
FAKE_GITLEAKS_FAILURE = """
import sys
sys.stderr.write("synthetic gitleaks failure\\n")
sys.exit(2)
"""
# Fake trufflehog (filesystem mode): one JSON line for <path>/fixtures/sample.txt. Like real
# versions, it also copies the secret into SecretParts and ExtraData.
FAKE_TRUFFLEHOG_FINDING = """
import json, os, sys
path = sys.argv[2]
secret = "dummy_test_" + "secret_999"
print(json.dumps({"DetectorName": "Generic", "Raw": secret, "RawV2": secret + ":extra",
                  "SecretParts": {"key": secret}, "ExtraData": {"note": "seen " + secret},
                  "SourceMetadata": {"Data": {"Filesystem": {"file": os.path.join(path, "fixtures", "sample.txt"), "line": 7}}}}))
"""


def load_scanner_module():
    """Imports the script for unit tests without writing __pycache__ next to it."""
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("soc_repo_scanner", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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

    def write_target(self, content, name="config.txt"):
        path = os.path.join(self.target, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)

    def read_single(self, pattern):
        matches = glob.glob(pattern)
        self.assertEqual(len(matches), 1, f"expected one file matching {pattern}, found {matches}")
        with open(matches[0], encoding="utf-8") as f:
            return f.read()

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

    # v1.9: allowlisting (.reposcannerignore / --ignore-file)

    def test_ignore_path_glob_suppresses_findings(self):
        self.write_target(SYNTHETIC_SECRET_LINE, name=FIXTURE_FILE)
        self.write_target("# test fixtures\n\nfixtures/*\n", name=".reposcannerignore")
        result = self.run_scanner("--local", self.target, "--fail-on-findings")
        self.assert_exit(result, 0)
        self.assertIn("0 secret finding(s) (1 ignored)", result.stdout)

    def test_ignore_regex_suppresses_only_matching_findings(self):
        self.write_target(SYNTHETIC_SECRET_LINE, name="a.txt")
        self.write_target(OTHER_SECRET_LINE, name="b.txt")
        self.write_target("regex:^dummy_test_\n", name=".reposcannerignore")
        result = self.run_scanner("--local", self.target, "--fail-on-findings")
        self.assert_exit(result, 1)
        self.assertIn("1 secret finding(s) (1 ignored)", result.stdout)
        self.assertIn(OTHER_SECRET_VALUE, result.stdout)
        self.assertNotIn(SYNTHETIC_SECRET_VALUE, result.stdout)

    def test_ignore_file_option_replaces_target_file(self):
        self.write_target(SYNTHETIC_SECRET_LINE)
        self.write_target("path:*\n", name=".reposcannerignore")
        custom = os.path.join(self.tmp, "empty-rules")
        with open(custom, "w", encoding="utf-8") as f:
            f.write("# no rules\n")
        result = self.run_scanner("--local", self.target, "--ignore-file", custom, "--fail-on-findings")
        self.assert_exit(result, 1)

    def test_strict_missing_ignore_file_exits_3(self):
        self.write_target("nothing sensitive here\n")
        result = self.run_scanner("--local", self.target, "--strict",
                                  "--ignore-file", os.path.join(self.tmp, "missing-rules"))
        self.assert_exit(result, 3)

    def test_strict_invalid_regex_rule_exits_3(self):
        self.write_target("nothing sensitive here\n")
        self.write_target("regex:[unclosed\n", name=".reposcannerignore")
        result = self.run_scanner("--local", self.target, "--strict")
        self.assert_exit(result, 3)
        self.assertIn("Invalid regex on line 1", result.stdout)

    def test_ignore_rules_apply_to_gitleaks_results(self):
        self.write_target("nothing sensitive here\n")
        self.write_target("path:fixtures/*\n", name=".reposcannerignore")
        self.add_fake_tool("gitleaks", FAKE_GITLEAKS_FINDING)
        result = self.run_scanner("--local", self.target, "--fail-on-findings")
        self.assert_exit(result, 0)
        self.assertIn("Gitleaks finished, no findings (1 ignored)", result.stdout)

    def test_ignore_rules_apply_to_trufflehog_results(self):
        self.write_target("nothing sensitive here\n")
        self.write_target("regex:^dummy_test_\n", name=".reposcannerignore")
        self.add_fake_tool("trufflehog", FAKE_TRUFFLEHOG_FINDING)
        result = self.run_scanner("--local", self.target, "--fail-on-findings")
        self.assert_exit(result, 0)
        self.assertIn("TruffleHog finished, no findings (1 ignored)", result.stdout)

    def make_git_repo_with_ignore_file(self):
        """Commits a synthetic secret plus a .reposcannerignore that allowlists it; returns a file:// URL."""
        self.write_target(SYNTHETIC_SECRET_LINE)
        self.write_target("regex:^dummy_test_\n", name=".reposcannerignore")
        git = ["git", "-C", self.target, "-c", "user.name=Test", "-c", "user.email=test@example.com"]
        for cmd in (["init", "-q"], ["add", "."], ["commit", "-q", "-m", "synthetic fixture"]):
            subprocess.run(git + cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return "file://" + self.target

    @unittest.skipUnless(shutil.which("git"), "git is required for URL mode")
    def test_url_mode_skips_target_ignore_file_by_default(self):
        url = self.make_git_repo_with_ignore_file()
        result = self.run_scanner(url, "--fail-on-findings")
        self.assert_exit(result, 1)
        self.assertIn("Skipping target .reposcannerignore in URL mode", result.stdout)
        self.assertIn(SYNTHETIC_SECRET_VALUE, result.stdout)

    @unittest.skipUnless(shutil.which("git"), "git is required for URL mode")
    def test_url_mode_trust_target_ignore_applies_rules(self):
        url = self.make_git_repo_with_ignore_file()
        result = self.run_scanner(url, "--fail-on-findings", "--trust-target-ignore")
        self.assert_exit(result, 0)
        self.assertIn("0 secret finding(s) (1 ignored)", result.stdout)

    # v1.9: --redact

    def test_redact_masks_report_and_scanner_sidecars(self):
        self.write_target(SYNTHETIC_SECRET_LINE)
        self.add_fake_tool("gitleaks", FAKE_GITLEAKS_FINDING)
        self.add_fake_tool("trufflehog", FAKE_TRUFFLEHOG_FINDING)
        out = os.path.join(self.tmp, "out")
        result = self.run_scanner("--local", self.target, "--redact", "--output-dir", out)
        self.assert_exit(result, 0)
        masked = SYNTHETIC_SECRET_VALUE[:4] + "****" + SYNTHETIC_SECRET_VALUE[-4:]

        log = self.read_single(os.path.join(out, "soc_repo_scanner-*.log"))
        self.assertNotIn(SYNTHETIC_SECRET_VALUE, log)
        self.assertIn(f"[config.txt] Line 1 [KV]: api_key = {masked}", log)

        gitleaks = json.loads(self.read_single(os.path.join(out, "gitleaks-report-*.json")))[0]
        self.assertEqual(gitleaks["Secret"], masked)
        self.assertNotIn(SYNTHETIC_SECRET_VALUE, gitleaks["Match"])
        self.assertTrue(gitleaks["File"].endswith(FIXTURE_FILE))
        self.assertEqual((gitleaks["StartLine"], gitleaks["RuleID"]), (7, "generic-api-key"))

        trufflehog = json.loads(self.read_single(os.path.join(out, "trufflehog-report-*.json")))
        self.assertEqual(trufflehog["Raw"], masked)
        self.assertEqual(trufflehog["SecretParts"]["key"], masked)
        self.assertNotIn(SYNTHETIC_SECRET_VALUE, trufflehog["RawV2"])
        self.assertTrue(trufflehog["SourceMetadata"]["Data"]["Filesystem"]["file"].endswith(FIXTURE_FILE))
        self.assertEqual(trufflehog["SourceMetadata"]["Data"]["Filesystem"]["line"], 7)

        for path in glob.glob(os.path.join(out, "*")):
            with open(path, encoding="utf-8") as f:
                self.assertNotIn(SYNTHETIC_SECRET_VALUE, f.read(), path)

    def test_default_run_keeps_plaintext_values(self):
        self.write_target(SYNTHETIC_SECRET_LINE)
        self.add_fake_tool("gitleaks", FAKE_GITLEAKS_FINDING)
        out = os.path.join(self.tmp, "out")
        result = self.run_scanner("--local", self.target, "--output-dir", out)
        self.assert_exit(result, 0)
        log = self.read_single(os.path.join(out, "soc_repo_scanner-*.log"))
        self.assertIn(f"[config.txt] Line 1 [KV]: api_key = {SYNTHETIC_SECRET_VALUE}", log)
        gitleaks = json.loads(self.read_single(os.path.join(out, "gitleaks-report-*.json")))[0]
        self.assertEqual(gitleaks["Secret"], SYNTHETIC_SECRET_VALUE)

    # v1.10: IPv4 + IPv6 detection
    def test_mixed_ipv4_ipv6_scan_sorts_versions(self):
        self.write_target(
            "primary = 2001:db8::1\n"
            "backup  = 10.0.0.5\n"
            "mapped  = ::ffff:8.8.8.8\n"
            "iface   = fe80::1%eth0\n"
            "Server is 192.0.2.10.\n"
            "local   = ::1 127.0.0.1\n",
            name="hosts.conf",
        )
        out = os.path.join(self.tmp, "out")
        result = self.run_scanner("--local", self.target, "--output-dir", out)
        self.assert_exit(result, 0)
        self.assertNotIn("Traceback", result.stdout + result.stderr)
        log = self.read_single(os.path.join(out, "soc_repo_scanner-*.log"))
        section = log.split("[2] INFRASTRUCTURE EXPOSURE (IP ADDRESS):", 1)[1].split("[3]", 1)[0]
        reported = [line.strip()[2:] for line in section.splitlines() if line.strip().startswith("- ")]
        self.assertEqual(reported, ["8.8.8.8", "10.0.0.5", "192.0.2.10", "2001:db8::1", "fe80::1"])


class MaskingTest(unittest.TestCase):
    """Unit tests for the masking helpers."""

    @classmethod
    def setUpClass(cls):
        cls.scanner = load_scanner_module()

    def test_mask_secret_long_value_keeps_first_and_last_four(self):
        self.assertEqual(self.scanner.mask_secret("abcdefghiwxyz"), "abcd****wxyz")
        self.assertEqual(self.scanner.mask_secret("123456789"), "1234****6789")

    def test_mask_secret_short_value_fully_hidden(self):
        self.assertEqual(self.scanner.mask_secret("12345678"), "********")
        self.assertEqual(self.scanner.mask_secret("ab"), "********")

    def test_mask_spans_merges_overlapping_secrets(self):
        line = "key=" + OTHER_SECRET_VALUE + " end"
        start = line.index(OTHER_SECRET_VALUE)
        span = (start, start + len(OTHER_SECRET_VALUE))
        masked = self.scanner.mask_spans(line, [span, (start + 2, span[1])])
        self.assertEqual(masked, "key=" + self.scanner.mask_secret(OTHER_SECRET_VALUE) + " end")


class IpDetectionTest(unittest.TestCase):
    """Unit tests for IPv4/IPv6 extraction and validation."""

    @classmethod
    def setUpClass(cls):
        cls.scanner = load_scanner_module()

    def assert_ips(self, line, expected):
        self.assertEqual(self.scanner.extract_ips(line), set(expected), repr(line))

    def test_ipv6_full_compressed_ula_and_link_local_detected(self):
        self.assert_ips("addr = 2001:0db8:85a3:0000:0000:8a2e:0370:7334", ["2001:db8:85a3::8a2e:370:7334"])
        self.assert_ips("dns = 2001:db8::1", ["2001:db8::1"])
        self.assert_ips("dns = 2606:4700:4700::1111", ["2606:4700:4700::1111"])
        self.assert_ips("ula = fd00::1", ["fd00::1"])
        self.assert_ips("ll = fe80::1", ["fe80::1"])
        self.assert_ips("ll = [2001:db8::2]:443", ["2001:db8::2"])

    def test_ipv6_zone_id_is_stripped(self):
        self.assert_ips("ll = fe80::1%eth0", ["fe80::1"])
        self.assert_ips("Bound to fe80::1%en0.", ["fe80::1"])

    def test_loopback_and_unspecified_excluded(self):
        for line in ("::1", "127.0.0.1", "127.8.9.10", "::", "0.0.0.0", "::ffff:127.0.0.1"):
            self.assert_ips(line, [])

    def test_invalid_and_non_ip_strings_rejected(self):
        for line in ("999.999.999.999", "01.02.03.004", "010.0.0.1", "::ffff:010.0.0.1", "at 12:34:56", "2024-01-01T12:34:56Z", "mac aa:bb:cc:dd:ee:ff",
                     "Foo::abc", "std::vector", "v1.2.3.4", "1.2.3.4.5", "oid 1.3.6.1.4.1",
                     "1:2:3:4:5:6:7:8:9"):
            self.assert_ips(line, [])

    def test_ipv4_contexts_detected(self):
        self.assert_ips("Server is 10.0.0.1.", ["10.0.0.1"])
        self.assert_ips("url = http://10.0.0.1/api", ["10.0.0.1"])
        self.assert_ips("HOST=10.0.0.1", ["10.0.0.1"])
        self.assert_ips("host: 10.0.0.1:8080", ["10.0.0.1"])

    def test_ipv4_mapped_ipv6_reported_once_as_ipv4(self):
        self.assert_ips("mapped = ::ffff:8.8.8.8", ["8.8.8.8"])
        self.assert_ips("::ffff:8.8.8.8 and 8.8.8.8", ["8.8.8.8"])

    def test_mixed_versions_on_one_line(self):
        self.assert_ips("ips: 10.0.0.1, fe80::2, 2001:db8::3", ["10.0.0.1", "fe80::2", "2001:db8::3"])


if __name__ == "__main__":
    unittest.main()

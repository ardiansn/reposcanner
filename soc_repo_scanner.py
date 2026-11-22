import os
import re
import json
import fnmatch
import subprocess
import argparse
import ipaddress
import shutil
import stat
import sys
import traceback
from datetime import datetime
from urllib.parse import urlsplit

# ==========================================
# REGEX CONFIGURATION (HYBRID) - VERSION 1.10
# ==========================================
# IPv4: nothing word-like or a dot before it (rejects v1.2.3.4, 1.2.3.4.5, 1.3.6.1.4.1); a trailing full stop is allowed
REGEX_IPV4 = re.compile(r'(?<![A-Za-z0-9_.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?!\d|\.\d)')
# IPv6 candidates: colon-separated hex groups with an optional embedded IPv4 tail and %zone suffix.
# Not glued to a word, colon or dot, so Foo::abc and slices of longer runs are skipped.
# The regex only finds candidates; extract_ips() requires '::' or 8 groups and ipaddress decides validity.
REGEX_IPV6 = re.compile(
    r'(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}'
    r'(?:(?:[0-9]{1,3}\.){3}[0-9]{1,3}|[0-9A-Fa-f]{1,4})?'
    r'(?:%[0-9A-Za-z_]+(?:[.-][0-9A-Za-z_]+)*)?'
    r'(?![\w:]|\.\w)')
REGEX_EMAIL = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
REGEX_URL_USERINFO = re.compile(r'://[^/\s@]*@')

# TIER 1: Generic keywords that MUST be in assignment format (variable = value)
# Keyword may carry a suffix (SECRET_KEY, API_KEY_PROD) and a closing quote ("api_key": ...);
# '==' comparisons are rejected, ':=' is allowed.
REGEX_SECRETS_KV = re.compile(
    r'(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|jwt|webhook)'
    r'[\w-]*["\']?\s*(?::=?|=(?!=))\s*["\']?([^\s"\'`,;]+)["\']?',
    re.IGNORECASE
)

# TIER 2: Direct detection without assignment (High-confidence patterns)
# Case-sensitive so plain text like "basic auth" / "bearer token" is not flagged;
# Bearer/Basic tokens must be long enough and contain non-letter characters.
REGEX_SECRETS_DIRECT = re.compile(
    r'(BEGIN (RSA|OPENSSH|EC|DSA)? ?PRIVATE KEY|(?:mongodb(?:\+srv)?|redis)://\S+|'
    r'Bearer\s+(?=[A-Za-z0-9\-._~+/]*[0-9\-._~+/])[A-Za-z0-9\-._~+/]{16,}=*|'
    r'(?i:authorization):\s+.*|'
    r'Basic\s+(?=[A-Za-z0-9+/]*[0-9+/])[A-Za-z0-9+/]{8,}={0,2}|ssh-rsa\s+[A-Za-z0-9+/]+|'
    r'A(K|S)IA[A-Z0-9]{16}|ghp_[a-zA-Z0-9]{36}|glpat-[a-zA-Z0-9\-]{20})'
)

# File extensions skipped during static text scanning
IGNORE_EXT = ['.png', '.jpg', '.jpeg', '.gif', '.mp4', '.zip', '.tar', '.gz', '.pdf', '.exe', '.dll', '.so']

# Allowlist file looked up in the root of the scanned target (unless --ignore-file is given)
DEFAULT_IGNORE_FILE = ".reposcannerignore"

# Fields holding the raw secret in scanner reports. With --redact, these values are masked
# wherever they appear in an entry, since newer scanner versions copy them into other fields
# (e.g. TruffleHog's SecretParts).
GITLEAKS_SECRET_FIELDS = ("Match", "Secret")
TRUFFLEHOG_SECRET_FIELDS = ("Raw", "RawV2", "SecretParts")

# Exit codes (only used when --fail-on-findings / --strict are set; otherwise the script exits 0)
EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_OPERATIONAL_ERROR = 3

class DualLogger(object):
    """Duplicates terminal output into a log file."""
    def __init__(self, filename):
        self.terminal = sys.stdout
        self.log = open(filename, "a", encoding="utf-8")

    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)

    def flush(self):
        self.terminal.flush()
        self.log.flush()

class IgnoreRules(object):
    """Allowlist rules from .reposcannerignore: path globs and regexes on secret values/lines."""
    def __init__(self):
        self.path_globs = []
        self.regexes = []

    def is_ignored(self, relpath, *texts):
        if relpath:
            relpath = relpath.replace(os.sep, '/')
            if any(fnmatch.fnmatch(relpath, glob) for glob in self.path_globs):
                return True
        return any(regex.search(text) for regex in self.regexes for text in texts if text)

class ScanContext(object):
    """Run-wide settings and counters: findings and operational errors drive the exit code."""
    def __init__(self, output_dir, ignore_file=None, redact=False, trust_target_ignore=True):
        self.output_dir = output_dir
        self.ignore_file = ignore_file
        self.redact = redact
        # False in URL mode unless --trust-target-ignore: a cloned repo must not allowlist its own secrets
        self.trust_target_ignore = trust_target_ignore
        self.rules = IgnoreRules()
        self.findings = 0
        self.ignored = 0
        self.errors = 0

    def error(self, message):
        print(message)
        self.errors += 1

def mask_secret(value):
    """Keeps the first and last 4 characters of values longer than 8 characters; hides shorter ones fully."""
    if len(value) > 8:
        return value[:4] + "****" + value[-4:]
    return "********"

def mask_spans(line, spans):
    """Masks the given (start, end) spans of a line; overlapping spans are merged first."""
    merged = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    for start, end in reversed(merged):
        line = line[:start] + mask_secret(line[start:end]) + line[end:]
    return line

def string_values(value):
    """All non-empty strings in a JSON value (nested dicts and lists included)."""
    if isinstance(value, dict):
        return [s for v in value.values() for s in string_values(v)]
    if isinstance(value, list):
        return [s for v in value for s in string_values(v)]
    return [value] if isinstance(value, str) and value else []

def redact_entry(entry, secret_fields):
    """Masks every occurrence of the entry's secret values in all of its string fields."""
    secrets = sorted({s for field in secret_fields for s in string_values(entry.get(field))}, key=len, reverse=True)

    def scrub(value):
        if isinstance(value, dict):
            return {k: scrub(v) for k, v in value.items()}
        if isinstance(value, list):
            return [scrub(v) for v in value]
        if isinstance(value, str):
            # Longest first, so a secret that contains another one is masked as a whole
            for secret in secrets:
                if secret in value:
                    value = value.replace(secret, mask_secret(secret))
        return value

    return scrub(entry)

def ignored_suffix(count):
    return f" ({count} ignored)" if count else ""

def to_relpath(path, root):
    """Path relative to the target root, as used by path: rules (scanner reports may hold absolute paths)."""
    if not path:
        return None
    if os.path.isabs(path):
        return os.path.relpath(path, os.path.abspath(root))
    return path

def parse_ip(text):
    """Returns the ipaddress object for text, or None if it is not a valid IPv4/IPv6 address.
    A %zone suffix (fe80::1%eth0) is dropped first because Python < 3.9 cannot parse it.
    IPv4-mapped IPv6 (::ffff:8.8.8.8) becomes its IPv4 address, so it is reported once and
    prints the same on every Python version.
    Dotted octets with a leading zero (010.0.0.1) are rejected explicitly: some Python 3.7/3.8
    releases accept them, newer ones do not."""
    core = text.split('%', 1)[0]
    dotted = core.rsplit(':', 1)[-1]
    if '.' in dotted and any(len(part) > 1 and part.startswith('0') for part in dotted.split('.')):
        return None
    try:
        addr = ipaddress.ip_address(core)
    except ValueError:
        return None
    if addr.version == 6 and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return addr

def is_exposed_ip(addr):
    """Only loopback and unspecified addresses are excluded; private, link-local, ULA,
    multicast and documentation ranges are kept as infrastructure context."""
    return not (addr.is_loopback or addr.is_unspecified)

def extract_ips(line):
    """Returns the exposed IPv4 and IPv6 addresses in one line, in canonical form."""
    ips = set()

    def take_ipv6(match):
        candidate = match.group(0)
        core = candidate.split('%', 1)[0]
        # Full form needs 8 groups (an embedded IPv4 tail counts as 2); shorter forms need '::'
        if '::' not in core and core.count(':') + ('.' in core) != 7:
            return candidate
        addr = parse_ip(core)
        if addr is None:
            return candidate
        if is_exposed_ip(addr):
            ips.add(str(addr))
        # Blank the valid IPv6 span so the IPv4 regex does not report its embedded IPv4 tail again
        return ' ' * len(candidate)

    if ':' in line:
        line = REGEX_IPV6.sub(take_ipv6, line)
    for candidate in REGEX_IPV4.findall(line):
        addr = parse_ip(candidate)
        if addr is not None and is_exposed_ip(addr):
            ips.add(str(addr))
    return ips

def check_binary(binary_name):
    return shutil.which(binary_name) is not None

def is_git_repo(path):
    # .git can be a file (worktrees, submodules), so only check that it exists
    return os.path.exists(os.path.join(path, '.git'))

def load_ignore_rules(target_dir, ctx):
    """Loads --ignore-file, or <target>/.reposcannerignore if present, into ctx.rules."""
    explicit = ctx.ignore_file is not None
    path = ctx.ignore_file if explicit else os.path.join(target_dir, DEFAULT_IGNORE_FILE)
    if not explicit and not os.path.isfile(path):
        return
    if not explicit and not ctx.trust_target_ignore:
        print(f"[!] Skipping target {DEFAULT_IGNORE_FILE} in URL mode (pass --trust-target-ignore or --ignore-file to apply)")
        return

    try:
        with open(path, encoding="utf-8") as ignore_file:
            lines = ignore_file.read().splitlines()
    except (OSError, ValueError) as e:
        ctx.error(f"[!] Cannot read ignore file '{path}': {e}")
        return

    for line_no, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('regex:'):
            pattern = line[len('regex:'):].strip()
            try:
                if not pattern:
                    raise re.error("empty pattern")
                ctx.rules.regexes.append(re.compile(pattern))
            except re.error as e:
                ctx.error(f"[!] Invalid regex on line {line_no} of ignore file '{path}': {e}")
        else:
            glob = line[len('path:'):].strip() if line.startswith('path:') else line
            # Globs are relative to the target root, so drop a leading './' or '/'
            glob = re.sub(r'^(\./|/)+', '', glob)
            if glob:
                ctx.rules.path_globs.append(glob)

    # Loud on purpose: an ignore file inside a scanned repository can hide its own secrets
    print(f"[!] Ignore rules loaded from '{path}': {len(ctx.rules.path_globs)} path rule(s), "
          f"{len(ctx.rules.regexes)} regex rule(s). Matching findings are suppressed.")

def run_gitleaks(repo_path, repo_name, timestamp, ctx):
    if not check_binary("gitleaks"):
        print("  [-] Binary 'gitleaks' not found on the system. Skipping Gitleaks scan.")
        return

    # Git repos are scanned through their history; plain folders are scanned as files on disk
    git_mode = is_git_repo(repo_path)
    print(f"  [*] Running Gitleaks ({'git history' if git_mode else 'filesystem'} mode)...")
    report_filename = f"gitleaks-report-{repo_name}-{timestamp}.json"
    report_path = os.path.join(ctx.output_dir, report_filename)

    cmd = [
        "gitleaks", "detect",
        "--source", repo_path,
        "--no-git=false" if git_mode else "--no-git",
        "--report-format", "json",
        "--report-path", report_path
    ]

    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        # gitleaks also uses exit 1 for fatal errors; the report is only written if the scan completes
        if result.returncode not in (0, 1) or not os.path.exists(report_path):
            ctx.error(f"  [!] Gitleaks error (exit {result.returncode}): {result.stderr.strip()}")
            return
        # The JSON report is a list with one entry per finding ("[]" when clean)
        with open(report_path, encoding="utf-8") as report_file:
            results = json.load(report_file)

        count = ignored = 0
        for item in results:
            if ctx.rules.is_ignored(to_relpath(item.get("File"), repo_path), item.get("Secret"), item.get("Match")):
                ignored += 1
            else:
                count += 1
        ctx.findings += count
        ctx.ignored += ignored

        if ctx.redact and results:
            results = [redact_entry(item, GITLEAKS_SECRET_FIELDS) for item in results]
            with open(report_path, "w", encoding="utf-8") as report_file:
                json.dump(results, report_file, indent=1)

        if count:
            print(f"  [+] Gitleaks finished, FINDINGS DETECTED ({count}){ignored_suffix(ignored)}. Report saved to: {report_path}")
        else:
            print(f"  [+] Gitleaks finished, no findings{ignored_suffix(ignored)}. Report saved to: {report_path}")
    except (OSError, ValueError) as e:
        ctx.error(f"  [!] Failed to run Gitleaks or read its report: {e}")

def run_trufflehog(repo_path, repo_name, timestamp, ctx):
    if not check_binary("trufflehog"):
        print("  [-] Binary 'trufflehog' not found on the system. Skipping TruffleHog scan.")
        return

    git_mode = is_git_repo(repo_path)
    print(f"  [*] Running TruffleHog ({'git history' if git_mode else 'filesystem'} mode)...")
    report_filename = f"trufflehog-report-{repo_name}-{timestamp}.json"
    report_path = os.path.join(ctx.output_dir, report_filename)
    abs_repo_path = os.path.abspath(repo_path)

    # No shell: arguments are passed as a list so the repo name cannot be used for command injection
    if git_mode:
        cmd = ["trufflehog", "git", f"file://{abs_repo_path}", "--json", "--no-update"]
    else:
        cmd = ["trufflehog", "filesystem", abs_repo_path, "--json", "--no-update"]

    try:
        with open(report_path, "w", encoding="utf-8") as report_file:
            result = subprocess.run(cmd, stdout=report_file, stderr=subprocess.PIPE, text=True)

        # JSON Lines: one finding per non-empty line
        entries = []
        count = ignored = 0
        with open(report_path, encoding="utf-8") as report_file:
            for line in report_file:
                if not line.strip():
                    continue
                try:
                    item = json.loads(line)
                except ValueError:
                    # Cannot be filtered or redacted, so count it and keep it only in unredacted reports
                    ctx.error("  [!] TruffleHog output contains a line that is not valid JSON.")
                    count += 1
                    entries.append(None)
                    continue
                data = (item.get("SourceMetadata") or {}).get("Data") or {}
                path = next((v.get("file") for v in data.values() if isinstance(v, dict) and v.get("file")), None)
                if ctx.rules.is_ignored(to_relpath(path, repo_path), item.get("Raw"), item.get("RawV2")):
                    ignored += 1
                else:
                    count += 1
                entries.append(item)
        ctx.findings += count
        ctx.ignored += ignored

        if ctx.redact and entries:
            with open(report_path, "w", encoding="utf-8") as report_file:
                for item in entries:
                    if item is None:
                        continue
                    report_file.write(json.dumps(redact_entry(item, TRUFFLEHOG_SECRET_FIELDS)) + "\n")

        if result.returncode != 0:
            ctx.error(f"  [!] TruffleHog error (exit {result.returncode}): {result.stderr.strip()}")
            if entries:
                print(f"  [!] Partial report (incomplete scan) saved to: {report_path}")
            else:
                os.remove(report_path)
        elif count:
            print(f"  [+] TruffleHog finished, FINDINGS DETECTED ({count}){ignored_suffix(ignored)}. Report saved to: {report_path}")
        elif ignored:
            print(f"  [+] TruffleHog finished, no findings{ignored_suffix(ignored)}. Report saved to: {report_path}")
        else:
            os.remove(report_path)
            print("  [+] TruffleHog finished, no findings.")
    except OSError as e:
        ctx.error(f"  [!] Failed to run TruffleHog: {e}")

def scan_file(filepath, ctx):
    """Returns IPs, emails and secret records ({line_no, kind, key, value, line, spans}) found in one file."""
    findings = {
        'ips': set(),
        'emails': set(),
        'secrets': []
    }

    # Skip symlinks and non-regular files (FIFO, device) to avoid reading host files or hanging
    try:
        st = os.lstat(filepath)
    except OSError as e:
        ctx.error(f"[!] Error reading file {filepath}: {e}")
        return findings
    if not stat.S_ISREG(st.st_mode):
        return findings

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line_no, line in enumerate(f, 1):
                findings['ips'].update(extract_ips(line))
                # Strip credentials in URLs (scheme://user:pass@host) so the password is not read as an email
                for email in REGEX_EMAIL.findall(REGEX_URL_USERINFO.sub('://', line)):
                    findings['emails'].add(email)

                # Both tiers are always checked: a loose KV match must not hide a high-confidence pattern
                secret_kv_match = REGEX_SECRETS_KV.search(line)
                secret_direct_match = REGEX_SECRETS_DIRECT.search(line)
                # Every secret on the line is masked when a [PATTERN] line is shown with --redact
                spans = []
                if secret_kv_match:
                    spans.append(secret_kv_match.span(2))
                if secret_direct_match:
                    spans.append(secret_direct_match.span())

                if secret_kv_match:
                    findings['secrets'].append({
                        'line_no': line_no, 'kind': 'KV', 'key': secret_kv_match.group(1),
                        'value': secret_kv_match.group(2), 'line': line, 'spans': spans,
                    })
                if secret_direct_match:
                    findings['secrets'].append({
                        'line_no': line_no, 'kind': 'PATTERN', 'key': None,
                        'value': secret_direct_match.group(0), 'line': line, 'spans': spans,
                    })

    except Exception as e:
        ctx.error(f"[!] Error reading file {filepath}: {e}")

    return findings

def format_secret(secret, redact):
    """One report line per finding; secrets stay in plaintext unless --redact is set."""
    if secret['kind'] == 'KV':
        value = mask_secret(secret['value']) if redact else secret['value']
        return f"Line {secret['line_no']} [KV]: {secret['key']} = {value}"
    line = mask_spans(secret['line'], secret['spans']) if redact else secret['line']
    raw_line = line.strip()
    display_line = raw_line if len(raw_line) <= 120 else raw_line[:120] + "...[TRUNCATED]"
    return f"Line {secret['line_no']} [PATTERN]: {display_line}"

def get_git_authors(repo_path, ctx):
    if not is_git_repo(repo_path):
        return ["[!] Not a Git repository or .git folder not found."]

    try:
        result = subprocess.run(
            ['git', 'log', '--format=%aN | %aE'],
            cwd=repo_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        if result.returncode == 0:
            authors = set(result.stdout.strip().split('\n'))
            return list(authors)
        else:
            ctx.errors += 1
            return [f"[!] Failed to run Git: {result.stderr.strip()}"]
    except Exception as e:
        ctx.errors += 1
        return [f"[!] Git is not installed or returned an error: {e}"]

def main(directory, repo_name, timestamp, ctx):
    print(f"\n=== SOC REPOSITORY TRIAGE SCANNER V1.10 ===")
    print(f"Target Directory: {directory}")
    print(f"Session ID: {repo_name}-{timestamp}\n")

    load_ignore_rules(directory, ctx)
    if ctx.redact:
        print("[*] Redaction enabled: secret values are masked in this report and in the scanner reports.")

    all_ips = set()
    all_emails = set()
    all_secrets = []
    ignored_secrets = 0

    print("[*] Starting basic text scan (Fast Scan)...")
    # Unreadable subfolders count as operational errors instead of being skipped silently
    walk_errors = lambda e: ctx.error(f"[!] Cannot read directory {e.filename}: {e.strerror}")
    real_output_dir = os.path.realpath(ctx.output_dir)
    for root, dirs, files in os.walk(directory, onerror=walk_errors):
        if '.git' in dirs:
            dirs.remove('.git')
        # Do not scan our own logs/reports when the output folder is inside the target
        dirs[:] = [d for d in dirs if os.path.realpath(os.path.join(root, d)) != real_output_dir]

        for file in files:
            if any(file.lower().endswith(ext) for ext in IGNORE_EXT):
                continue
            filepath = os.path.join(root, file)
            relpath = os.path.relpath(filepath, directory)
            result = scan_file(filepath, ctx)
            all_ips.update(result['ips'])
            all_emails.update(result['emails'])
            for sec in result['secrets']:
                if ctx.rules.is_ignored(relpath, sec['value'], sec['line'].strip()):
                    ignored_secrets += 1
                else:
                    all_secrets.append(f"[{file}] {format_secret(sec, ctx.redact)}")
    ctx.findings += len(all_secrets)
    ctx.ignored += ignored_secrets

    print("[*] Extracting Git metadata (Author Analysis)...")
    authors = get_git_authors(directory, ctx)

    print("\n" + "="*40)
    print("CODE FORENSIC ANALYSIS RESULTS")
    print("="*40)

    print("\n[1] BASIC SECRETS SEARCH (HYBRID REGEX):")
    if all_secrets:
        for s in all_secrets:
            print(f"  - {s}")
    else:
        print("  - No basic secret indicators found.")
    if ignored_secrets:
        print(f"  - {ignored_secrets} finding(s) suppressed by ignore rules.")

    print("\n[2] INFRASTRUCTURE EXPOSURE (IP ADDRESS):")
    if all_ips:
        # IPv4 first, then IPv6: addresses of different versions cannot be compared directly
        for ip in sorted(all_ips, key=lambda a: (ipaddress.ip_address(a).version, ipaddress.ip_address(a))):
            print(f"  - {ip}")
    else:
        print("  - No exposed IP addresses found.")

    print("\n[3] PII DATA (EMAIL):")
    if all_emails:
        for email in list(all_emails)[:10]:
            print(f"  - {email}")
        if len(all_emails) > 10:
            print(f"  - ...and {len(all_emails) - 10} more emails.")
    else:
        print("  - No email entities found.")

    print("\n[4] ACTOR ANALYSIS (GIT AUTHORS):")
    for author in authors:
        print(f"  - {author}")

    print("\n[5] ADVANCED SCAN (GITLEAKS & TRUFFLEHOG):")
    run_gitleaks(directory, repo_name, timestamp, ctx)
    run_trufflehog(directory, repo_name, timestamp, ctx)

    print("="*40)

def setup_logging(repo_name, ctx):
    """Creates the session timestamp and duplicates stdout into the output folder. Returns the timestamp, or None on failure."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filepath = os.path.join(ctx.output_dir, f"soc_repo_scanner-{repo_name}-{timestamp}.log")
    try:
        os.makedirs(ctx.output_dir, exist_ok=True)
        sys.stdout = DualLogger(log_filepath)
    except OSError as e:
        ctx.error(f"[-] CRITICAL ERROR: Cannot write to output directory '{ctx.output_dir}': {e}")
        return None
    return timestamp

def setup_local(local_path, ctx):
    """Scans a local folder in place (no clone), including uncommitted and untracked files."""
    target_dir = os.path.abspath(os.path.expanduser(local_path))
    if not os.path.isdir(target_dir):
        ctx.error(f"[-] CRITICAL ERROR: Local folder not found: '{local_path}'")
        return
    if not os.access(target_dir, os.R_OK | os.X_OK):
        ctx.error(f"[-] CRITICAL ERROR: Local folder is not readable: '{local_path}'")
        return

    # The folder name is only used for log/report file names, so replace unsafe characters
    folder_name = re.sub(r'[^A-Za-z0-9._-]', '_', os.path.basename(target_dir)) or 'root'
    repo_name = f"local_{folder_name}"

    timestamp = setup_logging(repo_name, ctx)
    if timestamp is None:
        return
    print(f"[*] Local mode: scanning '{target_dir}' in place "
          f"({'Git repository' if is_git_repo(target_dir) else 'not a Git repository'}).")
    main(target_dir, repo_name, timestamp, ctx)

def setup_and_clone(repo_url, ctx):
    """Sets up logging and the 'repos' directory, runs git clone, and starts the scan."""
    # Extract the owner/org and repository name from the URL (without query string / fragment)
    path_parts = [p for p in urlsplit(repo_url).path.split('/') if p]
    repo_name = path_parts[-1] if path_parts else ''
    if repo_name.endswith('.git'):
        repo_name = repo_name[:-4]
    owner = path_parts[-2] if len(path_parts) >= 2 else ''

    # Validate names so they cannot escape the repos/ folder (e.g. '..')
    for part in (owner, repo_name):
        if part and (not re.fullmatch(r'[A-Za-z0-9._-]+', part) or part in ('.', '..')):
            ctx.error(f"[-] CRITICAL ERROR: Invalid repository name: '{part}'")
            return
    if not repo_name:
        ctx.error(f"[-] CRITICAL ERROR: Repository name not found in URL: '{repo_url}'")
        return

    # Include the owner so orgA/app and orgB/app do not share the same folder
    if owner:
        repo_name = f"{owner}_{repo_name}"

    # 1. Setup Logging
    timestamp = setup_logging(repo_name, ctx)
    if timestamp is None:
        return

    # 2. Set up the target repository
    base_dir = "repos"
    try:
        os.makedirs(base_dir, exist_ok=True)
    except OSError as e:
        ctx.error(f"[-] CRITICAL ERROR: Cannot create '{base_dir}' directory: {e}")
        return
    target_dir = os.path.join(base_dir, repo_name)

    # 3. Run Git Clone
    if os.path.exists(target_dir):
        # Make sure the existing folder is a clone of the same URL before reusing it
        remote = subprocess.run(
            ["git", "-C", target_dir, "remote", "get-url", "origin"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        existing_url = remote.stdout.strip()
        if remote.returncode != 0 or existing_url.rstrip('/') != repo_url.rstrip('/'):
            ctx.error(f"[-] CRITICAL ERROR: Directory '{target_dir}' already exists but is not a clone of {repo_url} "
                      f"(origin: '{existing_url or 'none'}'). Remove/move that folder and run again.")
            return
        print(f"[*] Directory '{target_dir}' already exists. Updating clone (git pull --ff-only)...")
        pull = subprocess.run(
            ["git", "-C", target_dir, "pull", "--ff-only"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        if pull.returncode != 0:
            ctx.error(f"[!] Failed to update clone, scanning the existing copy: {pull.stderr.strip()}")
    else:
        print(f"[*] Cloning repository from {repo_url} into '{target_dir}'...")
        if not check_binary("git"):
            ctx.error("[-] CRITICAL ERROR: 'git' not found on the system. Please install git first.")
            return

        try:
            # '--' prevents a URL starting with '-' from being parsed as a git option
            result = subprocess.run(["git", "clone", "--", repo_url, target_dir], capture_output=True, text=True)
            if result.returncode != 0:
                ctx.error(f"[-] git clone failed: {result.stderr.strip()}")
                return
            print("[+] Git clone succeeded.")
        except Exception as e:
            ctx.error(f"[-] An error occurred while running git clone: {e}")
            return

    # Proceed to scan the cloned directory
    main(target_dir, repo_name, timestamp, ctx)

def exit_code(ctx, fail_on_findings, strict):
    """Operational errors (--strict) take precedence over findings (--fail-on-findings)."""
    if strict and ctx.errors:
        return EXIT_OPERATIONAL_ERROR
    if fail_on_findings and ctx.findings:
        return EXIT_FINDINGS
    return EXIT_OK

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="SOC Triage Script for Leaked Repositories (Version 1.10)")
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("url", nargs="?", help="Repository URL (example: https://github.com/org/repo)")
    target.add_argument("--local", metavar="PATH", help="Scan a local folder in place, without cloning (any path)")
    parser.add_argument("--output-dir", metavar="DIR", default="log",
                        help="Directory for the log file and scanner reports (default: ./log)")
    parser.add_argument("--ignore-file", metavar="FILE",
                        help="Allowlist file to use instead of <target>/.reposcannerignore")
    parser.add_argument("--trust-target-ignore", action="store_true",
                        help="URL mode: apply the cloned repository's own .reposcannerignore (skipped by default)")
    parser.add_argument("--redact", action="store_true",
                        help="Mask secret values in the report and in the Gitleaks/TruffleHog reports")
    parser.add_argument("--fail-on-findings", action="store_true",
                        help="Exit with code 1 if any secret is found (built-in regex, Gitleaks or TruffleHog)")
    parser.add_argument("--strict", action="store_true",
                        help="Exit with code 3 on operational errors (clone, path, output, scanner failures)")
    args = parser.parse_args()

    ctx = ScanContext(
        output_dir=os.path.abspath(os.path.expanduser(args.output_dir)),
        ignore_file=os.path.abspath(os.path.expanduser(args.ignore_file)) if args.ignore_file else None,
        redact=args.redact,
        # --local targets are the analyst's own folders; cloned repositories are untrusted by default
        trust_target_ignore=bool(args.local) or args.trust_target_ignore,
    )
    try:
        if args.local:
            setup_local(args.local, ctx)
        else:
            setup_and_clone(args.url, ctx)
    except Exception:
        traceback.print_exc()
        sys.stdout.flush()
        # An unexpected crash is an operational error; without --strict keep Python's usual exit code 1
        sys.exit(EXIT_OPERATIONAL_ERROR if args.strict else 1)

    print(f"[*] Summary: {ctx.findings} secret finding(s){ignored_suffix(ctx.ignored)}, {ctx.errors} operational error(s).")
    sys.stdout.flush()
    sys.exit(exit_code(ctx, args.fail_on_findings, args.strict))

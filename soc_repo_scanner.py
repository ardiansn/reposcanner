import os
import re
import subprocess
import argparse
import ipaddress
import shutil
import stat
import sys
from datetime import datetime
from urllib.parse import urlsplit

# ==========================================
# REGEX CONFIGURATION (HYBRID) - VERSION 1.7
# ==========================================
# Lookarounds reject longer version strings (e.g. 1.2.3.4.5); octets are validated via is_exposed_ip()
REGEX_IP = re.compile(r'(?<![\d.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![\d.])')
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

def is_exposed_ip(ip):
    """True if the IP is valid (each octet 0-255) and is not loopback / 0.0.0.0."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_loopback or addr.is_unspecified)

def check_binary(binary_name):
    return shutil.which(binary_name) is not None

def is_git_repo(path):
    # .git can be a file (worktrees, submodules), so only check that it exists
    return os.path.exists(os.path.join(path, '.git'))

def run_gitleaks(repo_path, repo_name, timestamp):
    if not check_binary("gitleaks"):
        print("  [-] Binary 'gitleaks' not found on the system. Skipping Gitleaks scan.")
        return

    # Git repos are scanned through their history; plain folders are scanned as files on disk
    git_mode = is_git_repo(repo_path)
    print(f"  [*] Running Gitleaks ({'git history' if git_mode else 'filesystem'} mode)...")
    report_filename = f"gitleaks-report-{repo_name}-{timestamp}.json"
    # Write the report into the log/ folder
    report_path = os.path.join(os.getcwd(), "log", report_filename)

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
        report_written = os.path.exists(report_path)
        if result.returncode == 0 and report_written:
            print(f"  [+] Gitleaks finished, no findings. Report saved to: {report_path}")
        elif result.returncode == 1 and report_written:
            print(f"  [+] Gitleaks finished, FINDINGS DETECTED. Report saved to: {report_path}")
        else:
            print(f"  [!] Gitleaks error (exit {result.returncode}): {result.stderr.strip()}")
    except Exception as e:
        print(f"  [!] Failed to run Gitleaks: {e}")

def run_trufflehog(repo_path, repo_name, timestamp):
    if not check_binary("trufflehog"):
        print("  [-] Binary 'trufflehog' not found on the system. Skipping TruffleHog scan.")
        return

    git_mode = is_git_repo(repo_path)
    print(f"  [*] Running TruffleHog ({'git history' if git_mode else 'filesystem'} mode)...")
    report_filename = f"trufflehog-report-{repo_name}-{timestamp}.json"
    # Write the report into the log/ folder
    report_path = os.path.join(os.getcwd(), "log", report_filename)
    abs_repo_path = os.path.abspath(repo_path)

    # No shell: arguments are passed as a list so the repo name cannot be used for command injection
    if git_mode:
        cmd = ["trufflehog", "git", f"file://{abs_repo_path}", "--json", "--no-update"]
    else:
        cmd = ["trufflehog", "filesystem", abs_repo_path, "--json", "--no-update"]

    try:
        with open(report_path, "w", encoding="utf-8") as report_file:
            result = subprocess.run(cmd, stdout=report_file, stderr=subprocess.PIPE, text=True)
        has_findings = os.path.getsize(report_path) > 0
        if result.returncode != 0:
            print(f"  [!] TruffleHog error (exit {result.returncode}): {result.stderr.strip()}")
            if has_findings:
                print(f"  [!] Partial report (incomplete scan) saved to: {report_path}")
            else:
                os.remove(report_path)
        elif has_findings:
            print(f"  [+] TruffleHog finished, FINDINGS DETECTED. Report saved to: {report_path}")
        else:
            os.remove(report_path)
            print("  [+] TruffleHog finished, no findings.")
    except Exception as e:
        print(f"  [!] Failed to run TruffleHog: {e}")

def scan_file(filepath):
    findings = {
        'ips': set(),
        'emails': set(),
        'secrets': []
    }
    
    # Skip symlinks and non-regular files (FIFO, device) to avoid reading host files or hanging
    try:
        st = os.lstat(filepath)
    except OSError as e:
        print(f"[!] Error reading file {filepath}: {e}")
        return findings
    if not stat.S_ISREG(st.st_mode):
        return findings

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line_no, line in enumerate(f, 1):
                for ip in REGEX_IP.findall(line):
                    if is_exposed_ip(ip):
                        findings['ips'].add(ip)
                # Strip credentials in URLs (scheme://user:pass@host) so the password is not read as an email
                for email in REGEX_EMAIL.findall(REGEX_URL_USERINFO.sub('://', line)):
                    findings['emails'].add(email)

                # Both tiers are always checked: a loose KV match must not hide a high-confidence pattern
                secret_kv_match = REGEX_SECRETS_KV.search(line)
                if secret_kv_match:
                    key, value = secret_kv_match.group(1), secret_kv_match.group(2)
                    findings['secrets'].append(f"Line {line_no} [KV]: {key} = {value}")

                # Secrets are kept in plaintext for investigation/evidence
                secret_direct_match = REGEX_SECRETS_DIRECT.search(line)
                if secret_direct_match:
                    raw_line = line.strip()
                    display_line = raw_line if len(raw_line) <= 120 else raw_line[:120] + "...[TRUNCATED]"
                    findings['secrets'].append(f"Line {line_no} [PATTERN]: {display_line}")
                    
    except Exception as e:
        print(f"[!] Error reading file {filepath}: {e}")
        
    return findings

def get_git_authors(repo_path):
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
            return [f"[!] Failed to run Git: {result.stderr.strip()}"]
    except Exception as e:
        return [f"[!] Git is not installed or returned an error: {e}"]

def main(directory, repo_name, timestamp):
    print(f"\n=== SOC REPOSITORY TRIAGE SCANNER V1.7 ===")
    print(f"Target Directory: {directory}")
    print(f"Session ID: {repo_name}-{timestamp}\n")
    
    all_ips = set()
    all_emails = set()
    all_secrets = []
    
    print("[*] Starting basic text scan (Fast Scan)...")
    for root, dirs, files in os.walk(directory):
        if '.git' in dirs:
            dirs.remove('.git')
            
        for file in files:
            if any(file.lower().endswith(ext) for ext in IGNORE_EXT):
                continue
            filepath = os.path.join(root, file)
            result = scan_file(filepath)
            all_ips.update(result['ips'])
            all_emails.update(result['emails'])
            for sec in result['secrets']:
                all_secrets.append(f"[{file}] {sec}")

    print("[*] Extracting Git metadata (Author Analysis)...")
    authors = get_git_authors(directory)

    print("\n" + "="*40)
    print("CODE FORENSIC ANALYSIS RESULTS")
    print("="*40)
    
    print("\n[1] BASIC SECRETS SEARCH (HYBRID REGEX):")
    if all_secrets:
        for s in all_secrets:
            print(f"  - {s}")
    else:
        print("  - No basic secret indicators found.")

    print("\n[2] INFRASTRUCTURE EXPOSURE (IP ADDRESS):")
    if all_ips:
        for ip in sorted(all_ips, key=ipaddress.ip_address):
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
    run_gitleaks(directory, repo_name, timestamp)
    run_trufflehog(directory, repo_name, timestamp)
    
    print("="*40)

def setup_logging(repo_name):
    """Creates the session timestamp and duplicates stdout into log/. Returns the timestamp."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs("log", exist_ok=True)
    log_filepath = os.path.join("log", f"soc_repo_scanner-{repo_name}-{timestamp}.log")
    sys.stdout = DualLogger(log_filepath)
    return timestamp

def setup_local(local_path):
    """Scans a local folder in place (no clone), including uncommitted and untracked files."""
    target_dir = os.path.abspath(os.path.expanduser(local_path))
    if not os.path.isdir(target_dir):
        print(f"[-] CRITICAL ERROR: Local folder not found: '{local_path}'")
        return

    # The folder name is only used for log/report file names, so replace unsafe characters
    folder_name = re.sub(r'[^A-Za-z0-9._-]', '_', os.path.basename(target_dir)) or 'root'
    repo_name = f"local_{folder_name}"

    timestamp = setup_logging(repo_name)
    print(f"[*] Local mode: scanning '{target_dir}' in place "
          f"({'Git repository' if is_git_repo(target_dir) else 'not a Git repository'}).")
    main(target_dir, repo_name, timestamp)

def setup_and_clone(repo_url):
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
            print(f"[-] CRITICAL ERROR: Invalid repository name: '{part}'")
            return
    if not repo_name:
        print(f"[-] CRITICAL ERROR: Repository name not found in URL: '{repo_url}'")
        return

    # Include the owner so orgA/app and orgB/app do not share the same folder
    if owner:
        repo_name = f"{owner}_{repo_name}"

    # 1. Setup Logging
    timestamp = setup_logging(repo_name)

    # 2. Set up the target repository
    base_dir = "repos"
    os.makedirs(base_dir, exist_ok=True)
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
            print(f"[-] CRITICAL ERROR: Directory '{target_dir}' already exists but is not a clone of {repo_url} "
                  f"(origin: '{existing_url or 'none'}'). Remove/move that folder and run again.")
            return
        print(f"[*] Directory '{target_dir}' already exists. Updating clone (git pull --ff-only)...")
        pull = subprocess.run(
            ["git", "-C", target_dir, "pull", "--ff-only"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        if pull.returncode != 0:
            print(f"[!] Failed to update clone, scanning the existing copy: {pull.stderr.strip()}")
    else:
        print(f"[*] Cloning repository from {repo_url} into '{target_dir}'...")
        if not check_binary("git"):
            print("[-] CRITICAL ERROR: 'git' not found on the system. Please install git first.")
            return
            
        try:
            # '--' prevents a URL starting with '-' from being parsed as a git option
            result = subprocess.run(["git", "clone", "--", repo_url, target_dir], capture_output=True, text=True)
            if result.returncode != 0:
                print(f"[-] git clone failed: {result.stderr.strip()}")
                return
            print("[+] Git clone succeeded.")
        except Exception as e:
            print(f"[-] An error occurred while running git clone: {e}")
            return

    # Proceed to scan the cloned directory
    main(target_dir, repo_name, timestamp)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="SOC Triage Script for Leaked Repositories (Version 1.7)")
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("url", nargs="?", help="Repository URL (example: https://github.com/org/repo)")
    target.add_argument("--local", metavar="PATH", help="Scan a local folder in place, without cloning (any path)")
    args = parser.parse_args()

    if args.local:
        setup_local(args.local)
    else:
        setup_and_clone(args.url)
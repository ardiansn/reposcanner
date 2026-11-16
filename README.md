# SOC Repository Triage Scanner

A single-file Python tool for quickly triaging a Git repository or local folder that may have exposed **secrets, API keys, tokens and credentials**. It combines a fast built-in regex scan of the files on disk with optional deep scans of the full commit history by [Gitleaks](https://github.com/gitleaks/gitleaks) and [TruffleHog](https://github.com/trufflesecurity/trufflehog), and adds context useful for an investigation: exposed IP addresses, email addresses and Git commit authors.

Current version: **1.8**

> **Defensive use only.** This tool is intended for Blue Team, SOC, DevSecOps and authorized repository-hygiene work: finding and responding to credential leaks in repositories you own or are authorized to assess. See [Authorized Use & Disclaimer](#authorized-use--disclaimer).

## Contents

- [How it works](#how-it-works)
- [Authorized Use & Disclaimer](#authorized-use--disclaimer)
- [Features](#features)
- [Prerequisites & Installation](#prerequisites--installation)
- [Usage & Examples](#usage--examples)
- [Output](#output)
- [Exit Codes](#exit-codes)
- [Limitations](#limitations)
- [Running Tests](#running-tests)
- [Remediation Best Practices](#remediation-best-practices)
- [License](#license)

## How it works

1. **Get the target.** In URL mode the repository is cloned into `repos/` (or an existing clone there is updated). In `--local` mode the folder is scanned in place, without cloning.
2. **Fast scan.** Every file in the working tree is read line by line and checked for secret patterns, IP addresses and email addresses.
3. **Author analysis.** For Git repositories, all commit authors (name and email) are listed from `git log`.
4. **Advanced scan.** If installed, Gitleaks and TruffleHog scan the target. Git repositories are scanned through their commit history; plain folders are scanned as files on disk.
5. **Report.** Results are printed to the terminal and saved to a log file in `log/` (or the folder given with `--output-dir`), next to the Gitleaks and TruffleHog JSON reports.
6. **Exit code.** By default the run exits `0`. With `--fail-on-findings` and `--strict` the exit code reports findings and operational errors, so the scanner can gate a CI/CD pipeline.

## Authorized Use & Disclaimer

This project exists to help defenders **find and fix** leaked credentials. Use it only:

- on repositories and folders you own, or that you are explicitly authorized to audit (for example, as part of your organization's security operations, incident response or an approved assessment);
- for defensive purposes such as leak detection, incident triage, evidence collection and credential-rotation follow-up.

Do not use it to collect, test or use credentials belonging to others, or against any repository without authorization. You are responsible for complying with applicable laws, your organization's policies and the terms of the hosting platform.

**Findings are written in plaintext.** For investigation and evidence purposes, the scanner does not mask secrets in the terminal output, the log file or the Gitleaks report. Treat everything in the output folder (`log/` by default) as sensitive: restrict its permissions, never commit it (it is excluded by `.gitignore`), and delete it when the case is closed.

The software is provided "as is", without warranty of any kind. A clean scan does not guarantee that a repository is free of secrets.

## Features

**Built-in regex scan (files on disk)**

- *Assignment-style secrets* (case-insensitive): a keyword followed by `=`, `:` or `:=` and a value. Keywords: `password`, `passwd`, `pwd`, `secret`, `token`, `api_key` / `api-key` / `apikey`, `access_key`, `private_key`, `jwt`, `webhook`. Keywords may have a prefix or suffix (`DB_PASSWORD`, `SECRET_KEY`, `API_KEY_PROD`) and may be quoted JSON/YAML keys (`"api_key": "..."`). `==` comparisons are ignored.
- *High-confidence patterns* (no assignment needed):
  - Private key headers (`BEGIN RSA/OPENSSH/EC/DSA PRIVATE KEY`)
  - `mongodb://`, `mongodb+srv://` and `redis://` connection strings
  - `Bearer` and `Basic` authorization tokens, and `Authorization:` headers
  - `ssh-rsa` public keys
  - AWS access key IDs (`AKIA…` / `ASIA…`)
  - GitHub personal access tokens (`ghp_…`)
  - GitLab personal access tokens (`glpat-…`)
- **Exposed IP addresses:** valid IPv4 addresses, excluding loopback and `0.0.0.0`; version strings like `1.2.3.4.5` are ignored.
- **Email addresses (PII):** credentials inside URLs (`scheme://user:pass@host`) are stripped first so they are not reported as emails.
- **Safe file handling:** symbolic links and special files are skipped, as are the `.git` folder and binary/media files with these extensions: `.png .jpg .jpeg .gif .mp4 .zip .tar .gz .pdf .exe .dll .so`.

**Repository context**

- **Commit authors:** unique `name | email` pairs from the full Git history.

**Advanced scanners (optional)**

- **Gitleaks:** git-history mode for repositories, filesystem mode (`--no-git`) for plain folders. Writes a JSON report.
- **TruffleHog:** `git` mode for repositories, `filesystem` mode for plain folders. Writes a JSON Lines report.
- Each scanner is skipped with a message if its binary is not installed.

**Safety measures**

- Repository and owner names taken from a URL are validated so they cannot escape the `repos/` folder.
- A folder in `repos/` is reused only if its `origin` remote matches the requested URL; it is then updated with `git pull --ff-only`.
- External tools are run without a shell, so repository names cannot be used for command injection.
- `--local` mode only reads the target folder; it never modifies it.

## Prerequisites & Installation

| Requirement | Needed for | Notes |
|---|---|---|
| Python 3.7 or newer | Everything | Standard library only, no `pip` packages required |
| Git | URL mode (cloning), author analysis | Not needed to `--local` scan a plain folder |
| Gitleaks v8 | Advanced scan (optional) | Uses the `gitleaks detect` command |
| TruffleHog v3 | Advanced scan (optional) | Uses the `git` and `filesystem` commands |

Install the optional scanners with your package manager, for example on macOS with Homebrew:

```bash
brew install gitleaks trufflehog
```

Other platforms: see the installation instructions of [Gitleaks](https://github.com/gitleaks/gitleaks#installing) and [TruffleHog](https://github.com/trufflesecurity/trufflehog#floppy_disk-installation).

Get the scanner:

```bash
git clone https://github.com/<your-account>/reposcanner.git
cd reposcanner
python3 soc_repo_scanner.py --help
```

## Usage & Examples

```text
usage: soc_repo_scanner.py [-h] [--output-dir DIR] [--fail-on-findings]
                           [--strict]
                           (--local PATH | url)
```

Exactly one target is required: either a repository URL or `--local PATH`.

| Argument | Description |
|---|---|
| `url` | Repository to clone into `repos/<owner>_<repo>` and scan. Any URL or path that `git clone` accepts, for example `https://github.com/org/repo`. |
| `--local PATH` | Scan an existing folder in place, without cloning. Accepts absolute, relative and `~` paths. The folder does not need to be a Git repository. |
| `--output-dir DIR` | Folder for the log file and the Gitleaks/TruffleHog reports. Created if it does not exist. Default: `log/` in the current working directory. |
| `--fail-on-findings` | Exit with code `1` if any secret is found by the built-in regex scan, Gitleaks or TruffleHog. |
| `--strict` | Exit with code `3` if an operational error occurs (see [Exit Codes](#exit-codes)). Takes precedence over `--fail-on-findings`. |
| `-h`, `--help` | Show help and exit. |

The output format and the scanners used are fixed. Without `--fail-on-findings` and `--strict` the run always exits `0`, as in earlier versions.

**Scan a remote repository**

```bash
python3 soc_repo_scanner.py https://github.com/org/repo
```

The repository is cloned to `repos/org_repo`. Running the same command again reuses that clone and updates it with `git pull --ff-only`.

**Scan a local repository, including uncommitted and untracked files**

```bash
python3 soc_repo_scanner.py --local /path/to/project
python3 soc_repo_scanner.py --local ~/projects/app
```

**Scan a plain folder (for example, an extracted archive)**

```bash
python3 soc_repo_scanner.py --local ./extracted-archive
```

Author analysis is skipped, and Gitleaks/TruffleHog run in filesystem mode.

**Scan commit history**

Commit history is scanned automatically whenever the target is a Git repository and Gitleaks and/or TruffleHog are installed. There is no separate flag.

**Write reports to a separate folder**

```bash
python3 soc_repo_scanner.py --local /path/to/project --output-dir /path/to/case-reports
```

**Use in a CI/CD pipeline**

Fail the job when a secret is found (exit `1`) or when the scan could not run properly (exit `3`):

```bash
python3 soc_repo_scanner.py --local . --fail-on-findings --strict --output-dir "$RUNNER_TEMP/secret-scan"
```

For example, as a GitHub Actions step:

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0   # full history, so Gitleaks/TruffleHog can scan every commit
- name: Scan for exposed secrets
  run: python3 soc_repo_scanner.py --local . --fail-on-findings --strict --output-dir "$RUNNER_TEMP/secret-scan"
```

Keep the output folder outside the scanned folder where possible, and do not upload it as a public build artifact: the reports contain the secrets in plaintext.

> **Where files are written:** `log/` (unless `--output-dir` is given) and `repos/` are created in the **current working directory**, not next to the script. Run the scanner from the folder where you want results to go.

## Output

**Terminal and log file**

Everything printed to the terminal is also saved to the output folder (`log/` by default, or `--output-dir`):

```text
log/soc_repo_scanner-<name>-<YYYYMMDD_HHMMSS>.log
```

`<name>` is `<owner>_<repo>` in URL mode and `local_<folder>` in `--local` mode. The report has five sections, followed by a one-line summary:

```text
========================================
CODE FORENSIC ANALYSIS RESULTS
========================================

[1] BASIC SECRETS SEARCH (HYBRID REGEX):
  - [config.py] Line 12 [KV]: API_KEY = <value>
  - [deploy.sh] Line 4 [PATTERN]: <full line containing the match>

[2] INFRASTRUCTURE EXPOSURE (IP ADDRESS):
  - 203.0.113.10

[3] PII DATA (EMAIL):
  - dev@example.com

[4] ACTOR ANALYSIS (GIT AUTHORS):
  - Jane Doe | jane@example.com

[5] ADVANCED SCAN (GITLEAKS & TRUFFLEHOG):
  [*] Running Gitleaks (git history mode)...
  [+] Gitleaks finished, FINDINGS DETECTED (1). Report saved to: <output-dir>/gitleaks-report-<name>-<timestamp>.json
  [*] Running TruffleHog (git history mode)...
  [+] TruffleHog finished, no findings.
========================================
[*] Summary: 3 secret finding(s), 0 operational error(s).
```

- `[KV]` findings show the matched keyword and its value.
- `[PATTERN]` findings show the whole line, cut to 120 characters (`...[TRUNCATED]`).
- Findings show the file name only, not its folder, plus the line number.
- At most 10 email addresses are listed, followed by a count of the rest.
- The summary counts secret findings from all three sources. The same secret found by more than one of them is counted once per source.

**Advanced scanner reports** (in the output folder)

| File | Format | When it is kept |
|---|---|---|
| `gitleaks-report-<name>-<timestamp>.json` | Gitleaks JSON | Whenever Gitleaks completes, even with no findings |
| `trufflehog-report-<name>-<timestamp>.json` | TruffleHog JSON Lines (one finding per line) | Only when TruffleHog reports findings; a partial report is kept if TruffleHog fails midway |

All of these files contain secrets in plaintext.

## Exit Codes

By default the exit code does not reflect findings or handled errors, so existing scripts keep working. `--fail-on-findings` and `--strict` turn the exit code into a pass/fail signal for CI/CD and pre-commit checks.

| Code | Meaning |
|---|---|
| `0` | Success. Without the flags: the run finished, whether or not secrets were found or handled errors occurred. With `--fail-on-findings`: no secrets were found. With `--strict`: no operational errors occurred. |
| `1` | `--fail-on-findings` is set and at least one secret was found. Without `--strict`, also returned if the script crashes with an unexpected Python error. |
| `2` | Invalid command-line usage: no target, both a URL and `--local`, or an unknown option. |
| `3` | `--strict` is set and an operational error occurred. Takes precedence over `1` when both apply. |

**What counts as a finding** (`--fail-on-findings`): any secret reported by the built-in regex scan (section `[1]`), Gitleaks or TruffleHog. IP addresses, email addresses and Git authors are investigation context and do not count.

**What counts as an operational error** (`--strict`):

- invalid repository name or URL, `git` missing, failed `git clone`, an existing `repos/` folder that is not a clone of the URL, or a failed `git pull`
- a `--local` path that does not exist or cannot be read, and files or subfolders that cannot be read during the scan
- an output folder (or `repos/`) that cannot be created or written
- Gitleaks or TruffleHog failing to run or to complete, or an unreadable Gitleaks report
- `git log` failing during author analysis (for example, a repository with no commits)
- an unexpected Python error

A scanner that is not installed is skipped and does **not** count as an error, since both are optional. Errors are always printed with `CRITICAL ERROR` or `[!]`, and the summary line at the end shows how many occurred.

## Limitations

- The built-in regex scan reads only the current files on disk. Commit history is covered only when Gitleaks or TruffleHog is installed.
- In URL mode only committed content is scanned. Use `--local` to include uncommitted and untracked files.
- Each line reports at most one assignment-style finding and one pattern finding.
- Generic keyword matching can produce false positives (for example `tokenizer = Tokenizer()`) and flags values read from the environment (`API_KEY = os.environ[...]`). Review every finding.
- Some connection strings (such as `postgres://` and `mysql://`) and many vendor token formats are not matched by the built-in regex. Gitleaks and TruffleHog cover far more formats.
- Gitleaks and TruffleHog scan only the history; uncommitted and untracked files in a Git repository are checked only by the built-in regex scan.
- If the output folder is inside the scanned folder, the built-in scan skips it, but Gitleaks and TruffleHog in filesystem mode (non-Git folders) may scan earlier reports there. Use an output folder outside the target, especially with `--fail-on-findings`.
- `--fail-on-findings` fails on any finding, including false positives. There is no allowlist yet, so review and fix or move the flagged lines.

## Running Tests

The test suite uses only the Python standard library. Each test runs the scanner in a temporary folder that is removed afterwards. Gitleaks and TruffleHog are replaced by small fakes, so the results do not depend on what is installed.

```bash
python3 -m unittest discover -s tests -v
```

## Remediation Best Practices

When a secret is confirmed:

1. **Revoke or rotate it first.** Treat any secret that reached a repository as compromised, even if it was removed later or the repository is private. Rewriting history does not undo exposure: forks, clones, caches and CI logs may still hold it.
2. **Check for misuse** in the affected service's access logs for the period the secret was exposed.
3. **Remove it from the code** and load it from a secret manager or environment variables instead.
4. **Then clean the history** if needed, with a tool such as [`git filter-repo`](https://github.com/newren/git-filter-repo), and coordinate a force-push with everyone who has a clone. On hosted platforms, old commits may remain reachable by ID until the provider purges them.
5. **Prevent recurrence** with pre-commit hooks or CI secret scanning (Gitleaks or TruffleHog), and `.gitignore` entries for `.env` and key files.
6. **Handle the evidence securely:** restrict access to the output folder (`log/` by default), and delete reports once they are no longer needed.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

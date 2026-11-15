# SOC Repository Triage Scanner

A single-file Python tool for quickly triaging a Git repository or local folder that may have exposed **secrets, API keys, tokens and credentials**. It combines a fast built-in regex scan of the files on disk with optional deep scans of the full commit history by [Gitleaks](https://github.com/gitleaks/gitleaks) and [TruffleHog](https://github.com/trufflesecurity/trufflehog), and adds context useful for an investigation: exposed IP addresses, email addresses and Git commit authors.

Current version: **1.7**

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
- [Remediation Best Practices](#remediation-best-practices)

## How it works

1. **Get the target.** In URL mode the repository is cloned into `repos/` (or an existing clone there is updated). In `--local` mode the folder is scanned in place, without cloning.
2. **Fast scan.** Every file in the working tree is read line by line and checked for secret patterns, IP addresses and email addresses.
3. **Author analysis.** For Git repositories, all commit authors (name and email) are listed from `git log`.
4. **Advanced scan.** If installed, Gitleaks and TruffleHog scan the target. Git repositories are scanned through their commit history; plain folders are scanned as files on disk.
5. **Report.** Results are printed to the terminal and saved to a log file in `log/`, next to the Gitleaks and TruffleHog JSON reports.

## Authorized Use & Disclaimer

This project exists to help defenders **find and fix** leaked credentials. Use it only:

- on repositories and folders you own, or that you are explicitly authorized to audit (for example, as part of your organization's security operations, incident response or an approved assessment);
- for defensive purposes such as leak detection, incident triage, evidence collection and credential-rotation follow-up.

Do not use it to collect, test or use credentials belonging to others, or against any repository without authorization. You are responsible for complying with applicable laws, your organization's policies and the terms of the hosting platform.

**Findings are written in plaintext.** For investigation and evidence purposes, the scanner does not mask secrets in the terminal output, the log file or the Gitleaks report. Treat everything in `log/` as sensitive: restrict its permissions, never commit it (it is excluded by `.gitignore`), and delete it when the case is closed.

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
usage: soc_repo_scanner.py [-h] (--local PATH | url)
```

Exactly one target is required: either a repository URL or `--local PATH`.

| Argument | Description |
|---|---|
| `url` | Repository to clone into `repos/<owner>_<repo>` and scan. Any URL or path that `git clone` accepts, for example `https://github.com/org/repo`. |
| `--local PATH` | Scan an existing folder in place, without cloning. Accepts absolute, relative and `~` paths. The folder does not need to be a Git repository. |
| `-h`, `--help` | Show help and exit. |

There are no other flags: output location, format and scanners are fixed (see [Output](#output)).

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

> **Where files are written:** `log/` and `repos/` are created in the **current working directory**, not next to the script. Run the scanner from the folder where you want results to go.

## Output

**Terminal and log file**

Everything printed to the terminal is also saved to:

```text
log/soc_repo_scanner-<name>-<YYYYMMDD_HHMMSS>.log
```

`<name>` is `<owner>_<repo>` in URL mode and `local_<folder>` in `--local` mode. The report has five sections:

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
  [+] Gitleaks finished, FINDINGS DETECTED. Report saved to: <cwd>/log/gitleaks-report-<name>-<timestamp>.json
  [*] Running TruffleHog (git history mode)...
  [+] TruffleHog finished, no findings.
========================================
```

- `[KV]` findings show the matched keyword and its value.
- `[PATTERN]` findings show the whole line, cut to 120 characters (`...[TRUNCATED]`).
- Findings show the file name only, not its folder, plus the line number.
- At most 10 email addresses are listed, followed by a count of the rest.

**Advanced scanner reports**

| File | Format | When it is kept |
|---|---|---|
| `log/gitleaks-report-<name>-<timestamp>.json` | Gitleaks JSON | Whenever Gitleaks completes, even with no findings |
| `log/trufflehog-report-<name>-<timestamp>.json` | TruffleHog JSON Lines (one finding per line) | Only when TruffleHog reports findings; a partial report is kept if TruffleHog fails midway |

All of these files contain secrets in plaintext.

## Exit Codes

The scanner is a triage tool for analysts and **does not signal findings through its exit code**.

| Code | Meaning |
|---|---|
| `0` | The run finished, **whether or not secrets were found**. Handled errors also exit with `0`: invalid repository name, failed clone, missing local folder, scanner errors. Check the output for `CRITICAL ERROR` or `[!]` lines. |
| `2` | Invalid command-line usage (no target, or both a URL and `--local`). |
| `1` | An unexpected Python error, for example no write permission in the current directory. |

Because of this, it is not suitable on its own as a blocking CI/CD or pre-commit check. For pipeline gating, run Gitleaks or TruffleHog directly, which return a non-zero exit code when they find secrets.

## Limitations

- The built-in regex scan reads only the current files on disk. Commit history is covered only when Gitleaks or TruffleHog is installed.
- In URL mode only committed content is scanned. Use `--local` to include uncommitted and untracked files.
- Each line reports at most one assignment-style finding and one pattern finding.
- Generic keyword matching can produce false positives (for example `tokenizer = Tokenizer()`) and flags values read from the environment (`API_KEY = os.environ[...]`). Review every finding.
- Some connection strings (such as `postgres://` and `mysql://`) and many vendor token formats are not matched by the built-in regex. Gitleaks and TruffleHog cover far more formats.
- Gitleaks and TruffleHog scan only the history; uncommitted and untracked files in a Git repository are checked only by the built-in regex scan.

## Remediation Best Practices

When a secret is confirmed:

1. **Revoke or rotate it first.** Treat any secret that reached a repository as compromised, even if it was removed later or the repository is private. Rewriting history does not undo exposure: forks, clones, caches and CI logs may still hold it.
2. **Check for misuse** in the affected service's access logs for the period the secret was exposed.
3. **Remove it from the code** and load it from a secret manager or environment variables instead.
4. **Then clean the history** if needed, with a tool such as [`git filter-repo`](https://github.com/newren/git-filter-repo), and coordinate a force-push with everyone who has a clone. On hosted platforms, old commits may remain reachable by ID until the provider purges them.
5. **Prevent recurrence** with pre-commit hooks or CI secret scanning (Gitleaks or TruffleHog), and `.gitignore` entries for `.env` and key files.
6. **Handle the evidence securely:** restrict access to `log/`, and delete reports once they are no longer needed.

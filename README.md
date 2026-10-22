# privesc-auditor — Linux Privilege Escalation Auditor

A small, dependency-free, **read-only** command-line tool that enumerates a
Linux system for common privilege-escalation *misconfigurations* and reports
them as prioritized findings for human review.

It is written for authorized security audits, system hardening, and CTF
practice. It performs **no exploitation** and makes **no changes** to the host.

---

## Purpose

Manually checking every SUID bit, sudo rule, cron job, capability, and
world-writable path on a host is tedious and error-prone. `privesc-auditor`
automates the *enumeration* step and presents the results in one clean report,
ranked by severity, so a human can focus on verification and remediation.

## What the tool does

- Enumerates the host (user, uid/gid, distro, kernel, architecture).
- Scans for SUID/SGID binaries and flags writable, known-risky, or
  non-baseline ones.
- Reads Linux file **capabilities** and flags dangerous ones (e.g.
  `cap_setuid`, `cap_sys_admin`).
- Reviews `sudoers` policy for `NOPASSWD`, `!authenticate`, and risky
  `env_keep` entries, follows `#include`/`@include`/`#includedir` directives,
  and flags writable policy files and directories (including drop-ins under
  `/etc/sudoers.d`).
- Reviews cron locations for writable job files, writable job directories, and
  writable scripts referenced by jobs, plus `/etc/crontab` itself.
- Reviews systemd units for writable unit files and writable `ExecStart`
  targets.
- Inspects running root processes for writable backing executables.
- Checks the filesystem for writable `$PATH` directories, relative `$PATH`
  entries, missing sticky bits on world-writable dirs, and writable/readable
  sensitive files (`/etc/passwd`, `/etc/shadow`, …).
- Applies a **coarse** kernel-version heuristic against a small built-in table
  of well-known local-privesc CVEs.
- Emits either a human-readable report or machine-readable JSON.
- Returns an exit code reflecting the worst severity found (useful in CI).

## What the tool does NOT do

- It does **not** exploit anything, launch payloads, or attempt escalation.
- It does **not** modify, create, or delete any file on the host.
- It does **not** phone home or send data anywhere; all output goes to stdout.
- It does **not** prove a finding is exploitable — every finding needs human
  verification.
- It does **not** follow symlinks while walking directories (avoids loops and
  symlink-based surprises).
- It does **not** perform authenticated package-manager queries or consult a
  live CVE feed; CVE matching is a local, version-range heuristic only.

## Installation

No dependencies beyond a C11 compiler and a POSIX libc. Copy `main.c` to the
target and compile (see below). The result is a single self-contained binary.

```bash
git clone <your-repo> privesc-auditor && cd privesc-auditor
```

## Compilation

Standard build (warnings-as-documentation, with compiler hardening):

```bash
cc -std=c11 -Wall -Wextra -Wpedantic -O2 \
   -D_FORTIFY_SOURCE=2 -fstack-protector-strong \
   -o privesc-auditor main.c
```

Development build with sanitizers (recommended while modifying the code):

```bash
cc -std=c11 -Wall -Wextra -Wpedantic -g -O1 \
   -fsanitize=address,undefined -fno-omit-frame-pointer \
   -o privesc-auditor.san main.c
```

> **Note (macOS):** AddressSanitizer on Apple's toolchain can abort during
> early init when `getpwuid()` pulls in system directory services
> (`asan_init_is_running` CHECK). This is a known platform limitation of
> Apple-ASan, not a defect in this program. Use the UndefinedBehaviorSanitizer
> build (`-fsanitize=undefined`) on macOS, or run the ASan build on Linux.

The tool targets Linux at runtime. It still compiles and runs on macOS/BSD,
where Linux-only scans (capabilities, `/proc` processes) are skipped with an
informational note.

## Usage

```bash
./privesc-auditor              # run all scans, human-readable report
./privesc-auditor --verbose    # include INFO-level findings
./privesc-auditor --json       # machine-readable JSON
./privesc-auditor --check suid # run a single category (repeatable)
./privesc-auditor --help
```

### CLI options

| Option              | Description                                             |
| ------------------- | ------------------------------------------------------- |
| `--help`, `-h`      | Show help and exit.                                     |
| `--version`         | Show version and exit.                                  |
| `--verbose`, `-v`   | Include INFO-level findings in text output.             |
| `--json`            | Emit JSON instead of the text report.                   |
| `--no-color`        | Disable ANSI colors (also auto-off when not a TTY).     |
| `--check <cat>`     | Run only the named category. Repeat to select several.  |

**Exit codes:** `0` = nothing notable, `1` = low/medium findings,
`2` = at least one high, `3` = at least one critical. Error in arguments = `2`
(printed to stderr).

## Scanner categories

| Category       | What it inspects                                                   |
| -------------- | ----------------------------------------------------------------- |
| `system`       | User, uid/gid, distro, kernel, architecture.                      |
| `suid`         | SUID/SGID binaries; writable / known-risky / non-baseline ones.   |
| `capabilities` | File capabilities via `security.capability` xattr (Linux only).   |
| `sudo`         | `/etc/sudoers` and `/etc/sudoers.d/*` policy review.              |
| `cron`         | System crontab, `cron.d`/`cron.*`, spool dirs; writable targets.  |
| `services`     | systemd unit files and their `ExecStart` targets.                 |
| `processes`    | Root-owned processes with a writable on-disk executable (Linux).  |
| `filesystem`   | Writable `$PATH` dirs, relative `$PATH`, sticky bits, sensitive files. |
| `package`      | Kernel-version heuristic against a small built-in CVE table.      |

## Severity levels

| Level      | Meaning                                                              |
| ---------- | ------------------------------------------------------------------- |
| `CRITICAL` | Direct, high-confidence escalation primitive (e.g. writable SUID root binary, writable sudoers policy file or drop-in directory, writable `/etc/passwd`). |
| `HIGH`     | Strong escalation path likely (writable cron/service target, dangerous capability, writable `$PATH`). |
| `MEDIUM`   | Notable misconfiguration worth investigating (non-baseline SUID, passwordless sudo rule, missing sticky bit). |
| `LOW`      | Minor hygiene issue.                                                 |
| `INFO`     | Context / baseline facts; hidden unless `--verbose`.                 |

## Confidence levels

| Level       | Meaning                                                            |
| ----------- | ---------------------------------------------------------------- |
| `CONFIRMED` | The condition was directly observed (e.g. a file *is* writable by the current user). |
| `LIKELY`    | Strong signal and a plausible escalation path, but context-dependent. |
| `POSSIBLE`  | Heuristic match / weak signal; most prone to false positives.     |

Confidence and severity are **independent**: a high-severity issue can be only
`POSSIBLE` (e.g. a kernel-version CVE match), and a low-severity issue can be
`CONFIRMED`.

## CVE matching limitations

The `package` scanner matches the running kernel's `major.minor` version against
a **small, static** table of famous local-privesc CVEs (Dirty COW, Dirty Pipe,
etc.). This is intentionally coarse:

- It matches **version ranges**, not the actual presence of vulnerable code.
- It does **not** account for distribution **backported patches** — most
  vendors fix CVEs without changing the upstream version number, so a matched
  kernel is very often *already patched*.
- It does **not** consult any live CVE database and is not exhaustive.
- `pkexec`/PwnKit (CVE-2021-4034) is flagged purely on SUID presence, not on
  the polkit package version.

Treat every `package` finding as *"this kernel line was historically affected —
go verify against your vendor's advisory and package version."*

## False positives

Expect them, especially at `POSSIBLE` confidence. Common causes:

- "Non-standard SUID binary" simply means the path is not on the tool's small
  built-in baseline; many legitimate vendor binaries will appear here.
- `NOPASSWD` sudo rules are sometimes intentional and appropriately scoped.
- A writable `$PATH` directory under your own home is normal for user-local
  tooling but is still reported, because it matters when another user's
  privileged process inherits that `PATH`.
- Kernel CVE matches ignore backports (see above).

Always confirm manually before acting on a finding.

## Permissions required

- Runs as **any user**; no root required. Findings reflect *that user's* view
  of the system, which is exactly what you want when assessing what an
  unprivileged account could leverage.
- As an unprivileged user, some files are unreadable (e.g. other users'
  crontabs, root-only unit directories); those are silently skipped, so a run
  as root will naturally surface more.
- The tool never requests or needs elevated privileges to do its work.

## Security considerations

- The tool only **reads** state; it never writes to the host.
- It never follows symlinks during directory walks, avoiding symlink loops and
  redirection to unexpected targets.
- Directory walks are depth-bounded to avoid pathological traversal.
- All output is local (stdout); nothing is transmitted off-host.
- Output may contain sensitive paths and configuration snippets — treat report
  files and JSON output as sensitive and store them accordingly.
- Run it only on systems you are **authorized** to assess.

## Example output

```
========================================
 Linux Privilege Escalation Auditor
========================================

User:   analyst
UID:    1000
Distro: Debian GNU/Linux 12 (bookworm)
Kernel: Linux 6.1.0-18-amd64

[+] System enumeration
[+] SUID/SGID scan
[+] Capability scan
[+] Sudo scan
[+] Cron scan
[+] Service scan
[+] Process scan
[+] Filesystem scan
[+] Package/CVE scan

Findings: 17
Critical: 1
High:     4
Medium:   7
Low:      3
Info:     2

Potential privilege-escalation paths:

[CRITICAL] Writable root-owned SUID binary
  Category:   suid
  Confidence: CONFIRMED
  Path:       /opt/tools/backup
  Detail:     SUID binary is writable by the current user - direct code
              execution as owner is likely.

[HIGH] Writable file in cron job
  Category:   cron
  Confidence: LIKELY
  Path:       /opt/scripts/cleanup.sh
  Detail:     Referenced by /etc/crontab and writable by current user.

[MEDIUM] Non-standard SUID binary
  Category:   suid
  Confidence: POSSIBLE
  Path:       /usr/bin/example

NOTE: Findings are audit results requiring human verification, not proof of exploitability.
```

JSON output (`--json`) mirrors the same data as a single object with `host`,
`summary`, and a `findings` array — suitable for piping into `jq` or a pipeline.

## Limitations

- Baseline lists (expected SUID and SGID binaries, "risky" binaries) are
  small and curated, not exhaustive; tune them for your environment.
- Capability and `/proc` process scans are Linux-only.
- No parsing of LD/loader configs, NFS `no_root_squash`, container/namespace
  escapes, kernel module signing, or SELinux/AppArmor posture — the tool covers
  the common classic vectors, not every possible one.
- The CVE heuristic is coarse and backport-blind (see above).
- Findings are **audit results requiring human verification, not automatic
  proof of exploitability.**
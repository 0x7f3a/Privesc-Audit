# Check reference

<!-- Generated from main.c by `tests/check-docs.py --write`. Do not edit by hand. -->

Every finding the tool can emit carries a stable `check_id`. The table
below is extracted from the `add_finding()` call sites in `main.c`, so it
cannot drift from what the binary actually reports.

Platform is the preprocessor scope of the call site: `linux` and `windows`
checks are compiled only into that build, `both` into either. Severity and
confidence are what the code passes at the call site; a few checks vary at
runtime (see the notes under the tables).

**111 check ids.**

### `system` (3)

| Check ID | Severity | Confidence | Platform | Title |
| -------- | -------- | ---------- | -------- | ----- |
| `sys.profile` | INFO | CONFIRMED | linux, windows | System profile |
| `sys.running_as_root` | INFO | CONFIRMED | linux | Running as root |
| `sys.running_elevated` | INFO | CONFIRMED | windows | Running elevated |

### `suid` (10)

| Check ID | Severity | Confidence | Platform | Title |
| -------- | -------- | ---------- | -------- | ----- |
| `suid.baseline` | INFO | CONFIRMED | linux | Standard SUID binary |
| `suid.gtfobins` | HIGH | LIKELY | linux | Known-exploitable SUID binary |
| `suid.nonroot_suid` | LOW | POSSIBLE | linux | Non-root-owned SUID binary |
| `suid.nonstandard` | MEDIUM | POSSIBLE | linux | Non-standard SUID binary |
| `suid.sgid_baseline` | INFO | CONFIRMED | linux | Standard SGID binary |
| `suid.sgid_nonroot` | LOW | POSSIBLE | linux | Non-root-owned SGID binary |
| `suid.sgid_root` | MEDIUM | POSSIBLE | linux | Root-owned SGID binary |
| `suid.writable_nonroot_owned` | HIGH | CONFIRMED | linux | Writable non-root-owned privileged binary |
| `suid.writable_root_auditor` | INFO | CONFIRMED | linux | Writable privileged binary (root auditor) |
| `suid.writable_root_owned` | CRITICAL | CONFIRMED | linux | Writable root-owned binary |

### `capabilities` (18)

| Check ID | Severity | Confidence | Platform | Title |
| -------- | -------- | ---------- | -------- | ----- |
| `cap.cap_chown` | MEDIUM | POSSIBLE | linux | File capability set |
| `cap.cap_dac_override` | HIGH | LIKELY | linux | File capability set |
| `cap.cap_dac_read_search` | HIGH | LIKELY | linux | File capability set |
| `cap.cap_fowner` | MEDIUM | POSSIBLE | linux | File capability set |
| `cap.cap_fsetid` | MEDIUM | POSSIBLE | linux | File capability set |
| `cap.cap_net_admin` | MEDIUM | POSSIBLE | linux | File capability set |
| `cap.cap_setgid` | HIGH | LIKELY | linux | File capability set |
| `cap.cap_setpcap` | HIGH | LIKELY | linux | File capability set |
| `cap.cap_setuid` | CRITICAL | LIKELY | linux | File capability set |
| `cap.cap_sys_admin` | CRITICAL | LIKELY | linux | File capability set |
| `cap.cap_sys_chroot` | MEDIUM | POSSIBLE | linux | File capability set |
| `cap.cap_sys_module` | CRITICAL | LIKELY | linux | File capability set |
| `cap.cap_sys_ptrace` | HIGH | LIKELY | linux | File capability set |
| `cap.cap_sys_rawio` | HIGH | LIKELY | linux | File capability set |
| `cap.cap_sys_time` | LOW | POSSIBLE | linux | File capability set |
| `cap.enumerated` | INFO | CONFIRMED | linux | Files with capabilities enumerated |
| `cap.present` | INFO | CONFIRMED | linux | File capability set (informational) |
| `cap.unavailable` | INFO | CONFIRMED | windows | Capability scan unavailable |

### `sudo` (12)

| Check ID | Severity | Confidence | Platform | Title |
| -------- | -------- | ---------- | -------- | ----- |
| `sudo.env_keep_loader` | HIGH | LIKELY | linux | Dangerous sudo env_keep |
| `sudo.fallback_available` | INFO | CONFIRMED | linux | sudo -n -l fallback available but disabled |
| `sudo.fallback_empty` | INFO | CONFIRMED | linux | sudo -n -l returned nothing |
| `sudo.fallback_failed` | LOW | POSSIBLE | linux | sudo -n -l fallback failed to run |
| `sudo.fallback_used` | INFO | CONFIRMED | linux | sudo -n -l fallback used |
| `sudo.no_authenticate` | MEDIUM | LIKELY | linux | sudo !authenticate |
| `sudo.nopasswd` | HIGH / MEDIUM | LIKELY | linux | Passwordless sudo rule |
| `sudo.sudoers_dir_writable` | CRITICAL | CONFIRMED | linux | Writable sudoers directory |
| `sudo.sudoers_dir_writable_root_auditor` | INFO | CONFIRMED | linux | Writable sudoers directory (root auditor) |
| `sudo.sudoers_unreadable` | INFO | CONFIRMED | linux | /etc/sudoers unreadable |
| `sudo.sudoers_writable` | CRITICAL | CONFIRMED | linux | Writable sudoers file |
| `sudo.sudoers_writable_root_auditor` | INFO | CONFIRMED | linux | Writable sudoers file (root auditor) |

### `cron` (12)

| Check ID | Severity | Confidence | Platform | Title |
| -------- | -------- | ---------- | -------- | ----- |
| `const char *check_id_root` | INFO | CONFIRMED | linux | const char *title_root |
| `const char *check_id_user` | HIGH | CONFIRMED | linux | const char *title_user |
| `cron.crontab_writable` | HIGH | CONFIRMED | linux | Writable /etc/crontab |
| `cron.crontab_writable_root_auditor` | INFO | CONFIRMED | linux | Writable /etc/crontab (root auditor) |
| `cron.unparsed_line` | LOW | POSSIBLE | linux | Unparsed cron line |
| `cron.unparsed_token` | LOW | POSSIBLE | linux | Relative command in cron job |
| `cron.writable_dir` | HIGH | CONFIRMED | linux | Writable cron directory |
| `cron.writable_dir_root_auditor` | INFO | CONFIRMED | linux | Writable cron directory (root auditor) |
| `cron.writable_file` | HIGH | CONFIRMED | linux | Writable cron job file |
| `cron.writable_file_root_auditor` | INFO | CONFIRMED | linux | Writable cron job file (root auditor) |
| `cron.writable_ref` | HIGH | LIKELY | linux | Writable file referenced by cron job |
| `cron.writable_ref_root_auditor` | INFO | CONFIRMED | linux | Writable cron-referenced file (root auditor) |

### `services` (15)

| Check ID | Severity | Confidence | Platform | Title |
| -------- | -------- | ---------- | -------- | ----- |
| `svc.enumerated` | INFO | CONFIRMED | windows | Services enumerated |
| `svc.unavailable` | INFO | CONFIRMED | windows | Service scan unavailable |
| `svc.unquoted_path` | MEDIUM / INFO | POSSIBLE | windows | Unquoted service path |
| `svc.unquoted_path_root_auditor` | INFO | CONFIRMED | windows | Writable directory on unquoted service path (elevated auditor) |
| `svc.unquoted_path_writable` | HIGH | CONFIRMED | windows | Unquoted service path with writable directory |
| `svc.writable_dir` | HIGH / MEDIUM | LIKELY | windows | Service in writable directory |
| `svc.writable_dir_root_auditor` | INFO | CONFIRMED | windows | Writable service directory (elevated auditor) |
| `svc.writable_exec_nonroot` | MEDIUM | LIKELY | linux | Writable service executable (non-root unit) |
| `svc.writable_exec_root` | HIGH | LIKELY | linux | Writable service executable (runs as root) |
| `svc.writable_exec_root_auditor` | INFO | CONFIRMED | linux | Writable service executable (root auditor) |
| `svc.writable_image` | CRITICAL / HIGH | CONFIRMED | windows | Writable service image (privileged account) / Writable service image (non-privileged account) |
| `svc.writable_image_root_auditor` | INFO | CONFIRMED | windows | Writable service image (elevated auditor) |
| `svc.writable_root_auditor` | INFO | CONFIRMED | linux | Writable unit (root auditor) |
| `svc.writable_unit` | HIGH | CONFIRMED | linux | Writable systemd unit |
| `svc.writable_unit_dir` | HIGH | CONFIRMED | linux | Unit in writable directory |

### `processes` (5)

| Check ID | Severity | Confidence | Platform | Title |
| -------- | -------- | ---------- | -------- | ----- |
| `proc.coverage_limitation` | INFO | CONFIRMED | linux | Process scan coverage limitation |
| `proc.deleted_exe` | LOW | POSSIBLE | linux | Root process with deleted backing executable |
| `proc.unavailable` | INFO | CONFIRMED | linux | Process scan unavailable |
| `proc.writable_exe` | HIGH | LIKELY | linux | Root process with writable binary |
| `proc.writable_exe_root_auditor` | INFO | CONFIRMED | linux | Root process writable by root (auditor) |

### `filesystem` (17)

| Check ID | Severity | Confidence | Platform | Title |
| -------- | -------- | ---------- | -------- | ----- |
| `fs.path_empty_component` | MEDIUM | LIKELY | linux | Empty $PATH component |
| `fs.path_empty_component` | LOW | LIKELY | windows | Empty PATH component |
| `fs.path_not_dir` | LOW | CONFIRMED | linux | Non-directory $PATH entry |
| `fs.path_overlong` | LOW | CONFIRMED | linux | Overlong $PATH value |
| `fs.path_overlong` | LOW | CONFIRMED | windows | Overlong PATH value |
| `fs.path_relative` | MEDIUM | LIKELY | linux | Relative entry in $PATH |
| `fs.path_relative` | MEDIUM | LIKELY | windows | Relative entry in PATH |
| `fs.path_writable` | HIGH | CONFIRMED | linux | Writable directory in $PATH |
| `fs.path_writable` | HIGH | CONFIRMED | windows | Writable directory in PATH |
| `fs.path_writable_root_auditor` | INFO | CONFIRMED | linux | Writable $PATH directory (root auditor) |
| `fs.path_writable_root_auditor` | INFO | CONFIRMED | windows | Writable PATH directory (elevated auditor) |
| `fs.path_writable_user_profile` | LOW | CONFIRMED | both | Writable directory in your own PATH / Writable directories in your own PATH |
| `fs.sensitive_writable` | CRITICAL / HIGH | CONFIRMED | linux | Writable sensitive file |
| `fs.sensitive_writable_root_auditor` | INFO | CONFIRMED | linux | Writable sensitive file (root auditor) |
| `fs.shadow_readable` | HIGH | CONFIRMED | linux | Readable shadow file |
| `fs.sticky_missing` | MEDIUM | CONFIRMED | linux | World-writable dir without sticky bit |
| `perm.unevaluated` | INFO | CONFIRMED | windows | Permission checks that could not be evaluated |

### `package` (4)

| Check ID | Severity | Confidence | Platform | Title |
| -------- | -------- | ---------- | -------- | ----- |
| `pkg.kernel_cve_candidate` | HIGH | POSSIBLE | linux | Upstream kernel CVE candidate (unconfirmed) |
| `pkg.kernel_version_unknown` | INFO | POSSIBLE | linux | Kernel version unknown |
| `pkg.pwnkit_surface` | MEDIUM | POSSIBLE | linux | pkexec present (PwnKit surface) |
| `pkg.pwnkit_surface_unknown_version` | MEDIUM | POSSIBLE | linux | pkexec present (PwnKit surface) |

### `autostart` (11)

| Check ID | Severity | Confidence | Platform | Title |
| -------- | -------- | ---------- | -------- | ----- |
| `auto.always_install_elevated` | CRITICAL / INFO | CONFIRMED | windows | AlwaysInstallElevated enabled |
| `auto.always_install_elevated_partial` | MEDIUM | CONFIRMED | windows | AlwaysInstallElevated partially configured |
| `auto.run_key_writable` | CRITICAL | CONFIRMED | windows | Writable machine-wide autostart key |
| `auto.run_key_writable_root_auditor` | INFO | CONFIRMED | windows | Writable autostart key (elevated auditor) |
| `auto.run_target_writable` | HIGH | LIKELY | windows | Writable autostart target |
| `auto.run_target_writable_root_auditor` | INFO | CONFIRMED | windows | Writable autostart target (elevated auditor) |
| `auto.startup_dir_root_auditor` | INFO | CONFIRMED | windows | Writable Startup folder (elevated auditor) |
| `auto.startup_dir_user_writable` | INFO | CONFIRMED | windows | Writable per-user Startup folder (own account) |
| `auto.startup_dir_writable` | HIGH | CONFIRMED | windows | Writable all-users Startup folder |
| `auto.startup_file_root_auditor` | INFO | CONFIRMED | windows | Writable Startup entry (elevated auditor) |
| `auto.startup_file_writable` | HIGH | CONFIRMED | windows | Writable all-users Startup entry |

### `privileges` (3)

| Check ID | Severity | Confidence | Platform | Title |
| -------- | -------- | ---------- | -------- | ----- |
| `priv.dangerous` | CRITICAL / HIGH / MEDIUM | CONFIRMED | windows | Dangerous privilege enabled / Dangerous privilege present (disabled) |
| `priv.integrity_level` | INFO | CONFIRMED | windows | Token integrity level |
| `priv.unavailable` | INFO | CONFIRMED | windows | Privilege scan unavailable |

### `platform` (1)

| Check ID | Severity | Confidence | Platform | Title |
| -------- | -------- | ---------- | -------- | ----- |
| `platform.not_applicable` | INFO | CONFIRMED | both | Scan not applicable on this platform |

## Notes

- `sys.profile`, `sys.running_as_root` / `sys.running_elevated` and the
  `perm.*` family are informational context rather than defects.
- Cron ids ending in `_root_auditor` are the same condition judged from an
  elevated identity: they downgrade to `INFO` when the audit runs as root,
  while the plain id is `HIGH` for an unprivileged user.
- Capability ids come from `cap_table[]`; any permitted capability outside
  that table is still reported, but only through `cap.present`.
- Unquoted-service and writable-path checks may be emitted several times
  for one root cause; duplicates are collapsed by `add_finding()`.
- `check_id`s are stable across releases: pipelines may key on them.
- The `platform` group is emitted for a `--check` category that only   exists on the other operating system, so its category is whichever   one was requested.

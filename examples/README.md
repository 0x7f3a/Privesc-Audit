# Example reports

Real, unmodified output from this tool — not hand-written samples.

| File                  | Produced by                            | Host                                     |
| --------------------- | -------------------------------------- | ---------------------------------------- |
| `linux-report.txt`    | `./privesc-auditor --verbose --no-color` | Ubuntu 24.04 container, non-root user    |
| `linux-report.json`   | `./privesc-auditor --verbose --json`     | same run, machine-readable form          |

Both files describe the **same run**: 28 findings (1 `HIGH`, 27 `INFO`), scan
coverage `PARTIAL`. The container is a nearly stock system, so the interesting
part of the report is the structure rather than the number of defects:

- `fs.path_writable` — a writable directory on `$PATH`, the one real finding;
- `suid.baseline` / `suid.sgid_baseline` — every stock SUID/SGID binary listed
  as `INFO`, because they are on the expected baseline;
- `sys.profile` and `cap.enumerated` — enumeration context;
- the **Scan coverage** block, which states what could *not* be read instead of
  pretending it was clean.

Regenerate them on any Linux host:

```bash
make
./privesc-auditor --verbose --no-color > examples/linux-report.txt
./privesc-auditor --verbose --json     > examples/linux-report.json
```

Expect a different shape of result on a real target: a hardened or messy host
produces `CRITICAL`/`HIGH` entries that the container does not have. A Windows
report looks the same in structure with `host.platform` set to `windows` and
the `services`, `autostart` and `privileges` categories filled in; capture one
with `privesc-auditor.exe --verbose --json` on a Windows machine.
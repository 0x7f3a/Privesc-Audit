#!/usr/bin/env bash
# Regression suite for privesc-auditor.
#
#   tests/run.sh          run every check
#   make test             same thing
#
# Checks are end-to-end: they build the real binary, run it against this host
# and compare what it reports with ground truth gathered independently
# (find(1), the JSON schema, the generated check reference).

set -uo pipefail
cd "$(dirname "$0")/.."

rc=0
ok()   { printf '  \033[32mok\033[0m    %s\n' "$1"; }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; rc=1; }
note() { printf '        %s\n' "$1"; }
step() { printf '\n%s\n' "$1"; }

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
SRC=main.c
BIN="$TMP/privesc-auditor"

command -v python3 >/dev/null 2>&1 || { echo "tests: python3 is required" >&2; exit 1; }

# ---------------------------------------------------------------- build
step "Build"
if cc -std=c11 -Wall -Wextra -Wpedantic -Werror -O2 \
      -D_FORTIFY_SOURCE=2 -fstack-protector-strong -o "$BIN" "$SRC" 2>"$TMP/build.log"; then
    ok "warning-free build (-Wall -Wextra -Wpedantic -Werror)"
else
    bad "build produced diagnostics"
    sed 's/^/        /' "$TMP/build.log" | head -20
fi

if [ ! -x "$BIN" ]; then
    echo "tests: binary missing, aborting" >&2
    exit 1
fi

"$BIN" --version >"$TMP/version.txt" 2>&1
if grep -q '^privesc-auditor [0-9]' "$TMP/version.txt"; then
    ok "--version: $(cat "$TMP/version.txt")"
else
    bad "--version output unexpected: $(cat "$TMP/version.txt")"
fi

# ---------------------------------------------------------------- unit
step "Unit tests (helper logic)"
if cc -std=c11 -Wall -Wextra -Wpedantic -Werror -O1 -o "$TMP/unit" tests/unit.c 2>"$TMP/unit-build.log"; then
    if "$TMP/unit" >"$TMP/unit.txt" 2>&1; then
        ok "helper unit tests pass ($(grep -c '^  ok' "$TMP/unit.txt") assertions)"
    else
        bad "helper unit tests failed"
        grep -A2 'FAIL' "$TMP/unit.txt" | head -20 | sed 's/^/        /'
    fi
else
    bad "unit test build failed"
    head -10 "$TMP/unit-build.log" | sed 's/^/        /'
fi

if cc -std=c11 -Wall -Wextra -Wpedantic -Werror -O1 -o "$TMP/fp" tests/fp.c 2>"$TMP/fp-build.log"; then
    if "$TMP/fp" >"$TMP/fp.txt" 2>&1; then
        ok "false-positive matrix passes ($(grep -c '^  ok' "$TMP/fp.txt") cases)"
    else
        bad "false-positive matrix failed"
        grep -A3 'FAIL' "$TMP/fp.txt" | head -24 | sed 's/^/        /'
    fi
else
    bad "false-positive matrix build failed"
    head -10 "$TMP/fp-build.log" | sed 's/^/        /'
fi

# ---------------------------------------------------------------- runs
step "Runs"
"$BIN" --verbose --no-color >"$TMP/report.txt" 2>"$TMP/report.err"
text_rc=$?
"$BIN" --verbose --json >"$TMP/report.json" 2>"$TMP/json.err"
json_rc=$?
"$BIN" --json >"$TMP/default.json" 2>/dev/null
default_rc=$?

for name in text json; do
    case $name in text) e=$text_rc;; json) e=$json_rc;; esac
    if [ "$e" -ge 0 ] && [ "$e" -le 3 ]; then
        ok "$name run exited $e (documented exit-code range 0-3)"
    else
        bad "$name run exited $e (out of range)"
    fi
done
[ -s "$TMP/report.err" ] && { bad "text run wrote to stderr"; cat "$TMP/report.err"; } \
                         || ok "text run is silent on stderr"
grep -q '\[+\] System enumeration' "$TMP/report.txt" && ok "text report contains scan progress" \
                                                     || bad "text report missing scan progress"
grep -q 'Scan coverage:' "$TMP/report.txt" && ok "text report states scan coverage" \
                                            || bad "text report missing scan coverage"
grep -q 'root  ♛' "$TMP/report.txt" && ok "text report opens with the ASCII-art banner" \
                                     || bad "text report missing the ASCII-art banner"
if grep -q 'human-verified' "$TMP/report.json"; then
    bad "ASCII-art banner leaked into the JSON report"
else
    ok "JSON report stays art-free"
fi
grep -q 'Next steps:' "$TMP/report.txt" && ok "text report suggests next steps" \
                                     || bad "text report has no next-step suggestions"
if grep -q '"actions": \[' "$TMP/report.json"; then
    ok "JSON findings carry an actions array"
else
    bad "JSON findings carry no actions"
fi
"$BIN" --verbose --json --no-actions >"$TMP/noact.json" 2>/dev/null
if grep -q '"actions"' "$TMP/noact.json"; then
    bad "--no-actions still emitted actions"
else
    ok "--no-actions omits the actions array"
fi

# A default run must not describe the other platform's scans as "not
# applicable": that note only makes sense for a category the caller asked for.
if grep -q 'platform.not_applicable' "$TMP/report.txt"; then
    bad "default run reported other-platform scans as not applicable"
else
    ok "default run says nothing about other-platform scans"
fi
"$BIN" --check autostart --json >"$TMP/na.json" 2>"$TMP/na.err"
if grep -q 'Windows build only' "$TMP/na.err"; then
    ok "--check autostart explains itself on stderr"
else
    bad "--check autostart produced no explanation"
fi
"$BIN" --check autostart --verbose --json >"$TMP/na.json" 2>/dev/null
if python3 -c 'import json,sys; f=json.load(open(sys.argv[1]))["findings"]; sys.exit(0 if any(x["check_id"] == "platform.not_applicable" for x in f) else 1)' "$TMP/na.json"; then
    ok "--verbose JSON records the note as INFO"
else
    bad "--verbose JSON lost the not-applicable note"
fi

# End-to-end Linux behaviour: a writable PATH directory outside $HOME is a real
# HIGH and must drive exit code 2, not merely appear in a listing.
mkdir -p "$TMP/planted"
PATH="$TMP/planted:/usr/bin:/bin" "$BIN" --json >"$TMP/planted.json" 2>/dev/null
planted_rc=$?
if python3 - "$TMP/planted.json" "$TMP/planted" "$planted_rc" <<'PY'
import json, sys
rep = json.load(open(sys.argv[1]))
path, rc = sys.argv[2], int(sys.argv[3])
hits = [f for f in rep["findings"]
        if f["check_id"] == "fs.path_writable" and f["path"] == path]
errs = []
if len(hits) != 1:
    errs.append("expected one fs.path_writable for %s, got %d" % (path, len(hits)))
elif hits[0]["severity"] != "HIGH":
    errs.append("severity is %s, expected HIGH" % hits[0]["severity"])
if rc != 2:
    errs.append("exit code %d, expected 2 for a HIGH finding" % rc)
if errs:
    print("        " + "\n        ".join(errs))
    sys.exit(1)
PY
then
    ok "a writable PATH directory outside HOME is HIGH and exits 2"
else
    bad "end-to-end HIGH path is wrong (see above)"
fi

# A directory whose name contains a space must survive the round trip.
mkdir -p "$TMP/with space"
PATH="$TMP/with space:/usr/bin:/bin" "$BIN" --verbose --json >"$TMP/space.json" 2>/dev/null
if grep -q "with space" "$TMP/space.json"; then
    ok "a PATH directory containing a space is reported intact"
else
    bad "a PATH directory containing a space was mangled"
fi

# Two identical runs must produce identical reports.
"$BIN" --verbose --no-color >"$TMP/det1.txt" 2>/dev/null
"$BIN" --verbose --no-color >"$TMP/det2.txt" 2>/dev/null
if cmp -s "$TMP/det1.txt" "$TMP/det2.txt"; then
    ok "repeated runs are byte-identical"
else
    bad "output is not deterministic between runs"
fi

# HOME=/ must not turn the account's own tools into system directories: the
# passwd home is used instead, so any own-profile directory stays LOW.
env HOME=/ "$BIN" --json >"$TMP/home-root.json" 2>/dev/null
home_root_rc=$?
if python3 - "$TMP/home-root.json" "$home_root_rc" <<'PY'
import json, os, pwd, sys
rep = json.load(open(sys.argv[1]))
rc = int(sys.argv[2])
home = pwd.getpwuid(os.getuid()).pw_dir.rstrip("/")
errs = []
for f in rep["findings"]:
    p = f.get("path", "")
    if f["check_id"] == "fs.path_writable" and home and (
            p == home or p.startswith(home + "/")):
        errs.append("own-profile directory rated HIGH with HOME=/: %s" % p)
if rc > 1:
    errs.append("exit code %d with HOME=/, expected 0 or 1" % rc)
if errs:
    print("        " + "\n        ".join(errs))
    sys.exit(1)
PY
then
    ok "HOME=/ falls back to the passwd home instead of misrating it"
else
    bad "HOME=/ misclassified an own-profile directory"
fi

# With HOME unset the profile must still be known (via the passwd entry), or
# the account's own tools turn into a HIGH and exit code 2.
env -u HOME "$BIN" --json >"$TMP/nohome.json" 2>/dev/null
nohome_rc=$?
if python3 - "$TMP/nohome.json" "$nohome_rc" <<'PY'
import json, sys
rep = json.load(open(sys.argv[1]))
rc = int(sys.argv[2])
errs = []
for f in rep["findings"]:
    if f["check_id"] == "fs.path_writable":
        errs.append("fs.path_writable rated HIGH with HOME unset: %s" % f["path"])
if rc > 1:
    errs.append("exit code %d with HOME unset, expected 0 or 1" % rc)
if errs:
    print("        " + "\n        ".join(errs))
    sys.exit(1)
PY
then
    ok "an unset HOME does not turn own-profile directories into HIGH"
else
    bad "an unset HOME misclassified a writable PATH directory"
fi

# An unset PATH must be stated, not silently skipped.
env -u PATH "$BIN" --verbose --json >"$TMP/nopath.json" 2>/dev/null
if python3 -c 'import json,sys; ids={f["check_id"] for f in json.load(open(sys.argv[1]))["findings"]}; sys.exit(0 if "fs.path_unset" in ids else 1)' "$TMP/nopath.json"; then
    ok "an unset PATH is reported instead of skipped silently"
else
    bad "an unset PATH produced no note"
fi

# An empty report is still valid JSON with total 0 and an empty array.
"$BIN" --check system --json >"$TMP/empty.json" 2>/dev/null
if python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if d["summary"]["total"] == 0 and d["findings"] == [] else 1)' "$TMP/empty.json"; then
    ok "a run with nothing to report is valid JSON (total 0, empty array)"
else
    bad "empty report is not valid JSON as expected"
fi

"$BIN" --check no-such-category >/dev/null 2>&1
if [ $? -eq 2 ]; then
    ok "--check with an unknown category exits 2"
else
    bad "--check with an unknown category did not exit 2"
fi

# Calibration: a writable directory inside the account's own profile must not
# be reported HIGH, and must be summarised under a single LOW finding.
python3 - "$TMP/report.json" <<'PY' && ok "PATH severity is calibrated to ownership" \
                                    || bad "PATH severity calibration regressed"
import json, os, sys
f = json.load(open(sys.argv[1]))["findings"]
home = os.environ.get("HOME", "").rstrip("/")
errs = []
for x in f:
    if x.get("check_id") == "fs.path_writable" and home:
        p = x.get("path", "")
        if p == home or p.startswith(home + "/"):
            errs.append("in-profile directory reported HIGH: %s" % p)
    if x.get("check_id") == "fs.path_writable_user_profile" and x.get("severity") != "LOW":
        errs.append("profile summary is %s, expected LOW" % x.get("severity"))
if errs:
    print("        " + "\n        ".join(errs))
    sys.exit(1)
PY

# ---------------------------------------------------------------- JSON
step "JSON schema"
python3 - "$TMP/report.json" "$TMP/default.json" <<'PY' && ok "JSON invariants hold" || bad "JSON invariants"
import json, sys

rep = json.load(open(sys.argv[1]))
dft = json.load(open(sys.argv[2]))
errs = []

if rep.get("tool") != "privesc-auditor":
    errs.append("tool field is %r" % rep.get("tool"))
for key in ("host", "summary", "findings", "coverage"):
    if key not in rep:
        errs.append("missing top-level key %r" % key)

f = rep["findings"]
s = rep["summary"]
if s["total"] != len(f):
    errs.append("summary.total %s != %d findings" % (s["total"], len(f)))
counts = {k: 0 for k in ("critical", "high", "medium", "low", "info")}
for item in f:
    sev = item.get("severity", "").lower()
    if sev in counts:
        counts[sev] += 1
    else:
        errs.append("unknown severity %r" % item.get("severity"))
    for key in ("check_id", "category", "severity", "confidence", "title", "detail"):
        if key not in item:
            errs.append("finding missing %r: %r" % (key, item))
    if not item.get("check_id", "").count("."):
        errs.append("check_id %r is not dotted" % item.get("check_id"))
if any(s.get(k) != v for k, v in counts.items()):
    errs.append("summary %s does not match recounted severities %s"
                % ({k: s.get(k) for k in counts}, counts))
if sum(v for k, v in counts.items() if k != "info") != \
   sum(s.get(k, 0) for k in ("critical", "high", "medium", "low")):
    errs.append("non-info severity counts disagree")
if rep["host"].get("platform") != "linux":
    errs.append("host.platform is %r" % rep["host"].get("platform"))
if rep["host"].get("uid") is None:
    errs.append("host.uid must not be null on Linux")
if not isinstance(rep["coverage"], dict):
    errs.append("coverage is not an object")

# default (non-verbose) run must hide INFO but keep everything else
info_default = sum(1 for x in dft["findings"] if x["severity"] == "INFO")
if info_default:
    errs.append("non-verbose JSON still contains %d INFO findings" % info_default)
if dft["summary"]["total"] != len(dft["findings"]):
    errs.append("non-verbose summary.total disagrees with findings length")

if errs:
    print("        " + "\n        ".join(errs))
    sys.exit(1)
PY

# exit code must reflect the worst severity of that same run
expected=$(python3 -c '
import json,sys
s=json.load(open(sys.argv[1]))["summary"]
print(3 if s["critical"] else 2 if s["high"] else
      1 if (s["medium"] or s["low"]) else 0)' "$TMP/default.json")
if [ "$default_rc" = "$expected" ]; then
    ok "exit code $default_rc matches worst severity in the run"
else
    bad "exit code $default_rc, expected $expected from summary"
fi

# ---------------------------------------------------------------- honesty
step "No duplicated findings"
python3 - "$TMP/report.json" <<'PY' && ok "every (check_id, path, detail) triple is unique" \
                                     || bad "duplicate findings present"
import json, sys
f = json.load(open(sys.argv[1]))["findings"]
seen, dup = set(), []
for x in f:
    k = (x.get("check_id"), x.get("path"), x.get("detail"))
    if k in seen:
        dup.append(k)
    seen.add(k)
if dup:
    print("        " + "\n        ".join("%s %s" % (d[0], d[1]) for d in dup[:5]))
    sys.exit(1)
PY

# ---------------------------------------------------------------- docs
step "Documentation"
tests/check-docs.py >/dev/null 2>&1 && ok "docs/checks.md matches main.c" \
    || { bad "docs/checks.md is stale (tests/check-docs.py --write)"; tests/check-docs.py 2>&1 | sed 's/^/        /'; }

missing=$(python3 - "$TMP/report.json" docs/checks.md <<'PY'
import json, sys, re
ids = {x["check_id"] for x in json.load(open(sys.argv[1]))["findings"]}
doc = set(re.findall(r"^\| `([a-z][\w.]+)` \|", open(sys.argv[2]).read(), re.M))
for i in sorted(ids - doc):
    print(i)
PY
)
if [ -z "$missing" ]; then
    ok "every check_id this run emitted is documented in docs/checks.md"
else
    bad "undocumented check_ids: $(echo "$missing" | tr '\n' ' ')"
fi

# ------------------------------------------------ ground truth: SUID/SGID
step "Ground truth: SUID/SGID against find(1)"
"$BIN" --check suid --verbose --json >"$TMP/suid.json" 2>/dev/null
{
    # mirrors the scan roots in main.c (scan_suid): same roots, same depth
    for d in /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin \
             /usr/lib /opt; do
        [ -d "$d" ] && find "$d" -xdev -maxdepth 4 -type f \
            \( -perm -4000 -o -perm -2000 \) 2>/dev/null
    done
} | while IFS= read -r p; do realpath "$p"; done | sort -u >"$TMP/find.txt"
python3 - "$TMP/suid.json" >"$TMP/tool.txt" <<'PY'
import json, os, sys
f = json.load(open(sys.argv[1]))["findings"]
paths = {x["path"] for x in f if x.get("category") == "suid" and x.get("path")}
# compare real paths: /bin and /usr/bin are the same directory on usr-merged
# systems and the tool reports whichever root it walked first.
print("\n".join(sorted(os.path.realpath(p) for p in paths)))
PY
if diff -u "$TMP/find.txt" "$TMP/tool.txt" >"$TMP/suid.diff"; then
    ok "identical sets ($(wc -l <"$TMP/find.txt") privileged binaries)"
else
    bad "SUID/SGID sets differ between find(1) and the tool"
    sed 's/^/        /' "$TMP/suid.diff" | head -20
fi

# ------------------------------------------------------- category isolation
step "--check isolation"
for cat in suid cron sudo filesystem; do
    "$BIN" --check "$cat" --json >"$TMP/cat.json" 2>/dev/null
    if python3 -c 'import json,sys; cats={f["category"] for f in json.load(open(sys.argv[1]))["findings"]}; sys.exit(0 if cats <= {sys.argv[2]} else 1)' "$TMP/cat.json" "$cat"; then
        ok "--check $cat only reports the $cat category"
    else
        bad "--check $cat leaked a category that was not selected"
    fi
done

# ------------------------------------------------------------- arguments
step "Argument handling"
"$BIN" --no-such-flag >"$TMP/bad.out" 2>"$TMP/bad.err"
if [ $? -eq 2 ] && [ -s "$TMP/bad.err" ]; then
    ok "unknown flag exits 2 with a message on stderr"
else
    bad "unknown flag handling: rc=$? stdout=$(wc -c <"$TMP/bad.out") stderr=$(cat "$TMP/bad.err")"
fi

# ---------------------------------------------- root path (real uid 0)
# The matrix can set Options.is_root, but only a real uid 0 proves the
# downgrade logic against the kernel. An unprivileged user namespace maps the
# test user to root without any privileges on the host.
step "Root path: real uid 0 in an unprivileged user namespace"
ROOT_NS=0
if command -v unshare >/dev/null 2>&1 && unshare -Ur true 2>/dev/null; then
    ROOT_NS=1
fi
if [ "$ROOT_NS" -eq 0 ]; then
    if [ "${REQUIRE_ROOT_NS:-0}" = 1 ]; then
        bad "unprivileged user namespaces are unavailable (REQUIRE_ROOT_NS=1)"
    else
        note "skipped: unshare -Ur is not permitted on this host"
    fi
else
    mkdir -p "$TMP/root-planted"
    PATH="$TMP/root-planted:/usr/bin:/bin" unshare -Ur "$BIN" --verbose --json \
        >"$TMP/root.json" 2>"$TMP/root.err"
    root_rc=$?
    if python3 - "$TMP/root.json" "$root_rc" "$TMP/root-planted" <<'PY'
import json, sys
rep = json.load(open(sys.argv[1]))
rc, planted = int(sys.argv[2]), sys.argv[3]
errs = []
host = rep.get("host", {})
if host.get("uid") != 0:
    errs.append("host.uid is %r inside the namespace, expected 0" % host.get("uid"))
if host.get("elevated") is not True:
    errs.append("host.elevated is %r for uid 0" % host.get("elevated"))
severe = [f for f in rep["findings"] if f["severity"] in ("HIGH", "CRITICAL")]
if severe:
    errs.append("uid 0 run reported %d HIGH/CRITICAL finding(s): %s"
                % (len(severe), ", ".join(f["check_id"] for f in severe[:3])))
hits = [f for f in rep["findings"]
        if f["check_id"] == "fs.path_writable_root_auditor" and f["path"] == planted]
if len(hits) != 1:
    errs.append("writable PATH dir not downgraded to INFO as uid 0 (%d hits)" % len(hits))
elif hits[0]["severity"] != "INFO":
    errs.append("downgraded finding is %s, expected INFO" % hits[0]["severity"])
if not any(f["check_id"] == "sys.running_as_root" for f in rep["findings"]):
    errs.append("sys.running_as_root is missing from the uid 0 run")
noise = [f for f in rep["findings"]
         if f["check_id"] in ("suid.nonroot_suid", "suid.sgid_nonroot")]
if noise:
    errs.append("uid 0 in a user namespace reports %d owner-mismatch finding(s), "
                "e.g. %s" % (len(noise), noise[0]["path"]))
if not any(f["check_id"] == "suid.userns_owner_unmapped" for f in rep["findings"]):
    errs.append("missing suid.userns_owner_unmapped note")
if rc > 1:
    errs.append("exit code %d as uid 0, expected 0 or 1" % rc)
if errs:
    print("        " + "\n        ".join(errs))
    sys.exit(1)
PY
    then
        ok "real uid 0 downgrades writable-by-me findings to INFO (exit $root_rc)"
    else
        bad "the uid-0 run does not behave as documented"
    fi
    if [ -s "$TMP/root.err" ]; then
        bad "the uid-0 run wrote to stderr"
        head -3 "$TMP/root.err" | sed 's/^/        /'
    else
        ok "the uid-0 run is silent on stderr"
    fi
fi

# ---------------------------------------------------------- sanitizers
step "Sanitizers"
if cc -std=c11 -Wall -Wextra -Wpedantic -g -O1 \
       -fsanitize=address,undefined -fno-omit-frame-pointer \
       -o "$TMP/privesc-auditor.san" "$SRC" 2>"$TMP/san-build.log"; then
    "$TMP/privesc-auditor.san" --verbose --no-color >"$TMP/san.txt" 2>"$TMP/san.err"
    san_rc=$?
    "$TMP/privesc-auditor.san" --verbose --json >"$TMP/san.json" 2>>"$TMP/san.err"
    san_json_rc=$?
    if [ "$san_json_rc" -gt 3 ] && [ "$san_rc" -le 3 ]; then san_rc=$san_json_rc; fi
    if [ -s "$TMP/san.err" ] && grep -qE 'AddressSanitizer|runtime error:|LeakSanitizer' "$TMP/san.err"; then
        bad "ASan/UBSan reported problems"
        grep -E 'AddressSanitizer|runtime error:|LeakSanitizer' "$TMP/san.err" | head -5 | sed 's/^/        /'
    elif [ "$san_rc" -gt 3 ]; then
        bad "sanitizer build exited $san_rc"
    else
        ok "ASan/UBSan run is clean, text and JSON (exit $san_rc)"
    fi
else
    bad "sanitizer build failed"
    head -10 "$TMP/san-build.log" | sed 's/^/        /'
fi

printf '\n'
if [ "$rc" -eq 0 ]; then
    printf '\033[32mAll checks passed.\033[0m\n'
else
    printf '\033[31mSome checks failed.\033[0m\n'
fi
exit "$rc"
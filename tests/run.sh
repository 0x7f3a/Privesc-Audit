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

# ---------------------------------------------------------- sanitizers
step "Sanitizers"
if cc -std=c11 -Wall -Wextra -Wpedantic -g -O1 \
       -fsanitize=address,undefined -fno-omit-frame-pointer \
       -o "$TMP/privesc-auditor.san" "$SRC" 2>"$TMP/san-build.log"; then
    "$TMP/privesc-auditor.san" --verbose --no-color >"$TMP/san.txt" 2>"$TMP/san.err"
    san_rc=$?
    if [ -s "$TMP/san.err" ] && grep -qE 'AddressSanitizer|runtime error:|LeakSanitizer' "$TMP/san.err"; then
        bad "ASan/UBSan reported problems"
        grep -E 'AddressSanitizer|runtime error:|LeakSanitizer' "$TMP/san.err" | head -5 | sed 's/^/        /'
    elif [ "$san_rc" -gt 3 ]; then
        bad "sanitizer build exited $san_rc"
    else
        ok "ASan/UBSan run is clean (exit $san_rc)"
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
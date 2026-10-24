#!/usr/bin/env python3
"""Generate (or verify) docs/checks.md from the add_finding() call sites in main.c.

Every check id the tool can emit is a literal in the source, except for two
shapes that are resolved here:

  * report_writable_cron_path(...) receives the id as a parameter, so its call
    sites are expanded into the user-auditor and root-auditor variants;
  * the capability scan builds "cap.<name>" from cap_table[], so every table
    row becomes one check id with the severity the table assigns it.

Usage:
    tests/check-docs.py --write   rewrite docs/checks.md
    tests/check-docs.py           exit 1 if docs/checks.md is out of date
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "main.c"
OUT = ROOT / "docs" / "checks.md"

CAT = {
    "CAT_SYSTEM": "system",
    "CAT_SUID": "suid",
    "CAT_CAPABILITIES": "capabilities",
    "CAT_SUDO": "sudo",
    "CAT_CRON": "cron",
    "CAT_SERVICES": "services",
    "CAT_PROCESSES": "processes",
    "CAT_FILESYSTEM": "filesystem",
    "CAT_PACKAGE": "package",
    "CAT_AUTOSTART": "autostart",
    "CAT_PRIVILEGES": "privileges",
}
SEV = {
    "SEV_CRITICAL": "CRITICAL",
    "SEV_HIGH": "HIGH",
    "SEV_MEDIUM": "MEDIUM",
    "SEV_LOW": "LOW",
    "SEV_INFO": "INFO",
}
CONF = {
    "CONF_CONFIRMED": "CONFIRMED",
    "CONF_LIKELY": "LIKELY",
    "CONF_POSSIBLE": "POSSIBLE",
}
CAT_ORDER = list(CAT.values()) + ["platform"]  # "platform" = cross-cutting ids


def split_calls(src, name="add_finding"):
    """Yield (line_number, [arg_strings]) for every call to `name`."""
    out = []
    for m in re.finditer(re.escape(name) + r"\s*\(", src):
        i = src.index("(", m.start()) + 1
        depth, in_str, esc, cur, args = 1, False, False, "", []
        while i < len(src) and depth > 0:
            c = src[i]
            if in_str:
                cur += c
                if esc:
                    esc = False
                elif c == "\\":
                    esc = True
                elif c == '"':
                    in_str = False
            elif c == '"':
                in_str, cur = True, cur + c
            elif c in "({":
                depth, cur = depth + 1, cur + c
            elif c in ")}":
                depth -= 1
                if depth == 0:
                    args.append(cur.strip())
                    break
                cur += c
            elif c == "," and depth == 1:
                args.append(cur.strip())
                cur = ""
            else:
                cur += c
            i += 1
        line = src.count("\n", 0, m.start()) + 1
        out.append((line, [a.strip() for a in args]))
    return out


def platform_at(lines):
    """Track #ifdef nesting so each call site can be labelled linux/windows."""
    stack = []  # (condition_text, is_else_branch)
    res = {}
    for n, raw in enumerate(lines, 1):
        s = raw.strip()
        if s.startswith("#if"):
            stack.append((s, False))
        elif s.startswith("#elif") and stack:
            stack[-1] = (s, False)
        elif s.startswith("#else") and stack:
            stack[-1] = (stack[-1][0], True)
        elif s.startswith("#endif") and stack:
            stack.pop()
        flag = "both"
        for cond, is_else in reversed(stack):  # innermost scope wins
            negated = is_else
            if cond.startswith("#ifndef") or "!defined" in cond:
                negated = not negated
            win, lin = "_WIN32" in cond, "__linux__" in cond
            if win:
                flag = "windows" if not negated else "linux"
                break
            if lin:
                flag = "linux" if not negated else "windows"
                break
        res[n] = flag
    return res


def strip_formats(title):
    return re.sub(r"%[-+ #0-9.*]*[diouxXeEfFgGaAcspn%]", "…", title)


SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def runtime_values(expr, lines, line, prefix, table):
    """Resolve a severity/confidence argument that is not a bare enum.

    A call may pass a variable or a ternary; collect every enum the call site
    and the lines just above it can assign, so the table shows the values the
    check can actually produce (highest first).
    """
    found = [table.get(t) for t in re.findall(prefix + r"_\w+", expr)]
    if not found:  # a bare variable: look at the assignments above the call
        window = "\n".join(lines[max(0, line - 41):line - 1])
        ident = re.escape(expr.split(".")[-1].strip())
        for pat in (rf"\b{ident}\s*=\s*({prefix}_\w+)",
                    rf"Severity\s+{ident}\s*=\s*({prefix}_\w+)",
                    rf"Confidence\s+{ident}\s*=\s*({prefix}_\w+)"):
            found += [table.get(t) for t in re.findall(pat, window)]
    vals = list(dict.fromkeys(v for v in found if v))
    if not vals and (".sev" in expr or "->sev" in expr):
        vals = table_severities(expr, lines, line)
    if not vals:
        return "runtime"
    if prefix == "SEV":
        vals.sort(key=lambda v: SEV_RANK.get(v, -1), reverse=True)
    return " / ".join(vals)


def table_severities(expr, lines, line):
    """Severity values carried by a lookup table (name[idx].sev)."""
    base = expr.split("[")[0].split(".")[0].split("->")[0].strip()
    if "->" in expr or "." in expr.split("[")[-1]:  # e.g. `c->sev` -> &array[i]
        window = "\n".join(lines[max(0, line - 41):line - 1])
        m = re.search(rf"\*\s*{re.escape(base)}\s*=\s*&?(\w+)\[", window)
        if m:
            base = m.group(1)
    m = re.search(rf"{re.escape(base)}\s*\[\s*\]\s*=\s*\{{", "\n".join(lines))
    if not m:
        return []
    body = "\n".join(lines)[m.end():]
    end = re.search(r"^\s*\};", body, re.M)  # the initializer's closing brace
    body = body[:end.start()] if end else body[:4000]
    sevs = []
    for row in re.findall(r"\{([^{}]*)\}", body):
        fields = [f.strip() for f in row.split(",")]
        if fields and fields[0] in ("NULL", '"NULL"'):
            continue  # sentinel row: the loop stops there, never reported
        sevs += [SEV[t] for t in re.findall(r"SEV_\w+", row) if t in SEV]
    return list(dict.fromkeys(sevs))


def string_of(expr):
    """Concatenate adjacent C string literals in an expression."""
    parts = re.findall(r'"((?:[^"\\]|\\.)*)"', expr)
    if not parts:
        return None
    text = "".join(parts).replace('\\"', '"').replace("\\\\", "\\")
    if "?" in expr and len(parts) > 1:  # ternary: two alternative titles
        text = " / ".join(strip_formats(p.replace('\\"', '"')) for p in parts)
    else:
        text = strip_formats(text)
    return text


def collect():
    src = SRC.read_text()
    lines = src.splitlines()
    plat = platform_at(lines)
    rows = []

    for line, args in split_calls(src):
        if len(args) < 6:
            continue
        if args[1].startswith("const char *"):  # the definition, not a call
            continue
        if not args[1].startswith('"'):  # ids built at runtime are documented
            continue  # through their table rows (see cap_table handling below)
        cat = CAT.get(args[2])
        if cat is None:
            # a handful of ids are emitted for whichever category was selected
            if args[2].startswith("(Category)"):
                cat = "platform"
            else:
                continue
        sev = runtime_values(args[3], lines, line, "SEV", SEV)
        conf = runtime_values(args[4], lines, line, "CONF", CONF)
        title = string_of(args[5]) or args[5]
        rows.append(
            dict(id=args[1].strip('"'), cat=cat, sev=sev, conf=conf,
                 title=title, line=line, plat=plat[line],
                 derived=False)
        )

    # report_writable_cron_path(fl, o, title_user, title_root,
    #                            check_id_user, check_id_root, path, detail)
    for line, args in split_calls(src, "report_writable_cron_path"):
        if len(args) < 7:
            continue
        p = plat[line]
        rows.append(dict(id=args[4].strip('"'), cat="cron", sev="HIGH",
                         conf="CONFIRMED", title=string_of(args[2]) or args[2],
                         line=line, plat=p, derived=True))
        rows.append(dict(id=args[5].strip('"'), cat="cron", sev="INFO",
                         conf="CONFIRMED", title=string_of(args[3]) or args[3],
                         line=line, plat=p, derived=True))

    # cap.%s built from cap_table[] (bit, name, sev)
    m = re.search(r"cap_table\[\]\s*=\s*\{(.*?)\n\};", src, re.S)
    if m:
        capline = src.count("\n", 0, m.start()) + 1
        p = plat[capline]
        for name, sev in re.findall(
                r"\{\s*\d+,\s*\"([^\"]+)\",\s*(SEV_\w+)", m.group(1)):
            rows.append(dict(id="cap." + name, cat="capabilities",
                             sev=SEV[sev],
                             conf="LIKELY" if sev in ("SEV_HIGH", "SEV_CRITICAL")
                                  else "POSSIBLE",
                             title="File capability set", line=capline,
                             plat=p, derived=True))
    return rows


def render(rows):
    # The same check id can legitimately appear at more than one call site
    # (a Linux and a Windows variant of one scan, or two sites that report an
    # identical condition); collapse those into a single row per platform set.
    merged = {}
    for r in rows:
        key = (r["id"], r["cat"], r["sev"], r["conf"], r["title"])
        merged.setdefault(key, set()).add(r["plat"])
    rows = [dict(id=k[0], cat=k[1], sev=k[2], conf=k[3], title=k[4],
                 plat=", ".join(sorted(v, key=["linux", "windows", "both"].index)))
            for k, v in merged.items()]
    out = [
        "# Check reference",
        "",
        "<!-- Generated from main.c by `tests/check-docs.py --write`. "
        "Do not edit by hand. -->",
        "",
        "Every finding the tool can emit carries a stable `check_id`. The table",
        "below is extracted from the `add_finding()` call sites in `main.c`, so it",
        "cannot drift from what the binary actually reports.",
        "",
        "Platform is the preprocessor scope of the call site: `linux` and `windows`",
        "checks are compiled only into that build, `both` into either. Severity and",
        "confidence are what the code passes at the call site; a few checks vary at",
        "runtime (see the notes under the tables).",
        "",
    ]
    out.append(f"**{len(rows)} check ids.**")
    out.append("")
    for cat in CAT_ORDER:
        sel = sorted([r for r in rows if r["cat"] == cat], key=lambda r: r["id"])
        if not sel:
            continue
        out.append(f"### `{cat}` ({len(sel)})")
        out.append("")
        out.append("| Check ID | Severity | Confidence | Platform | Title |")
        out.append("| -------- | -------- | ---------- | -------- | ----- |")
        for r in sel:
            title = r["title"].replace("|", "\\|")
            out.append(f"| `{r['id']}` | {r['sev']} | {r['conf']} | "
                       f"{r['plat']} | {title} |")
        out.append("")
    out += [
        "## Notes",
        "",
        "- `sys.profile`, `sys.running_as_root` / `sys.running_elevated` and the",
        "  `perm.*` family are informational context rather than defects.",
        "- Cron ids ending in `_root_auditor` are the same condition judged from an",
        "  elevated identity: they downgrade to `INFO` when the audit runs as root,",
        "  while the plain id is `HIGH` for an unprivileged user.",
        "- Capability ids come from `cap_table[]`; any permitted capability outside",
        "  that table is still reported, but only through `cap.present`.",
        "- Unquoted-service and writable-path checks may be emitted several times",
        "  for one root cause; duplicates are collapsed by `add_finding()`.",
        "- `check_id`s are stable across releases: pipelines may key on them.",
        "- The `platform` group is emitted for a `--check` category that only "
        "  exists on the other operating system, so its category is whichever "
        "  one was requested.",
        "",
    ]
    return "\n".join(out)


def main():
    rows = collect()
    if not rows:
        print("check-docs: no add_finding() call sites found", file=sys.stderr)
        return 1
    text = render(rows)
    if "--write" in sys.argv:
        OUT.parent.mkdir(parents=True, exist_ok=True)
        OUT.write_text(text)
        print(f"check-docs: wrote {OUT.relative_to(ROOT)} ({len(rows)} ids)")
        return 0
    if not OUT.exists() or OUT.read_text() != text:
        print("check-docs: docs/checks.md is out of date; "
              "run `tests/check-docs.py --write`", file=sys.stderr)
        return 1
    print(f"check-docs: {len(rows)} ids match docs/checks.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
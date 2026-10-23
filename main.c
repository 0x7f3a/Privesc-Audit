/*
 * privesc-auditor - Linux Privilege Escalation Auditor
 *
 * A read-only, defensive enumeration tool that inspects the local system for
 * common privilege-escalation *misconfigurations* and reports them as findings
 * for human review. It performs NO exploitation and makes NO changes to the
 * host. Intended for authorized security audits, hardening, and CTF practice.
 *
 * Single-file by design. Organized into logical sections:
 *   1. Types (enums / structs)
 *   2. Finding store + reporting helpers
 *   3. Utility helpers
 *   4. Scanners (one function per category)
 *   5. Output (text + JSON)
 *   6. CLI + main
 *
 * See README.md for full documentation, limitations, and caveats.
 * See fixes.md for the review history behind the fixes in this revision.
 */

#define _GNU_SOURCE

#ifdef _WIN32
/* The Windows port is a plain Win32 API build (no POSIX layer): services,
 * registry, token privileges and ACL-based permission checks. */
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#include <windows.h>
#include <io.h>
#include <aclapi.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifndef _WIN32
#include <dirent.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <sys/utsname.h>
#endif

#ifdef __linux__
#include <sys/xattr.h>
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* MSVC spells the reentrant tokenizer strtok_s; same signature and semantics
 * as strtok_r, which glibc/mingw provide. */
#if defined(_MSC_VER) && !defined(strtok_r)
#define strtok_r strtok_s
#endif

/* ========================================================================
 * Section 1: Types
 * ==================================================================== */

#define TOOL_NAME    "privesc-auditor"
#define TOOL_VERSION "2.0.1"  /* 2.0: Windows port; 2.0.1: real ACL verdicts */

#ifdef _WIN32
#define TOOL_PLATFORM "windows"
#else
#define TOOL_PLATFORM "linux"
#endif

typedef enum {
    SEV_INFO = 0,
    SEV_LOW,
    SEV_MEDIUM,
    SEV_HIGH,
    SEV_CRITICAL,
    SEV_COUNT
} Severity;

typedef enum {
    CONF_POSSIBLE = 0, /* heuristic match, weak signal */
    CONF_LIKELY,       /* strong signal, plausible path */
    CONF_CONFIRMED     /* directly observed condition (e.g. writable file) */
} Confidence;

typedef enum {
    CAT_SYSTEM = 0,
    CAT_SUID,
    CAT_CAPABILITIES,
    CAT_SUDO,
    CAT_CRON,
    CAT_SERVICES,
    CAT_PROCESSES,
    CAT_FILESYSTEM,
    CAT_PACKAGE,
    CAT_AUTOSTART,   /* Windows: Run/RunOnce, Startup folders, AlwaysInstallElevated */
    CAT_PRIVILEGES,  /* Windows: dangerous token privileges */
    CAT_COUNT
} Category;

typedef struct {
    Category   category;
    Severity   severity;
    Confidence confidence;
    char       check_id[64];  /* stable identifier, comparable across releases */
    char       title[128];
    char       path[1024];
    char       detail[1024];
} Finding;

typedef struct {
    Finding *items;
    size_t   count;
    size_t   cap;
} FindingList;

/* Which scans to run (bitmask over Category) */
typedef struct {
    bool verbose;
    bool json;
    bool use_color;
    bool is_root;         /* privileged auditor: uid 0 on POSIX, elevated admin
                           * on Windows. Findings caused only by that elevated
                           * access are downgraded to INFO. */
    bool sudo_fallback;    /* opt-in: shell out to `sudo -n -l` if sudoers unreadable */
    unsigned long selected; /* bit per Category; 0 interpreted as "all" */
} Options;

#ifdef _WIN32
typedef unsigned audit_id_t; /* Windows has no uid/gid; kept for the shared struct */
#else
typedef uid_t audit_id_t;
#endif

/* Cached host facts, gathered once. */
typedef struct {
    char   user[256];
    audit_id_t uid;             /* POSIX only; 0 on Windows (not applicable) */
    audit_id_t gid;
    char   platform[16];        /* "linux" or "windows" */
    bool   elevated;            /* Windows: token is an elevated administrator */
    char   distro[256];
    char   kernel[256];
    char   kernel_release[256]; /* raw uname release, for CVE matching */
    char   arch[128];
} HostInfo;

/* Coverage/completeness bookkeeping (fixes.md item 2 and item 12). */
typedef struct {
    int paths_skipped_unreadable;   /* individual files/dirs skipped mid-walk */
    int roots_unreadable;           /* a scan root existed but couldn't be read (real failure) */
    int roots_missing_expected;     /* a scan root simply doesn't exist on this distro (expected) */
} ScanStats;

/* ========================================================================
 * Section 2: Finding store + reporting helpers
 * ==================================================================== */

static const char *severity_name(Severity s) {
    switch (s) {
        case SEV_CRITICAL: return "CRITICAL";
        case SEV_HIGH:     return "HIGH";
        case SEV_MEDIUM:   return "MEDIUM";
        case SEV_LOW:      return "LOW";
        case SEV_INFO:     return "INFO";
        default:           return "UNKNOWN";
    }
}

static const char *severity_color(Severity s) {
    switch (s) {
        case SEV_CRITICAL: return "\033[1;35m"; /* bold magenta */
        case SEV_HIGH:     return "\033[1;31m"; /* bold red */
        case SEV_MEDIUM:   return "\033[1;33m"; /* bold yellow */
        case SEV_LOW:      return "\033[1;36m"; /* bold cyan */
        case SEV_INFO:     return "\033[1;37m"; /* bold white */
        default:           return "\033[0m";
    }
}

static const char *confidence_name(Confidence c) {
    switch (c) {
        case CONF_CONFIRMED: return "CONFIRMED";
        case CONF_LIKELY:    return "LIKELY";
        case CONF_POSSIBLE:  return "POSSIBLE";
        default:             return "UNKNOWN";
    }
}

static const char *category_name(Category c) {
    switch (c) {
        case CAT_SYSTEM:       return "system";
        case CAT_SUID:         return "suid";
        case CAT_CAPABILITIES: return "capabilities";
        case CAT_SUDO:         return "sudo";
        case CAT_CRON:         return "cron";
        case CAT_SERVICES:     return "services";
        case CAT_PROCESSES:    return "processes";
        case CAT_FILESYSTEM:   return "filesystem";
        case CAT_PACKAGE:      return "package";
        case CAT_AUTOSTART:    return "autostart";
        case CAT_PRIVILEGES:   return "privileges";
        default:               return "unknown";
    }
}

static void fl_init(FindingList *fl) {
    fl->items = NULL;
    fl->count = 0;
    fl->cap = 0;
}

static void fl_free(FindingList *fl) {
    free(fl->items);
    fl->items = NULL;
    fl->count = fl->cap = 0;
}

/* Append a finding. Uses printf-style formatting for the detail string.
 * check_id is a short, stable, dotted identifier (e.g. "suid.writable_root")
 * so findings are comparable across tool releases even if title text changes. */
static void add_finding(FindingList *fl, const char *check_id, Category cat,
                        Severity sev, Confidence conf, const char *title,
                        const char *path, const char *detail_fmt, ...) {
    /* Format the detail first so an exact duplicate can be recognised and
     * dropped. Several scanners legitimately reach the same conclusion more
     * than once (e.g. the four identical `run-parts` jobs in a stock
     * /etc/crontab, or two lines of the same cron.d file); repeating an
     * identical finding adds no information and inflates the counts. */
    char detail[1024] = "";
    if (detail_fmt) {
        va_list ap;
        va_start(ap, detail_fmt);
        vsnprintf(detail, sizeof(detail), detail_fmt, ap);
        va_end(ap);
    }

    const char *id = check_id ? check_id : "unspecified";
    const char *p  = path ? path : "";
    for (size_t i = 0; i < fl->count; i++) {
        const Finding *e = &fl->items[i];
        if (e->category == cat && e->severity == sev &&
            strcmp(e->check_id, id) == 0 && strcmp(e->path, p) == 0 &&
            strcmp(e->detail, detail) == 0)
            return;
    }

    if (fl->count == fl->cap) {
        size_t ncap = fl->cap ? fl->cap * 2 : 32;
        Finding *tmp = realloc(fl->items, ncap * sizeof(*tmp));
        if (!tmp) {
            fprintf(stderr, "%s: out of memory\n", TOOL_NAME);
            return; /* drop the finding rather than crash */
        }
        fl->items = tmp;
        fl->cap = ncap;
    }

    Finding *f = &fl->items[fl->count++];
    f->category = cat;
    f->severity = sev;
    f->confidence = conf;

    snprintf(f->check_id, sizeof(f->check_id), "%s", id);
    snprintf(f->title, sizeof(f->title), "%s", title ? title : "");
    snprintf(f->path, sizeof(f->path), "%s", p);
    snprintf(f->detail, sizeof(f->detail), "%s", detail);
}

/* ========================================================================
 * Section 3: Utility helpers
 * ==================================================================== */

static bool cat_selected(const Options *o, Category c) {
    if (o->selected == 0) return true; /* default: all */
    return (o->selected & (1UL << c)) != 0;
}

/* True if the current process can write to path (follows symlinks).
 *
 * IMPORTANT (fixes.md item 1): when the auditor itself runs as root, this is
 * true for almost every file on the system - that is root's normal access,
 * not an unprivileged escalation primitive. Callers must consult
 * Options.is_root and relabel/downgrade findings accordingly; this helper
 * only answers the narrow factual question "can the current identity write
 * this path right now" and makes no claim about what that means. */
#ifndef _WIN32
static bool is_writable_by_me(const char *path) {
    return access(path, W_OK) == 0;
}
#endif

/* ---- Windows command-line/path helpers --------------------------------
 *
 * Pure string logic (no Win32 calls), so these also build and are unit-tested
 * on POSIX. They model what the Service Control Manager / CreateProcess will
 * actually launch, which is where unquoted-service-path hijacks come from. */

/* Case-insensitive substring search; returns a pointer to the first match. */
static inline const char *str_ci_str(const char *hay, const char *needle) {
    if (!needle[0]) return hay;
    for (const char *p = hay; *p; p++) {
        size_t i = 0;
        while (needle[i] && p[i] &&
               tolower((unsigned char)p[i]) == tolower((unsigned char)needle[i]))
            i++;
        if (!needle[i]) return p;
    }
    return NULL;
}

static inline bool win_path_is_quoted(const char *s) {
    while (*s == ' ' || *s == '\t') s++;
    return *s == '"';
}

/* The executable a service command line / Run value actually names.
 *
 * For a quoted image this is the text inside the quotes. For an unquoted one
 * the loader's *first* attempt is only the text up to the first space
 * ("C:\\Program" in `C:\\Program Files\\App\\svc.exe`), which does not
 * exist; the file the service really runs is the whole path ending in .exe.
 * Inspecting only the first token made every writable-image check examine a
 * nonexistent path and silently report nothing. */
static inline bool win_image_path(const char *cmd, char *out, size_t outsz) {
    if (outsz < 2) return false;
    out[0] = '\0';
    while (*cmd == ' ' || *cmd == '\t') cmd++;

    size_t n = 0;
    if (*cmd == '"') {
        cmd++;
        while (*cmd && *cmd != '"') {
            if (n + 1 < outsz) out[n++] = *cmd;
            cmd++;
        }
        out[n] = '\0';
        return n > 0;
    }

    /* Unquoted: up to the end of the first ".exe" that finishes a path
     * component (end of string, space or tab). A directory named
     * `foo.exe.d` does not end the image, and `svc.exe -k netsvcs` stops at
     * the argument. */
    const char *end = NULL;
    for (const char *p = cmd; (p = str_ci_str(p, ".exe")) != NULL; p += 4) {
        const char *after = p + 4;
        if (*after == '\0' || *after == ' ' || *after == '\t') {
            end = after;
            break;
        }
    }
    if (end) {
        size_t len = (size_t)(end - cmd);
        while (len > 0 && (cmd[len - 1] == ' ' || cmd[len - 1] == '\t')) len--;
        if (len >= outsz) len = outsz - 1;
        memcpy(out, cmd, len);
        out[len] = '\0';
        return len > 0;
    }

    /* No extension in the command line at all: fall back to the first token. */
    while (*cmd && *cmd != ' ' && *cmd != '\t') {
        if (n + 1 < outsz) out[n++] = *cmd;
        cmd++;
    }
    out[n] = '\0';
    return n > 0;
}

/* An unquoted image path is ambiguous when ".exe" only appears after the first
 * space (e.g. `C:\Program Files\App\svc.exe`). `C:\Windows\system32\svchost.exe
 * -k netsvcs` has its extension before the first space and is unambiguous. */
static inline bool win_unquoted_ambiguous(const char *cmd) {
    if (win_path_is_quoted(cmd)) return false;
    const char *sp = strpbrk(cmd, " \t");
    if (!sp) return false;
    const char *exe = str_ci_str(cmd, ".exe");
    return exe != NULL && exe > sp;
}

/* The idx-th file CreateProcess would try for an unquoted command line: the
 * text up to the idx-th space plus ".exe". Returns false when exhausted. */
static inline bool win_unquoted_candidate(const char *cmd, int idx,
                                          char *exe_out, size_t exesz) {
    exe_out[0] = '\0';
    int seen = 0;
    for (const char *p = cmd; *p; p++) {
        if (*p != ' ' && *p != '\t') continue;
        size_t len = (size_t)(p - cmd);
        while (len > 0 && (cmd[len - 1] == ' ' || cmd[len - 1] == '\t')) len--;
        if (len == 0 || len + 5 > exesz) continue;
        if (seen++ != idx) continue;

        memcpy(exe_out, cmd, len);
        exe_out[len] = '\0';
        if (!(len >= 4 && str_ci_str(exe_out + len - 4, ".exe") == exe_out + len - 4))
            memcpy(exe_out + len, ".exe", 5); /* includes the terminator */
        return true;
    }
    return false;
}

/* Directory portion, including the trailing separator: "C:\a\b.exe" ->
 * "C:\a\"; the drive root behaves the same way ("C:\Program.exe" -> "C:\"). */
static inline bool win_dirname(const char *path, char *out, size_t outsz) {
    const char *last = NULL;
    for (const char *p = path; *p; p++)
        if (*p == '\\' || *p == '/') last = p;
    if (!outsz) return false;
    if (!last) { out[0] = '\0'; return false; }
    size_t len = (size_t)(last - path) + 1;
    if (len >= outsz) len = outsz - 1;
    memcpy(out, path, len);
    out[len] = '\0';
    return true;
}

static inline bool str_eq_ci(const char *a, const char *b) {
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return false;
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

/* Drive-absolute (C:\... or C:/...) or UNC (\\server\share). */
static inline bool win_is_abs_path(const char *p) {
    if (!p || !*p) return false;
    if (p[0] == '\\' && p[1] == '\\') return true;
    return isalpha((unsigned char)p[0]) && p[1] == ':' &&
           (p[2] == '\\' || p[2] == '/');
}

#ifdef _WIN32
/* ---- Windows API helpers ---------------------------------------------- */

/* UTF-8 (report/JSON) <-> UTF-16 (Win32). Caller frees the result. */
static wchar_t *win_wide(const char *utf8) {
    if (!utf8) return NULL;
    int need = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, NULL, 0);
    if (need <= 0) return NULL;
    wchar_t *w = malloc((size_t)need * sizeof(*w));
    if (!w) return NULL;
    if (MultiByteToWideChar(CP_UTF8, 0, utf8, -1, w, need) <= 0) {
        free(w);
        return NULL;
    }
    return w;
}

static char *win_utf8(const wchar_t *w) {
    if (!w) return NULL;
    int need = WideCharToMultiByte(CP_UTF8, 0, w, -1, NULL, 0, NULL, NULL);
    if (need <= 0) return NULL;
    char *s = malloc((size_t)need);
    if (!s) return NULL;
    if (WideCharToMultiByte(CP_UTF8, 0, w, -1, s, need, NULL, NULL) <= 0) {
        free(s);
        return NULL;
    }
    return s;
}

/* Objects whose DACL could not be evaluated. A check that could not run is
 * not the same as "not writable", and reporting it as such would be a silent
 * false negative, so the count is surfaced at the end of the scan. */
static int win_acl_unverified = 0;

/* AccessCheck() requires an *impersonation* token. Handing it the process's
 * primary token fails with ERROR_NO_IMPERSONATION_TOKEN (1309) on every
 * object, which made every writability verdict a silent "no". Duplicate the
 * process token once and reuse the impersonation handle. */
static HANDLE win_acl_token(void) {
    static HANDLE cached = NULL;
    static bool looked_up = false;
    if (looked_up) return cached;
    looked_up = true;

    HANDLE primary = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &primary))
        return NULL;

    HANDLE imp = NULL;
    if (!DuplicateTokenEx(primary, TOKEN_QUERY, NULL, SecurityImpersonation,
                          TokenImpersonation, &imp))
        imp = NULL;

    CloseHandle(primary);
    cached = imp;
    return cached;
}

/* 1 = granted, 0 = denied, -1 = the call itself failed (unknown). */
static int win_access_check3(PSECURITY_DESCRIPTOR sd, DWORD access,
                             GENERIC_MAPPING *map) {
    HANDLE tok = win_acl_token();
    if (!tok) return -1;

    PRIVILEGE_SET privs;
    DWORD privsz = sizeof(privs);
    DWORD granted = 0;
    BOOL ok = FALSE;
    if (AccessCheck(sd, tok, access, map, &privs, &privsz, &granted, &ok))
        return ok ? 1 : 0;
    return -1;
}

/* SIDs held by the current process token (user first, then groups), cached for
 * the lifetime of the run. Used only by the DACL fallback below. */
static bool win_sid_is_mine(PSID sid) {
    static bool init = false;
    static PSID user_sid = NULL;
    static TOKEN_GROUPS *groups = NULL;
    static bool usable = false;

    if (!init) {
        init = true;
        HANDLE tok = NULL;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
            DWORD len = 0;
            GetTokenInformation(tok, TokenUser, NULL, 0, &len);
            if (len) {
                TOKEN_USER *tu = malloc(len);
                if (tu && GetTokenInformation(tok, TokenUser, tu, len, &len)) {
                    DWORD n = GetLengthSid(tu->User.Sid);
                    user_sid = malloc(n);
                    if (user_sid && CopySid(n, user_sid, tu->User.Sid)) usable = true;
                }
                free(tu);
            }

            len = 0;
            GetTokenInformation(tok, TokenGroups, NULL, 0, &len);
            if (len) {
                TOKEN_GROUPS *tg = malloc(len);
                if (tg && GetTokenInformation(tok, TokenGroups, tg, len, &len))
                    groups = tg;
                else
                    free(tg);
            }
            CloseHandle(tok);
        }
    }

    if (!usable) return false;
    if (user_sid && EqualSid(sid, user_sid)) return true;
    if (groups) {
        for (DWORD i = 0; i < groups->GroupCount; i++) {
            if (groups->Groups[i].Attributes & SE_GROUP_USE_FOR_DENY_ONLY) continue;
            if (EqualSid(sid, groups->Groups[i].Sid)) return true;
        }
    }
    return false;
}

/* Evaluate the DACL directly (deny ACEs first, then allow ACEs), the way the
 * kernel would. This is the fallback for hosts where AccessCheck itself fails
 * - without it, every permission verdict on such a host would silently be
 * "not writable". */
static int win_dacl_decide(PSECURITY_DESCRIPTOR sd, PACL dacl, DWORD access,
                           GENERIC_MAPPING *map) {
    (void)sd;
    if (!dacl) return 1; /* NULL DACL: full control for everyone */

    ACL_SIZE_INFORMATION si;
    if (!GetAclInformation(dacl, &si, sizeof(si), AclSizeInformation)) return -1;

    DWORD allow = 0, deny = 0;
    for (DWORD i = 0; i < si.AceCount; i++) {
        LPVOID ace = NULL;
        if (!GetAce(dacl, i, &ace) || !ace) return -1;
        ACE_HEADER *h = ace;

        DWORD mask;
        PSID sid;
        if (h->AceType == ACCESS_ALLOWED_ACE_TYPE) {
            ACCESS_ALLOWED_ACE *a = ace;
            mask = a->Mask;
            sid = (PSID)&a->SidStart;
        } else if (h->AceType == ACCESS_DENIED_ACE_TYPE) {
            ACCESS_DENIED_ACE *d = ace;
            mask = d->Mask;
            sid = (PSID)&d->SidStart;
        } else {
            /* Object ACEs carry a SID in a variable-length tail; skip them
             * rather than mis-read the mask. */
            continue;
        }
        if (!IsValidSid(sid) || !win_sid_is_mine(sid)) continue;

        /* Expand generic rights carried inside the ACE. */
        DWORD m = mask & ~(GENERIC_ALL | GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE);
        if (mask & GENERIC_ALL) m |= map->GenericAll;
        if (mask & GENERIC_READ) m |= map->GenericRead;
        if (mask & GENERIC_WRITE) m |= map->GenericWrite;
        if (mask & GENERIC_EXECUTE) m |= map->GenericExecute;

        if (h->AceType == ACCESS_ALLOWED_ACE_TYPE) allow |= m;
        else deny |= m;
    }

    if (access & deny) return 0;
    return ((access & allow) == access) ? 1 : 0;
}

/* Final answer for one object: kernel check first, DACL arithmetic second.
 * Anything that could not be decided is counted, never reported as "no". */
static bool win_effective_write(PSECURITY_DESCRIPTOR sd, PACL dacl, DWORD access,
                                GENERIC_MAPPING *map) {
    int verdict = win_access_check3(sd, access, map);
    if (verdict < 0) verdict = win_dacl_decide(sd, dacl, access, map);
    if (verdict < 0) {
        win_acl_unverified++;
        return false;
    }
    return verdict == 1;
}

/* One INFO line so a run where permissions could not be evaluated never looks
 * like a run where everything was simply not writable. */
static void win_report_acl_gaps(FindingList *fl) {
    if (win_acl_unverified <= 0) return;
    add_finding(fl, "perm.unevaluated", CAT_FILESYSTEM, SEV_INFO, CONF_CONFIRMED,
                "Permission checks that could not be evaluated", NULL,
                "%d DACL check(s) failed (AccessCheck/DuplicateTokenEx), so those "
                "objects are reported as not writable without evidence. Treat "
                "writability findings on this host as incomplete.",
                win_acl_unverified);
}

/* Effective write access to a file or directory. */
static bool is_writable_by_me(const char *path) {
    wchar_t *wpath = win_wide(path);
    if (!wpath) return false;

    bool writable = false;
    PACL dacl = NULL;
    PSECURITY_DESCRIPTOR sd = NULL;
    DWORD rc = GetNamedSecurityInfoW(wpath, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                                     NULL, NULL, &dacl, NULL, &sd);
    if (rc != ERROR_SUCCESS && rc != ERROR_FILE_NOT_FOUND && rc != ERROR_PATH_NOT_FOUND)
        win_acl_unverified++; /* exists but unreadable, or the query failed */
    if (rc == ERROR_SUCCESS) {
        GENERIC_MAPPING map;
        map.GenericRead = FILE_GENERIC_READ;
        map.GenericWrite = FILE_GENERIC_WRITE;
        map.GenericExecute = FILE_GENERIC_EXECUTE;
        map.GenericAll = FILE_ALL_ACCESS;
        writable = win_effective_write(sd, dacl, FILE_GENERIC_WRITE, &map);
        LocalFree(sd);
    }
    free(wpath);
    return writable;
}

/* Effective KEY_SET_VALUE access to a registry key (root is HKLM or HKCU). */
static bool win_reg_write_allowed(HKEY root, const char *subkey) {
    const char *provider = (root == HKEY_LOCAL_MACHINE) ? "MACHINE" : "CURRENT_USER";
    wchar_t wprovider[32];
    if (MultiByteToWideChar(CP_UTF8, 0, provider, -1, wprovider, 32) <= 0) return false;
    wchar_t *wsub = win_wide(subkey);
    if (!wsub) return false;

    wchar_t full[1024];
    swprintf(full, sizeof(full) / sizeof(full[0]), L"%s\\%s", wprovider, wsub);
    free(wsub);

    bool writable = false;
    PACL dacl = NULL;
    PSECURITY_DESCRIPTOR sd = NULL;
    if (GetNamedSecurityInfoW(full, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION,
                              NULL, NULL, &dacl, NULL, &sd) == ERROR_SUCCESS) {
        GENERIC_MAPPING map;
        map.GenericRead = KEY_READ;
        map.GenericWrite = KEY_WRITE;
        map.GenericExecute = KEY_EXECUTE;
        map.GenericAll = KEY_ALL_ACCESS;
        writable = win_effective_write(sd, dacl, KEY_SET_VALUE, &map);
        LocalFree(sd);
    }
    return writable;
}

static bool win_process_elevated(void) {
    HANDLE tok = NULL;
    bool elevated = false;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        TOKEN_ELEVATION te;
        DWORD sz = 0;
        if (GetTokenInformation(tok, TokenElevation, &te, sizeof(te), &sz))
            elevated = te.TokenIsElevated != 0;
        CloseHandle(tok);
    }
    return elevated;
}

/* Read a REG_SZ/REG_EXPAND_SZ value as UTF-8. False if absent or not a string. */
static bool win_reg_read_string(HKEY root, const char *subkey, const char *value,
                                char *out, size_t outsz) {
    if (outsz) out[0] = '\0';
    wchar_t *wsub = win_wide(subkey);
    wchar_t *wval = win_wide(value);
    if (!wsub || !wval) { free(wsub); free(wval); return false; }

    bool ok = false;
    HKEY key;
    if (RegOpenKeyExW(root, wsub, 0, KEY_READ, &key) == ERROR_SUCCESS) {
        DWORD type = 0, bytes = 0;
        if (RegQueryValueExW(key, wval, NULL, &type, NULL, &bytes) == ERROR_SUCCESS &&
            (type == REG_SZ || type == REG_EXPAND_SZ) &&
            bytes >= sizeof(wchar_t) && bytes <= 8192) {
            wchar_t *buf = malloc(bytes + sizeof(wchar_t));
            if (buf) {
                if (RegQueryValueExW(key, wval, NULL, &type, (BYTE *)buf, &bytes) == ERROR_SUCCESS) {
                    buf[bytes / sizeof(wchar_t) - 1] = L'\0';
                    char *u = win_utf8(buf);
                    if (u) {
                        snprintf(out, outsz, "%s", u);
                        free(u);
                        ok = true;
                    }
                }
                free(buf);
            }
        }
        RegCloseKey(key);
    }
    free(wsub);
    free(wval);
    return ok;
}

static bool win_reg_read_dword(HKEY root, const char *subkey, const char *value,
                               DWORD *out) {
    wchar_t *wsub = win_wide(subkey);
    wchar_t *wval = win_wide(value);
    if (!wsub || !wval) { free(wsub); free(wval); return false; }

    bool ok = false;
    HKEY key;
    if (RegOpenKeyExW(root, wsub, 0, KEY_READ, &key) == ERROR_SUCCESS) {
        DWORD type = 0, data = 0, bytes = sizeof(data);
        if (RegQueryValueExW(key, wval, NULL, &type, (BYTE *)&data, &bytes) == ERROR_SUCCESS &&
            type == REG_DWORD) {
            *out = data;
            ok = true;
        }
        RegCloseKey(key);
    }
    free(wsub);
    free(wval);
    return ok;
}

static void win_arch_string(char *out, size_t outsz) {
    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    const char *a = "unknown";
    switch (si.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64: a = "x86_64"; break;
        case PROCESSOR_ARCHITECTURE_ARM64: a = "arm64";  break;
        case PROCESSOR_ARCHITECTURE_INTEL: a = "x86";    break;
        case PROCESSOR_ARCHITECTURE_ARM:   a = "arm";    break;
        default: break;
    }
    snprintf(out, outsz, "%s", a);
}

/* Expand %SystemRoot% and friends so paths can be tested as-is. */
static void win_expand_env(const char *in, char *out, size_t outsz) {
    wchar_t *win = win_wide(in);
    if (!win) {
        snprintf(out, outsz, "%s", in);
        return;
    }
    wchar_t wout[2048];
    DWORD n = ExpandEnvironmentStringsW(win, wout,
                                        (DWORD)(sizeof(wout) / sizeof(wout[0])));
    if (n > 0 && n <= sizeof(wout) / sizeof(wout[0])) {
        char *u = win_utf8(wout);
        snprintf(out, outsz, "%s", u ? u : in);
        free(u);
    } else {
        snprintf(out, outsz, "%s", in);
    }
    free(win);
}
#endif /* _WIN32 */

/* Trim leading/trailing whitespace in place; returns pointer into s. */
static char *trim(char *s) {
    while (*s && isspace((unsigned char)*s)) s++;
    if (!*s) return s;
    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) *end-- = '\0';
    return s;
}

#ifndef _WIN32
/* True if path is world-writable (others write bit set), per lstat mode.
 * Unlike is_writable_by_me(), this is identity-independent and remains a
 * meaningful signal even when the auditor runs as root. */
static bool mode_world_writable(mode_t m) {
    return (m & S_IWOTH) != 0;
}

/* Parse "major.minor.patch" from a kernel release string. */
static void parse_kernel_version(const char *rel, int *maj, int *min, int *pat) {
    *maj = *min = *pat = 0;
    sscanf(rel, "%d.%d.%d", maj, min, pat);
}

/* Does tok look like a shell env assignment, e.g. "PATH=/x:/y" or "FOO=bar"? */
static bool looks_like_env_assign(const char *tok) {
    const char *eq = strchr(tok, '=');
    if (!eq || eq == tok) return false;
    if (!isalpha((unsigned char)tok[0]) && tok[0] != '_') return false;
    for (const char *p = tok; p < eq; p++)
        if (!isalnum((unsigned char)*p) && *p != '_') return false;
    return true;
}

/* ---- Dev/inode "seen" set, for cross-root dedup (fixes.md item 6) ------
 *
 * Open-addressed hash set (linear probing), not a linear-scan array: every
 * directory and file visited by walk_dir() is inserted here, so testing
 * membership against an array made a whole scan quadratic in the file count
 * (measured on this code: 10k files ~0.05s, 20k ~0.16s, 40k ~0.57s). The
 * API is unchanged; callers still get "was this (dev,ino) already seen?". */

typedef struct { dev_t dev; ino_t ino; } DevIno;

typedef struct {
    DevIno        *slots;
    unsigned char *used;
    size_t         cap;   /* power of two; 0 until first insert */
    size_t         count; /* live entries */
} SeenSet;

static void seen_set_init(SeenSet *s) {
    s->slots = NULL;
    s->used = NULL;
    s->cap = 0;
    s->count = 0;
}

static void seen_set_free(SeenSet *s) {
    free(s->slots);
    free(s->used);
    seen_set_init(s);
}

static size_t seen_hash(dev_t dev, ino_t ino, size_t cap) {
    uint64_t x = (uint64_t)(uintmax_t)dev * 0x9E3779B97F4A7C15ULL +
                 (uint64_t)(uintmax_t)ino + 0x165667B19E3779F9ULL;
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 29;
    return (size_t)(x & (uint64_t)(cap - 1));
}

static bool seen_set_grow(SeenSet *s) {
    size_t ncap = s->cap ? s->cap * 2 : 256;
    DevIno *slots = calloc(ncap, sizeof(*slots));
    unsigned char *used = calloc(ncap, 1);
    if (!slots || !used) {
        free(slots);
        free(used);
        return false;
    }
    for (size_t i = 0; i < s->cap; i++) {
        if (!s->used[i]) continue;
        size_t j = seen_hash(s->slots[i].dev, s->slots[i].ino, ncap);
        while (used[j]) j = (j + 1) & (ncap - 1);
        used[j] = 1;
        slots[j] = s->slots[i];
    }
    free(s->slots);
    free(s->used);
    s->slots = slots;
    s->used = used;
    s->cap = ncap;
    return true;
}

/* Returns true if (dev,ino) was already present (i.e. this is a duplicate);
 * otherwise records it and returns false. */
static bool seen_set_check_add(SeenSet *s, dev_t dev, ino_t ino) {
    /* Keep load factor under 70% so linear probing stays cheap. */
    if (s->cap == 0 || (s->count + 1) * 10 >= s->cap * 7) {
        if (!seen_set_grow(s)) {
            /* Allocation failure: still answer the membership question from
             * the existing table, but don't record the new entry (fail open,
             * as before - a possible duplicate beats a crash or a miss). */
            for (size_t i = 0; i < s->cap; i++)
                if (s->used[i] && s->slots[i].dev == dev && s->slots[i].ino == ino)
                    return true;
            return false;
        }
    }

    size_t i = seen_hash(dev, ino, s->cap);
    for (;;) {
        if (!s->used[i]) {
            s->used[i] = 1;
            s->slots[i] = (DevIno){ dev, ino };
            s->count++;
            return false;
        }
        if (s->slots[i].dev == dev && s->slots[i].ino == ino) return true;
        i = (i + 1) & (s->cap - 1);
    }
}
#endif /* !_WIN32 */

/* ========================================================================
 * Section 4: Scanners
 * ==================================================================== */

/* ---- 4.0 Host enumeration --------------------------------------------- */

static void gather_host_info(HostInfo *h) {
    memset(h, 0, sizeof(*h));
    snprintf(h->platform, sizeof(h->platform), "%s", TOOL_PLATFORM);

#ifdef _WIN32
    wchar_t wuser[256];
    DWORD uname_len = (DWORD)(sizeof(wuser) / sizeof(wuser[0]));
    if (GetUserNameW(wuser, &uname_len)) {
        char *u = win_utf8(wuser);
        snprintf(h->user, sizeof(h->user), "%s", u ? u : "unknown");
        free(u);
    } else {
        snprintf(h->user, sizeof(h->user), "unknown");
    }

    h->elevated = win_process_elevated();

    /* GetVersionEx is manifest-lied on 8.1+, so ask ntdll for the real build. */
    typedef struct {
        ULONG size, major, minor, build, platform;
        WCHAR csd[128];
    } audit_osver;
    typedef LONG (WINAPI *rtl_get_version_fn)(audit_osver *);

    audit_osver ver;
    memset(&ver, 0, sizeof(ver));
    ver.size = sizeof(ver);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    rtl_get_version_fn rtl = ntdll
        ? (rtl_get_version_fn)(void *)GetProcAddress(ntdll, "RtlGetVersion") : NULL;

    if (rtl && rtl(&ver) == 0) {
        snprintf(h->kernel, sizeof(h->kernel), "Windows NT %lu.%lu.%lu",
                 (unsigned long)ver.major, (unsigned long)ver.minor,
                 (unsigned long)ver.build);
        snprintf(h->kernel_release, sizeof(h->kernel_release), "%lu",
                 (unsigned long)ver.build);
    } else {
        snprintf(h->kernel, sizeof(h->kernel), "Windows NT (version unknown)");
        snprintf(h->kernel_release, sizeof(h->kernel_release), "0");
    }

    char product[128] = "", display[64] = "";
    DWORD ubr = 0;
    win_reg_read_string(HKEY_LOCAL_MACHINE,
                        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                        "ProductName", product, sizeof(product));
    win_reg_read_string(HKEY_LOCAL_MACHINE,
                        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                        "DisplayVersion", display, sizeof(display));
    win_reg_read_dword(HKEY_LOCAL_MACHINE,
                       "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                       "UBR", &ubr);
    snprintf(h->distro, sizeof(h->distro), "%s%s%s (build %s.%lu)",
             product[0] ? product : "Windows", display[0] ? " " : "", display,
             h->kernel_release, (unsigned long)ubr);

    win_arch_string(h->arch, sizeof(h->arch));
    return;
#else
    h->uid = getuid();
    h->gid = getgid();

    struct passwd *pw = getpwuid(h->uid);
    snprintf(h->user, sizeof(h->user), "%s", pw ? pw->pw_name : "unknown");

    struct utsname un;
    if (uname(&un) == 0) {
        snprintf(h->kernel, sizeof(h->kernel), "%s %s", un.sysname, un.release);
        snprintf(h->kernel_release, sizeof(h->kernel_release), "%s", un.release);
        snprintf(h->arch, sizeof(h->arch), "%s", un.machine);
    } else {
        snprintf(h->kernel, sizeof(h->kernel), "unknown");
    }

    /* Distro via /etc/os-release PRETTY_NAME, else fallbacks. */
    FILE *fp = fopen("/etc/os-release", "r");
    snprintf(h->distro, sizeof(h->distro), "unknown");
    if (fp) {
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "PRETTY_NAME=", 12) == 0) {
                char *v = line + 12;
                v = trim(v);
                /* strip surrounding quotes */
                size_t len = strlen(v);
                if (len >= 2 && v[0] == '"' && v[len - 1] == '"') {
                    v[len - 1] = '\0';
                    v++;
                }
                snprintf(h->distro, sizeof(h->distro), "%s", v);
                break;
            }
        }
        fclose(fp);
    }
#endif /* _WIN32 */
}

static void scan_system(FindingList *fl, const HostInfo *h, const Options *o) {
#ifdef _WIN32
    if (h->elevated) {
        add_finding(fl, "sys.running_elevated", CAT_SYSTEM, SEV_INFO, CONF_CONFIRMED,
                    "Running elevated", NULL,
                    "The audit is running with an elevated administrator token. "
                    "Findings that only say \"writable by the current user\" are "
                    "downgraded to INFO, because an elevated administrator can "
                    "write almost everything and that is not itself an "
                    "unprivileged escalation path.");
    }
    add_finding(fl, "sys.profile", CAT_SYSTEM, SEV_INFO, CONF_CONFIRMED,
                "System profile", NULL,
                "user=%s os=%s kernel=%s arch=%s elevated=%s",
                h->user, h->distro, h->kernel, h->arch,
                h->elevated ? "yes" : "no");
#else
    if (h->uid == 0) {
        add_finding(fl, "sys.running_as_root", CAT_SYSTEM, SEV_INFO, CONF_CONFIRMED,
                    "Running as root", NULL,
                    "Audit is running as root (uid 0). Findings that merely say "
                    "\"writable by the current user\" are downgraded to INFO "
                    "throughout this report, since root's ability to write files "
                    "is expected and is not itself an unprivileged escalation path.");
    }
    add_finding(fl, "sys.profile", CAT_SYSTEM, SEV_INFO, CONF_CONFIRMED,
                "System profile", NULL,
                "user=%s uid=%u gid=%u distro=%s kernel=%s arch=%s",
                h->user, (unsigned)h->uid, (unsigned)h->gid,
                h->distro, h->kernel, h->arch);
#endif
    (void)o;
}

#ifndef _WIN32

/* ---- 4.1 SUID / SGID scan --------------------------------------------- */

/*
 * Binaries that are *expected* to be SUID on a normal system. Presence is
 * reported as INFO. Anything SUID that is also writable, or not on this list,
 * gets elevated attention.
 */
static const char *known_suid[] = {
    /* /usr/bin and /bin variants are both listed because this tool's
     * cross-root dedup (fixes.md item 6) reports each binary under whichever
     * scan root it's discovered through first, which on merged-usr distros
     * may be the /bin alias rather than the canonical /usr/bin path. */
    "/usr/bin/sudo", "/bin/sudo",
    "/usr/bin/su", "/bin/su",
    "/usr/bin/passwd", "/bin/passwd",
    "/usr/bin/chsh", "/bin/chsh",
    "/usr/bin/chfn", "/bin/chfn",
    "/usr/bin/newgrp", "/bin/newgrp",
    "/usr/bin/gpasswd", "/bin/gpasswd",
    "/usr/bin/mount", "/bin/mount",
    "/usr/bin/umount", "/bin/umount",
    "/usr/bin/pkexec", "/bin/pkexec",
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    "/usr/bin/fusermount", "/bin/fusermount",
    "/usr/bin/fusermount3", "/bin/fusermount3",
    "/usr/lib/openssh/ssh-keysign",
    "/usr/bin/ping", "/bin/ping",
    /* Other stock Debian/Ubuntu/Kali setuid-root helpers. These are shipped
     * SUID by their packages (mount helpers, pppd, the Xorg wrapper, the
     * polkit agent helper, Chromium's sandbox, the Kismet capture helpers and
     * the rsh-redone clients); reporting each of them as a MEDIUM "non-standard
     * SUID" on every stock Kali host was baseline noise. Tune for your own
     * environment - anything not listed here is still reported. */
    "/usr/sbin/mount.nfs", "/sbin/mount.nfs",
    "/usr/sbin/mount.cifs", "/sbin/mount.cifs",
    "/usr/sbin/pppd", "/sbin/pppd",
    "/usr/bin/ntfs-3g", "/bin/ntfs-3g",
    "/usr/bin/vmware-user-suid-wrapper", "/bin/vmware-user-suid-wrapper",
    "/usr/lib/chromium/chrome-sandbox",
    "/usr/lib/xorg/Xorg.wrap",
    "/usr/lib/polkit-1/polkit-agent-helper-1",
    "/usr/libexec/polkit-agent-helper-1",
    "/usr/bin/rsh-redone-rsh", "/bin/rsh-redone-rsh",
    "/usr/bin/rsh-redone-rlogin", "/bin/rsh-redone-rlogin",
    "/usr/bin/kismet_cap_linux_bluetooth", "/bin/kismet_cap_linux_bluetooth",
    "/usr/bin/kismet_cap_rz_killerbee", "/bin/kismet_cap_rz_killerbee",
    "/usr/bin/kismet_cap_nrf_52840", "/bin/kismet_cap_nrf_52840",
    "/usr/bin/kismet_cap_ti_cc_2540", "/bin/kismet_cap_ti_cc_2540",
    "/usr/bin/kismet_cap_hak5_wifi_coconut", "/bin/kismet_cap_hak5_wifi_coconut",
    "/usr/bin/kismet_cap_nrf_mousejack", "/bin/kismet_cap_nrf_mousejack",
    "/usr/bin/kismet_cap_nxp_kw41z", "/bin/kismet_cap_nxp_kw41z",
    "/usr/bin/kismet_cap_nrf_51822", "/bin/kismet_cap_nrf_51822",
    "/usr/bin/kismet_cap_ubertooth_one", "/bin/kismet_cap_ubertooth_one",
    "/usr/bin/kismet_cap_linux_wifi", "/bin/kismet_cap_linux_wifi",
    "/usr/bin/kismet_cap_ti_cc_2531", "/bin/kismet_cap_ti_cc_2531",
    NULL
};

/*
 * GTFOBins-style SUID binaries that are well-known escalation primitives when
 * found SUID. This is a *curated subset* for prioritization only.
 * (fixes.md item 13: deduped - the stray-leading-space entries below were
 * exact duplicates of entries already present, since basename_in() also
 * tolerates stray spaces defensively.)
 */
static const char *dangerous_suid[] = {
    "nmap", "vim", "vi", "nano", "less", "more", "man", "find", "bash",
    "sh", "dash", "zsh", "python", "python2", "python3", "perl", "ruby",
    "lua", "php", "awk", "gawk", "nawk", "tee", "cp", "mv", "env", "nice",
    "tar", "zip", "unzip", "gdb", "tclsh", "expect",
    "nc", "ncat", "socat", "ftp", "gimp", "node", "make", "cmake",
    "emacs", "rsync", "scp", "ld.so", "busybox", "docker",
    "dmesg", "strace", "ltrace", "systemctl", "flock", "ionice",
    NULL
};

/*
 * Binaries that are *expected* to be SGID on a normal Linux system (mail,
 * shadow, tty, crontab, ssh-agent and utempter helpers). Root-owned SGID on
 * one of these paths is reported as INFO; any other root-owned SGID binary is
 * still reported for review.
 *
 * Without this list every stock Debian/Ubuntu host produced a MEDIUM finding
 * for each of chage, expiry, unix_chkpwd, pam_extrausers_chkpwd, ssh-agent and
 * utempter, which is baseline noise rather than a misconfiguration. As with
 * known_suid[], the list is path-based (not basename-based) so a copy of a
 * trusted binary planted somewhere else is not silently whitelisted.
 */
static const char *known_sgid[] = {
    "/usr/bin/chage", "/bin/chage",
    "/usr/bin/expiry", "/bin/expiry",
    "/usr/bin/wall", "/bin/wall",
    "/usr/bin/write", "/bin/write",
    "/usr/bin/bsd-write", "/bin/bsd-write",
    "/usr/bin/crontab", "/bin/crontab",
    "/usr/bin/locate", "/bin/locate",
    "/usr/bin/mlocate", "/bin/mlocate",
    "/usr/bin/plocate", "/bin/plocate",
    "/usr/lib/xorg/Xorg.wrap",
    "/usr/bin/ssh-agent", "/bin/ssh-agent",
    "/usr/bin/screen", "/bin/screen",
    "/usr/sbin/unix_chkpwd", "/sbin/unix_chkpwd",
    "/usr/sbin/pam_extrausers_chkpwd", "/sbin/pam_extrausers_chkpwd",
    "/usr/lib/openssh/ssh-keysign",
    "/usr/lib/utempter/utempter",
    "/usr/libexec/utempter/utempter",
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    "/usr/libexec/dbus-1/dbus-daemon-launch-helper",
    "/usr/lib/postfix/postdrop",
    "/usr/lib/postfix/postqueue",
    "/usr/libexec/postfix/postdrop",
    "/usr/libexec/postfix/postqueue",
    "/usr/sbin/postdrop", "/usr/sbin/postqueue",
    "/usr/lib/mailutils/dotlock",
    NULL
};

static bool basename_in(const char *path, const char *const *list) {
    const char *b = strrchr(path, '/');
    b = b ? b + 1 : path;
    for (int i = 0; list[i]; i++) {
        const char *entry = list[i];
        while (*entry == ' ') entry++; /* tolerate stray spaces in table */
        if (strcmp(b, entry) == 0) return true;
    }
    return false;
}

static bool path_in(const char *path, const char *const *list) {
    for (int i = 0; list[i]; i++)
        if (strcmp(path, list[i]) == 0) return true;
    return false;
}

/* SGID baseline lookup. Exact paths cover the common layouts; a few helpers
 * also live under a multiarch triplet directory (/usr/lib/<triplet>/...),
 * which cannot be enumerated statically, so those are matched by suffix - but
 * only inside the trusted /usr/lib and /usr/libexec trees, so a planted copy
 * of a trusted helper elsewhere is never whitelisted. */
static bool sgid_baseline_path(const char *path) {
    if (path_in(path, known_sgid)) return true;

    if (strncmp(path, "/usr/lib/", 9) != 0 && strncmp(path, "/usr/libexec/", 13) != 0)
        return false;

    static const char *suffixes[] = {
        "/utempter/utempter",
        "/dbus-1.0/dbus-daemon-launch-helper",
        "/postfix/postdrop",
        "/postfix/postqueue",
        "/mailutils/dotlock",
        "/openssh/ssh-keysign",
        NULL
    };
    size_t plen = strlen(path);
    for (int i = 0; suffixes[i]; i++) {
        size_t slen = strlen(suffixes[i]);
        if (plen > slen && strcmp(path + plen - slen, suffixes[i]) == 0) return true;
    }
    return false;
}

/*
 * Recursive directory walk with a bounded depth, invoking cb on each regular
 * file. Never follows symlinks (avoids loops/redirection surprises) - this is
 * intentional and documented behavior for suid/capability/service scans.
 *
 * fixes.md item 2: records skipped/missing/unreadable paths into *stats
 * instead of silently dropping them, and distinguishes a root that simply
 * doesn't exist on this distro (expected) from one that exists but can't be
 * read (a real scan failure).
 *
 * fixes.md item 6: dedups by (device, inode) via *seen so that overlapping
 * scan roots (e.g. /bin symlinked into /usr/bin on merged-usr distros) don't
 * produce duplicate findings or duplicate traversal work.
 */
static void walk_dir(const char *dir, int depth, int max_depth,
                     void (*cb)(const char *, const struct stat *, void *),
                     void *ctx, SeenSet *seen, ScanStats *stats, bool top_level) {
    if (depth > max_depth) return;

    struct stat dirid;
    if (stat(dir, &dirid) != 0) {
        if (top_level) {
            if (errno == ENOENT) stats->roots_missing_expected++;
            else stats->roots_unreadable++;
        } else {
            stats->paths_skipped_unreadable++;
        }
        return;
    }
    /* If we've already walked this exact directory via another path (e.g.
     * /bin -> /usr/bin), skip re-walking and re-reporting it. */
    if (seen_set_check_add(seen, dirid.st_dev, dirid.st_ino)) return;

    DIR *d = opendir(dir);
    if (!d) {
        if (top_level) stats->roots_unreadable++;
        else stats->paths_skipped_unreadable++;
        return;
    }

    struct dirent *de;
    char child[4096];
    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        int n = snprintf(child, sizeof(child), "%s/%s", dir, de->d_name);
        if (n < 0 || (size_t)n >= sizeof(child)) {
            stats->paths_skipped_unreadable++;
            continue;
        }

        struct stat st;
        if (lstat(child, &st) != 0) {
            stats->paths_skipped_unreadable++;
            continue;
        }

        if (S_ISLNK(st.st_mode)) continue; /* never follow symlinks */

        if (S_ISDIR(st.st_mode)) {
            walk_dir(child, depth + 1, max_depth, cb, ctx, seen, stats, false);
        } else if (S_ISREG(st.st_mode)) {
            if (seen_set_check_add(seen, st.st_dev, st.st_ino)) continue; /* dup via hardlink/alias */
            cb(child, &st, ctx);
        }
    }
    closedir(d);
}

typedef struct { FindingList *fl; const Options *o; } SuidCtx;

static void suid_cb(const char *path, const struct stat *st, void *vctx) {
    SuidCtx *c = (SuidCtx *)vctx;
    bool suid = (st->st_mode & S_ISUID) != 0;
    bool sgid = (st->st_mode & S_ISGID) != 0;
    if (!suid && !sgid) return;

    bool root_owned = (st->st_uid == 0);
    bool writable   = is_writable_by_me(path);
    bool baseline   = path_in(path, known_suid);
    bool dangerous  = basename_in(path, dangerous_suid);
    const char *bit = suid && sgid ? "SUID+SGID" : (suid ? "SUID" : "SGID");

    /* --- fixes.md item 1: writable + privileged bit, under a root auditor -- */
    if (writable && (suid || sgid)) {
        if (c->o->is_root) {
            add_finding(c->fl, "suid.writable_root_auditor", CAT_SUID, SEV_INFO,
                        CONF_CONFIRMED, "Writable privileged binary (root auditor)",
                        path, "%s binary is writable by root, the identity running "
                        "this audit. That reflects root's own access, not an "
                        "unprivileged escalation path.", bit);
        } else if (root_owned) {
            add_finding(c->fl, "suid.writable_root_owned", CAT_SUID, SEV_CRITICAL,
                        CONF_CONFIRMED, "Writable root-owned binary", path,
                        "%s binary is writable by the current user - direct code "
                        "execution as owner is likely.", bit);
        } else {
            add_finding(c->fl, "suid.writable_nonroot_owned", CAT_SUID, SEV_HIGH,
                        CONF_CONFIRMED, "Writable non-root-owned privileged binary",
                        path, "%s binary (owner uid=%u) is writable by the current "
                        "user - direct code execution as that owner is likely.",
                        bit, (unsigned)st->st_uid);
        }
        return;
    }

    /* --- SUID handling --- */
    if (suid && root_owned) {
        if (dangerous) {
            add_finding(c->fl, "suid.gtfobins", CAT_SUID, SEV_HIGH, CONF_LIKELY,
                        "Known-exploitable SUID binary", path,
                        "%s root-owned binary is a well-known escalation primitive "
                        "(GTFOBins-style). Verify intent.", bit);
        } else if (!baseline) {
            add_finding(c->fl, "suid.nonstandard", CAT_SUID, SEV_MEDIUM, CONF_POSSIBLE,
                        "Non-standard SUID binary", path,
                        "%s root-owned binary not on the expected baseline list.", bit);
        } else {
            add_finding(c->fl, "suid.baseline", CAT_SUID, SEV_INFO, CONF_CONFIRMED,
                        "Standard SUID binary", path,
                        "%s binary (uid=%u), on the expected baseline list.",
                        bit, (unsigned)st->st_uid);
        }
    } else if (suid && !root_owned) {
        /* fixes.md item 3a: non-root-owned SUID used to fall silently into the
         * same INFO bucket as baseline binaries. It's unusual and deserves its
         * own finding - effective privilege is the file owner's, not root's. */
        add_finding(c->fl, "suid.nonroot_suid", CAT_SUID, SEV_LOW, CONF_POSSIBLE,
                    "Non-root-owned SUID binary", path,
                    "SUID bit set but owner is uid=%u, not root. Unusual; verify "
                    "intent. Effective privilege on execution is the owner's, "
                    "not root's.", (unsigned)st->st_uid);
    }

    /* --- fixes.md item 3: SGID as a first-class, separately-flagged case ---
     * Uses the SGID baseline the same way the SUID branch above uses
     * known_suid[], so stock shadow/tty/mail helpers stay INFO instead of
     * producing a MEDIUM finding on every normal host. */
    if (sgid) {
        bool baseline_sgid = sgid_baseline_path(path);
        if (root_owned && baseline_sgid) {
            add_finding(c->fl, "suid.sgid_baseline", CAT_SUID, SEV_INFO, CONF_CONFIRMED,
                        "Standard SGID binary", path,
                        "SGID binary (group gid=%u) on the expected baseline list.",
                        (unsigned)st->st_gid);
        } else if (root_owned) {
            add_finding(c->fl, "suid.sgid_root", CAT_SUID, SEV_MEDIUM, CONF_POSSIBLE,
                        "Root-owned SGID binary", path,
                        "SGID bit grants the file's group on execution (group "
                        "gid=%u) and the path is not on the expected SGID "
                        "baseline. Verify this is expected.",
                        (unsigned)st->st_gid);
        } else {
            add_finding(c->fl, "suid.sgid_nonroot", CAT_SUID, SEV_LOW, CONF_POSSIBLE,
                        "Non-root-owned SGID binary", path,
                        "SGID bit set, group-id=%u, owner uid=%u.",
                        (unsigned)st->st_gid, (unsigned)st->st_uid);
        }
    }
}

static void scan_suid(FindingList *fl, const Options *o, ScanStats *stats) {
    static const char *roots[] = {
        "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin",
        "/usr/local/sbin", "/usr/lib", "/opt", NULL
    };
    SuidCtx ctx = { fl, o };
    SeenSet seen;
    seen_set_init(&seen);
    for (int i = 0; roots[i]; i++)
        walk_dir(roots[i], 0, 4, suid_cb, &ctx, &seen, stats, true);
    seen_set_free(&seen);
}

/* ---- 4.2 Capability scan ---------------------------------------------- */

/*
 * File capabilities live in the "security.capability" extended attribute on
 * Linux. We read it directly (no libcap dependency). We decode just enough to
 * flag dangerous capabilities by their known bit indices.
 *
 * fixes.md item 7: cap_sys_chroot and cap_sys_time had the wrong bit numbers
 * (verified against <linux/capability.h>), cap_sys_ptrace wasn't checked at
 * all, and cap_sys_module / cap_sys_rawio were missing entirely.
 */
#ifdef __linux__
static const struct { int bit; const char *name; Severity sev; } cap_table[] = {
    { 0,  "cap_chown",            SEV_MEDIUM   },
    { 1,  "cap_dac_override",     SEV_HIGH     },
    { 2,  "cap_dac_read_search",  SEV_HIGH     },
    { 3,  "cap_fowner",           SEV_MEDIUM   },
    { 4,  "cap_fsetid",           SEV_MEDIUM   },
    { 6,  "cap_setgid",           SEV_HIGH     },
    { 7,  "cap_setuid",           SEV_CRITICAL },
    { 8,  "cap_setpcap",          SEV_HIGH     },
    { 12, "cap_net_admin",        SEV_MEDIUM   },
    { 16, "cap_sys_module",       SEV_CRITICAL }, /* load kernel modules -> instant root */
    { 17, "cap_sys_rawio",        SEV_HIGH     },
    { 18, "cap_sys_chroot",       SEV_MEDIUM   }, /* was bit 19 */
    { 19, "cap_sys_ptrace",       SEV_HIGH     }, /* previously unchecked */
    { 21, "cap_sys_admin",        SEV_CRITICAL },
    { 25, "cap_sys_time",         SEV_LOW      }, /* was bit 24 */
    { -1, NULL,                   SEV_INFO     }
};

/* Readable names for every capability bit that appears in practice, so a file
 * carrying capabilities the high-risk table does not list is still reported
 * instead of producing silence. */
static const char *cap_bit_name(int bit) {
    static const char *names[] = {
        "cap_chown", "cap_dac_override", "cap_dac_read_search", "cap_fowner",
        "cap_fsetid", "cap_kill", "cap_setgid", "cap_setuid", "cap_setpcap",
        "cap_linux_immutable", "cap_net_bind_service", "cap_net_broadcast",
        "cap_net_admin", "cap_net_raw", "cap_ipc_lock", "cap_ipc_owner",
        "cap_sys_module", "cap_sys_rawio", "cap_sys_chroot", "cap_sys_ptrace",
        "cap_sys_pacct", "cap_sys_admin", "cap_sys_boot", "cap_sys_nice",
        "cap_sys_resource", "cap_sys_time", "cap_sys_tty_config", "cap_mknod",
        "cap_lease", "cap_audit_write", "cap_audit_control", "cap_setfcap",
        "cap_mac_override", "cap_mac_admin", "cap_syslog", "cap_wake_alarm",
        "cap_block_suspend", "cap_audit_read", "cap_perfmon", "cap_bpf",
        "cap_checkpoint_restore"
    };
    if (bit < 0 || bit >= (int)(sizeof(names) / sizeof(names[0]))) return NULL;
    return names[bit];
}

typedef struct { FindingList *fl; int files; } CapCtx;

static void cap_cb(const char *path, const struct stat *st, void *vctx) {
    (void)st;
    CapCtx *c = (CapCtx *)vctx;
    unsigned char buf[64];
    ssize_t n = getxattr(path, "security.capability", buf, sizeof(buf));
    if (n <= 0) return;

    /* VFS cap data: magic+flags (4 bytes LE), then permitted/inheritable
     * dwords per 32-bit block. We OR the permitted words for a bitset. */
    unsigned long long permitted = 0;
    if (n >= 12) {
        permitted |= (unsigned long long)(buf[4] | (buf[5] << 8) |
                     (buf[6] << 16) | ((unsigned)buf[7] << 24));
    }
    if (n >= 20) { /* v2: second 32-bit block of permitted at offset 12 */
        permitted |= ((unsigned long long)(buf[12] | (buf[13] << 8) |
                      (buf[14] << 16) | ((unsigned)buf[15] << 24))) << 32;
    }

    c->files++;

    /* Always describe what the file actually carries. Without this a host whose
     * only capabilities are, say, cap_net_raw produced an empty capability
     * section, which reads as "nothing found" rather than "nothing risky". */
    char present[512];
    size_t used = 0;
    present[0] = '\0';
    for (int bit = 0; bit < 41 && used + 1 < sizeof(present); bit++) {
        if (!(permitted & (1ULL << bit))) continue;
        const char *nm = cap_bit_name(bit);
        char tmp[48];
        if (nm) snprintf(tmp, sizeof(tmp), "%s%s", used ? ", " : "", nm);
        else snprintf(tmp, sizeof(tmp), "%scap_bit_%d", used ? ", " : "", bit);
        size_t add = strlen(tmp);
        if (used + add + 1 >= sizeof(present)) break;
        memcpy(present + used, tmp, add + 1);
        used += add;
    }
    add_finding(c->fl, "cap.present", CAT_CAPABILITIES, SEV_INFO, CONF_CONFIRMED,
                "File capability set (informational)", path,
                "Binary carries %s in its permitted set.", present[0] ? present : "capabilities");

    for (int i = 0; cap_table[i].name; i++) {
        if (permitted & (1ULL << cap_table[i].bit)) {
            Confidence conf = (cap_table[i].sev >= SEV_HIGH)
                                  ? CONF_LIKELY : CONF_POSSIBLE;
            char id[64];
            snprintf(id, sizeof(id), "cap.%s", cap_table[i].name);
            add_finding(c->fl, id, CAT_CAPABILITIES, cap_table[i].sev, conf,
                        "File capability set", path,
                        "Binary has %s in its permitted set.",
                        cap_table[i].name);
        }
    }
}
#endif /* __linux__ */

static void scan_capabilities(FindingList *fl, const Options *o, ScanStats *stats) {
    (void)o;
#ifdef __linux__
    static const char *roots[] = {
        "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin",
        "/usr/local/sbin", "/opt", NULL
    };
    CapCtx ctx = { fl, 0 };
    SeenSet seen;
    seen_set_init(&seen);
    for (int i = 0; roots[i]; i++)
        walk_dir(roots[i], 0, 4, cap_cb, &ctx, &seen, stats, true);
    seen_set_free(&seen);

    add_finding(fl, "cap.enumerated", CAT_CAPABILITIES, SEV_INFO, CONF_CONFIRMED,
                "Files with capabilities enumerated", NULL,
                "%d file(s) with a security.capability attribute inspected.", ctx.files);
#else
    add_finding(fl, "cap.unavailable", CAT_CAPABILITIES, SEV_INFO, CONF_CONFIRMED,
                "Capability scan unavailable", NULL,
                "File capabilities are a Linux feature; skipped on this OS.");
#endif
}

/* ---- 4.3 Sudo scan ----------------------------------------------------
 *
 * fixes.md items 1, 8, 9:
 *   - /etc/sudoers is normally unreadable to a non-root user; fall back to
 *     parsing `sudo -n -l` only if the person opts in via --sudo-fallback,
 *     and always label that fallback explicitly (it shells out, can fail
 *     silently, and may write to the system sudo log).
 *   - honor #include / #includedir directives instead of treating them as
 *     plain comments (sudo 1.9+ also accepts the @include / @includedir
 *     spelling, which is what many current distros ship).
 *   - skip sudoers.d filenames containing '.' or ending in '~', which real
 *     sudo/visudo ignore.
 *   - a writable /etc/sudoers under a root auditor is expected, not a finding.
 *   - a writable sudoers *include* file, or a writable sudoers directory, is
 *     the same escalation primitive as a writable /etc/sudoers; only the
 *     top-level file used to be checked, so a world-writable drop-in under
 *     /etc/sudoers.d was silently ignored.
 */

#define SUDO_INCLUDE_MAX_DEPTH 8

static bool sudoers_filename_active(const char *name) {
    if (name[0] == '.') return false;
    size_t len = strlen(name);
    if (len == 0) return false;
    if (name[len - 1] == '~') return false;
    if (strchr(name, '.') != NULL) return false; /* visudo ignores dotted names */
    return true;
}

static void inspect_sudo_line(FindingList *fl, const char *source, const char *s) {
    if (strstr(s, "NOPASSWD")) {
        Severity sev = SEV_MEDIUM;
        if (strstr(s, "ALL") && (strstr(s, "(ALL") || strstr(s, "(root")))
            sev = SEV_HIGH;
        add_finding(fl, "sudo.nopasswd", CAT_SUDO, sev, CONF_LIKELY,
                    "Passwordless sudo rule", source,
                    "NOPASSWD rule: %.200s", s);
    }
    if (strstr(s, "!authenticate")) {
        add_finding(fl, "sudo.no_authenticate", CAT_SUDO, SEV_MEDIUM, CONF_LIKELY,
                    "sudo !authenticate", source,
                    "Rule disables authentication: %.200s", s);
    }
    if (strstr(s, "env_keep") &&
        (strstr(s, "LD_PRELOAD") || strstr(s, "LD_LIBRARY_PATH"))) {
        add_finding(fl, "sudo.env_keep_loader", CAT_SUDO, SEV_HIGH, CONF_LIKELY,
                    "Dangerous sudo env_keep", source,
                    "env_keep preserves loader variable: %.200s", s);
    }
}

static void scan_sudo_dir(FindingList *fl, const Options *o, const char *dir, int depth,
                          ScanStats *stats);

static void scan_sudo_file(FindingList *fl, const Options *o, const char *path, int depth,
                           ScanStats *stats) {
    if (depth > SUDO_INCLUDE_MAX_DEPTH) return;

    /* Checked before the read attempt: a policy file we can write but not read
     * is still writable, and injecting a rule is the escalation.
     * Covers /etc/sudoers itself as well as every #include'd / @include'd file. */
    if (is_writable_by_me(path)) {
        if (o->is_root) {
            add_finding(fl, "sudo.sudoers_writable_root_auditor", CAT_SUDO, SEV_INFO,
                        CONF_CONFIRMED, "Writable sudoers file (root auditor)", path,
                        "Writable by root, the identity running this audit; not an "
                        "unprivileged escalation signal.");
        } else {
            add_finding(fl, "sudo.sudoers_writable", CAT_SUDO, SEV_CRITICAL, CONF_CONFIRMED,
                        "Writable sudoers file", path,
                        "This sudo policy file is writable by the current user, so "
                        "arbitrary rules (for example NOPASSWD: ALL) could be added.");
        }
    }

    FILE *fp = fopen(path, "r");
    if (!fp) {
        if (errno == ENOENT) stats->roots_missing_expected++;
        else stats->roots_unreadable++;
        return;
    }

    char line[2048];
    while (fgets(line, sizeof(line), fp)) {
        char *s = trim(line);
        if (*s == '\0') continue;

        if (*s == '#' || *s == '@') {
            /* #include/#includedir (and sudo 1.9+ @include/@includedir) are
             * directives, not comments. */
            const char *rest = s + 1;
            if (strncmp(rest, "include ", 8) == 0) {
                scan_sudo_file(fl, o, trim((char *)rest + 8), depth + 1, stats);
            } else if (strncmp(rest, "includedir ", 11) == 0) {
                scan_sudo_dir(fl, o, trim((char *)rest + 11), depth + 1, stats);
            }
            continue; /* ordinary comment, or directive already handled */
        }

        inspect_sudo_line(fl, path, s);
    }
    fclose(fp);
}

static void scan_sudo_dir(FindingList *fl, const Options *o, const char *dir, int depth,
                          ScanStats *stats) {
    if (depth > SUDO_INCLUDE_MAX_DEPTH) return;

    /* sudo reads every active file in the directory, so being able to create
     * one is equivalent to being able to write the policy. */
    if (is_writable_by_me(dir)) {
        if (o->is_root) {
            add_finding(fl, "sudo.sudoers_dir_writable_root_auditor", CAT_SUDO, SEV_INFO,
                        CONF_CONFIRMED, "Writable sudoers directory (root auditor)",
                        dir, "Writable by root, the identity running this audit; "
                        "not an unprivileged escalation signal.");
        } else {
            add_finding(fl, "sudo.sudoers_dir_writable", CAT_SUDO, SEV_CRITICAL,
                        CONF_CONFIRMED, "Writable sudoers directory", dir,
                        "New sudo policy files could be dropped here; sudo reads "
                        "every active file in this directory.");
        }
    }

    DIR *d = opendir(dir);
    if (!d) {
        if (errno == ENOENT) stats->roots_missing_expected++;
        else stats->roots_unreadable++;
        return;
    }
    struct dirent *de;
    char p[4096];
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.') continue;
        if (!sudoers_filename_active(de->d_name)) continue; /* item 9: visudo-ignored names */
        snprintf(p, sizeof(p), "%s/%s", dir, de->d_name);
        scan_sudo_file(fl, o, p, depth, stats);
    }
    closedir(d);
}

static void scan_sudo(FindingList *fl, const Options *o, ScanStats *stats) {
    FILE *probe = fopen("/etc/sudoers", "r");
    if (probe) {
        fclose(probe);
        scan_sudo_file(fl, o, "/etc/sudoers", 0, stats);
    } else {
        int err = errno;
        add_finding(fl, "sudo.sudoers_unreadable", CAT_SUDO, SEV_INFO, CONF_CONFIRMED,
                    "/etc/sudoers unreadable", "/etc/sudoers",
                    "Direct read failed (errno=%d: %s). This is expected for a "
                    "non-root user.", err, strerror(err));
        if (o->sudo_fallback) {
            add_finding(fl, "sudo.fallback_used", CAT_SUDO, SEV_INFO, CONF_CONFIRMED,
                        "sudo -n -l fallback used", NULL,
                        "Falling back to 'sudo -n -l' since /etc/sudoers was "
                        "unreadable. This shells out to sudo, can fail silently "
                        "without a cached/noninteractive grant, and may write an "
                        "entry to the system sudo log - it is NOT equivalent to a "
                        "plain file read, which is why it is opt-in.");
            FILE *pp = popen("sudo -n -l 2>/dev/null", "r");
            if (pp) {
                char line[2048];
                bool any = false;
                while (fgets(line, sizeof(line), pp)) {
                    char *s = trim(line);
                    if (*s == '\0') continue;
                    any = true;
                    inspect_sudo_line(fl, "sudo -n -l", s);
                }
                pclose(pp);
                if (!any)
                    add_finding(fl, "sudo.fallback_empty", CAT_SUDO, SEV_INFO, CONF_CONFIRMED,
                                "sudo -n -l returned nothing", NULL,
                                "No cached/noninteractive sudo authorization, or no "
                                "rules apply to this user; fallback yielded no data.");
            } else {
                add_finding(fl, "sudo.fallback_failed", CAT_SUDO, SEV_LOW, CONF_POSSIBLE,
                            "sudo -n -l fallback failed to run", NULL,
                            "Could not execute 'sudo -n -l' as a fallback.");
            }
        } else {
            add_finding(fl, "sudo.fallback_available", CAT_SUDO, SEV_INFO, CONF_CONFIRMED,
                        "sudo -n -l fallback available but disabled", NULL,
                        "Re-run with --sudo-fallback to attempt 'sudo -n -l' as a "
                        "read fallback (opt-in: shells out to sudo, see --help).");
        }
    }

    /* Writability of /etc/sudoers itself, of every include, and of the
     * sudoers.d directory is reported from scan_sudo_file()/scan_sudo_dir()
     * so that one code path covers all of them instead of only the top-level
     * file. */
    scan_sudo_dir(fl, o, "/etc/sudoers.d", 0, stats);
}

/* ---- 4.4 Cron scan ------------------------------------------------------
 *
 * fixes.md item 9: parse the schedule/user fields and inspect only the
 * command portion; distinguish system crontabs (have a user field) from
 * per-user crontabs (don't); handle `sh -c '...'`, leading env assignments,
 * common wrappers (sudo/env/nice/...), and quoting well enough to unwrap one
 * level; mark anything else as unparsed/relative rather than silently
 * treating every absolute-looking token as "the" executed command.
 */

static const char *cron_wrappers[] = {
    "sudo", "env", "nohup", "nice", "ionice", "timeout", "xargs", "setsid", NULL
};

/* Shell control/test tokens that show up inside cron commands (e.g.
 * `test -e /x || /y`) but aren't themselves a command to evaluate. Skipping
 * these (and bare flags) keeps "unparsed token" noise down to things that
 * actually look like an unresolved command. */
static bool is_shell_noise_token(const char *tok) {
    static const char *noise[] = {
        "test", "[", "]", "&&", "||", ";", "|",
        "then", "fi", "do", "done",
        /* Structural shell keywords: a cron job may legitimately start a
         * command with one of these after `&&` (e.g. Debian's /etc/cron.d/php
         * uses `[ -x ... ] && if [ ! -d ... ]; then ...`), so they are syntax,
         * not a command that PATH could resolve. */
        "if", "elif", "else", "while", "until", "for", "case", "esac",
        "{", "}", "in", "select", NULL
    };
    if (tok[0] == '-') return true; /* flag, e.g. -e, -f, -c */
    for (int i = 0; noise[i]; i++)
        if (strcmp(tok, noise[i]) == 0) return true;
    return false;
}

/* Shell builtins and control keywords that can legitimately appear as the
 * command word of a cron job (`cd / && run-parts ...` is in Debian's stock
 * /etc/crontab). They are never resolved through PATH, so flagging them as
 * a "relative command" would only add noise. */
static bool is_shell_builtin(const char *tok) {
    static const char *builtins[] = {
        "cd", "exec", "eval", "source", ".", ":", "set", "unset", "export",
        "local", "readonly", "declare", "typeset", "shift", "return", "exit",
        "true", "false", "echo", "printf", "read", "umask", "trap", "wait",
        "alias", "unalias", "type", "command", "builtin", "let", "ulimit",
        "getopts", "break", "continue", "kill", "pwd", "hash", "jobs",
        NULL
    };
    for (int i = 0; builtins[i]; i++)
        if (strcmp(tok, builtins[i]) == 0) return true;
    return false;
}

/* Strip shell quoting and separators from a path token in place, so that
 * `'/opt/x.sh'`, `/opt/x.sh;`, `/opt/x.sh)` and `/opt/x.sh` all resolve to
 * the same file. Without this, every quoted path in a cron job or in the
 * scripts under /etc/cron.{hourly,daily,...} silently failed the stat() and
 * was never checked for writability. */
static void strip_shell_affixes(char *tok) {
    static const char *affix = "\"'`;|&(){}[]<>,!";
    size_t len = strlen(tok);
    size_t start = 0;
    while (tok[start] && strchr(affix, tok[start])) start++;
    if (start) {
        memmove(tok, tok + start, len - start + 1);
        len -= start;
    }
    while (len > 0 && strchr(affix, tok[len - 1])) tok[--len] = '\0';
}

/* Inspect a whitespace-tokenized command string (already past schedule/user
 * fields) for absolute paths worth a writability check.
 *
 * job_context separates the two callers:
 *   - true:  a crontab command field. A relative command is worth a single
 *            note there, since cron resolves it through PATH.
 *   - false: the body of a script in /etc/cron.{hourly,daily,weekly,monthly}.
 *            That is arbitrary shell code, so tokens such as `if`, `]`, `\`
 *            or `local` are ordinary syntax, not findings; only absolute
 *            paths are inspected. Reporting every non-absolute token there
 *            used to bury real findings under 150+ LOW false positives on a
 *            stock Debian/Ubuntu host.
 *
 * cmd_user may be NULL (per-user crontab / script context: "runs as the
 * owning user"). */
static void inspect_token_list(FindingList *fl, const Options *o, const char *file,
                               const char *cmd_user, char *s, bool job_context) {
    char *save = NULL;
    bool command_position = true; /* next non-wrapper token is a command word */

    for (char *tok = strtok_r(s, " \t", &save); tok; tok = strtok_r(NULL, " \t", &save)) {
        if (looks_like_env_assign(tok)) continue;

        /* A control operator ends a command and starts a new one, so what
         * follows is again in command position. This runs on the raw token,
         * before quote/separator stripping, because stripping would erase an
         * operator such as "&&" entirely. */
        if (strcmp(tok, "&&") == 0 || strcmp(tok, "||") == 0 ||
            strcmp(tok, ";") == 0 || strcmp(tok, "|") == 0 ||
            strcmp(tok, "&") == 0 || strcmp(tok, "then") == 0 ||
            strcmp(tok, "else") == 0 || strcmp(tok, "do") == 0) {
            command_position = true;
            continue;
        }

        strip_shell_affixes(tok);
        if (*tok == '\0') continue;

        bool is_wrapper = false;
        const char *b = strrchr(tok, '/'); b = b ? b + 1 : tok;
        for (int i = 0; cron_wrappers[i]; i++) {
            if (strcmp(b, cron_wrappers[i]) == 0) { is_wrapper = true; break; }
        }
        if (is_wrapper) continue; /* keep scanning for the real command token */

        if (strcmp(b, "sh") == 0 || strcmp(b, "bash") == 0 || strcmp(b, "dash") == 0) {
            /* `sh -c '...'` bodies are unwrapped separately by the caller
             * (inspect_cron_entry) before tokenizing reaches here; a bare
             * shell invocation without a parsed -c body is left unparsed. */
            continue;
        }

        if (is_shell_noise_token(tok)) continue;

        if (tok[0] != '/') {
            /* Only a relative *command* word of a real crontab job is
             * interesting. Its arguments and script syntax are not, so this
             * must be in command position and must not be a shell builtin. */
            if (job_context && command_position && !is_shell_builtin(tok)) {
                if (cmd_user)
                    add_finding(fl, "cron.unparsed_token", CAT_CRON, SEV_LOW, CONF_POSSIBLE,
                                "Relative command in cron job", file,
                                "Token '%.100s' (job runs as %s) is relative or not a "
                                "recognized wrapper; not inspected for writability.",
                                tok, cmd_user);
                else
                    add_finding(fl, "cron.unparsed_token", CAT_CRON, SEV_LOW, CONF_POSSIBLE,
                                "Relative command in cron job", file,
                                "Token '%.100s' is relative or not a recognized "
                                "wrapper; not inspected for writability.", tok);
            }
            command_position = false;
            continue;
        }

        command_position = false;
        struct stat st;
        if (stat(tok, &st) != 0) continue; /* dangling path, not our concern here */
        if (!S_ISREG(st.st_mode)) continue;
        if (!is_writable_by_me(tok)) continue;

        if (o->is_root) {
            add_finding(fl, "cron.writable_ref_root_auditor", CAT_CRON, SEV_INFO,
                        CONF_CONFIRMED, "Writable cron-referenced file (root auditor)",
                        tok, "Writable by root, the identity running this audit; "
                        "not an unprivileged escalation signal.");
        } else {
            add_finding(fl, "cron.writable_ref", CAT_CRON, SEV_HIGH, CONF_LIKELY,
                        "Writable file referenced by cron job", tok,
                        "Referenced by %s and writable by current user.", file);
        }
    }
}

/* Parse one crontab-format line: "[@keyword | 5 schedule fields] [user] command". */
static void inspect_cron_entry(FindingList *fl, const Options *o, const char *file,
                               bool has_user_field, char *line) {
    char *s = trim(line);
    if (*s == '\0' || *s == '#') return;

    /* Environment assignment line (PATH=, MAILTO=, SHELL=...) - not a job. */
    {
        char probe[2048];
        snprintf(probe, sizeof(probe), "%s", s);
        char *psave = NULL;
        char *first = strtok_r(probe, " \t", &psave);
        if (first && looks_like_env_assign(first)) return;
    }

    char copy[2048];
    snprintf(copy, sizeof(copy), "%s", s);
    char *save = NULL;

    char *tok = strtok_r(copy, " \t", &save);
    if (!tok) return;

    if (tok[0] == '@') {
        /* single schedule token, e.g. @reboot, @daily - nothing more to skip */
    } else {
        for (int i = 1; i < 5; i++) {
            tok = strtok_r(NULL, " \t", &save);
            if (!tok) {
                add_finding(fl, "cron.unparsed_line", CAT_CRON, SEV_LOW, CONF_POSSIBLE,
                            "Unparsed cron line", file,
                            "Line does not match the expected 5-field/@keyword "
                            "schedule format; left unparsed: %.150s", s);
                return;
            }
        }
    }

    char userbuf[256] = "";
    const char *cmd_user = NULL;
    if (has_user_field) {
        tok = strtok_r(NULL, " \t", &save);
        if (!tok) return;
        snprintf(userbuf, sizeof(userbuf), "%s", tok);
        cmd_user = userbuf;
    }

    char *cmdstart = save; /* strtok_r leaves this at the unconsumed remainder */
    if (!cmdstart || !*cmdstart) return;

    /* Unwrap one level of `sh -c '...'` / `bash -c "..."`. */
    char *scpos = strstr(cmdstart, " -c ");
    if (scpos) {
        char *q = scpos + 4;
        while (*q == ' ') q++;
        if (*q == '\'' || *q == '"') {
            char quote = *q++;
            char *end = strchr(q, quote);
            if (end) {
                size_t ilen = (size_t)(end - q);
                char inner[2048];
                if (ilen >= sizeof(inner)) ilen = sizeof(inner) - 1;
                memcpy(inner, q, ilen);
                inner[ilen] = '\0';
                inspect_token_list(fl, o, file, cmd_user, inner, true);
                return;
            }
        }
    }

    char cmdcopy[2048];
    snprintf(cmdcopy, sizeof(cmdcopy), "%s", cmdstart);
    inspect_token_list(fl, o, file, cmd_user, cmdcopy, true);
}

static void scan_cron_crontab_file(FindingList *fl, const Options *o, const char *path,
                                   bool has_user_field, ScanStats *stats) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        if (errno == ENOENT) stats->roots_missing_expected++;
        else stats->roots_unreadable++;
        return;
    }
    char line[2048];
    while (fgets(line, sizeof(line), fp))
        inspect_cron_entry(fl, o, path, has_user_field, line);
    fclose(fp);
}

/* cron.hourly/daily/weekly/monthly entries are executable scripts, not
 * crontab-format lines - scan their content for absolute writable refs only,
 * without trying to parse schedule/user fields that don't exist there (and
 * without flagging shell syntax as a "relative command"). */
static void inspect_script_for_writable_refs(FindingList *fl, const Options *o, const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) return;
    char line[2048];
    while (fgets(line, sizeof(line), fp)) {
        char *s = trim(line);
        if (*s == '\0' || *s == '#') continue;
        char copy[2048];
        snprintf(copy, sizeof(copy), "%s", s);
        inspect_token_list(fl, o, path, NULL, copy, false);
    }
    fclose(fp);
}

static void report_writable_cron_path(FindingList *fl, const Options *o,
                                      const char *title_user, const char *title_root,
                                      const char *check_id_user, const char *check_id_root,
                                      const char *path, const char *detail) {
    if (o->is_root)
        add_finding(fl, check_id_root, CAT_CRON, SEV_INFO, CONF_CONFIRMED,
                    title_root, path,
                    "Writable by root, the identity running this audit; not an "
                    "unprivileged escalation signal.");
    else
        add_finding(fl, check_id_user, CAT_CRON, SEV_HIGH, CONF_CONFIRMED,
                    title_user, path, "%s", detail);
}

static void scan_cron(FindingList *fl, const Options *o, ScanStats *stats) {
    scan_cron_crontab_file(fl, o, "/etc/crontab", /*has_user_field=*/true, stats);

    /* The system crontab itself is the highest-value cron target and was the
     * one file in this scan never checked for writability (only the files
     * inside the cron directories were). */
    if (is_writable_by_me("/etc/crontab"))
        report_writable_cron_path(fl, o, "Writable /etc/crontab",
                                  "Writable /etc/crontab (root auditor)",
                                  "cron.crontab_writable", "cron.crontab_writable_root_auditor",
                                  "/etc/crontab",
                                  "/etc/crontab is writable by the current user; root "
                                  "scheduled commands could be added or replaced.");

    static const struct { const char *dir; bool has_user_field; bool is_script_dir; } dirs[] = {
        { "/etc/cron.d",            true,  false },
        { "/etc/cron.hourly",       false, true  },
        { "/etc/cron.daily",        false, true  },
        { "/etc/cron.weekly",       false, true  },
        { "/etc/cron.monthly",      false, true  },
        { "/var/spool/cron",        false, false },
        { "/var/spool/cron/crontabs", false, false },
        { NULL, false, false }
    };

    for (int i = 0; dirs[i].dir; i++) {
        DIR *d = opendir(dirs[i].dir);
        if (!d) {
            if (errno == ENOENT) stats->roots_missing_expected++;
            else stats->roots_unreadable++;
            continue;
        }

        if (is_writable_by_me(dirs[i].dir))
            report_writable_cron_path(fl, o, "Writable cron directory",
                                      "Writable cron directory (root auditor)",
                                      "cron.writable_dir", "cron.writable_dir_root_auditor",
                                      dirs[i].dir, "New scheduled jobs could be added here.");

        struct dirent *de;
        char p[4096];
        while ((de = readdir(d)) != NULL) {
            if (de->d_name[0] == '.') continue;
            snprintf(p, sizeof(p), "%s/%s", dirs[i].dir, de->d_name);
            struct stat st;
            if (stat(p, &st) != 0) { stats->paths_skipped_unreadable++; continue; }
            if (!S_ISREG(st.st_mode)) continue;

            if (is_writable_by_me(p))
                report_writable_cron_path(fl, o, "Writable cron job file",
                                          "Writable cron job file (root auditor)",
                                          "cron.writable_file", "cron.writable_file_root_auditor",
                                          p, "Scheduled job file is writable by current user.");

            if (dirs[i].is_script_dir)
                inspect_script_for_writable_refs(fl, o, p);
            else
                scan_cron_crontab_file(fl, o, p, dirs[i].has_user_field, stats);
        }
        closedir(d);
    }
}

/* ---- 4.5 Service scan (systemd) -----------------------------------------
 *
 * fixes.md item 10:
 *   - check the unit's parent directory for writability, not just the file.
 *   - consider User= before calling a writable ExecStart* target a root path.
 *   - resolve .wants//.requires symlinks whose target falls outside the
 *     already-scanned roots (most point back into an already-scanned root,
 *     so only genuinely-external targets are inspected, avoiding duplicate
 *     findings).
 *   - coverage of scanned-vs-unreadable unit directories comes for free from
 *     walk_dir()'s ScanStats threading.
 */

typedef struct { FindingList *fl; const Options *o; } SvcCtx;

static void svc_cb(const char *path, const struct stat *st, void *vctx) {
    (void)st;
    SvcCtx *c = (SvcCtx *)vctx;
    size_t len = strlen(path);
    bool is_service = (len >= 8 && strcmp(path + len - 8, ".service") == 0);
    bool is_timer   = (len >= 6 && strcmp(path + len - 6, ".timer") == 0);
    if (!is_service && !is_timer) return;

    char parent[4096];
    snprintf(parent, sizeof(parent), "%s", path);
    char *slash = strrchr(parent, '/');
    if (slash) *slash = '\0';

    bool file_writable = is_writable_by_me(path);
    bool dir_writable   = is_writable_by_me(parent);

    if (file_writable || dir_writable) {
        if (c->o->is_root) {
            add_finding(c->fl, "svc.writable_root_auditor", CAT_SERVICES, SEV_INFO,
                        CONF_CONFIRMED, "Writable unit (root auditor)", path,
                        "Writable by root, the identity running this audit; not an "
                        "unprivileged escalation signal.");
        } else if (file_writable) {
            add_finding(c->fl, "svc.writable_unit", CAT_SERVICES, SEV_HIGH, CONF_CONFIRMED,
                        "Writable systemd unit", path,
                        "Unit file is writable; its ExecStart could be hijacked.");
        } else {
            add_finding(c->fl, "svc.writable_unit_dir", CAT_SERVICES, SEV_HIGH, CONF_CONFIRMED,
                        "Unit in writable directory", path,
                        "Unit file's directory (%s) is writable by the current "
                        "user; the unit could be replaced even though the file "
                        "itself is not directly writable.", parent);
        }
        return;
    }

    FILE *fp = fopen(path, "r");
    if (!fp) return;

    char line[2048];
    char run_user[256] = "";
    bool have_user = false;
    char exec_target[2048] = "";
    char exec_directive[32] = "";
    bool have_exec = false;

    while (fgets(line, sizeof(line), fp)) {
        char *s = trim(line);
        if (strncmp(s, "User=", 5) == 0) {
            snprintf(run_user, sizeof(run_user), "%s", trim(s + 5));
            have_user = (run_user[0] != '\0');
            continue;
        }
        if (strncmp(s, "Exec", 4) == 0) {
            char *eq = strchr(s, '=');
            if (!eq) continue;
            size_t dl = (size_t)(eq - s);
            char directive[32];
            if (dl >= sizeof(directive)) dl = sizeof(directive) - 1;
            memcpy(directive, s, dl);
            directive[dl] = '\0';

            char *cmd = trim(eq + 1);
            while (*cmd == '-' || *cmd == '@' || *cmd == '+' || *cmd == '!')
                cmd++; /* systemd exec prefixes */
            char *sp = strpbrk(cmd, " \t");
            if (sp) *sp = '\0';
            if (cmd[0] == '/') {
                struct stat bst;
                if (stat(cmd, &bst) == 0 && S_ISREG(bst.st_mode) && is_writable_by_me(cmd)) {
                    snprintf(exec_target, sizeof(exec_target), "%s", cmd);
                    snprintf(exec_directive, sizeof(exec_directive), "%s", directive);
                    have_exec = true;
                }
            }
        }
    }
    fclose(fp);

    if (!have_exec) return;

    bool runs_as_root = !have_user || strcmp(run_user, "root") == 0;
    if (c->o->is_root) {
        add_finding(c->fl, "svc.writable_exec_root_auditor", CAT_SERVICES, SEV_INFO,
                    CONF_CONFIRMED, "Writable service executable (root auditor)",
                    exec_target, "Writable by root; not an unprivileged escalation signal.");
    } else if (runs_as_root) {
        add_finding(c->fl, "svc.writable_exec_root", CAT_SERVICES, SEV_HIGH, CONF_LIKELY,
                    "Writable service executable (runs as root)", exec_target,
                    "%s target of %s is writable, and the unit has no non-root "
                    "User= (or is explicitly User=root).", exec_directive, path);
    } else {
        add_finding(c->fl, "svc.writable_exec_nonroot", CAT_SERVICES, SEV_MEDIUM, CONF_LIKELY,
                    "Writable service executable (non-root unit)", exec_target,
                    "%s target of %s is writable, but the unit runs as User=%s, "
                    "not root - escalation would be to that user, not root.",
                    exec_directive, path, run_user);
    }
}

/* Resolve symlinks under unit .wants/.requires directories whose target falls
 * outside the roots already walked (tracked via *seen); most point back into
 * an already-scanned root and are correctly left alone to avoid duplicates. */
static void scan_wants_symlinks(FindingList *fl, const Options *o, const char *dir,
                                SeenSet *seen, ScanStats *stats, int depth) {
    if (depth > 6) return; /* unit dirs are shallow; bound defensively */
    DIR *d = opendir(dir);
    if (!d) return;

    struct dirent *de;
    char child[4096];
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.') continue;
        int n = snprintf(child, sizeof(child), "%s/%s", dir, de->d_name);
        if (n < 0 || (size_t)n >= sizeof(child)) continue;

        struct stat lst;
        if (lstat(child, &lst) != 0) { stats->paths_skipped_unreadable++; continue; }

        if (S_ISDIR(lst.st_mode)) {
            scan_wants_symlinks(fl, o, child, seen, stats, depth + 1);
            continue;
        }
        if (!S_ISLNK(lst.st_mode)) continue;

        char raw[4096];
        ssize_t rn = readlink(child, raw, sizeof(raw) - 1);
        if (rn <= 0) continue;
        raw[rn] = '\0';

        char resolved[8192];
        if (raw[0] == '/') {
            snprintf(resolved, sizeof(resolved), "%s", raw);
        } else {
            char dirbuf[4096];
            snprintf(dirbuf, sizeof(dirbuf), "%s", child);
            char *sl = strrchr(dirbuf, '/');
            if (sl) *sl = '\0';
            snprintf(resolved, sizeof(resolved), "%s/%s", dirbuf, raw);
        }

        char canon[PATH_MAX];
        if (!realpath(resolved, canon)) continue;

        struct stat tst;
        if (stat(canon, &tst) != 0) continue;
        if (!S_ISREG(tst.st_mode)) continue;

        /* Already covered by a normally-scanned root -> skip (avoid dup). */
        if (seen_set_check_add(seen, tst.st_dev, tst.st_ino)) continue;

        SvcCtx ctx = { fl, o };
        svc_cb(canon, &tst, &ctx);
    }
    closedir(d);
}

static void scan_services(FindingList *fl, const Options *o, ScanStats *stats) {
    static const char *roots[] = {
        "/etc/systemd/system", "/lib/systemd/system",
        "/usr/lib/systemd/system", "/run/systemd/system", NULL
    };
    SvcCtx ctx = { fl, o };
    SeenSet seen;
    seen_set_init(&seen);

    for (int i = 0; roots[i]; i++)
        walk_dir(roots[i], 0, 3, svc_cb, &ctx, &seen, stats, true);
    for (int i = 0; roots[i]; i++)
        scan_wants_symlinks(fl, o, roots[i], &seen, stats, 0);

    seen_set_free(&seen);
}

/* ---- 4.6 Process scan ---------------------------------------------------
 *
 * fixes.md item 8:
 *   - state the /proc visibility limitation explicitly.
 *   - never strip the `(deleted)` readlink suffix and stat() the reconstructed
 *     path - a different file may now exist there. Use /proc/<pid>/exe
 *     directly (stat()/access() on it resolve to the original inode even
 *     after unlink); when the link text contains "(deleted)", report the
 *     executable as deleted/uninspectable-by-path instead of silently
 *     dropping or misidentifying it.
 *   - under a root auditor, every root-owned process looks "writable" - not
 *     an escalation signal in that case.
 */
static void scan_processes(FindingList *fl, const Options *o) {
    add_finding(fl, "proc.coverage_limitation", CAT_PROCESSES, SEV_INFO, CONF_CONFIRMED,
                "Process scan coverage limitation", NULL,
                "/proc/<pid>/exe is only readable for the invoking user's own "
                "processes, or for all processes if this audit itself runs as "
                "root. As a non-root user this scan is blind to most other "
                "users' and root's processes.");

    DIR *d = opendir("/proc");
    if (!d) {
        add_finding(fl, "proc.unavailable", CAT_PROCESSES, SEV_INFO, CONF_CONFIRMED,
                    "Process scan unavailable", NULL,
                    "/proc not present; process inspection skipped.");
        return;
    }

    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        bool numeric = de->d_name[0] != '\0';
        for (const char *p = de->d_name; *p; p++)
            if (!isdigit((unsigned char)*p)) { numeric = false; break; }
        if (!numeric) continue;

        char base[320];
        snprintf(base, sizeof(base), "/proc/%s", de->d_name);
        struct stat pst;
        if (stat(base, &pst) != 0) continue; /* not ours/root's, or already gone */
        if (pst.st_uid != 0) continue;       /* only root-owned processes matter here */

        char exe_path[328];
        snprintf(exe_path, sizeof(exe_path), "%s/exe", base);

        struct stat est;
        if (stat(exe_path, &est) != 0) continue; /* unreadable or process gone */

        char target[4096];
        ssize_t n = readlink(exe_path, target, sizeof(target) - 1);
        bool deleted = false;
        if (n > 0) {
            target[n] = '\0';
            if (strstr(target, " (deleted)") != NULL) deleted = true;
        } else {
            target[0] = '\0';
        }

        if (deleted) {
            add_finding(fl, "proc.deleted_exe", CAT_PROCESSES, SEV_LOW, CONF_POSSIBLE,
                        "Root process with deleted backing executable",
                        target[0] ? target : exe_path,
                        "PID %s's on-disk executable has been deleted/replaced "
                        "since the process started; the original inode is still "
                        "running but cannot be checked for writability by path.",
                        de->d_name);
            continue;
        }

        /* access()/stat() on /proc/<pid>/exe resolve to the real running
         * inode even after unlink, so this is safe without reconstructing
         * any path from the (untrusted-for-this-purpose) readlink text. */
        if (!is_writable_by_me(exe_path)) continue;

        if (o->is_root) {
            add_finding(fl, "proc.writable_exe_root_auditor", CAT_PROCESSES, SEV_INFO,
                        CONF_CONFIRMED, "Root process writable by root (auditor)",
                        exe_path, "Writable by root, the identity running this "
                        "audit; not an unprivileged escalation signal.");
        } else {
            add_finding(fl, "proc.writable_exe", CAT_PROCESSES, SEV_HIGH, CONF_LIKELY,
                        "Root process with writable binary", target[0] ? target : exe_path,
                        "PID %s runs as root from a writable executable.", de->d_name);
        }
    }
    closedir(d);
}

/* ---- 4.7 Filesystem scan -------------------------------------------------
 *
 * fixes.md items 4 and 5:
 *   - parse $PATH without strtok_r, which silently discards leading,
 *     trailing, and doubled colons - exactly the empty components (== cwd)
 *     that matter most.
 *   - verify a PATH entry is actually a directory before calling it a
 *     "writable PATH directory".
 *   - report (rather than silently truncate) an overlong PATH value.
 */
static void scan_filesystem(FindingList *fl, const Options *o) {
    /* 4.7a World-writable directories missing the sticky bit (/tmp-style). */
    static const char *dirs[] = { "/tmp", "/var/tmp", "/dev/shm", NULL };
    for (int i = 0; dirs[i]; i++) {
        struct stat st;
        if (lstat(dirs[i], &st) != 0) continue;
        if (mode_world_writable(st.st_mode) && !(st.st_mode & S_ISVTX))
            add_finding(fl, "fs.sticky_missing", CAT_FILESYSTEM, SEV_MEDIUM, CONF_CONFIRMED,
                        "World-writable dir without sticky bit", dirs[i],
                        "Others can delete/replace files in this directory.");
    }

    /* 4.7b $PATH: writable dirs, relative entries, empty entries. */
    const char *path_env = getenv("PATH");
    if (path_env) {
        char copy[8192];
        size_t pelen = strlen(path_env);
        if (pelen >= sizeof(copy)) {
            add_finding(fl, "fs.path_overlong", CAT_FILESYSTEM, SEV_LOW, CONF_CONFIRMED,
                        "Overlong $PATH value", NULL,
                        "$PATH is %zu bytes, exceeding this tool's %zu-byte parse "
                        "buffer; it was truncated for analysis, so results for "
                        "$PATH may be incomplete.", pelen, sizeof(copy) - 1);
        }
        snprintf(copy, sizeof(copy), "%s", path_env);

        char *p = copy;
        while (1) {
            char *colon = strchr(p, ':');
            if (colon) *colon = '\0';
            char *entry = p;

            if (entry[0] == '\0') {
                add_finding(fl, "fs.path_empty_component", CAT_FILESYSTEM, SEV_MEDIUM,
                            CONF_LIKELY, "Empty $PATH component", NULL,
                            "An empty PATH entry (leading/trailing/doubled colon) "
                            "is equivalent to the current directory (.) and can "
                            "enable binary planting depending on cwd.");
            } else if (entry[0] != '/') {
                add_finding(fl, "fs.path_relative", CAT_FILESYSTEM, SEV_MEDIUM, CONF_LIKELY,
                            "Relative entry in $PATH", entry,
                            "Non-absolute PATH entry enables binary planting.");
            } else {
                struct stat st;
                if (stat(entry, &st) != 0) {
                    /* dangling PATH entry - nothing to plant into right now */
                } else if (!S_ISDIR(st.st_mode)) {
                    add_finding(fl, "fs.path_not_dir", CAT_FILESYSTEM, SEV_LOW, CONF_CONFIRMED,
                                "Non-directory $PATH entry", entry,
                                "PATH entry exists but is not a directory; it "
                                "cannot supply executables as intended.");
                } else if (is_writable_by_me(entry)) {
                    if (o->is_root)
                        add_finding(fl, "fs.path_writable_root_auditor", CAT_FILESYSTEM,
                                    SEV_INFO, CONF_CONFIRMED,
                                    "Writable $PATH directory (root auditor)", entry,
                                    "Writable by root, the identity running this "
                                    "audit; not an unprivileged escalation signal.");
                    else
                        add_finding(fl, "fs.path_writable", CAT_FILESYSTEM, SEV_HIGH,
                                    CONF_CONFIRMED, "Writable directory in $PATH", entry,
                                    "A writable PATH dir allows planting trojan binaries.");
                }
            }

            if (!colon) break;
            p = colon + 1;
        }
    }

    /* 4.7c Sensitive files that should never be writable/readable. */
    static const struct { const char *path; bool check_read; Severity sev; } sens[] = {
        { "/etc/passwd", false, SEV_CRITICAL },
        { "/etc/shadow", true,  SEV_CRITICAL },
        { "/etc/group",  false, SEV_HIGH     },
        { "/etc/gshadow",true,  SEV_HIGH     },
        { "/root/.ssh/authorized_keys", false, SEV_HIGH },
        { NULL, false, SEV_INFO }
    };
    for (int i = 0; sens[i].path; i++) {
        if (is_writable_by_me(sens[i].path)) {
            if (o->is_root)
                add_finding(fl, "fs.sensitive_writable_root_auditor", CAT_FILESYSTEM,
                            SEV_INFO, CONF_CONFIRMED,
                            "Writable sensitive file (root auditor)", sens[i].path,
                            "Writable by root, the identity running this audit; "
                            "not an unprivileged escalation signal.");
            else
                add_finding(fl, "fs.sensitive_writable", CAT_FILESYSTEM, sens[i].sev,
                            CONF_CONFIRMED, "Writable sensitive file", sens[i].path,
                            "This file is writable by the current user.");
        } else if (sens[i].check_read && access(sens[i].path, R_OK) == 0) {
            add_finding(fl, "fs.shadow_readable", CAT_FILESYSTEM, SEV_HIGH, CONF_CONFIRMED,
                        "Readable shadow file", sens[i].path,
                        "Password hashes are readable by the current user.");
        }
    }
}

/* ---- 4.8 Package / kernel CVE heuristic -----------------------------------
 *
 * fixes.md item 11 (scoped down from a full OVAL/NVD-backed DB):
 *   - compare full major.minor.patch, not just major.minor.
 *   - query installed package version via dpkg-query/rpm for package-based
 *     CVEs (PwnKit) instead of inferring anything from kernel version.
 *   - always label table matches "candidate, unconfirmed" in the output
 *     itself - never "matched", since the table can't confirm distro
 *     applicability or backports on its own.
 *   - keep "unknown" (couldn't parse kernel version) distinct and never
 *     collapse it into "not vulnerable".
 */
typedef struct {
    const char *cve;
    const char *name;
    int maj_lo, min_lo, pat_lo; /* inclusive lower bound */
    int maj_hi, min_hi, pat_hi; /* inclusive upper bound */
    Severity sev;
} KernelCVE;

static const KernelCVE kernel_cves[] = {
    { "CVE-2016-5195",  "Dirty COW",           2, 6, 0,   4, 8,  0,  SEV_HIGH },
    { "CVE-2021-4034",  "PwnKit (pkexec)",     0, 0, 0,   0, 0,  0,  SEV_HIGH }, /* package-based, handled separately */
    { "CVE-2022-0847",  "Dirty Pipe",          5, 8, 0,   5, 16, 11, SEV_HIGH },
    { "CVE-2021-22555", "Netfilter heap OOB",  2, 6, 0,   5, 11, 0,  SEV_HIGH },
    { "CVE-2017-16995", "eBPF verifier",       4, 4, 0,   4, 14, 0,  SEV_HIGH },
    { "CVE-2021-3493",  "OverlayFS (Ubuntu)",  5, 4, 0,   5, 11, 0,  SEV_HIGH },
    { NULL, NULL, 0,0,0, 0,0,0, SEV_INFO }
};

static bool version_in_range(int maj, int min, int pat, const KernelCVE *c) {
    long v  = (long)maj * 1000000L + (long)min * 1000L + pat;
    long lo = (long)c->maj_lo * 1000000L + (long)c->min_lo * 1000L + c->pat_lo;
    long hi = (long)c->maj_hi * 1000000L + (long)c->min_hi * 1000L + c->pat_hi;
    return v >= lo && v <= hi;
}

/* Query an installed package version via dpkg or rpm, whichever is present.
 * Read-only package-manager metadata queries - no privilege required. */
static bool query_package_version(const char *pkg, char *out, size_t outsz) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "dpkg-query -W -f='${Version}' %s 2>/dev/null", pkg);
    FILE *pp = popen(cmd, "r");
    if (pp) {
        bool ok = (fgets(out, outsz, pp) != NULL) && out[0] != '\0';
        pclose(pp);
        if (ok) return true;
    }
    snprintf(cmd, sizeof(cmd), "rpm -q --qf '%%{VERSION}-%%{RELEASE}' %s 2>/dev/null", pkg);
    pp = popen(cmd, "r");
    if (pp) {
        bool ok = (fgets(out, outsz, pp) != NULL) && out[0] != '\0' &&
                  strstr(out, "not installed") == NULL;
        pclose(pp);
        if (ok) return true;
    }
    out[0] = '\0';
    return false;
}

static void scan_package(FindingList *fl, const HostInfo *h, const Options *o) {
    (void)o;
    int maj, min, pat;
    parse_kernel_version(h->kernel_release, &maj, &min, &pat);

    if (maj == 0) {
        add_finding(fl, "pkg.kernel_version_unknown", CAT_PACKAGE, SEV_INFO, CONF_POSSIBLE,
                    "Kernel version unknown", NULL,
                    "Could not parse kernel version '%s' for CVE matching. This "
                    "is UNKNOWN, not \"not vulnerable\".", h->kernel_release);
        return;
    }

    for (int i = 0; kernel_cves[i].cve; i++) {
        const KernelCVE *c = &kernel_cves[i];
        if (c->maj_hi == 0 && c->maj_lo == 0) continue; /* package-based entry, not version-ranged */
        if (version_in_range(maj, min, pat, c)) {
            add_finding(fl, "pkg.kernel_cve_candidate", CAT_PACKAGE, c->sev, CONF_POSSIBLE,
                        "Upstream kernel CVE candidate (unconfirmed)", h->kernel_release,
                        "Kernel %d.%d.%d falls within the historical upstream-"
                        "affected range for %s (%s). This is an UPSTREAM CANDIDATE "
                        "ONLY, unconfirmed: distro backports are not accounted "
                        "for. Verify against your vendor's advisory and installed "
                        "package/kernel-patch version before treating this as "
                        "exploitable.", maj, min, pat, c->name, c->cve);
        }
    }

    /* pkexec/PwnKit: presence + SUID is the signal; applicability depends on
     * the installed polkit package version, not the kernel version. */
    struct stat st;
    if (stat("/usr/bin/pkexec", &st) == 0 && (st.st_mode & S_ISUID)) {
        char ver[128];
        /* Debian renamed policykit-1 to polkitd; check both spellings (and
         * the upstream name) so the version is known on current Kali/Ubuntu. */
        if (query_package_version("policykit-1", ver, sizeof(ver)) ||
            query_package_version("polkitd", ver, sizeof(ver)) ||
            query_package_version("polkit", ver, sizeof(ver))) {
            add_finding(fl, "pkg.pwnkit_surface", CAT_PACKAGE, SEV_MEDIUM, CONF_POSSIBLE,
                        "pkexec present (PwnKit surface)", "/usr/bin/pkexec",
                        "SUID pkexec present; installed polkit package version is "
                        "%s. CVE-2021-4034 applicability depends on this package "
                        "version, not kernel version - verify against the vendor "
                        "advisory.", trim(ver));
        } else {
            add_finding(fl, "pkg.pwnkit_surface_unknown_version", CAT_PACKAGE, SEV_MEDIUM,
                        CONF_POSSIBLE, "pkexec present (PwnKit surface)", "/usr/bin/pkexec",
                        "SUID pkexec present but the installed polkit package "
                        "version could not be determined (no dpkg/rpm, or the "
                        "query failed). Verify manually against vendor advisories "
                        "for CVE-2021-4034.");
        }
    }
}

#else /* _WIN32 */

/* ---- 4W. Windows scanners ---------------------------------------------
 *
 * Same finding model, categories, severities and JSON as the POSIX build, with
 * Windows escalation primitives in place of SUID/sudo/cron:
 *   services    unquoted image paths, writable service images/directories
 *   autostart   HKLM Run/RunOnce, Startup folders, AlwaysInstallElevated
 *   filesystem  writable directories in %PATH%
 *   privileges  dangerous token privileges, integrity level
 *
 * Every check is read-only: permissions are tested with AccessCheck against
 * the object's DACL, never by opening the target for writing. As on POSIX,
 * findings caused only by the auditor's own elevated token are downgraded to
 * INFO (Options.is_root is set for an elevated administrator).
 */

#ifndef SECURITY_MANDATORY_MEDIUM_RID
#define SECURITY_MANDATORY_MEDIUM_RID 0x2000
#endif
#ifndef SECURITY_MANDATORY_HIGH_RID
#define SECURITY_MANDATORY_HIGH_RID 0x3000
#endif
#ifndef SECURITY_MANDATORY_SYSTEM_RID
#define SECURITY_MANDATORY_SYSTEM_RID 0x4000
#endif

static const char *win_error_text(DWORD err) {
    static char buf[256];
    DWORD n = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                             NULL, err, 0, buf, (DWORD)sizeof(buf), NULL);
    if (!n) {
        snprintf(buf, sizeof(buf), "error %lu", (unsigned long)err);
        return buf;
    }
    return trim(buf);
}

static bool win_account_is_privileged(const char *account) {
    if (!account || !*account) return true; /* LocalSystem */
    return str_eq_ci(account, "LocalSystem") ||
           str_eq_ci(account, "SYSTEM") ||
           str_eq_ci(account, "NT AUTHORITY\\SYSTEM") ||
           str_eq_ci(account, "NT AUTHORITY\\LocalService") ||
           str_eq_ci(account, "NT AUTHORITY\\NetworkService") ||
           str_eq_ci(account, "LocalService") ||
           str_eq_ci(account, "NetworkService");
}

/* Inspect one service's configuration. */
static void win_inspect_service(FindingList *fl, const Options *o, SC_HANDLE scm,
                                const wchar_t *name) {
    SC_HANDLE svc = OpenServiceW(scm, name, SERVICE_QUERY_CONFIG);
    if (!svc) return; /* no permission, or the service disappeared */

    DWORD needed = 0;
    QueryServiceConfigW(svc, NULL, 0, &needed);
    if (needed == 0) {
        CloseServiceHandle(svc);
        return;
    }

    QUERY_SERVICE_CONFIGW *cfg = malloc(needed);
    if (!cfg) {
        CloseServiceHandle(svc);
        return;
    }
    if (!QueryServiceConfigW(svc, cfg, needed, &needed)) {
        free(cfg);
        CloseServiceHandle(svc);
        return;
    }

    char *svc_name = win_utf8(name);
    char *raw = win_utf8(cfg->lpBinaryPathName ? cfg->lpBinaryPathName : L"");
    char *acct = win_utf8(cfg->lpServiceStartName ? cfg->lpServiceStartName : L"");

    if (!raw || !raw[0]) {
        free(svc_name); free(raw); free(acct); free(cfg);
        CloseServiceHandle(svc);
        return;
    }

    char cmd[2048];
    win_expand_env(raw, cmd, sizeof(cmd));

    char image[1024];
    bool have_image = win_image_path(cmd, image, sizeof(image));
    bool privileged = win_account_is_privileged(acct);
    const char *acct_label = (acct && *acct) ? acct : "LocalSystem";
    const char *shown = have_image ? image : cmd;

    /* 1. Unquoted image path whose extension appears only after a space. */
    if (win_unquoted_ambiguous(cmd)) {
        bool hijackable = false;
        char cand[1024], dir[1024];
        for (int i = 0; win_unquoted_candidate(cmd, i, cand, sizeof(cand)); i++) {
            /* The last candidate is the service's own image; its directory is
             * covered by the writable-directory check below. */
            if (str_eq_ci(cand, image)) continue;
            if (!win_dirname(cand, dir, sizeof(dir))) continue;
            if (!is_writable_by_me(dir)) continue;
            hijackable = true;

            if (o->is_root) {
                add_finding(fl, "svc.unquoted_path_root_auditor", CAT_SERVICES, SEV_INFO,
                            CONF_CONFIRMED,
                            "Writable directory on unquoted service path (elevated auditor)",
                            dir, "Directory is writable by the identity running this "
                            "audit; not an unprivileged escalation signal.");
            } else {
                add_finding(fl, "svc.unquoted_path_writable", CAT_SERVICES, SEV_HIGH,
                            CONF_CONFIRMED,
                            "Unquoted service path with writable directory", dir,
                            "Service '%s' (runs as %s) has an unquoted image path. "
                            "The loader would also try '%s', which the current user "
                            "could create.",
                            svc_name ? svc_name : "?", acct_label, cand);
            }
            break;
        }

        if (!hijackable) {
            add_finding(fl, "svc.unquoted_path", CAT_SERVICES,
                        o->is_root ? SEV_INFO : SEV_MEDIUM, CONF_POSSIBLE,
                        "Unquoted service path", shown,
                        "Service '%s' has an unquoted image path containing spaces. "
                        "No candidate directory is writable by the current user, but "
                        "another account could still plant an executable.",
                        svc_name ? svc_name : "?");
        }
    }

    /* 2. Writable image, else writable image directory. */
    if (have_image && is_writable_by_me(image)) {
        if (o->is_root) {
            add_finding(fl, "svc.writable_image_root_auditor", CAT_SERVICES, SEV_INFO,
                        CONF_CONFIRMED, "Writable service image (elevated auditor)", image,
                        "Writable by the identity running this audit; not an "
                        "unprivileged escalation signal.");
        } else {
            add_finding(fl, "svc.writable_image", CAT_SERVICES,
                        privileged ? SEV_CRITICAL : SEV_HIGH, CONF_CONFIRMED,
                        privileged ? "Writable service image (privileged account)"
                                   : "Writable service image (non-privileged account)",
                        image,
                        "Service '%s' runs as %s from an image writable by the "
                        "current user - replacing it executes code as that account.",
                        svc_name ? svc_name : "?", acct_label);
        }
    } else if (have_image) {
        char dir[1024];
        if (win_dirname(image, dir, sizeof(dir)) && is_writable_by_me(dir)) {
            if (o->is_root) {
                add_finding(fl, "svc.writable_dir_root_auditor", CAT_SERVICES, SEV_INFO,
                            CONF_CONFIRMED,
                            "Writable service directory (elevated auditor)", dir,
                            "Writable by the identity running this audit; not an "
                            "unprivileged escalation signal.");
            } else {
                add_finding(fl, "svc.writable_dir", CAT_SERVICES,
                            privileged ? SEV_HIGH : SEV_MEDIUM, CONF_LIKELY,
                            "Service in writable directory", dir,
                            "The directory holding service '%s' (runs as %s) is "
                            "writable, so its image could be replaced.",
                            svc_name ? svc_name : "?", acct_label);
            }
        }
    }

    free(svc_name);
    free(raw);
    free(acct);
    free(cfg);
    CloseServiceHandle(svc);
}

static void scan_services(FindingList *fl, const Options *o, ScanStats *stats) {
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL,
                                   SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) {
        stats->roots_unreadable++;
        add_finding(fl, "svc.unavailable", CAT_SERVICES, SEV_INFO, CONF_CONFIRMED,
                    "Service scan unavailable", NULL,
                    "OpenSCManager failed (%s); service findings are incomplete.",
                    win_error_text(GetLastError()));
        return;
    }

    DWORD bytes = 256 * 1024;
    BYTE *buf = malloc(bytes);
    if (!buf) {
        CloseServiceHandle(scm);
        return;
    }

    int inspected = 0;
    for (int attempt = 0; attempt < 3; attempt++) {
        DWORD resume = 0;
        bool need_more = false;
        inspected = 0;

        for (;;) {
            DWORD needed = 0, returned = 0;
            if (!EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                                       SERVICE_STATE_ALL, buf, bytes, &needed,
                                       &returned, &resume, NULL)) {
                if (GetLastError() == ERROR_MORE_DATA) need_more = true;
                break;
            }

            ENUM_SERVICE_STATUS_PROCESSW *list = (ENUM_SERVICE_STATUS_PROCESSW *)buf;
            for (DWORD i = 0; i < returned; i++) {
                win_inspect_service(fl, o, scm, list[i].lpServiceName);
                inspected++;
            }
            if (resume == 0) break;
        }

        if (!need_more) break;

        /* `resume` points into the old buffer, so growing it means starting
         * over; add_finding() collapses any duplicate findings. */
        DWORD bigger = bytes * 2;
        BYTE *nb = realloc(buf, bigger);
        if (!nb) break;
        buf = nb;
        bytes = bigger;
    }

    add_finding(fl, "svc.enumerated", CAT_SERVICES, SEV_INFO, CONF_CONFIRMED,
                "Services enumerated", NULL, "%d services inspected.", inspected);

    free(buf);
    CloseServiceHandle(scm);
}

/* ---- 4W.2 Autostart ---------------------------------------------------- */

static void win_scan_run_key(FindingList *fl, const Options *o, HKEY root,
                             const char *subkey, const char *label) {
    wchar_t *wsub = win_wide(subkey);
    if (!wsub) return;

    HKEY key;
    if (RegOpenKeyExW(root, wsub, 0, KEY_READ, &key) != ERROR_SUCCESS) {
        free(wsub);
        return;
    }
    free(wsub);

    bool machine_wide = (root == HKEY_LOCAL_MACHINE);
    if (machine_wide && win_reg_write_allowed(root, subkey)) {
        if (o->is_root) {
            add_finding(fl, "auto.run_key_writable_root_auditor", CAT_AUTOSTART, SEV_INFO,
                        CONF_CONFIRMED, "Writable autostart key (elevated auditor)", label,
                        "Writable by the identity running this audit; not an "
                        "unprivileged escalation signal.");
        } else {
            add_finding(fl, "auto.run_key_writable", CAT_AUTOSTART, SEV_CRITICAL,
                        CONF_CONFIRMED, "Writable machine-wide autostart key", label,
                        "%s is writable by the current user; a new value runs code "
                        "for every user who logs on.", label);
        }
    }

    for (DWORD idx = 0;; idx++) {
        wchar_t vname[512];
        DWORD vname_len = (DWORD)(sizeof(vname) / sizeof(vname[0]));
        BYTE data[4096];
        DWORD data_len = sizeof(data);
        DWORD type = 0;

        LONG rc = RegEnumValueW(key, idx, vname, &vname_len, NULL, &type, data, &data_len);
        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc == ERROR_MORE_DATA) continue; /* value too big for this buffer */
        if (rc != ERROR_SUCCESS) break;
        if ((type != REG_SZ && type != REG_EXPAND_SZ) || data_len < sizeof(wchar_t))
            continue;

        wchar_t *wval = (wchar_t *)data;
        wval[data_len / sizeof(wchar_t) - 1] = L'\0';
        char *cmd = win_utf8(wval);
        if (!cmd || !*cmd) {
            free(cmd);
            continue;
        }

        char expanded[2048], image[1024];
        win_expand_env(cmd, expanded, sizeof(expanded));
        if (win_image_path(expanded, image, sizeof(image)) && is_writable_by_me(image)) {
            if (o->is_root) {
                add_finding(fl, "auto.run_target_writable_root_auditor", CAT_AUTOSTART,
                            SEV_INFO, CONF_CONFIRMED,
                            "Writable autostart target (elevated auditor)", image,
                            "Writable by the identity running this audit; not an "
                            "unprivileged escalation signal.");
            } else {
                add_finding(fl, "auto.run_target_writable", CAT_AUTOSTART, SEV_HIGH,
                            CONF_LIKELY, "Writable autostart target", image,
                            "%s launches this image, which is writable by the "
                            "current user.", label);
            }
        }
        free(cmd);
    }
    RegCloseKey(key);
}

static void win_scan_startup_folder(FindingList *fl, const Options *o,
                                    const char *env_var, const char *suffix,
                                    bool all_users) {
    const char *base = getenv(env_var);
    if (!base || !*base) return;

    char dir[1024];
    snprintf(dir, sizeof(dir), "%s\\%s", base, suffix);
    if (!win_is_abs_path(dir) || !is_writable_by_me(dir)) return;

    if (o->is_root) {
        add_finding(fl, "auto.startup_dir_root_auditor", CAT_AUTOSTART, SEV_INFO,
                    CONF_CONFIRMED, "Writable Startup folder (elevated auditor)", dir,
                    "Writable by the identity running this audit; not an unprivileged "
                    "escalation signal.");
    } else if (all_users) {
        add_finding(fl, "auto.startup_dir_writable", CAT_AUTOSTART, SEV_HIGH,
                    CONF_CONFIRMED, "Writable all-users Startup folder", dir,
                    "Anything placed here is executed for every user who logs on.");
    } else {
        add_finding(fl, "auto.startup_dir_user_writable", CAT_AUTOSTART, SEV_LOW,
                    CONF_CONFIRMED, "Writable per-user Startup folder", dir,
                    "This is the current user's own Startup folder; it runs whatever "
                    "is placed in it for this account only.");
    }

    if (!all_users) return;

    char pattern[1100];
    snprintf(pattern, sizeof(pattern), "%s\\*", dir);
    wchar_t *wpat = win_wide(pattern);
    if (!wpat) return;

    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(wpat, &fd);
    free(wpat);
    if (h == INVALID_HANDLE_VALUE) return;

    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        char *name = win_utf8(fd.cFileName);
        if (!name) continue;

        char file[2048];
        snprintf(file, sizeof(file), "%s\\%s", dir, name);
        free(name);

        if (!is_writable_by_me(file)) continue;

        if (o->is_root) {
            add_finding(fl, "auto.startup_file_root_auditor", CAT_AUTOSTART, SEV_INFO,
                        CONF_CONFIRMED, "Writable Startup entry (elevated auditor)",
                        file, "Writable by the identity running this audit; not an "
                        "unprivileged escalation signal.");
        } else {
            add_finding(fl, "auto.startup_file_writable", CAT_AUTOSTART, SEV_HIGH,
                        CONF_CONFIRMED, "Writable all-users Startup entry", file,
                        "This autostart entry can be replaced by the current user and "
                        "runs for every account that logs on.");
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

static void scan_autostart(FindingList *fl, const Options *o) {
    static const struct { const char *subkey; const char *label; } run_keys[] = {
        { "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "HKLM Run" },
        { "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "HKLM RunOnce" },
        { "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
          "HKLM Run (32-bit view)" },
        { "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
          "HKLM RunOnce (32-bit view)" },
        { NULL, NULL }
    };
    for (int i = 0; run_keys[i].subkey; i++)
        win_scan_run_key(fl, o, HKEY_LOCAL_MACHINE, run_keys[i].subkey, run_keys[i].label);

    win_scan_startup_folder(fl, o, "ProgramData",
                            "Microsoft\\Windows\\Start Menu\\Programs\\StartUp", true);
    win_scan_startup_folder(fl, o, "APPDATA",
                            "Microsoft\\Windows\\Start Menu\\Programs\\StartUp", false);

    /* AlwaysInstallElevated only elevates when both policies are enabled. */
    DWORD machine = 0, user_all = 0;
    bool m = win_reg_read_dword(HKEY_LOCAL_MACHINE,
                                "SOFTWARE\\Policies\\Microsoft\\Windows\\Installer",
                                "AlwaysInstallElevated", &machine) && machine == 1;
    bool u = win_reg_read_dword(HKEY_CURRENT_USER,
                                "SOFTWARE\\Policies\\Microsoft\\Windows\\Installer",
                                "AlwaysInstallElevated", &user_all) && user_all == 1;

    if (m && u) {
        add_finding(fl, "auto.always_install_elevated", CAT_AUTOSTART,
                    o->is_root ? SEV_INFO : SEV_CRITICAL, CONF_CONFIRMED,
                    "AlwaysInstallElevated enabled", NULL,
                    "Both machine and user policy enable AlwaysInstallElevated: any "
                    "MSI package installs with SYSTEM privileges. (INFO under an "
                    "elevated auditor, which can already write the policy.)");
    } else if (m || u) {
        add_finding(fl, "auto.always_install_elevated_partial", CAT_AUTOSTART, SEV_MEDIUM,
                    CONF_CONFIRMED, "AlwaysInstallElevated partially configured", NULL,
                    "Set in %s policy only. It takes effect only when both the "
                    "machine and user policies are enabled, but it indicates an "
                    "elevation-oriented configuration.", m ? "machine" : "user");
    }
}

/* ---- 4W.3 PATH ---------------------------------------------------------- */

static void scan_filesystem(FindingList *fl, const Options *o) {
    const char *path_env = getenv("PATH");
    if (!path_env || !*path_env) return;

    char copy[8192];
    size_t plen = strlen(path_env);
    if (plen >= sizeof(copy)) {
        add_finding(fl, "fs.path_overlong", CAT_FILESYSTEM, SEV_LOW, CONF_CONFIRMED,
                    "Overlong PATH value", NULL,
                    "PATH is %zu bytes, exceeding this tool's %zu-byte parse buffer; "
                    "it was truncated for analysis, so PATH results may be "
                    "incomplete.", plen, sizeof(copy) - 1);
    }
    snprintf(copy, sizeof(copy), "%s", path_env);

    char *p = copy;
    while (1) {
        char *semi = strchr(p, ';');
        if (semi) *semi = '\0';

        char *entry = trim(p);
        size_t len = strlen(entry);
        if (len >= 2 && entry[0] == '"' && entry[len - 1] == '"') {
            entry[len - 1] = '\0';
            entry++;
            len -= 2;
        }

        if (*entry == '\0') {
            add_finding(fl, "fs.path_empty_component", CAT_FILESYSTEM, SEV_MEDIUM,
                        CONF_LIKELY, "Empty PATH component", NULL,
                        "An empty PATH entry (leading/trailing/doubled semicolon) "
                        "resolves to the current directory, enabling binary planting.");
        } else if (!win_is_abs_path(entry)) {
            add_finding(fl, "fs.path_relative", CAT_FILESYSTEM, SEV_MEDIUM, CONF_LIKELY,
                        "Relative entry in PATH", entry,
                        "A non-absolute PATH entry enables binary planting.");
        } else {
            char expanded[1024];
            win_expand_env(entry, expanded, sizeof(expanded));
            if (is_writable_by_me(expanded)) {
                if (o->is_root) {
                    add_finding(fl, "fs.path_writable_root_auditor", CAT_FILESYSTEM,
                                SEV_INFO, CONF_CONFIRMED,
                                "Writable PATH directory (elevated auditor)", expanded,
                                "Writable by the identity running this audit; not an "
                                "unprivileged escalation signal.");
                } else {
                    add_finding(fl, "fs.path_writable", CAT_FILESYSTEM, SEV_HIGH,
                                CONF_CONFIRMED, "Writable directory in PATH", expanded,
                                "A writable PATH directory allows planting a trojan "
                                "executable or DLL.");
                }
            }
        }

        if (!semi) break;
        p = semi + 1;
    }
}

/* ---- 4W.4 Token privileges --------------------------------------------- */

static void scan_privileges(FindingList *fl, const Options *o) {
    static const struct {
        const char *name;
        Severity    sev;
        const char *why;
    } dangerous[] = {
        { "SeCreateTokenPrivilege", SEV_CRITICAL,
          "create arbitrary access tokens, including one for SYSTEM" },
        { "SeTcbPrivilege", SEV_CRITICAL,
          "act as part of the trusted computing base" },
        { "SeImpersonatePrivilege", SEV_HIGH,
          "impersonate tokens (potato-style SYSTEM escalation on many builds)" },
        { "SeAssignPrimaryTokenPrivilege", SEV_HIGH,
          "replace a process's primary token" },
        { "SeDebugPrivilege", SEV_HIGH,
          "open and modify arbitrary processes, including SYSTEM ones" },
        { "SeTakeOwnershipPrivilege", SEV_HIGH,
          "take ownership of any object, including system files" },
        { "SeLoadDriverPrivilege", SEV_HIGH,
          "load a kernel driver" },
        { "SeTrustedCredManAccessPrivilege", SEV_HIGH,
          "access stored credentials through Credential Manager" },
        { "SeBackupPrivilege", SEV_MEDIUM,
          "read any file regardless of its ACL" },
        { "SeRestorePrivilege", SEV_MEDIUM,
          "write any file regardless of its ACL" },
        { "SeRelabelPrivilege", SEV_MEDIUM,
          "change mandatory integrity labels" },
        { "SeManageVolumePrivilege", SEV_MEDIUM,
          "modify volume metadata, including filesystem journals" },
        { NULL, SEV_INFO, NULL }
    };

    HANDLE tok = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        add_finding(fl, "priv.unavailable", CAT_PRIVILEGES, SEV_INFO, CONF_CONFIRMED,
                    "Privilege scan unavailable", NULL,
                    "OpenProcessToken failed (%s).", win_error_text(GetLastError()));
        return;
    }

    DWORD len = 0;
    GetTokenInformation(tok, TokenPrivileges, NULL, 0, &len);
    TOKEN_PRIVILEGES *tp = malloc(len ? len : sizeof(TOKEN_PRIVILEGES));

    if (tp && len && GetTokenInformation(tok, TokenPrivileges, tp, len, &len)) {
        for (DWORD i = 0; i < tp->PrivilegeCount; i++) {
            wchar_t wname[128];
            DWORD wlen = (DWORD)(sizeof(wname) / sizeof(wname[0]));
            if (!LookupPrivilegeNameW(NULL, &tp->Privileges[i].Luid, wname, &wlen))
                continue;

            char *name = win_utf8(wname);
            if (!name) continue;

            for (int t = 0; dangerous[t].name; t++) {
                if (!str_eq_ci(name, dangerous[t].name)) continue;

                bool enabled = (tp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) != 0;
                add_finding(fl, "priv.dangerous", CAT_PRIVILEGES, dangerous[t].sev,
                            CONF_CONFIRMED,
                            enabled ? "Dangerous privilege enabled"
                                    : "Dangerous privilege present (disabled)",
                            name, "%s (%s in this token): %s.", name,
                            enabled ? "enabled" : "held but disabled", dangerous[t].why);
                break;
            }
            free(name);
        }
    }
    free(tp);

    /* Integrity level and elevation context (INFO). */
    DWORD ilen = 0;
    GetTokenInformation(tok, TokenIntegrityLevel, NULL, 0, &ilen);
    TOKEN_MANDATORY_LABEL *tml = malloc(ilen ? ilen : 1);
    if (tml && ilen && GetTokenInformation(tok, TokenIntegrityLevel, tml, ilen, &ilen)) {
        DWORD *rid = GetSidSubAuthority(
            tml->Label.Sid, (DWORD)(*GetSidSubAuthorityCount(tml->Label.Sid) - 1));
        const char *label;
        if (*rid < SECURITY_MANDATORY_MEDIUM_RID) label = "low";
        else if (*rid < SECURITY_MANDATORY_HIGH_RID) label = "medium";
        else if (*rid < SECURITY_MANDATORY_SYSTEM_RID) label = "high";
        else label = "system";

        add_finding(fl, "priv.integrity_level", CAT_PRIVILEGES, SEV_INFO, CONF_CONFIRMED,
                    "Token integrity level", NULL,
                    "Integrity level %s (RID 0x%lx), elevated=%s.", label,
                    (unsigned long)*rid, o->is_root ? "yes" : "no");
    }
    free(tml);

    CloseHandle(tok);
}

#endif /* _WIN32 */




/* ========================================================================
 * Section 5: Output
 * ==================================================================== */

static void count_by_severity(const FindingList *fl, const Options *o, int counts[SEV_COUNT]) {
    for (int i = 0; i < SEV_COUNT; i++) counts[i] = 0;
    for (size_t i = 0; i < fl->count; i++) {
        if (!o->verbose && fl->items[i].severity == SEV_INFO) continue;
        counts[fl->items[i].severity]++;
    }
}

/* Sort findings by severity (desc) for readable output. Simple insertion sort. */
static void sort_findings(FindingList *fl) {
    for (size_t i = 1; i < fl->count; i++) {
        Finding key = fl->items[i];
        size_t j = i;
        while (j > 0 && fl->items[j - 1].severity < key.severity) {
            fl->items[j] = fl->items[j - 1];
            j--;
        }
        fl->items[j] = key;
    }
}

static void print_banner(const HostInfo *h) {
    printf("========================================\n");
#ifdef _WIN32
    printf(" Windows Privilege Escalation Auditor\n");
#else
    printf(" Linux Privilege Escalation Auditor\n");
#endif
    printf("========================================\n\n");
    printf("User:   %s\n", h->user);
#ifdef _WIN32
    printf("OS:     %s\n", h->distro);
    printf("Kernel: %s\n", h->kernel);
    printf("Arch:   %s\n", h->arch);
    printf("Elevated: %s\n", h->elevated ? "yes" : "no");
#else
    printf("UID:    %u\n", (unsigned)h->uid);
    printf("Distro: %s\n", h->distro);
    printf("Kernel: %s\n", h->kernel);
#endif
    printf("\n");
}

/* fixes.md item 2 / 12: coverage line, shown in both text and JSON output so
 * a partial scan never looks identical to a clean one. */
static void print_coverage_text(const ScanStats *stats) {
    bool partial = (stats->roots_unreadable > 0) || (stats->paths_skipped_unreadable > 0);
    printf("Scan coverage: %s\n", partial ? "PARTIAL" : "complete");
    printf("  Paths skipped (unreadable mid-walk): %d\n", stats->paths_skipped_unreadable);
    printf("  Scan roots unreadable (real failure): %d\n", stats->roots_unreadable);
    printf("  Scan roots absent on this distro (expected): %d\n", stats->roots_missing_expected);
    printf("\n");
}

static void report_text(const FindingList *fl, const Options *o, const ScanStats *stats,
                        const char *const *ran, int nran) {
    int counts[SEV_COUNT];
    count_by_severity(fl, o, counts);

    /* count_by_severity() already excludes INFO unless --verbose, so the sum
     * is exactly the number of findings printed below. Counting fl->count
     * here made the header disagree with its own severity breakdown and with
     * the list whenever INFO items were suppressed. */
    int visible = counts[SEV_CRITICAL] + counts[SEV_HIGH] + counts[SEV_MEDIUM] +
                  counts[SEV_LOW] + counts[SEV_INFO];
    int actionable = counts[SEV_CRITICAL] + counts[SEV_HIGH] + counts[SEV_MEDIUM] +
                     counts[SEV_LOW];

    for (int i = 0; i < nran; i++)
        printf("[+] %s\n", ran[i]);
    printf("\n");

    print_coverage_text(stats);

    printf("Findings: %d\n", visible);
    printf("Critical: %d\n", counts[SEV_CRITICAL]);
    printf("High:     %d\n", counts[SEV_HIGH]);
    printf("Medium:   %d\n", counts[SEV_MEDIUM]);
    printf("Low:      %d\n", counts[SEV_LOW]);
    printf("Info:     %d\n", counts[SEV_INFO]);
    printf("\n");

    printf("Potential privilege-escalation paths:\n\n");

    const char *reset = o->use_color ? "\033[0m" : "";
    for (size_t i = 0; i < fl->count; i++) {
        const Finding *f = &fl->items[i];
        /* In non-verbose mode, suppress INFO-level noise - same rule the
         * JSON output now applies (fixes.md item 12). */
        if (!o->verbose && f->severity == SEV_INFO) continue;

        const char *col = o->use_color ? severity_color(f->severity) : "";
        printf("%s[%s]%s %s\n", col, severity_name(f->severity), reset, f->title);
        printf("  Check:      %s\n", f->check_id);
        printf("  Category:   %s\n", category_name(f->category));
        printf("  Confidence: %s\n", confidence_name(f->confidence));
        if (f->path[0])
            printf("  Path:       %s\n", f->path);
        if (f->detail[0])
            printf("  Detail:     %s\n", f->detail);
        printf("\n");
    }

    if (actionable == 0) {
        printf("No actionable findings at the selected verbosity.\n");
        if (!o->verbose)
            printf("(Re-run with --verbose to include INFO findings.)\n");
        printf("\n");
    }

    printf("NOTE: Findings are audit results requiring human verification, "
           "not proof of exploitability. A nonzero exit code means findings "
           "were reported - it does not mean exploitation was attempted or "
           "confirmed.\n");
}

/* Minimal JSON string escaper - escapes control characters so output stays
 * valid even for unusual path/system strings (fixes.md item 12). */
static void json_escape(FILE *out, const char *s) {
    for (; *s; s++) {
        switch (*s) {
            case '"':  fputs("\\\"", out); break;
            case '\\': fputs("\\\\", out); break;
            case '\n': fputs("\\n", out);  break;
            case '\r': fputs("\\r", out);  break;
            case '\t': fputs("\\t", out);  break;
            default:
                if ((unsigned char)*s < 0x20 || (unsigned char)*s == 0x7f)
                    fprintf(out, "\\u%04x", (unsigned char)*s);
                else
                    fputc(*s, out);
        }
    }
}

static void report_json(const FindingList *fl, const Options *o, const HostInfo *h,
                        const ScanStats *stats) {
    int counts[SEV_COUNT];
    count_by_severity(fl, o, counts);
    bool partial = (stats->roots_unreadable > 0) || (stats->paths_skipped_unreadable > 0);

    /* Number of findings actually written to the array below; total must match
     * it, otherwise `total` disagrees with `findings | length` and with the
     * severity breakdown whenever INFO items are suppressed. */
    size_t visible = (size_t)(counts[SEV_CRITICAL] + counts[SEV_HIGH] +
                              counts[SEV_MEDIUM] + counts[SEV_LOW] + counts[SEV_INFO]);

    printf("{\n");
    printf("  \"tool\": \"%s\",\n", TOOL_NAME);
    printf("  \"version\": \"%s\",\n", TOOL_VERSION);
    printf("  \"host\": {\n");
    printf("    \"platform\": \"%s\",\n", h->platform);
    printf("    \"elevated\": %s,\n", h->elevated ? "true" : "false");
    printf("    \"user\": \""); json_escape(stdout, h->user); printf("\",\n");
#ifdef _WIN32
    /* Windows has no uid; printing 0 would read as "root". */
    printf("    \"uid\": null,\n");
#else
    printf("    \"uid\": %u,\n", (unsigned)h->uid);
#endif
    printf("    \"distro\": \""); json_escape(stdout, h->distro); printf("\",\n");
    printf("    \"kernel\": \""); json_escape(stdout, h->kernel); printf("\",\n");
    printf("    \"arch\": \""); json_escape(stdout, h->arch); printf("\"\n");
    printf("  },\n");
    printf("  \"coverage\": {\n");
    printf("    \"partial\": %s,\n", partial ? "true" : "false");
    printf("    \"paths_skipped_unreadable\": %d,\n", stats->paths_skipped_unreadable);
    printf("    \"roots_unreadable\": %d,\n", stats->roots_unreadable);
    printf("    \"roots_missing_expected\": %d\n", stats->roots_missing_expected);
    printf("  },\n");
    printf("  \"summary\": {\n");
    printf("    \"total\": %zu,\n", visible);
    printf("    \"critical\": %d,\n", counts[SEV_CRITICAL]);
    printf("    \"high\": %d,\n", counts[SEV_HIGH]);
    printf("    \"medium\": %d,\n", counts[SEV_MEDIUM]);
    printf("    \"low\": %d,\n", counts[SEV_LOW]);
    printf("    \"info\": %d\n", counts[SEV_INFO]);
    printf("  },\n");
    printf("  \"findings\": [\n");

    /* fixes.md item 12: --verbose/INFO filtering must behave the same in
     * JSON as in text; the comma logic uses the count computed above. */
    size_t emitted = 0;
    for (size_t i = 0; i < fl->count; i++) {
        const Finding *f = &fl->items[i];
        if (!o->verbose && f->severity == SEV_INFO) continue;
        emitted++;
        printf("    {\n");
        printf("      \"check_id\": \""); json_escape(stdout, f->check_id); printf("\",\n");
        printf("      \"severity\": \"%s\",\n", severity_name(f->severity));
        printf("      \"confidence\": \"%s\",\n", confidence_name(f->confidence));
        printf("      \"category\": \"%s\",\n", category_name(f->category));
        printf("      \"title\": \""); json_escape(stdout, f->title); printf("\",\n");
        printf("      \"path\": \""); json_escape(stdout, f->path); printf("\",\n");
        printf("      \"detail\": \""); json_escape(stdout, f->detail); printf("\"\n");
        printf("    }%s\n", (emitted < visible) ? "," : "");
    }
    printf("  ]\n");
    printf("}\n");
}

/* ========================================================================
 * Section 6: CLI + main
 * ==================================================================== */

static void usage(FILE *out) {
    fprintf(out,
"%s %s - Privilege Escalation Auditor (read-only, %s)\n"
"\n"
"USAGE:\n"
"  %s [options]\n"
"\n"
"OPTIONS:\n"
"  --help              Show this help and exit\n"
"  --version           Show version and exit\n"
"  --verbose           Include INFO-level findings in output (text and JSON)\n"
"  --json              Emit machine-readable JSON instead of text\n"
"  --no-color          Disable ANSI colors in text output\n"
"  --check <category>  Run only one category (repeatable)\n",
        TOOL_NAME, TOOL_VERSION, TOOL_PLATFORM, TOOL_NAME);

#ifndef _WIN32
    fprintf(out,
"  --sudo-fallback     If /etc/sudoers can't be read directly, fall back to\n"
"                      parsing `sudo -n -l` output. Opt-in: this shells out\n"
"                      to sudo, can fail silently without a cached/non-\n"
"                      interactive grant, and may write to the sudo log.\n");
#endif

    fprintf(out, "\nCATEGORIES:\n");
#ifdef _WIN32
    fprintf(out,
"  system        Host / user / OS build enumeration\n"
"  services      Windows services: unquoted paths, writable images\n"
"  autostart     Run/RunOnce keys, Startup folders, AlwaysInstallElevated\n"
"  filesystem    Writable PATH directories\n"
"  privileges    Dangerous token privileges, integrity level\n");
#else
    fprintf(out,
"  system        Host / user / kernel enumeration\n"
"  suid          SUID / SGID binary scan\n"
"  capabilities  File capability scan (Linux only)\n"
"  sudo          sudoers policy review\n"
"  cron          Scheduled-task review\n"
"  services      systemd unit review\n"
"  processes     Root processes with writable binaries (Linux only)\n"
"  filesystem    Writable PATH dirs / sensitive files / sticky bits\n"
"  package       Kernel-version CVE heuristic (coarse) + package-based checks\n");
#endif

    fprintf(out,
"\nThis tool only reads system state. Findings require human verification\n"
"and are NOT proof of exploitability. A nonzero exit code means findings\n"
"were reported, not that exploitation was attempted or confirmed.\n");
}

static int category_from_name(const char *name, Category *out) {
    for (int c = 0; c < CAT_COUNT; c++) {
        if (strcmp(name, category_name((Category)c)) == 0) {
            *out = (Category)c;
            return 0;
        }
    }
    return -1;
}

/* Scans implemented on this platform. Selecting a category that only exists
 * on the other platform produces an INFO finding rather than a silent no-op. */
static bool category_available(Category c) {
#ifdef _WIN32
    switch (c) {
        case CAT_SYSTEM:
        case CAT_SERVICES:
        case CAT_AUTOSTART:
        case CAT_FILESYSTEM:
        case CAT_PRIVILEGES:
            return true;
        default:
            return false;
    }
#else
    return c != CAT_AUTOSTART && c != CAT_PRIVILEGES;
#endif
}

int main(int argc, char **argv) {
    Options o;
    o.verbose = false;
    o.json = false;
#ifdef _WIN32
    o.use_color = _isatty(_fileno(stdout)) ? true : false;
#else
    o.use_color = isatty(STDOUT_FILENO) ? true : false;
#endif
    o.is_root = false;
    o.sudo_fallback = false;
    o.selected = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--help") == 0 || strcmp(a, "-h") == 0) {
            usage(stdout);
            return 0;
        } else if (strcmp(a, "--version") == 0) {
            printf("%s %s\n", TOOL_NAME, TOOL_VERSION);
            return 0;
        } else if (strcmp(a, "--verbose") == 0 || strcmp(a, "-v") == 0) {
            o.verbose = true;
        } else if (strcmp(a, "--json") == 0) {
            o.json = true;
        } else if (strcmp(a, "--no-color") == 0) {
            o.use_color = false;
        } else if (strcmp(a, "--sudo-fallback") == 0) {
            o.sudo_fallback = true;
        } else if (strcmp(a, "--check") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "%s: --check requires a category\n", TOOL_NAME);
                return 2;
            }
            Category c;
            if (category_from_name(argv[++i], &c) != 0) {
                fprintf(stderr, "%s: unknown category '%s'\n", TOOL_NAME, argv[i]);
                return 2;
            }
            o.selected |= (1UL << c);
        } else {
            fprintf(stderr, "%s: unknown option '%s' (try --help)\n", TOOL_NAME, a);
            return 2;
        }
    }

    HostInfo host;
    gather_host_info(&host);
#ifdef _WIN32
    o.is_root = host.elevated;
#else
    o.is_root = (host.uid == 0);
#endif

    FindingList fl;
    fl_init(&fl);

    ScanStats stats;
    memset(&stats, 0, sizeof(stats));

    /* Track which scans actually ran, for the "[+] ..." banner. */
    const char *ran[CAT_COUNT];
    int nran = 0;

    if (cat_selected(&o, CAT_SYSTEM)) {
        scan_system(&fl, &host, &o);
        ran[nran++] = "System enumeration";
    }
#ifndef _WIN32
    if (cat_selected(&o, CAT_SUID)) {
        scan_suid(&fl, &o, &stats);
        ran[nran++] = "SUID/SGID scan";
    }
    if (cat_selected(&o, CAT_CAPABILITIES)) {
        scan_capabilities(&fl, &o, &stats);
        ran[nran++] = "Capability scan";
    }
    if (cat_selected(&o, CAT_SUDO)) {
        scan_sudo(&fl, &o, &stats);
        ran[nran++] = "Sudo scan";
    }
    if (cat_selected(&o, CAT_CRON)) {
        scan_cron(&fl, &o, &stats);
        ran[nran++] = "Cron scan";
    }
#endif
    if (cat_selected(&o, CAT_SERVICES)) {
        scan_services(&fl, &o, &stats);
        ran[nran++] = "Service scan";
    }
#ifndef _WIN32
    if (cat_selected(&o, CAT_PROCESSES)) {
        scan_processes(&fl, &o);
        ran[nran++] = "Process scan";
    }
#endif
    if (cat_selected(&o, CAT_FILESYSTEM)) {
        scan_filesystem(&fl, &o);
        ran[nran++] = "Filesystem scan";
    }
#ifdef _WIN32
    if (cat_selected(&o, CAT_AUTOSTART)) {
        scan_autostart(&fl, &o);
        ran[nran++] = "Autostart scan";
    }
    if (cat_selected(&o, CAT_PRIVILEGES)) {
        scan_privileges(&fl, &o);
        ran[nran++] = "Privilege scan";
    }
#else
    if (cat_selected(&o, CAT_PACKAGE)) {
        scan_package(&fl, &host, &o);
        ran[nran++] = "Package/CVE scan";
    }
#endif

    /* A category selected with --check that only exists on the other platform. */
    for (int c = 0; c < CAT_COUNT; c++) {
        if (!cat_selected(&o, (Category)c) || category_available((Category)c)) continue;
#ifdef _WIN32
        const char *other = "Linux";
#else
        const char *other = "Windows";
#endif
        add_finding(&fl, "platform.not_applicable", (Category)c, SEV_INFO, CONF_CONFIRMED,
                    "Scan not applicable on this platform", NULL,
                    "The '%s' scan is implemented in the %s build only.",
                    category_name((Category)c), other);
    }

#ifdef _WIN32
    /* A DACL check that could not run is not evidence of safety. */
    win_report_acl_gaps(&fl);
#endif

    sort_findings(&fl);

    if (o.json) {
        report_json(&fl, &o, &host, &stats);
    } else {
        print_banner(&host);
        report_text(&fl, &o, &stats, ran, nran);
    }

    /* Exit code reflects worst severity found (useful in CI / scripts):
     *   0 = nothing notable, 1 = low/medium, 2 = high, 3 = critical.
     * This does NOT mean exploitation was attempted or confirmed - see
     * --help / README for the full exit-code contract. */
    int counts[SEV_COUNT];
    count_by_severity(&fl, &o, counts);
    int rc = 0;
    if (counts[SEV_CRITICAL]) rc = 3;
    else if (counts[SEV_HIGH]) rc = 2;
    else if (counts[SEV_MEDIUM] || counts[SEV_LOW]) rc = 1;

    fl_free(&fl);
    return rc;
}

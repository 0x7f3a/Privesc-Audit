/*
 * False-positive matrix for privesc-auditor.
 *
 * Every check is driven directly against a synthetic host state - a temporary
 * PATH, temporary crontab lines, temporary systemd units, synthetic stat
 * buffers and capability blobs - so "this configuration must produce nothing"
 * becomes an executable assertion instead of a promise. Nothing outside the
 * temporary directory is touched, and no check is ever executed as a command.
 *
 * Included from main.c the same way tests/unit.c is: main() is renamed and the
 * internal scanners are called directly.
 */

#define main tool_main
#include "../main.c"
#undef main

static int        failures;
static FindingList fl;
static Options    opt;

static void reset(void) {
    fl_free(&fl);
    fl_init(&fl);
}

static int count_id(const char *id) {
    int n = 0;
    for (size_t i = 0; i < fl.count; i++)
        if (strcmp(fl.items[i].check_id, id) == 0) n++;
    return n;
}

static Severity worst(void) {
    Severity w = SEV_INFO;
    for (size_t i = 0; i < fl.count; i++)
        if (fl.items[i].severity > w) w = fl.items[i].severity;
    return w;
}

static void dump(const char *what) {
    printf("        case: %s\n", what);
    if (fl.count == 0) printf("        (no findings)\n");
    for (size_t i = 0; i < fl.count; i++)
        printf("        %-9s %-34s %s\n", severity_name(fl.items[i].severity),
               fl.items[i].check_id, fl.items[i].path);
}

/* No finding at all. */
static void expect_none(const char *what) {
    if (fl.count == 0) {
        printf("  ok    %s\n", what);
        return;
    }
    printf("  FAIL  %s: expected no findings\n", what);
    dump(what);
    failures++;
}

static void expect_within(const char *what, Severity ceiling) {
    if (worst() <= ceiling) {
        printf("  ok    %s\n", what);
        return;
    }
    printf("  FAIL  %s: expected nothing above %s\n", what, severity_name(ceiling));
    dump(what);
    failures++;
}

static void expect_one(const char *id, Severity sev, const char *what) {
    if (fl.count >= 1 && (size_t)count_id(id) == fl.count &&
        fl.items[0].severity == sev) {
        printf("  ok    %s\n", what);
        return;
    }
    printf("  FAIL  %s: expected exactly one %s at %s\n", what, id, severity_name(sev));
    dump(what);
    failures++;
}

static void expect_only_ids(const char *what, const char *id1, const char *id2) {
    for (size_t i = 0; i < fl.count; i++) {
        if (strcmp(fl.items[i].check_id, id1) != 0 &&
            (!id2 || strcmp(fl.items[i].check_id, id2) != 0)) {
            printf("  FAIL  %s: unexpected %s\n", what, fl.items[i].check_id);
            dump(what);
            failures++;
            return;
        }
    }
    printf("  ok    %s\n", what);
}

static void mkdir_ok(const char *p, mode_t mode) {
    if (mkdir(p, mode) != 0) {
        fprintf(stderr, "fp: mkdir %s failed\n", p);
        exit(2);
    }
}

static void write_file(const char *p, const char *body, mode_t mode) {
    FILE *fp = fopen(p, "w");
    if (!fp) {
        fprintf(stderr, "fp: cannot write %s\n", p);
        exit(2);
    }
    fputs(body, fp);
    fclose(fp);
    chmod(p, mode);
}

int main(void) {
    char root[] = "/tmp/pafpXXXXXX";
    if (!mkdtemp(root)) {
        fprintf(stderr, "fp: mkdtemp failed\n");
        return 2;
    }

    /* The PATH cases replace PATH with synthetic values, which would leave the
     * cleanup's `rm` unresolvable; keep the real one to restore first. */
    char saved_path[4096];
    const char *real_path = getenv("PATH");
    snprintf(saved_path, sizeof saved_path, "%s",
             (real_path && *real_path) ? real_path : "/usr/bin:/bin");

    char outside[512], notdir[512], dangling[512], unit_dir[512];
    char unit_writable_dir[512], wp[512], unit[512], unit_user[512];
    char unit_quoted[512], unit_pre[512], unit_timer[512], unit_clean[512];
    snprintf(outside, sizeof outside, "%s/outside", root);
    snprintf(notdir, sizeof notdir, "%s/notadir", root);
    snprintf(dangling, sizeof dangling, "%s/dangling", root);
    snprintf(unit_dir, sizeof unit_dir, "%s/units", root);
    snprintf(unit_writable_dir, sizeof unit_writable_dir, "%s/units-writable", root);
    snprintf(wp, sizeof wp, "%s/wp.sh", root);
    snprintf(unit, sizeof unit, "%s/units/a.service", root);
    snprintf(unit_user, sizeof unit_user, "%s/units/b.service", root);
    snprintf(unit_quoted, sizeof unit_quoted, "%s/units/c.service", root);
    snprintf(unit_pre, sizeof unit_pre, "%s/units/d.service", root);
    snprintf(unit_timer, sizeof unit_timer, "%s/units/e.timer", root);
    snprintf(unit_clean, sizeof unit_clean, "%s/units/f.service", root);

    mkdir_ok(outside, 0755);
    mkdir_ok(unit_dir, 0755);
    mkdir_ok(unit_writable_dir, 0755);
    write_file(notdir, "not a directory\n", 0644);
    write_file(wp, "#!/bin/sh\ntrue\n", 0755);

    /* Unit files must not be writable themselves, or svc_cb stops at the
     * writable-unit finding and never looks at the executable. */
    char body[1024];
    snprintf(body, sizeof body, "[Service]\nExecStart=%s\n", wp);
    write_file(unit, body, 0444);
    snprintf(body, sizeof body, "[Service]\nUser=www-data\nExecStart=%s\n", wp);
    write_file(unit_user, body, 0444);
    snprintf(body, sizeof body, "[Service]\nExecStart=\"%s\"\n", wp);
    write_file(unit_quoted, body, 0444);
    snprintf(body, sizeof body, "[Service]\nExecStart=/bin/true\nExecStartPre=%s\n", wp);
    write_file(unit_pre, body, 0444);
    write_file(unit_timer, "[Timer]\nOnCalendar=daily\n", 0444);
    write_file(unit_clean, "[Service]\nExecStart=/bin/true\n", 0444);
    chmod(unit_dir, 0555); /* directory not writable: only the image check runs */

    memset(&opt, 0, sizeof opt);
    opt.use_color = false;
    fl_init(&fl);

    /* ------------------------------------------------------------ PATH */
    printf("\nPATH\n");

    char home_bin[512];
    const char *home = getenv("HOME");
    if (home && home[0] == '/' && home[1]) {
        snprintf(home_bin, sizeof home_bin, "%s/pafp-bin", home);
        mkdir_ok(home_bin, 0755);

        char value[2048];
        snprintf(value, sizeof value, "%s:%s:/usr/bin", home_bin, outside);
        setenv("PATH", value, 1);
        reset();
        scan_filesystem(&fl, &opt);
        if (count_id("fs.path_writable_user_profile") == 1 &&
            count_id("fs.path_writable") == 1 && fl.count == 2) {
            printf("  ok    in-profile directory is aggregated into one LOW, outside one stays HIGH\n");
        } else {
            printf("  FAIL  in-profile/outside PATH classification\n");
            dump("PATH=home+outside");
            failures++;
        }
        if (fl.items[fl.count - 1].severity <= SEV_LOW)
            printf("  ok    the aggregated profile finding is LOW\n");
        else {
            printf("  FAIL  aggregated profile finding is %s\n",
                   severity_name(fl.items[fl.count - 1].severity));
            failures++;
        }

        snprintf(value, sizeof value, "%s:%s:/usr/bin", home_bin, home_bin);
        setenv("PATH", value, 1);
        reset();
        scan_filesystem(&fl, &opt);
        expect_one("fs.path_writable_user_profile", SEV_LOW,
                   "a directory repeated in PATH is still one finding");

        snprintf(value, sizeof value, "%s/:%s", home_bin, home_bin);
        setenv("PATH", value, 1);
        reset();
        scan_filesystem(&fl, &opt);
        expect_one("fs.path_writable_user_profile", SEV_LOW,
                   "the same directory with and without a trailing slash is one finding");

        rmdir(home_bin);
    }

    unsetenv("PATH");
    reset();
    scan_filesystem(&fl, &opt);
    expect_one("fs.path_unset", SEV_INFO, "an unset PATH is a coverage note, not silence");

    setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 1);
    reset();
    scan_filesystem(&fl, &opt);
    expect_none("a stock PATH produces no filesystem findings");

    char value[2048];
    snprintf(value, sizeof value, "/usr/bin:%s", notdir);
    setenv("PATH", value, 1);
    reset();
    scan_filesystem(&fl, &opt);
    expect_one("fs.path_not_dir", SEV_LOW, "a file on PATH is reported once, as LOW");

    snprintf(value, sizeof value, "/usr/bin:%s", dangling);
    setenv("PATH", value, 1);
    reset();
    scan_filesystem(&fl, &opt);
    expect_none("a dangling PATH entry is not reported");

    setenv("PATH", "/usr/bin::/bin", 1);
    reset();
    scan_filesystem(&fl, &opt);
    expect_one("fs.path_empty_component", SEV_MEDIUM, "an empty PATH entry is reported once");

    setenv("PATH", ".:/usr/bin", 1);
    reset();
    scan_filesystem(&fl, &opt);
    expect_one("fs.path_relative", SEV_MEDIUM, "a relative PATH entry is MEDIUM");

    {
        char big[9000];
        size_t used = 0;
        big[0] = '\0';
        while (used + 64 < sizeof big) {
            int w = snprintf(big + used, sizeof big - used, "/tmp/%060d:", (int)used);
            if (w < 0) break;
            used += (size_t)w;
        }
        setenv("PATH", big, 1);
        reset();
        scan_filesystem(&fl, &opt);
        if (count_id("fs.path_overlong") == 1 && count_id("fs.path_writable") == 0)
            printf("  ok    an overlong PATH is reported instead of silently truncated\n");
        else {
            printf("  FAIL  overlong PATH not reported\n");
            dump("overlong PATH");
            failures++;
        }
    }

    /* ----------------------------------------------------------- sudo */
    printf("\nsudoers\n");
    {
        static const struct {
            const char *line;
            const char *id;   /* NULL = no finding */
            Severity    sev;
            const char *what;
        } cases[] = {
            { "%sudo   ALL=(ALL:ALL) ALL", NULL, SEV_INFO,
              "a plain sudoers rule produces nothing" },
            { "%sudo ALL=(ALL:ALL) NOPASSWD: /usr/bin/apt", "sudo.nopasswd", SEV_MEDIUM,
              "a rule scoped to one binary is MEDIUM, not HIGH" },
            { "root ALL=(ALL:ALL) NOPASSWD: ALL", "sudo.nopasswd", SEV_HIGH,
              "NOPASSWD: ALL is HIGH" },
            { "%ops ALL=(root) SETENV: NOPASSWD: ALL", "sudo.nopasswd", SEV_HIGH,
              "tags before ALL do not hide a blank cheque" },
            { "deploy ALL=(root) NOPASSWD: /bin/systemctl restart app", "sudo.nopasswd",
              SEV_MEDIUM, "a systemctl rule is MEDIUM" },
            { "%dev ALL=(ALL) PASSWD: ALL", NULL, SEV_INFO,
              "PASSWD rules are not findings" },
            { "Defaults secure_path=\"/usr/local/sbin:/usr/local/bin:/usr/bin\"", NULL,
              SEV_INFO, "secure_path is not a finding" },
            { "Cmnd_Alias PKG = /usr/bin/apt, /usr/bin/dpkg", NULL, SEV_INFO,
              "a Cmnd_Alias definition is not a finding" },
            { "Defaults env_keep += \"LD_PRELOAD\"", "sudo.env_keep_loader", SEV_HIGH,
              "keeping LD_PRELOAD is HIGH" },
            { "Defaults!sudoedit env_keep -= \"LD_PRELOAD\"", NULL, SEV_INFO,
              "removing LD_PRELOAD from env_keep is not a finding" },
            { "%helpdesk ALL=(ALL) !authenticate", "sudo.no_authenticate", SEV_MEDIUM,
              "!authenticate is MEDIUM" },
            { "Defaults:%wheel !requiretty", NULL, SEV_INFO,
              "!requiretty alone is not reported" },
            { NULL, NULL, SEV_INFO, NULL }
        };
        for (int i = 0; cases[i].line; i++) {
            reset();
            inspect_sudo_line(&fl, "/etc/sudoers", cases[i].line);
            if (!cases[i].id) {
                expect_none(cases[i].what);
            } else {
                expect_one(cases[i].id, cases[i].sev, cases[i].what);
            }
        }
    }

    /* ----------------------------------------------------------- cron */
    printf("\ncron\n");
    {
        struct {
            const char *line;
            bool has_user;
            Severity    worst_ok;   /* findings above this are a failure */
            const char *what;
        } cases[] = {
            { "17 *\t* * *\troot    cd / && run-parts --report /etc/cron.hourly", true,
              SEV_INFO, "stock Debian crontab line (run-parts) is not actionable" },
            { "0 3 * * * root /usr/local/bin/backup.sh", true, SEV_INFO,
              "a normal absolute cron command is not reported" },
            { "@reboot root /opt/app/start.sh", true, SEV_INFO,
              "@reboot with an absolute command is not reported" },
            { "*/5 * * * * www-data /usr/share/app/worker.py", true, SEV_INFO,
              "per-user app cron job is not reported" },
            { "0 * * * * root test -x /usr/bin/foo || /usr/bin/bar", true, SEV_INFO,
              "shell tests and fallback commands are not reported" },
            { "0 4 * * * root flock -n /run/lock/x.lock -c \"/usr/bin/foo\"", true,
              SEV_INFO, "flock is treated as a wrapper" },
            { "MAILTO=\"\"", true, SEV_INFO, "an environment assignment is not a job" },
            { "SHELL=/bin/sh", true, SEV_INFO, "SHELL= is not a job" },
            { "0 1 * * root /bin/x", true, SEV_INFO,
              "a malformed schedule is an INFO note, not a finding" },
            { "0 1 * * * root %SHORTENED", true, SEV_INFO,
              "a percent-expanded argument is not a relative command finding" },
            { NULL, false, SEV_INFO, NULL }
        };
        for (int i = 0; cases[i].line; i++) {
            char line[1024];
            snprintf(line, sizeof line, "%s", cases[i].line);
            reset();
            inspect_cron_entry(&fl, &opt, "/etc/crontab", cases[i].has_user, line);
            if (worst() <= cases[i].worst_ok) {
                printf("  ok    %s\n", cases[i].what);
            } else {
                printf("  FAIL  %s\n", cases[i].what);
                dump(cases[i].line);
                failures++;
            }
        }

        char line[1024];
        snprintf(line, sizeof line, "0 1 * * * root %s", wp);
        reset();
        inspect_cron_entry(&fl, &opt, "/etc/crontab", true, line);
        expect_only_ids("a writable absolute cron target is still HIGH",
                        "cron.writable_ref", NULL);

        snprintf(line, sizeof line, "0 2 * * * root sh -c '%s'", wp);
        reset();
        inspect_cron_entry(&fl, &opt, "/etc/crontab", true, line);
        expect_only_ids("a writable target behind sh -c is still found",
                        "cron.writable_ref", NULL);

        snprintf(line, sizeof line, "0 3 * * * root /etc/passwd");
        reset();
        inspect_cron_entry(&fl, &opt, "/etc/crontab", true, line);
        expect_none("a root-owned non-writable cron target is not reported");
    }

    /* -------------------------------------------------------- services */
    printf("\nsystemd units\n");
    {
        SvcCtx ctx = { &fl, &opt };
        struct stat st;

        reset();
        if (stat(unit, &st) == 0) svc_cb(unit, &st, &ctx);
        expect_one("svc.writable_exec_root", SEV_HIGH,
                   "a writable ExecStart without User= runs as root (HIGH)");

        reset();
        if (stat(unit_user, &st) == 0) svc_cb(unit_user, &st, &ctx);
        expect_one("svc.writable_exec_nonroot", SEV_MEDIUM,
                   "a writable ExecStart with User= is MEDIUM");

        reset();
        if (stat(unit_quoted, &st) == 0) svc_cb(unit_quoted, &st, &ctx);
        expect_one("svc.writable_exec_root", SEV_HIGH,
                   "a quoted ExecStart is parsed, not skipped");

        reset();
        if (stat(unit_pre, &st) == 0) svc_cb(unit_pre, &st, &ctx);
        expect_one("svc.writable_exec_root", SEV_HIGH,
                   "a writable ExecStartPre is reported too");

        reset();
        if (stat(unit_clean, &st) == 0) svc_cb(unit_clean, &st, &ctx);
        expect_none("a unit running a non-writable binary is not reported");

        reset();
        if (stat(unit_timer, &st) == 0) svc_cb(unit_timer, &st, &ctx);
        expect_none("a timer with no Exec is not reported");

        /* Dropping an executable into a writable unit directory is the real
         * primitive; the file itself is never writable there. */
        char dropped[768];
        snprintf(dropped, sizeof dropped, "%s/g.service", unit_writable_dir);
        write_file(dropped, "[Service]\nExecStart=/bin/true\n", 0444);
        reset();
        if (stat(dropped, &st) == 0) svc_cb(dropped, &st, &ctx);
        expect_one("svc.writable_unit_dir", SEV_HIGH,
                   "a unit in a writable directory is HIGH");
        unlink(dropped);
    }

    /* -------------------------------------------------- SUID / SGID */
    printf("\nSUID / SGID\n");
    {
        SuidCtx ctx = { &fl, &opt };
        struct stat st;

        memset(&st, 0, sizeof st);
        st.st_uid = 0;
        st.st_gid = 0;
        st.st_mode = S_IFREG | S_ISUID | S_IXUSR | S_IRUSR | S_IWUSR;

        reset();
        suid_cb("/bin/su", &st, &ctx);
        expect_one("suid.baseline", SEV_INFO, "a stock SUID binary stays INFO");

        reset();
        suid_cb("/usr/bin/find", &st, &ctx);
        expect_one("suid.gtfobins", SEV_HIGH,
                   "a GTFOBins SUID binary is HIGH (not also SUID/MEDIUM)");

        reset();
        suid_cb("/opt/pafp-tool", &st, &ctx);
        expect_one("suid.nonstandard", SEV_MEDIUM,
                   "an unknown SUID binary is MEDIUM");

        st.st_mode = S_IFREG | S_IXUSR | S_IRUSR;
        reset();
        suid_cb("/usr/bin/true", &st, &ctx);
        expect_none("a binary without SUID/SGID is not reported");

        memset(&st, 0, sizeof st);
        st.st_uid = 0;
        st.st_gid = 0;
        st.st_mode = S_IFREG | S_ISGID | S_IXUSR | S_IRUSR;
        reset();
        suid_cb("/usr/bin/chage", &st, &ctx);
        expect_one("suid.sgid_baseline", SEV_INFO, "a stock SGID binary stays INFO");

        reset();
        suid_cb("/usr/bin/pafp-sgid", &st, &ctx);
        expect_one("suid.sgid_root", SEV_MEDIUM,
                   "an unknown root-owned SGID binary is MEDIUM");

        st.st_uid = 1000;
        reset();
        suid_cb("/usr/bin/pafp-suid", &st, &ctx);
        if (count_id("suid.nonroot_suid") == 0)
            printf("  ok    an SGID-only binary is not reported as non-root SUID\n");
        else {
            printf("  FAIL  SGID-only binary reported as non-root SUID\n");
            dump("SGID only");
            failures++;
        }
    }

    /* ---------------------------------------------------- capabilities */
    printf("\ncapabilities\n");
    {
        unsigned char v2[20] = { 0, 0, 0, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        unsigned long long perm = 0;

        v2[4] = 0x80;                    /* low word: bit 7 = cap_setuid */
        v2[12] = 0x80;                   /* high word: bit 7 = overall bit 39 */
        if (cap_decode(v2, sizeof v2, &perm) && perm == ((1ULL << 7) | (1ULL << 39)))
            printf("  ok    a v2 blob decodes both permitted words\n");
        else {
            printf("  FAIL  v2 blob decoded 0x%llx\n", perm);
            failures++;
        }

        unsigned char v1[12] = { 0, 0, 0, 0x01, 1, 0, 0, 0, 0, 0, 0, 0 };
        if (cap_decode(v1, sizeof v1, &perm) && perm == 1ULL)
            printf("  ok    a v1 blob decodes only the low word\n");
        else {
            printf("  FAIL  v1 blob decoded 0x%llx\n", perm);
            failures++;
        }

        v2[3] = 0x99;
        if (!cap_decode(v2, sizeof v2, &perm) && perm == 0)
            printf("  ok    a foreign xattr is rejected, not decoded\n");
        else {
            printf("  FAIL  a foreign xattr was decoded\n");
            failures++;
        }
        v2[3] = 0x02;

        if (!cap_decode(v2, 8, &perm))
            printf("  ok    a truncated blob is rejected\n");
        else {
            printf("  FAIL  a truncated blob was decoded\n");
            failures++;
        }

        reset();
        scan_capabilities(&fl, &opt, &(ScanStats){ 0, 0, 0 });
        if (worst() <= SEV_INFO)
            printf("  ok    non-escalating capabilities (cap_net_raw on ping) stay INFO\n");
        else {
            printf("  FAIL  a non-escalating capability was rated above INFO\n");
            dump("capabilities");
            failures++;
        }
    }

    /* --------------------------------------------- profile path matching */
    printf("\nprofile matching\n");
    {
        const char *saved = getenv("HOME");
        char copy[512] = "";
        if (saved) snprintf(copy, sizeof copy, "%s", saved);

        setenv("HOME", "/", 1);
        if (!path_in_user_profile("/usr/bin"))
            printf("  ok    HOME=/ does not swallow every absolute path\n");
        else {
            printf("  FAIL  HOME=/ matched /usr/bin\n");
            failures++;
        }

        /* With HOME unset the password database still knows the home
         * directory; not using it turned the account's own tools into a HIGH. */
        struct passwd *pw = getpwuid(getuid());
        unsetenv("HOME");
        if (pw && pw->pw_dir) {
            char inside[512];
            snprintf(inside, sizeof inside, "%s/pafp-inside", pw->pw_dir);
            if (path_in_user_profile(inside))
                printf("  ok    an unset HOME falls back to the passwd home directory\n");
            else {
                printf("  FAIL  an unset HOME lost the profile match\n");
                failures++;
            }
        }
        if (!path_in_user_profile("/usr/bin"))
            printf("  ok    an unset HOME still does not match system paths\n");
        else {
            printf("  FAIL  an unset HOME matched /usr/bin\n");
            failures++;
        }

        if (copy[0]) setenv("HOME", copy, 1);
    }

    /* ------------------------------------------------- root auditor */
    printf("\nroot auditor\n");
    {
        Options root_opt;
        memset(&root_opt, 0, sizeof root_opt);
        root_opt.is_root = true;

        char value[2048];
        snprintf(value, sizeof value, "/usr/bin:%s", outside);
        setenv("PATH", value, 1);
        reset();
        scan_filesystem(&fl, &root_opt);
        expect_within("writable PATH directories are INFO for a root auditor", SEV_INFO);

        char line[1024];
        snprintf(line, sizeof line, "0 1 * * * root %s", wp);
        reset();
        inspect_cron_entry(&fl, &root_opt, "/etc/crontab", true, line);
        expect_within("a writable cron target is INFO for a root auditor", SEV_INFO);

        SvcCtx rctx = { &fl, &root_opt };
        struct stat st;
        reset();
        if (stat(unit, &st) == 0) svc_cb(unit, &st, &rctx);
        expect_within("a writable ExecStart is INFO for a root auditor", SEV_INFO);

        memset(&st, 0, sizeof st);
        st.st_uid = 0;
        st.st_mode = S_IFREG | S_ISUID | S_IXUSR | S_IRUSR | S_IWUSR;
        SuidCtx rsuid = { &fl, &root_opt };
        reset();
        suid_cb(wp, &st, &rsuid);
        expect_within("root's own write access to a SUID binary is INFO, not CRITICAL",
                      SEV_INFO);

        /* The condition did not change, only who is looking: for a normal user
         * the same binary is the top severity. */
        SuidCtx usuid = { &fl, &opt };
        reset();
        suid_cb(wp, &st, &usuid);
        expect_one("suid.writable_root_owned", SEV_CRITICAL,
                   "the same writable root-owned SUID binary is CRITICAL for a user");
    }

    chmod(unit_dir, 0755);
    setenv("PATH", saved_path, 1);
    char cmd[600];
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", root);
    if (system(cmd) != 0) fprintf(stderr, "fp: cleanup failed\n");

    printf("\n");
    if (failures == 0) {
        printf("all false-positive cases passed\n");
        return 0;
    }
    printf("%d case(s) failed\n", failures);
    return 1;
}

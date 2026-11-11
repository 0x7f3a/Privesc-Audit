/*
 * Unit tests for the pure helpers in main.c.
 *
 * main.c is a single translation unit, so the test includes it with main()
 * renamed and then drives the internal functions directly. The Windows
 * path/service logic is built and exercised on POSIX on purpose: it is the
 * service-hijack heuristic, and it is otherwise untestable without a Windows
 * host. Everything here is read-only string work - no system state is touched.
 */

#define main tool_main
#include "../main.c"
#undef main

static int failures;

static void check(bool cond, const char *what) {
    if (cond) {
        printf("  ok    %s\n", what);
        return;
    }
    printf("  FAIL  %s\n", what);
    failures++;
}

static void check_str(const char *want, const char *got, const char *what) {
    if (strcmp(want, got) == 0) {
        printf("  ok    %s\n", what);
        return;
    }
    printf("  FAIL  %s (want \"%s\", got \"%s\")\n", what, want, got);
    failures++;
}

int main(void) {
    char buf[1024];

    printf("win_image_path\n");
    check(win_image_path("\"C:\\Program Files\\App\\svc.exe\" -k", buf, sizeof buf) &&
              strcmp(buf, "C:\\Program Files\\App\\svc.exe") == 0,
          "quoted image stops at the closing quote");
    check(win_image_path("C:\\Program Files\\App\\svc.exe -k netsvcs", buf, sizeof buf) &&
              strcmp(buf, "C:\\Program Files\\App\\svc.exe") == 0,
          "unquoted image keeps the whole path, not the first token");
    check(win_image_path("C:\\Windows\\system32\\svchost.exe -k netsvcs", buf, sizeof buf) &&
              strcmp(buf, "C:\\Windows\\system32\\svchost.exe") == 0,
          "system32 image without spaces");
    check(win_image_path("C:\\dir\\foo.exe.d\\bar.exe", buf, sizeof buf) &&
              strcmp(buf, "C:\\dir\\foo.exe.d\\bar.exe") == 0,
          "a directory named *.exe.d does not end the image");

    printf("win_unquoted_ambiguous\n");
    check(win_unquoted_ambiguous("C:\\Program Files\\App\\svc.exe"),
          "unquoted path with a space before .exe is ambiguous");
    check(!win_unquoted_ambiguous("\"C:\\Program Files\\App\\svc.exe\""),
          "quoted path is not ambiguous");
    check(!win_unquoted_ambiguous("C:\\Windows\\system32\\svchost.exe -k netsvcs"),
          "extension before the first space is unambiguous");

    printf("win_unquoted_candidate\n");
    check(win_unquoted_candidate("C:\\Program Files\\App\\svc.exe -k", 0, buf, sizeof buf) &&
              strcmp(buf, "C:\\Program.exe") == 0,
          "candidate 0 is the text up to the first space plus .exe");
    check(win_unquoted_candidate("C:\\Program Files\\App Dir\\svc.exe -k", 1, buf, sizeof buf) &&
              strcmp(buf, "C:\\Program Files\\App.exe") == 0,
          "candidate 1 is the next space boundary plus .exe");
    check(win_unquoted_candidate("C:\\Program Files\\App Dir\\svc.exe -k", 2, buf, sizeof buf) &&
              strcmp(buf, "C:\\Program Files\\App Dir\\svc.exe") == 0,
          "the service's own image is the last candidate");
    check(!win_unquoted_candidate("C:\\Program Files\\App\\svc.exe", 2, buf, sizeof buf),
          "the candidate list ends where the spaces end");

    printf("win_dirname\n");
    check(win_dirname("C:\\a\\b.exe", buf, sizeof buf) && strcmp(buf, "C:\\a\\") == 0,
          "dirname keeps the trailing separator");
    check(!win_dirname("svc.exe", buf, sizeof buf), "a bare name has no directory");

    printf("sudo rule parsing\n");
    check(sudo_rule_commands_all("root ALL=(ALL:ALL) NOPASSWD: ALL"),
          "NOPASSWD: ALL grants every command");
    check(!sudo_rule_commands_all("%sudo ALL=(ALL:ALL) NOPASSWD: /usr/bin/apt"),
          "a runas (ALL) field alone is not a blank cheque");
    check(!sudo_rule_commands_all("deploy ALL=(root) NOPASSWD: /bin/systemctl restart app"),
          "a scoped command is not ALL");
    check(sudo_rule_commands_all("ops ALL=(root) SETENV: NOPASSWD: ALL"),
          "tags before ALL are skipped");
    check(!sudo_rule_commands_all("root ALL=(ALL) /usr/bin/ls"),
          "a rule without NOPASSWD is irrelevant but still not ALL");

    printf("sudo severity\n");
    {
        FindingList fl;
        fl_init(&fl);
        inspect_sudo_line(&fl, "/etc/sudoers", "%sudo ALL=(ALL:ALL) NOPASSWD: /usr/bin/apt");
        check(fl.count == 1 && fl.items[0].severity == SEV_MEDIUM,
              "a scoped NOPASSWD rule is MEDIUM, not HIGH");
        fl_free(&fl);

        fl_init(&fl);
        inspect_sudo_line(&fl, "/etc/sudoers", "root ALL=(ALL:ALL) NOPASSWD: ALL");
        check(fl.count == 1 && fl.items[0].severity == SEV_HIGH,
              "NOPASSWD: ALL is HIGH");
        fl_free(&fl);
    }

    printf("path_in_user_profile\n");
    {
        const char *home = getenv("HOME");
        if (home && *home) {
            char inside[512], sibling[512];
            snprintf(inside, sizeof inside, "%s/bin", home);
            snprintf(sibling, sizeof sibling, "%s2/bin", home);
            check(path_in_user_profile(inside), "a directory inside HOME matches");
            check(!path_in_user_profile(sibling),
                  "a sibling whose name merely starts with HOME does not");
        } else {
            printf("  skip  HOME is unset\n");
        }
    }

    printf("next steps\n");
    {
        Finding f;
        char acts[ACTION_MAX][ACTION_LEN];

        memset(&f, 0, sizeof f);
        snprintf(f.check_id, sizeof f.check_id, "suid.gtfobins");
        snprintf(f.path, sizeof f.path, "/usr/bin/find");
        int n = suggest_actions(&f, acts, ACTION_MAX);
        check(n == 2 && strstr(acts[0], "ls -ld") && strstr(acts[1], "GTFOBins") &&
                  strstr(acts[1], "-p"),
              "a known SUID binary gets the confirm command plus the SUID payload");

        snprintf(f.check_id, sizeof f.check_id, "suid.nonstandard");
        snprintf(f.path, sizeof f.path, "/opt/weird-helper");
        n = suggest_actions(&f, acts, ACTION_MAX);
        check(n == 1 && strstr(acts[0], "ls -ld") != NULL,
              "an unknown binary gets only the confirm command");

        memset(&f, 0, sizeof f);
        snprintf(f.check_id, sizeof f.check_id, "cap.cap_setuid");
        snprintf(f.path, sizeof f.path, "/opt/tools/helper");
        n = suggest_actions(&f, acts, ACTION_MAX);
        check(n == 3 && strstr(acts[1], "getcap") && strstr(acts[2], "uid 0"),
              "a capability finding gets getcap plus what the capability buys");
    }

    printf("json_escape\n");
    {
        FILE *fp = tmpfile();
        if (!fp) {
            printf("  skip  tmpfile() unavailable\n");
        } else {
            char got[64] = "";
            json_escape(fp, "a\"b\\c\nd\x01");
            fflush(fp);
            long len = ftell(fp);
            rewind(fp);
            if (len > 0 && (size_t)len < sizeof got) {
                size_t rd = fread(got, 1, (size_t)len, fp);
                got[rd] = '\0';
            }
            fclose(fp);
            check_str("a\\\"b\\\\c\\nd\\u0001", got,
                      "quotes, backslashes, newlines and control bytes escape");
        }
    }

    printf("\n");
    if (failures == 0) {
        printf("all unit tests passed\n");
        return 0;
    }
    printf("%d unit test(s) failed\n", failures);
    return 1;
}

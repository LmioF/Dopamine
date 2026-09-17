#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static const char *scenario;
static unsigned failures, spawnCalls;
static int writer = -1, childWriter = -1, donorArgc;
static char *donorArgv[64];
static bool gDyldHookLog;
static int observedCount = -1;
static gid_t observedGroups[NGROUPS_MAX];
static void run_donor(int argc, char **argv);
static bool is(const char *name) { return !strcmp(scenario, name); }
static void check(bool condition, const char *message)
{
    if (!condition) { fprintf(stderr, "FAIL: %s\n", message); failures++; }
}
static int simple_atoi(const char *string) { return atoi(string); }
static char *_simple_getenv(char **env, const char *name) { return "1"; }
static int _simple_dprintf(int fd, const char *format, ...) { return 0; }
static int fixture_setgroups(int count, const gid_t *groups)
{
    observedCount = count;
    if (count < 0 || count > NGROUPS_MAX || !groups) { errno = EINVAL; return -1; }
    memcpy(observedGroups, groups, count * sizeof(gid_t));
    return 0;
}
static ssize_t fixture_write(int fd, const void *data, size_t size)
{
    check(fd == 3 && childWriter >= 0 && size == 1, "donor writes its exact result marker");
    return write(childWriter, data, size);
}
static int fixture_dup(posix_spawn_file_actions_t *actions, int source, int destination)
{
    writer = source;
    return posix_spawn_file_actions_adddup2(actions, source, destination);
}
static int fixture_spawn(pid_t *pid, const char *path, const posix_spawn_file_actions_t *actions,
    const posix_spawnattr_t *attributes, char *const argv[], char *const env[])
{
    spawnCalls++;
    *pid = 4242;
    childWriter = dup(writer);
    if (childWriter < 0) abort();
    for (donorArgc = 0; argv[donorArgc]; donorArgc++) {
        if (donorArgc >= 63) abort();
        donorArgv[donorArgc] = strdup(argv[donorArgc]);
    }
    donorArgv[donorArgc] = NULL;
    for (int i = 1; i < donorArgc; i++) {
        if (!strcmp(donorArgv[i], "--ngroups")) {
            if (is("wire-missing-count")) {
                free(donorArgv[i]); free(donorArgv[i + 1]);
                memmove(donorArgv + i, donorArgv + i + 2, (donorArgc - i - 1) * sizeof(char *));
                donorArgc -= 2;
            } else if (is("wire-bad-count")) {
                free(donorArgv[i + 1]); donorArgv[i + 1] = strdup("1junk");
            }
            break;
        }
    }
    if (is("wire-short-groups")) {
        for (int i = 1; i < donorArgc; i++) if (!strcmp(donorArgv[i], "--groups")) {
            for (int j = i + 1; j < donorArgc; j++) free(donorArgv[j]);
            donorArgc = i + 1;
            donorArgv[donorArgc] = NULL;
            break;
        }
    }
    return 0;
}
static int proc_paused(pid_t pid, bool *paused) { *paused = true; return 0; }
static int proc_get_pidversion(pid_t pid) { return 9; }
static int jbdPrepareCredentialHelper(pid_t pid, int version, uint64_t deadline) { return 0; }
static int fixture_kill(pid_t pid, int signal)
{
    check(pid == 4242, "only the modeled donor is addressed");
    if (signal == SIGCONT) run_donor(donorArgc, donorArgv);
    if (childWriter >= 0) close(childWriter);
    childWriter = -1;
    return 0;
}
static pid_t fixture_wait(pid_t pid, int *status, int options) { return pid; }
static int fixture_sleep(useconds_t usec) { return 0; }

#define setgid(...) 0
#define setregid(...) 0
#define setuid(...) 0
#define setreuid(...) 0
#define setgroups fixture_setgroups
#define write fixture_write
#define posix_spawn_file_actions_adddup2 fixture_dup
#define posix_spawn fixture_spawn
#define kill fixture_kill
#define waitpid fixture_wait
#define usleep fixture_sleep
#define roothide_bootlog(...) ((void)0)
#include "implementation.h"

int main(int argc, const char *argv[])
{
    if (argc != 2) return 2;
    scenario = argv[1];
    gid_t groups[NGROUPS_MAX];
    for (unsigned i = 0; i < NGROUPS_MAX; i++) groups[i] = is("two-stale-tail") ? 999 : 0;
    groups[0] = is("wrong-primary") ? 999 : 501;
    unsigned count = is("two-stale-tail") ? 2 : is("maximum") ? NGROUPS_MAX : 1;
    if (count > 1) groups[1] = 20;
    if (is("maximum")) for (unsigned i = 2; i < NGROUPS_MAX; i++) groups[i] = 100 + i;
    if (is("empty")) count = 0;
    if (is("oversized")) count = NGROUPS_MAX + 1;
    gid_t *input = is("null-groups") ? NULL : groups;
#if HAS_COUNTED_SENDER
    int result = target_proc_with_ucred_counted("/fixture/target", 501, 501, 501, 501, input, count);
#else
    int result = target_proc_with_ucred("/fixture/target", 501, 501, 501, 501, input);
#endif
    bool invalidInput = is("empty") || is("oversized") || is("null-groups") || is("wrong-primary");
    bool invalidWire = !strncmp(scenario, "wire-", 5);
    check(invalidInput || invalidWire ? result == -1 : result == 4242, "invalid groups or incomplete wire data never acknowledge a usable donor");
    if (invalidInput) check(!spawnCalls && observedCount == -1, "invalid group input never starts a donor");
    if (invalidWire) check(observedCount == -1, "malformed group arguments never perform identity changes");
    if (!invalidInput && !invalidWire) {
        check(observedCount == (int)count, "preserve authoritative supplementary group count");
        check(!memcmp(observedGroups, groups, count * sizeof(gid_t)), "preserve only active group memberships");
    }
    for (int i = 0; i < donorArgc; i++) free(donorArgv[i]);
    if (childWriter >= 0) close(childWriter);
    printf("%s: result=%d groups=%d spawns=%u failures=%u\n", scenario, result, observedCount, spawnCalls, failures);
    return failures ? 1 : 0;
}

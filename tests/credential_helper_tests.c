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

static enum { GOOD, BAD_MARKER, EARLY_EXIT, NO_REPLY, PATCH_FAILURE, RESUME_FAILURE, SPAWN_FAILURE } scenario;
static int childWriter = -1, originalWriter = -1;
static int patchCount, resumeCount, killCount, waitCount;
static short spawnFlags;
static bool uncachedLoader;

static void send_reply(void)
{
    if (scenario == NO_REPLY) return;
    if (scenario != EARLY_EXIT) {
        unsigned char reply = scenario == BAD_MARKER ? 0x13 : 0x42;
        assert(write(childWriter, &reply, 1) == 1);
    }
    close(childWriter);
    childWriter = -1;
}

static int test_adddup2(posix_spawn_file_actions_t *actions, int source, int destination)
{
    assert(destination == 3);
    originalWriter = source;
    return posix_spawn_file_actions_adddup2(actions, source, destination);
}

static int test_spawn(pid_t *pid, const char *path, const posix_spawn_file_actions_t *actions,
    const posix_spawnattr_t *attributes, char *const argv[], char *const envp[])
{
    (void)actions;
    assert(strcmp(path, "/fixture/target") == 0);
    assert(strcmp(argv[0], path) == 0 && strcmp(argv[1], "--fd") == 0 && strcmp(argv[2], "3") == 0);
    spawnFlags = 0;
    if (attributes) assert(posix_spawnattr_getflags(attributes, &spawnFlags) == 0);
    for (unsigned i = 0; envp[i]; i++) {
        if (strcmp(envp[i], "DYLD_IN_CACHE=0") == 0) uncachedLoader = true;
    }
    if (scenario == SPAWN_FAILURE) return ENOENT;
    *pid = 4242;
    childWriter = dup(originalWriter);
    assert(childWriter >= 0);
    if (!(spawnFlags & POSIX_SPAWN_START_SUSPENDED)) send_reply();
    return 0;
}

static int proc_paused(pid_t pid, bool *paused)
{
    assert(pid == 4242);
    *paused = true;
    return 0;
}

static int proc_get_pidversion(pid_t pid)
{
    assert(pid == 4242);
    return 9;
}

static int jbdPrepareCredentialHelper(pid_t pid, int pidversion, uint64_t deadline)
{
    assert(pid == 4242 && resumeCount == 0);
    assert(pidversion == 9);
    assert(deadline > clock_gettime_nsec_np(CLOCK_MONOTONIC));
    patchCount++;
    if (scenario == PATCH_FAILURE) errno = EIO;
    return scenario == PATCH_FAILURE ? -1 : 0;
}

static int test_kill(pid_t pid, int signal)
{
    assert(pid == 4242);
    if (signal == SIGCONT) {
        resumeCount++;
        if (scenario == RESUME_FAILURE) { errno = ESRCH; return -1; }
        assert(patchCount == 1);
        send_reply();
    }
    else {
        assert(signal == SIGKILL);
        killCount++;
        if (childWriter >= 0) close(childWriter);
        childWriter = -1;
    }
    return 0;
}

static pid_t test_waitpid(pid_t pid, int *status, int options)
{
    (void)options;
    assert(pid == 4242 && killCount == 1);
    waitCount++;
    if (status) *status = SIGKILL;
    return pid;
}

#define posix_spawn_file_actions_adddup2 test_adddup2
#define posix_spawn test_spawn
#define kill test_kill
#define waitpid test_waitpid
#define roothide_bootlog(...) ((void)0)
#include "helper-under-test.h"
#undef kill
#undef waitpid

static int descriptor_count(void)
{
    int result = 0;
    for (int fd = 0; fd < 1024; fd++) if (fcntl(fd, F_GETFD) != -1) result++;
    return result;
}

int main(void)
{
    for (scenario = GOOD; scenario <= SPAWN_FAILURE; scenario++) {
        int descriptors = descriptor_count();
        patchCount = resumeCount = killCount = waitCount = 0;
        spawnFlags = 0;
        uncachedLoader = false;
        gid_t groups[NGROUPS_MAX];
        for (unsigned i = 0; i < NGROUPS_MAX; i++) groups[i] = (gid_t)-1;
        groups[0] = 501;
        uint64_t start = clock_gettime_nsec_np(CLOCK_MONOTONIC);
        int result = target_proc_with_ucred("/fixture/target", 501, 501, 501, 501, groups);
        if (scenario == GOOD) {
            assert(result == 4242);
            assert(patchCount == 1 && resumeCount == 1 && killCount == 0);
            assert(spawnFlags & POSIX_SPAWN_START_SUSPENDED);
            assert(uncachedLoader);
        }
        else {
            assert(result == -1);
            if (scenario == SPAWN_FAILURE) assert(killCount == 0 && patchCount == 0);
            else assert(killCount == 1 && waitCount == 1);
        }
        if (scenario == NO_REPLY) assert(clock_gettime_nsec_np(CLOCK_MONOTONIC) - start < 7000000000ULL);
        assert(descriptor_count() == descriptors);
    }
    puts("credential helper preparation and failure cleanup passed");
    return 0;
}

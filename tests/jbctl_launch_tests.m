#import <Foundation/Foundation.h>
#import "NSString+Version.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *scenario;
static NSString *version;
static unsigned rootDepth, sandboxDepth, spawnCalls, waitCalls, continueCalls, killCalls, writeCalls;
static unsigned actionsLive, attributesLive, allocationCalls, allocationRefusal, allocationsLive;
static void *allocations[32];
static int readFD = 7, writeFD = 8;
static bool readerOpen, writerOpen, childWriterClosed, childReaderClosed, usedWaitfor, observedSuspension;
static unsigned failures;
static char *fixtureEnvironment[] = {"FIXTURE=1", NULL};

static bool is(const char *name) { return !strcmp(scenario, name); }
static void check(bool condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message);
        failures++;
    }
}

static void *fixture_malloc(size_t size)
{
    if (++allocationCalls == allocationRefusal) return NULL;
    void *allocation = malloc(size);
    if (!allocation) abort();
    allocations[allocationCalls - 1] = allocation;
    allocationsLive++;
    return allocation;
}

static void *fixture_calloc(size_t count, size_t size)
{
    void *allocation = fixture_malloc(count * size);
    if (allocation) memset(allocation, 0, count * size);
    return allocation;
}

static char *fixture_strdup(const char *string)
{
    char *allocation = fixture_malloc(strlen(string) + 1);
    if (allocation) strcpy(allocation, string);
    return allocation;
}

static void fixture_free(void *allocation)
{
    if (!allocation) return;
    for (unsigned i = 0; i < 32; i++) {
        if (allocations[i] == allocation) {
            allocations[i] = NULL;
            allocationsLive--;
            free(allocation);
            return;
        }
    }
    abort();
}

static int fixture_actions_init(posix_spawn_file_actions_t *actions)
{
    if (is("file-actions-failure")) return ENOMEM;
    *actions = (posix_spawn_file_actions_t)(uintptr_t)1;
    actionsLive++;
    return 0;
}

static int fixture_actions_destroy(posix_spawn_file_actions_t *actions)
{
    check(*actions != NULL && actionsLive == 1, "destroy only initialized file actions");
    actionsLive = 0;
    return 0;
}

static int fixture_attr_init(posix_spawnattr_t *attributes)
{
    if (is("attributes-failure")) return ENOMEM;
    *attributes = (posix_spawnattr_t)(uintptr_t)1;
    attributesLive++;
    return 0;
}

static int fixture_attr_destroy(posix_spawnattr_t *attributes)
{
    check(*attributes != NULL && attributesLive == 1, "destroy only initialized attributes");
    attributesLive = 0;
    return 0;
}

static int fixture_pipe(int descriptors[2])
{
    if (is("pipe-failure")) { errno = EMFILE; return -1; }
    descriptors[0] = readFD;
    descriptors[1] = writeFD;
    readerOpen = writerOpen = true;
    return 0;
}

static int fixture_close(int descriptor)
{
    if (descriptor == readFD && readerOpen) { readerOpen = false; return 0; }
    if (descriptor == writeFD && writerOpen) { writerOpen = false; return 0; }
    check(false, "close only owned pipe descriptors");
    errno = EBADF;
    return -1;
}

static int fixture_dup(posix_spawn_file_actions_t *actions, int source, int destination)
{
    if (is("dup-failure")) return EBADF;
    check(actionsLive == 1 && source == readFD && destination == 3, "correct barrier descriptor mapping");
    if (writeFD == destination) childWriterClosed = true;
    if (readFD == destination) childReaderClosed = true;
    return 0;
}

static int fixture_close_action(posix_spawn_file_actions_t *actions, int descriptor)
{
    if (is("close-action-failure")) return EBADF;
    check(actionsLive == 1 && descriptor != 3, "keep child barrier descriptor open");
    if (descriptor == writeFD) childWriterClosed = true;
    if (descriptor == readFD) childReaderClosed = true;
    return 0;
}

static int fixture_flags(posix_spawnattr_t *attributes, short flags)
{
    if (is("flags-failure")) return EINVAL;
    check(attributesLive == 1, "configure initialized attributes");
    observedSuspension = (flags & POSIX_SPAWN_START_SUSPENDED) != 0;
    return 0;
}

static int fixture_fcntl(int descriptor, int command, ...)
{
    check(descriptor == readFD || descriptor == writeFD, "fcntl only owned descriptors");
    if (is("nosigpipe-failure")) { errno = EBADF; return -1; }
    return 0;
}

static int fixture_spawn(pid_t *pid, const char *path, const posix_spawn_file_actions_t *actions,
                         const posix_spawnattr_t *attributes, char *const argv[], char *const env[])
{
    spawnCalls++;
    check(rootDepth == 1 && sandboxDepth == 1, "spawn inside temporary privilege scopes");
    check(actionsLive == 1 && attributesLive == 1, "spawn only after successful setup");
    check(!strcmp(path, "/fixture/basebin/jbctl") && !strcmp(argv[1], "fixture-action") && !strcmp(argv[2], "argument"), "preserve command arguments");
    usedWaitfor = argv[3] && !strcmp(argv[3], "--waitfor") && argv[4] && !strcmp(argv[4], "3") && !argv[5];
    if (is("spawn-failure") || is("legacy-spawn-failure")) return EAGAIN;
    *pid = is("invalid-pid") ? 0 : 42;
    return 0;
}

static int fixture_kill(pid_t pid, int signal)
{
    check(pid == 42, "never signal an invalid or process-group PID");
    if (signal == SIGCONT) {
        continueCalls++;
        check(!rootDepth && !sandboxDepth, "leave temporary privileges before resuming helper");
        if (is("legacy-resume-failure")) { errno = EPERM; return -1; }
    } else if (signal == SIGKILL) {
        killCalls++;
    } else {
        check(false, "unexpected signal");
    }
    return 0;
}

static ssize_t fixture_write(int descriptor, const void *bytes, size_t count)
{
    writeCalls++;
    check(descriptor == writeFD && writerOpen && count == 1 && *(const char *)bytes == 'w', "exact one-byte release marker");
    check(!rootDepth && !sandboxDepth, "leave temporary privileges before releasing barrier");
    if (is("write-failure")) { errno = EPIPE; return -1; }
    if (is("write-zero")) return 0;
    if (is("write-interrupted") && writeCalls == 1) { errno = EINTR; return -1; }
    return 1;
}

static int fixture_wait(pid_t pid)
{
    waitCalls++;
    check(pid == 42, "never wait for an invalid or process-group PID");
    check(!rootDepth && !sandboxDepth, "wait outside temporary privileges");
    check(!readerOpen && !writerOpen, "close parent pipe ends before waiting");
    return is("wait-status") ? 42 : 0;
}

#define JBROOT_PATH(path) "/fixture/basebin/jbctl"
#define environ fixtureEnvironment
#define malloc fixture_malloc
#define calloc fixture_calloc
#define strdup fixture_strdup
#define free fixture_free
#define posix_spawn_file_actions_init fixture_actions_init
#define posix_spawn_file_actions_destroy fixture_actions_destroy
#define posix_spawnattr_init fixture_attr_init
#define posix_spawnattr_destroy fixture_attr_destroy
#define posix_spawn_file_actions_adddup2 fixture_dup
#define posix_spawn_file_actions_addclose fixture_close_action
#define posix_spawnattr_setflags fixture_flags
#define posix_spawn fixture_spawn
#define pipe fixture_pipe
#define close fixture_close
#define fcntl fixture_fcntl
#define kill fixture_kill
#define write fixture_write
#define cmd_wait_for_exit fixture_wait

@interface DOEnvironmentManager : NSObject
- (NSString *)jailbrokenVersion;
- (void)runAsRoot:(void (^)(void))block;
- (void)runUnsandboxed:(void (^)(void))block;
- (int)spawnJbctlAsRootWithArgs:(NSArray *)arguments;
@end

@implementation DOEnvironmentManager
- (NSString *)jailbrokenVersion { return version; }
- (void)runAsRoot:(void (^)(void))block
{
    if (is("privilege-refusal")) return;
    rootDepth++;
    block();
    rootDepth--;
}
- (void)runUnsandboxed:(void (^)(void))block
{
    sandboxDepth++;
    block();
    sandboxDepth--;
}
#include "implementation.h"
@end

#undef malloc
#undef calloc
#undef strdup
#undef free
#undef close

int main(int argc, const char *argv[])
{
    @autoreleasepool {
        if (argc != 2) return 2;
        scenario = argv[1];
        bool legacy = is("legacy") || is("legacy-spawn-failure") || is("flags-failure") || is("legacy-resume-failure");
        version = legacy ? @"3.0.4" : (is("double-digit") ? @"3.0.10.0" : @"3.0.9.0");
        if (is("no-version")) version = nil;
        if (is("allocation-one")) allocationRefusal = 1;
        if (is("allocation-three")) allocationRefusal = 3;
        if (is("allocation-six")) allocationRefusal = 6;
        if (is("read-fd-three")) readFD = 3;
        if (is("write-fd-three")) writeFD = 3;
        int result = [[DOEnvironmentManager new] spawnJbctlAsRootWithArgs:@[@"fixture-action", @"argument"]];
        bool expectedFailure = strstr(scenario, "failure") || allocationRefusal || is("write-zero") || is("privilege-refusal") || is("invalid-pid");
        check(expectedFailure ? result != 0 : result == (is("wait-status") ? 42 : 0), "preserve failure or child exit status");
        check(!allocationsLive && !actionsLive && !attributesLive && !readerOpen && !writerOpen, "release all per-call allocations and resources");
        if (!expectedFailure) {
            check(spawnCalls == 1 && waitCalls == 1, "successful spawn has one wait");
            check(legacy ? observedSuspension && !usedWaitfor && continueCalls == 1 : usedWaitfor && !observedSuspension && !continueCalls, "version-correct launch strategy");
            if (!legacy) check(childWriterClosed && childReaderClosed, "child retains only the release reader at fd 3");
        }
        if (is("spawn-failure") || is("legacy-spawn-failure") || is("invalid-pid") || is("privilege-refusal")) {
            check(!waitCalls && !continueCalls && !killCalls && !writeCalls, "refused spawn never signals, releases or waits");
        }
        if (is("write-interrupted")) check(writeCalls == 2, "retry interrupted release write");
        for (unsigned i = 0; i < 32; i++) free(allocations[i]);
        printf("%s: result=%d failures=%u\n", scenario, result, failures);
        return failures ? 1 : 0;
    }
}

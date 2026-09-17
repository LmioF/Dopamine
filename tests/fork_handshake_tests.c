#include <errno.h>
#include <poll.h>
#include <setjmp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

static int failures;
static int pipeCall;
static int closeLog[16];
static int closeCount;
static int writeResults[8];
static int writeResultCount;
static int writeResultIndex;
static int readResults[8];
static int readResultCount;
static int readResultIndex;
static int pollResults[8];
static int pollResultCount;
static int pollResultIndex;
static int repairResult;
static int repairCalls;
static int killCalls;
static int forkResult;
static int firstProtocolCloseCount = -1;
static jmp_buf abortJump;
static bool abortExpected;

static void check(bool condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message);
        failures++;
    }
}

static void reset_state(void)
{
    failures = 0;
    pipeCall = 0;
    closeCount = 0;
    writeResultCount = writeResultIndex = 0;
    readResultCount = readResultIndex = 0;
    pollResultCount = pollResultIndex = 0;
    repairResult = 0;
    repairCalls = 0;
    killCalls = 0;
    forkResult = 0;
    firstProtocolCloseCount = -1;
    abortExpected = false;
    errno = 0;
}

static int test_pipe(int fds[2])
{
    if (pipeCall++ == 0) {
        fds[0] = 10;
        fds[1] = 11;
    } else {
        fds[0] = 12;
        fds[1] = 13;
    }
    return 0;
}

ssize_t ffsys_write(int fd, const void *buffer, size_t size)
{
    (void)fd;
    (void)buffer;
    check(size == 1, "protocol writes exactly one byte");
    if (firstProtocolCloseCount < 0) firstProtocolCloseCount = closeCount;
    if (writeResultIndex < writeResultCount) return writeResults[writeResultIndex++];
    return 1;
}

ssize_t ffsys_read(int fd, void *buffer, size_t size)
{
    (void)fd;
    check(size == 1, "protocol reads exactly one byte");
    if (firstProtocolCloseCount < 0) firstProtocolCloseCount = closeCount;
    if (readResultIndex < readResultCount) {
        ssize_t result = readResults[readResultIndex++];
        if (result == 1) *(char *)buffer = ' ';
        return result;
    }
    *(char *)buffer = ' ';
    return 1;
}

int ffsys_poll(struct pollfd *fds, unsigned int nfds, int timeout)
{
    check(nfds == 1, "polls one protocol endpoint");
    check(timeout > 0 && timeout <= 5000, "protocol wait has a finite deadline");
    if (firstProtocolCloseCount < 0) firstProtocolCloseCount = closeCount;
    int result = 1;
    if (pollResultIndex < pollResultCount) result = pollResults[pollResultIndex++];
    if (result == 1) fds[0].revents = POLLIN | POLLOUT;
    return result;
}

int ffsys_close(int fd)
{
    closeLog[closeCount++] = fd;
    return 0;
}

pid_t ffsys_fork(void)
{
    return forkResult;
}

static ssize_t test_read(int fd, void *buffer, size_t size)
{
    return ffsys_read(fd, buffer, size);
}

static ssize_t test_write(int fd, const void *buffer, size_t size)
{
    return ffsys_write(fd, buffer, size);
}

static int test_kill(pid_t pid, int signalNumber)
{
    check(pid == 123, "kills the fork child on parent-side protocol failure");
    check(signalNumber == SIGKILL, "uses SIGKILL for failed repair protocol");
    killCalls++;
    return 0;
}

int64_t jbclient_mach_fork_fix(pid_t pid)
{
    check(pid == 123, "repairs the expected child");
    repairCalls++;
    return repairResult;
}

static void test_abort(void)
{
    if (!abortExpected) {
        fprintf(stderr, "FAIL: unexpected abort\n");
        failures++;
    }
    longjmp(abortJump, 1);
}

#define pipe test_pipe
#define read test_read
#define write test_write
#define kill test_kill
#define abort test_abort
#include "implementation.h"
#undef abort
#undef kill
#undef write
#undef read
#undef pipe

static void expect_child_abort(void)
{
    abortExpected = true;
    if (setjmp(abortJump) == 0) {
        child_fixup();
        check(false, "child protocol failure must not return as repaired");
    }
    abortExpected = false;
}

static void expect_parent_abort(void)
{
    abortExpected = true;
    if (setjmp(abortJump) == 0) {
        parent_fixup(123);
        check(false, "parent protocol failure must not return as repaired");
    }
    abortExpected = false;
}

static int run(const char *scenario)
{
    reset_state();
    parentToChildPipe[0] = 10;
    parentToChildPipe[1] = 11;
    childToParentPipe[0] = 12;
    childToParentPipe[1] = 13;

    if (!strcmp(scenario, "child-read-eof")) {
        readResults[0] = 0;
        readResultCount = 1;
        expect_child_abort();
        check(readResultIndex == 1, "child observes acknowledgement EOF");
    } else if (!strcmp(scenario, "child-write-error")) {
        writeResults[0] = EPIPE;
        writeResultCount = 1;
        expect_child_abort();
        check(readResultIndex == 0, "failed readiness write does not wait for acknowledgement");
    } else if (!strcmp(scenario, "child-eintr")) {
        writeResults[0] = EINTR;
        writeResults[1] = 1;
        writeResultCount = 2;
        readResults[0] = EINTR;
        readResults[1] = 1;
        readResultCount = 2;
        child_fixup();
        check(writeResultIndex == 2, "child retries interrupted readiness write");
        check(readResultIndex == 2, "child retries interrupted acknowledgement read");
    } else if (!strcmp(scenario, "parent-read-eof")) {
        readResults[0] = 0;
        readResultCount = 1;
        expect_parent_abort();
        check(repairCalls == 0, "parent does not repair before child readiness");
        check(killCalls == 1, "parent terminates child after readiness failure");
    } else if (!strcmp(scenario, "parent-write-error")) {
        readResults[0] = 1;
        readResultCount = 1;
        writeResults[0] = EPIPE;
        writeResultCount = 1;
        expect_parent_abort();
        check(repairCalls == 1, "parent performs repair after readiness");
        check(killCalls == 1, "parent terminates child when acknowledgement fails");
    } else if (!strcmp(scenario, "parent-repair-error")) {
        readResults[0] = 1;
        readResultCount = 1;
        repairResult = 5;
        expect_parent_abort();
        check(repairCalls == 1, "parent attempts repair exactly once");
        check(killCalls == 1, "parent terminates child when repair fails");
    } else if (!strcmp(scenario, "child-unused-ends")) {
        forkResult = 0;
        forkfix___fork();
        check(firstProtocolCloseCount >= 2, "child closes unused pipe ends before handshaking");
        check(closeLog[0] == 11 && closeLog[1] == 12, "child closes parent write and child read ends first");
    } else if (!strcmp(scenario, "parent-unused-ends")) {
        forkResult = 123;
        forkfix___fork();
        check(firstProtocolCloseCount >= 2, "parent closes unused pipe ends before handshaking");
        check(closeLog[0] == 10 && closeLog[1] == 13, "parent closes parent read and child write ends first");
    } else {
        fprintf(stderr, "unknown scenario %s\n", scenario);
        return 2;
    }
    return failures ? 1 : 0;
}

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    return run(argv[1]);
}

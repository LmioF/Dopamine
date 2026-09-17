#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static unsigned readCalls, closeCalls, failures, cases;
static int readError, expectedFD, observedArgc;
static bool interrupted, eof, wrongByte, observedTerminator;

static ssize_t fixture_read(int fd, void *buffer, size_t count)
{
    readCalls++;
    if (fd != expectedFD) { errno = EBADF; return -1; }
    if (interrupted && readCalls == 1) { errno = EINTR; return -1; }
    if (readError) { errno = readError; return -1; }
    if (eof) return 0;
    if (!count) abort();
    *(char *)buffer = wrongByte ? 'x' : 'w';
    return 1;
}

static int fixture_close(int fd)
{
    closeCalls++;
    if (fd != expectedFD) { errno = EBADF; return -1; }
    return 0;
}

#define read fixture_read
#define close fixture_close
#include "implementation.h"
#undef read
#undef close

static void check(bool condition, const char *message)
{
    if (!condition) { fprintf(stderr, "FAIL: %s\n", message); failures++; }
}

static void reset(void)
{
    cases++;
    readCalls = closeCalls = 0;
    readError = 0;
    expectedFD = 3;
    observedArgc = -1;
    interrupted = eof = wrongByte = observedTerminator = false;
}

static int run(const char *fd)
{
    char *arguments[] = {"jbctl", "fixture-action", "--waitfor", (char *)fd, NULL};
    return run_gate(4, arguments);
}

int main(void)
{
    reset();
    check(run("3") == 0 && readCalls == 1 && closeCalls == 1 && observedArgc == 2 && observedTerminator, "ready token releases and removes private arguments");
    reset(); interrupted = true;
    check(run("3") == 0 && readCalls == 2 && closeCalls == 1, "EINTR is not completion");
    reset(); eof = true;
    check(run("3") != 0 && closeCalls == 1 && observedArgc == -1, "parent EOF forbids action");
    reset(); readError = EIO;
    check(run("3") != 0 && closeCalls == 1 && observedArgc == -1, "read refusal forbids action");
    reset(); wrongByte = true;
    check(run("3") != 0 && closeCalls == 1 && observedArgc == -1, "wrong release marker forbids action");
    const char *invalid[] = {"", "abc", "3tail", "-1", "2147483648", "999999999999999999999999999"};
    for (unsigned i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        reset();
        check(run(invalid[i]) != 0 && !readCalls && !closeCalls && observedArgc == -1, "invalid descriptor is rejected without touching it");
    }
    reset(); expectedFD = 0;
    check(run("0") == 0 && closeCalls == 1, "explicit descriptor zero is valid");
    reset();
    char *missingAction[] = {"jbctl", "--waitfor", "3", NULL};
    check(run_gate(3, missingAction) != 0 && !readCalls && !closeCalls, "barrier option requires an action");
    reset();
    char *normal[] = {"jbctl", "fixture-action", NULL};
    check(run_gate(2, normal) == 0 && !readCalls && !closeCalls && observedArgc == 2, "ordinary commands do not wait");
    printf("%u barrier cases, %u failures\n", cases, failures);
    return failures ? 1 : 0;
}

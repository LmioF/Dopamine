#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define F_GETFD 1
#define F_SETFD 2
#define F_GETPATH 50
#define F_SETPROTECTIONCLASS 64
#define PATH_MAX 1024

typedef struct { unsigned int val[8]; } audit_token_t;

enum { SANDBOX_FILTER_NONE = 0, SANDBOX_FILTER_PATH = 1, SANDBOX_FILTER_GLOBAL_NAME = 2 };

static int last_fcntl_argc;
static uintptr_t last_fcntl_arg;
static int last_sandbox_argc;
static uintptr_t last_sandbox_arg;

static int fcntl(int fd, int cmd, ...);

#define COUNT_ARGS_IMPL(_0,_1,_2,_3,_4,_5,_6,_7,_8,_9,_10,N,...) N
#define COUNT_ARGS(...) COUNT_ARGS_IMPL(0, ##__VA_ARGS__,10,9,8,7,6,5,4,3,2,1,0)
#define TEST_FCNTL_ORIG(fd, cmd, ...) \
    (last_fcntl_argc = COUNT_ARGS(__VA_ARGS__), \
     last_fcntl_arg = last_fcntl_argc ? (uintptr_t)(0, ##__VA_ARGS__) : 0, 123)

static int fake_sandbox_orig(audit_token_t au, const char *operation, int filter, ...)
{
    (void)au; (void)operation; (void)filter;
    return 456;
}

int (*sandbox_check_by_audit_token_orig)(audit_token_t, const char *, int, ...) = fake_sandbox_orig;

static int isSubPathOf(const char *a, const char *b) { (void)a; (void)b; return 0; }
static const char *jbroot(const char *p) { return p; }
static int isBlacklistedToken(audit_token_t *au) { (void)au; return 1; }
static const char *proc_get_path(int pid, void *unused) { (void)pid; (void)unused; return "x"; }
static int audit_token_to_pid(audit_token_t au) { (void)au; return 1; }
#define JBLogDebug(...) do {} while (0)

static int fcntl(int fd, int cmd, ...)
{
    va_list ap;
    (void)fd;
    va_start(ap, cmd);
    if (cmd == F_GETPATH) {
        char *path = va_arg(ap, char *);
        strcpy(path, "/tmp/not-jbroot");
    }
    va_end(ap);
    return 0;
}

#include "implementation.h"

static int sandbox_orig_capture(audit_token_t au, const char *operation, int filter, ...)
{
    (void)au; (void)operation;
    va_list ap;
    va_start(ap, filter);
    if (filter == SANDBOX_FILTER_NONE) {
        last_sandbox_argc = 0;
        last_sandbox_arg = 0;
    } else {
        last_sandbox_argc = 1;
        last_sandbox_arg = (uintptr_t)va_arg(ap, void *);
    }
    va_end(ap);
    return 789;
}

int main(void)
{
    char path[PATH_MAX];
    audit_token_t au = {0};

    last_fcntl_argc = -1;
    if (fcntl_hook(3, F_GETFD) != 123 || last_fcntl_argc != 0) return 1;
    if (fcntl_hook(3, F_SETFD, 7) != 123 || last_fcntl_argc != 1 || last_fcntl_arg != 7) return 2;
    if (fcntl_hook(3, F_GETPATH, path) != 123 || last_fcntl_argc != 1 || last_fcntl_arg != (uintptr_t)path) return 3;

    sandbox_check_by_audit_token_orig = sandbox_orig_capture;
    last_sandbox_argc = -1;
    if (sandbox_check_by_audit_token_hook(au, "process-info", SANDBOX_FILTER_NONE) != 789 || last_sandbox_argc != 0) return 4;
    if (sandbox_check_by_audit_token_hook(au, "file-read-data", SANDBOX_FILTER_PATH, path) != 789 || last_sandbox_argc != 1 || last_sandbox_arg != (uintptr_t)path) return 5;

    puts("ok");
    return 0;
}

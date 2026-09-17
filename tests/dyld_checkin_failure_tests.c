#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool dyld_patch_fallback_enabled;
static int hook_result;
static unsigned hook_calls;
static unsigned redirect_calls;
static unsigned dlopen_calls;

static void roothide_loader_trace(const char *phase, const char *path, int result)
{
    (void)phase; (void)path; (void)result;
}

static int init_dyldhooks(void)
{
    hook_calls++;
    return hook_result;
}

static void redirect_paths(const char *rootdir)
{
    (void)rootdir;
    redirect_calls++;
}

#define JBROOT_PATH(path) (path)
#define RTLD_NOW 2
static void *test_dlopen(const char *path, int mode)
{
    (void)path; (void)mode;
    dlopen_calls++;
    return (void *)1;
}
#define dlopen test_dlopen
#include "implementation.h"
#undef dlopen

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    dyld_patch_fallback_enabled = strcmp(argv[1], "not-required") != 0;
    hook_result = !strcmp(argv[1], "hook-failure") ? -1 : 0;
    roothide_init_with_checkin("/fixture");
    if (!strcmp(argv[1], "hook-failure"))
        return hook_calls == 1 && redirect_calls == 0 && dlopen_calls == 0 ? 0 : 1;
    if (!strcmp(argv[1], "hook-success"))
        return hook_calls == 1 && redirect_calls == 1 && dlopen_calls == 1 ? 0 : 1;
    return hook_calls == 0 && redirect_calls == 1 && dlopen_calls == 1 ? 0 : 1;
}

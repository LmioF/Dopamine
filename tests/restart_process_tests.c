#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#define CTL_KERN 1
#define KERN_ARGMAX 2
#define KERN_PROC 3
#define KERN_PROC_ALL 4
#define KERN_PROCARGS2 5

struct kinfo_proc { struct { pid_t p_pid; } kp_proc; char padding[60]; };
static const char *mode;
static const char expected_path[] = "/fixture/target";
static size_t allocated_size;
static int allocation_calls, argument_calls, signal_calls;
static int query_calls;
static void *allocations[2];

static void *fixture_malloc(size_t size)
{
    allocation_calls++;
    if ((!strcmp(mode, "allocation-refused") && allocation_calls == 2) ||
        (!strcmp(mode, "process-allocation-refused") && allocation_calls == 1)) return NULL;
    void *result = malloc(size);
    if (result) memset(result, 'X', size);
    assert(allocation_calls <= 2);
    allocations[allocation_calls - 1] = result;
    allocated_size = size;
    return result;
}

static void fixture_free(void *pointer)
{
    if (!pointer) return;
    for (unsigned i = 0; i < 2; i++) {
        if (allocations[i] == pointer) {
            allocations[i] = NULL;
            free(pointer);
            return;
        }
    }
    assert(false && "free must release one owned allocation exactly once");
}

static int fixture_sysctl(const int *mib, unsigned count, void *output, size_t *size, const void *input, size_t input_size)
{
    query_calls++;
    if (mib[1] == KERN_ARGMAX) {
        if (!strcmp(mode, "argmax-refused")) { errno = EIO; return -1; }
        *(int *)output = !strcmp(mode, "invalid-argmax") ? 0 :
                        !strcmp(mode, "negative-argmax") ? -1 : 4096;
        *size = !strcmp(mode, "truncated-argmax") ? 1 : sizeof(int);
        return 0;
    }
    if (mib[1] == KERN_PROC) {
        if (!output) {
            if (!strcmp(mode, "process-query-refused")) { errno = EIO; return -1; }
            *size = !strcmp(mode, "empty-table") ? 0 :
                    (!strcmp(mode, "reused-buffer") ? 3 : 2) * sizeof(struct kinfo_proc);
            return 0;
        }
        if (!strcmp(mode, "process-fill-refused")) { errno = EIO; return -1; }
        if (!strcmp(mode, "oversized-process-result")) { (*size)++; return 0; }
        struct kinfo_proc *processes = output;
        memset(processes, 0, *size);
        processes[1].kp_proc.p_pid = !strcmp(mode, "negative-pid") ? -42 : 42;
        if (!strcmp(mode, "reused-buffer")) {
            processes[1].kp_proc.p_pid = 41;
            processes[2].kp_proc.p_pid = 42;
        }
        return 0;
    }
    assert(mib[1] == KERN_PROCARGS2);
    argument_calls++;
    assert(output != NULL && "argument allocation failure must stop before sysctl");
    assert(*size <= allocated_size && "advertised argument capacity exceeds allocation");
    if (!strcmp(mode, "query-refused")) { errno = ESRCH; return -1; }
    size_t capacity = *size;
    assert(capacity == 4096 && "each argument query must receive the full allocation capacity");
    assert(capacity >= sizeof(int) + sizeof(expected_path));
    memset(output, 'X', capacity);
    const char *returned_path = !strcmp(mode, "unmatched") || mib[2] == 41 ? "/fixture/other" : expected_path;
    memcpy((char *)output + sizeof(int), returned_path, strlen(returned_path) + 1);
    if (!strcmp(mode, "truncated")) *size = sizeof(int);
    else if (!strcmp(mode, "unterminated")) *size = sizeof(int) + sizeof(expected_path) - 1;
    else if (!strcmp(mode, "oversized-result")) *size = capacity + 1;
    else if (!strcmp(mode, "short-record") || mib[2] == 41) *size = sizeof(int) + strlen(returned_path) + 1;
    else *size = 1024;
    return 0;
}

static int fixture_kill(pid_t pid, int sig)
{
    assert(pid == 42 && sig == SIGTERM);
    signal_calls++;
    return 0;
}

#define malloc fixture_malloc
#define free fixture_free
#define sysctl fixture_sysctl
#define kill fixture_kill
#include "implementation.h"
#undef malloc
#undef free
#undef sysctl
#undef kill

int main(int argc, char **argv)
{
    assert(argc == 2);
    mode = argv[1];
    killall(!strcmp(mode, "null-path") ? NULL : expected_path, SIGTERM);
    bool success = !strcmp(mode, "long-record") || !strcmp(mode, "invalid-argmax") ||
                   !strcmp(mode, "argmax-refused") || !strcmp(mode, "negative-argmax") ||
                   !strcmp(mode, "truncated-argmax") || !strcmp(mode, "short-record") ||
                   !strcmp(mode, "reused-buffer");
    assert(signal_calls == (success ? 1 : 0));
    if (strstr(mode, "allocation-refused")) assert(argument_calls == 0);
    if (!strcmp(mode, "negative-pid")) assert(argument_calls == 0);
    if (!strcmp(mode, "reused-buffer")) assert(argument_calls == 2);
    if (!strcmp(mode, "null-path")) assert(query_calls == 0 && allocation_calls == 0);
    assert(allocations[0] == NULL && allocations[1] == NULL);
    printf("%s: safe allocation, bounded parsing and expected signal count\n", mode);
    return 0;
}

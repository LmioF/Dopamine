#import <Foundation/Foundation.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

NSLock *trace_data_lock = nil;
NSMutableDictionary *trace_data_record = nil;

typedef struct {
    pid_t pid;
    bool cancelled;
    uint64_t traced_flag_addr;
    uint64_t detached_flag_addr;
} trace_data_t;

static int gScenario;
static int gKillCalls;
static int gReleaseCalls;

static int fixture_kill(pid_t pid, int sig)
{
    (void)pid;
    (void)sig;
    gKillCalls++;
    if (gScenario == 1) {
        errno = ESRCH;
        return -1;
    }
    if (gScenario == 2) {
        errno = EPERM;
        return -1;
    }
    return 0;
}

static void fixture_release_process_trace(trace_data_t *trace_data)
{
    gReleaseCalls++;
    [trace_data_record removeObjectForKey:@(trace_data->pid)];
    free(trace_data);
}

#define kill fixture_kill
#define release_process_trace fixture_release_process_trace
#define JBLogError(...) ((void)0)

#include "implementation.h"

#undef kill
#undef release_process_trace

static void require(bool condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

int main(int argc, const char *argv[])
{
    @autoreleasepool {
        if (argc != 2) return 2;
        if (!strcmp(argv[1], "success")) gScenario = 0;
        else if (!strcmp(argv[1], "gone")) gScenario = 1;
        else if (!strcmp(argv[1], "denied")) gScenario = 2;
        else return 2;

        trace_data_lock = [[NSLock alloc] init];
        trace_data_record = [[NSMutableDictionary alloc] init];
        trace_data_t *trace_data = calloc(1, sizeof(*trace_data));
        trace_data->pid = 42;
        trace_data->traced_flag_addr = 0x1111;
        [trace_data_record setObject:[NSValue valueWithPointer:trace_data] forKey:@42];

        int result = execTraceCancel(42, 0x2222);
        trace_data_t *remaining = (trace_data_t *)[[trace_data_record objectForKey:@42] pointerValue];

        require(gKillCalls == 1, "cancel sends one trap signal");
        if (gScenario == 0) {
            require(result == 0, "successful cancellation reports success");
            require(remaining == trace_data, "successful cancellation retains record until exception completes");
            require(remaining->cancelled, "successful cancellation marks record cancelled");
            require(remaining->detached_flag_addr == 0x2222, "successful cancellation publishes detached flag");
            require(gReleaseCalls == 0, "successful cancellation is not released early");
            [trace_data_record removeObjectForKey:@42];
            free(trace_data);
        } else if (gScenario == 1) {
            require(result == -1, "missing process reports cancellation failure");
            require(remaining == NULL, "missing process releases stale trace record");
            require(gReleaseCalls == 1, "missing process releases record exactly once");
        } else {
            require(result == -1, "signal refusal reports cancellation failure");
            require(remaining == trace_data, "retryable signal refusal retains trace record");
            require(!remaining->cancelled, "retryable signal refusal restores cancelled state");
            require(remaining->detached_flag_addr == 0, "retryable signal refusal restores detached flag");
            require(gReleaseCalls == 0, "retryable signal refusal does not release live trace");
            [trace_data_record removeObjectForKey:@42];
            free(trace_data);
        }
        return 0;
    }
}

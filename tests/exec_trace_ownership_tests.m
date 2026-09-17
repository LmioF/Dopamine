#import <Foundation/Foundation.h>
#include <dispatch/dispatch.h>
#include <mach/mach.h>
#include <mach/exception_types.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef ARM_THREAD_STATE64
#define ARM_THREAD_STATE64 6
#endif
#ifndef PT_ATTACHEXC
#define PT_ATTACHEXC 14
#endif

typedef struct {
    pid_t pid;
    bool cancelled;
    uint64_t traced_flag_addr;
    uint64_t detached_flag_addr;
    mach_port_t task;
    exception_mask_t saved_masks[EXC_TYPES_COUNT];
    mach_port_t saved_ports[EXC_TYPES_COUNT];
    exception_behavior_t saved_behaviors[EXC_TYPES_COUNT];
    thread_state_flavor_t saved_flavors[EXC_TYPES_COUNT];
    mach_msg_type_number_t saved_exception_types_count;
} trace_data_t;

NSLock *trace_data_lock = nil;
NSMutableDictionary *trace_data_record = nil;

static int gScenario;
static int gAllocCalls;
static int gFreeCalls;
static int gInstallCalls;
static int gRestoreCalls;
static int gTaskDeallocs;
static int gSavedPortDeallocs;
static int gPtraceCalls;

static void *fixture_malloc(size_t size)
{
    gAllocCalls++;
    return malloc(size);
}

static void fixture_free(void *ptr)
{
    if (ptr) gFreeCalls++;
    free(ptr);
}

static int fixture_proc_cantrace(pid_t pid)
{
    (void)pid;
    return 1;
}

static kern_return_t fixture_task_for_pid(mach_port_t self, pid_t pid, mach_port_t *task)
{
    (void)self;
    (void)pid;
    *task = 1234;
    return KERN_SUCCESS;
}

static kern_return_t fixture_task_get_exception_ports(
    task_t task,
    exception_mask_t mask,
    exception_mask_t *masks,
    mach_msg_type_number_t *count,
    mach_port_t *ports,
    exception_behavior_t *behaviors,
    thread_state_flavor_t *flavors)
{
    (void)task;
    (void)mask;
    if (gScenario == 1) {
        *count = 0;
        return KERN_FAILURE;
    }
    *count = 2;
    masks[0] = EXC_MASK_SOFTWARE;
    masks[1] = EXC_MASK_BREAKPOINT;
    ports[0] = 201;
    ports[1] = 202;
    behaviors[0] = EXCEPTION_DEFAULT;
    behaviors[1] = EXCEPTION_STATE_IDENTITY;
    flavors[0] = ARM_THREAD_STATE64;
    flavors[1] = ARM_THREAD_STATE64;
    return KERN_SUCCESS;
}

static kern_return_t fixture_task_set_exception_ports(
    task_t task,
    exception_mask_t mask,
    mach_port_t port,
    exception_behavior_t behavior,
    thread_state_flavor_t flavor)
{
    (void)task;
    (void)mask;
    (void)behavior;
    (void)flavor;
    if (port == 999) {
        gInstallCalls++;
        return gScenario == 2 ? KERN_FAILURE : KERN_SUCCESS;
    }
    gRestoreCalls++;
    return KERN_SUCCESS;
}

static kern_return_t fixture_mach_port_allocate(
    ipc_space_t task,
    mach_port_right_t right,
    mach_port_name_t *name)
{
    (void)task;
    (void)right;
    *name = 999;
    return KERN_SUCCESS;
}

static kern_return_t fixture_mach_port_insert_right(
    ipc_space_t task,
    mach_port_name_t name,
    mach_port_t poly,
    mach_msg_type_name_t polyPoly)
{
    (void)task;
    (void)name;
    (void)poly;
    (void)polyPoly;
    return KERN_SUCCESS;
}

static kern_return_t fixture_mach_port_deallocate(ipc_space_t task, mach_port_name_t name)
{
    (void)task;
    if (name == 1234) gTaskDeallocs++;
    if (name == 201 || name == 202) gSavedPortDeallocs++;
    return KERN_SUCCESS;
}

static int fixture_pthread_create(
    pthread_t *thread,
    const pthread_attr_t *attr,
    void *(*start)(void *),
    void *arg)
{
    (void)attr;
    (void)start;
    (void)arg;
    memset(thread, 0, sizeof(*thread));
    return 0;
}

static int fixture_pthread_threadid_np(pthread_t thread, uint64_t *tid)
{
    (void)thread;
    *tid = 1;
    return 0;
}

static void *exception_server(void *arg)
{
    (void)arg;
    return NULL;
}

static int fixture_ptrace(int request, pid_t pid, caddr_t addr, int data)
{
    (void)request;
    (void)pid;
    (void)addr;
    (void)data;
    gPtraceCalls++;
    return gScenario == 3 ? -1 : 0;
}

static char *fixture_mach_error_string(kern_return_t kr)
{
    (void)kr;
    return "fixture";
}

static void fixture_finish_process_trace(trace_data_t *traceData, bool success)
{
    (void)traceData;
    (void)success;
}

#define malloc fixture_malloc
#define free fixture_free
#define proc_cantrace fixture_proc_cantrace
#define task_for_pid fixture_task_for_pid
#define task_get_exception_ports fixture_task_get_exception_ports
#define task_set_exception_ports fixture_task_set_exception_ports
#define mach_port_allocate fixture_mach_port_allocate
#define mach_port_insert_right fixture_mach_port_insert_right
#define mach_port_deallocate fixture_mach_port_deallocate
#define pthread_create fixture_pthread_create
#define pthread_threadid_np fixture_pthread_threadid_np
#define ptrace fixture_ptrace
#define mach_error_string fixture_mach_error_string
#define finish_process_trace fixture_finish_process_trace
#define JBLogError(...) ((void)0)
#define JBLogDebug(...) ((void)0)

#include "implementation.h"

#undef malloc
#undef free
#undef proc_cantrace
#undef task_for_pid
#undef task_get_exception_ports
#undef task_set_exception_ports
#undef mach_port_allocate
#undef mach_port_insert_right
#undef mach_port_deallocate
#undef pthread_create
#undef pthread_threadid_np
#undef ptrace
#undef mach_error_string
#undef finish_process_trace

static void require(bool condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void resetCounters(void)
{
    gAllocCalls = 0;
    gFreeCalls = 0;
    gInstallCalls = 0;
    gRestoreCalls = 0;
    gTaskDeallocs = 0;
    gSavedPortDeallocs = 0;
    gPtraceCalls = 0;
}

int main(int argc, const char *argv[])
{
    @autoreleasepool {
        if (argc != 2) return 2;
        if (!strcmp(argv[1], "success")) gScenario = 0;
        else if (!strcmp(argv[1], "get-fail")) gScenario = 1;
        else if (!strcmp(argv[1], "set-fail")) gScenario = 2;
        else if (!strcmp(argv[1], "attach-fail")) gScenario = 3;
        else return 2;

        resetCounters();
        int result = execTraceProcess(42, 0x1234);

        require(gAllocCalls == 1, "one trace allocation");
        require(gTaskDeallocs == 1, "task right released exactly once");

        if (gScenario == 0) {
            require(result == 0, "successful attach reports success");
            require(gInstallCalls == 1, "exception port installed once");
            require(gPtraceCalls == 1, "ptrace attach attempted once");
            require(gFreeCalls == 0, "successful trace record remains owned by trace table");
            require(gSavedPortDeallocs == 0, "saved exception rights retained for active trace");
            require(gRestoreCalls == 0, "active trace does not restore ports early");
            trace_data_t *traceData = (trace_data_t *)[[trace_data_record objectForKey:@42] pointerValue];
            require(traceData != NULL, "successful trace record published");
            [trace_data_record removeObjectForKey:@42];
            free(traceData);
        }
        else if (gScenario == 1) {
            require(result == -1, "get-exception failure reports failure");
            require(gInstallCalls == 0, "no replacement port after get failure");
            require(gPtraceCalls == 0, "no attach after get failure");
            require(gFreeCalls == 1, "get-exception failure frees trace record");
            require(gSavedPortDeallocs == 0, "no saved rights returned on get failure");
        }
        else if (gScenario == 2) {
            require(result == -1, "set-exception failure reports failure");
            require(gInstallCalls == 1, "replacement port attempted once");
            require(gPtraceCalls == 0, "no attach after set failure");
            require(gFreeCalls == 1, "set-exception failure frees trace record");
            require(gSavedPortDeallocs == 2, "set-exception failure releases saved rights");
            require(gRestoreCalls == 0, "failed replacement does not restore an uninstalled port");
        }
        else {
            require(result == -1, "attach failure reports failure");
            require(gInstallCalls == 1, "replacement port installed once");
            require(gPtraceCalls == 1, "attach attempted once");
            require(gFreeCalls == 1, "attach failure frees trace record");
            require(gRestoreCalls == 2, "attach failure restores every saved exception port");
            require(gSavedPortDeallocs == 2, "attach failure releases saved rights");
            require([trace_data_record objectForKey:@42] == nil, "failed trace record not retained");
        }

        trace_data_record = nil;
        trace_data_lock = nil;
        return 0;
    }
}

#import <Foundation/Foundation.h>
#include <mach/mach.h>
#include <mach/arm/thread_status.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef __MigPackStructs
#define __MigPackStructs
#endif
#include "../BaseBin/libjailbreak/src/roothider/mach_exc.h"

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
static int gReceiveCalls;
static int gReplyCalls;
static int gThreadDeallocs;
static int gTaskDeallocs;
static int gThreadStateCalls;
static int gFinishCalls;
static kern_return_t gReplyCode = KERN_SUCCESS;

static mach_msg_return_t fixture_mach_msg(mach_msg_header_t *msg,
                                          mach_msg_option_t option,
                                          mach_msg_size_t send_size,
                                          mach_msg_size_t receive_limit,
                                          mach_port_name_t receive_name,
                                          mach_msg_timeout_t timeout,
                                          mach_port_name_t notify)
{
    (void)send_size;
    (void)receive_limit;
    (void)receive_name;
    (void)timeout;
    (void)notify;
    if (option & MACH_SEND_MSG) {
        __Reply__mach_exception_raise_t *reply = (__Reply__mach_exception_raise_t *)msg;
        gReplyCalls++;
        gReplyCode = reply->RetCode;
        return MACH_MSG_SUCCESS;
    }

    gReceiveCalls++;
    if (gReceiveCalls > 1) {
        bool ok = gReplyCalls == 1 && gThreadDeallocs == 1 && gTaskDeallocs == 1 && gReplyCode != KERN_SUCCESS;
        if (gScenario >= 2) ok = ok && gFinishCalls == 1;
        else ok = ok && gFinishCalls == 0;
        _Exit(ok ? 0 : 1);
    }

    __Request__mach_exception_raise_t *request = (__Request__mach_exception_raise_t *)msg;
    memset(request, 0, sizeof(*request));
    request->Head.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
    request->Head.msgh_remote_port = 777;
    request->Head.msgh_id = 2401;
    request->thread.name = 201;
    request->task.name = 202;
    request->NDR = NDR_record;
    request->exception = EXC_SOFTWARE;
    request->codeCnt = 2;
    request->code[0] = EXC_SOFT_SIGNAL;
    request->code[1] = SIGSTOP;
    return MACH_MSG_SUCCESS;
}

static kern_return_t fixture_pid_for_task(mach_port_name_t task, pid_t *pid)
{
    (void)task;
    if (gScenario == 0) {
        *pid = 0;
        return KERN_FAILURE;
    }
    *pid = 42;
    return KERN_SUCCESS;
}

static kern_return_t fixture_thread_get_state(thread_act_t thread,
                                               thread_state_flavor_t flavor,
                                               thread_state_t state,
                                               mach_msg_type_number_t *count)
{
    (void)thread;
    (void)flavor;
    gThreadStateCalls++;
    if ((gScenario == 2 && gThreadStateCalls == 1) ||
        (gScenario == 3 && gThreadStateCalls == 2)) {
        return KERN_FAILURE;
    }
    memset(state, 0, (size_t)(*count) * sizeof(natural_t));
    return KERN_SUCCESS;
}

static kern_return_t fixture_mach_port_deallocate(ipc_space_t task, mach_port_name_t name)
{
    (void)task;
    if (name == 201) gThreadDeallocs++;
    if (name == 202) gTaskDeallocs++;
    return KERN_SUCCESS;
}

static mach_port_t fixture_mach_task_self(void)
{
    return 100;
}

static char *fixture_mach_error_string(kern_return_t kr)
{
    (void)kr;
    return "fixture";
}

static char *fixture_proc_get_path(pid_t pid, void *unused)
{
    (void)pid;
    (void)unused;
    return "fixture";
}

static kern_return_t fixture_vm_write(vm_map_t target_task,
                                      vm_address_t address,
                                      vm_offset_t data,
                                      mach_msg_type_number_t data_count)
{
    (void)target_task;
    (void)address;
    (void)data;
    (void)data_count;
    return KERN_SUCCESS;
}

static int fixture_ptrace(int request, pid_t pid, caddr_t addr, int data)
{
    (void)request;
    (void)pid;
    (void)addr;
    (void)data;
    return 0;
}

static int fixture_roothide_patch_proc(pid_t pid)
{
    (void)pid;
    return 0;
}

static kern_return_t fixture_task_set_exception_ports(task_t task,
                                                       exception_mask_t mask,
                                                       mach_port_t port,
                                                       exception_behavior_t behavior,
                                                       thread_state_flavor_t flavor)
{
    (void)task;
    (void)mask;
    (void)port;
    (void)behavior;
    (void)flavor;
    return KERN_SUCCESS;
}

static int fixture_kill(pid_t pid, int sig)
{
    (void)pid;
    (void)sig;
    return 0;
}

static void fixture_finish_process_trace(trace_data_t *trace_data, bool success)
{
    (void)success;
    gFinishCalls++;
    [trace_data_record removeObjectForKey:@(trace_data->pid)];
    free(trace_data);
}

#ifdef __darwin_arm_thread_state64_ptrauth_strip
#undef __darwin_arm_thread_state64_ptrauth_strip
#endif
#define __darwin_arm_thread_state64_ptrauth_strip(state) ((void)(state))
#ifdef __darwin_arm_thread_state64_get_pc
#undef __darwin_arm_thread_state64_get_pc
#endif
#define __darwin_arm_thread_state64_get_pc(state) ((uintptr_t)0)
#define mach_msg(...) fixture_mach_msg(__VA_ARGS__)
#define pid_for_task fixture_pid_for_task
#define thread_get_state fixture_thread_get_state
#define mach_port_deallocate fixture_mach_port_deallocate
#ifdef mach_task_self
#undef mach_task_self
#endif
#define mach_task_self() fixture_mach_task_self()
#define mach_error_string fixture_mach_error_string
#define proc_get_path fixture_proc_get_path
#define vm_write fixture_vm_write
#ifndef PT_CONTINUE
#define PT_CONTINUE 7
#endif
#ifndef PT_DETACH
#define PT_DETACH 11
#endif
#define ptrace fixture_ptrace
#define roothide_patch_proc fixture_roothide_patch_proc
#define task_set_exception_ports fixture_task_set_exception_ports
#define kill fixture_kill
#define finish_process_trace fixture_finish_process_trace
#define JBLogError(...) ((void)0)
#define JBLogDebug(...) ((void)0)

#include "implementation.h"

#undef mach_msg
#undef pid_for_task
#undef thread_get_state
#undef mach_port_deallocate
#undef mach_task_self
#undef mach_error_string
#undef proc_get_path
#undef vm_write
#undef ptrace
#undef roothide_patch_proc
#undef task_set_exception_ports
#undef kill
#undef finish_process_trace

int main(int argc, const char *argv[])
{
    @autoreleasepool {
        if (argc != 2) return 2;
        if (!strcmp(argv[1], "pid-fail")) gScenario = 0;
        else if (!strcmp(argv[1], "no-trace")) gScenario = 1;
        else if (!strcmp(argv[1], "thread-state-fail")) gScenario = 2;
        else if (!strcmp(argv[1], "exception-state-fail")) gScenario = 3;
        else return 2;

        trace_data_lock = [[NSLock alloc] init];
        trace_data_record = [[NSMutableDictionary alloc] init];
        if (gScenario >= 2) {
            trace_data_t *trace_data = calloc(1, sizeof(*trace_data));
            trace_data->pid = 42;
            [trace_data_record setObject:[NSValue valueWithPointer:trace_data] forKey:@42];
        }
        exception_server((void *)(uintptr_t)999);
        return 3;
    }
}

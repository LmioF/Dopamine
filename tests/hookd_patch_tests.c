#include <assert.h>
#include <mach/mach.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static char events[64];
static unsigned eventCount;
static int targetPid;
static kern_return_t suspendResult;
static kern_return_t writableResult;
static kern_return_t writeResult;
static kern_return_t executableResult;
static kern_return_t resumeResult;
static kern_return_t terminateResult;
static vm_address_t patchAddress;
static vm_size_t patchSize;
static vm_address_t expectedProtectAddress;
static vm_size_t expectedProtectSize;

static void event(char value)
{
    assert(eventCount + 1 < sizeof(events));
    events[eventCount++] = value;
    events[eventCount] = 0;
}

static mach_port_t test_extract_task_port(mach_port_t client, mach_port_t target)
{
    assert(client == 100 && target == 200);
    event('E');
    return 300;
}

static kern_return_t test_pid_for_task(mach_port_t task, int *pid)
{
    assert(task == 300);
    event('P');
    *pid = targetPid;
    return KERN_SUCCESS;
}

static kern_return_t test_task_suspend(mach_port_t task)
{
    assert(task == 300);
    event('S');
    return suspendResult;
}

static kern_return_t test_task_resume(mach_port_t task)
{
    assert(task == 300);
    event('R');
    return resumeResult;
}

static kern_return_t test_task_terminate(mach_port_t task)
{
    assert(task == 300);
    event('T');
    return terminateResult;
}

static kern_return_t test_vm_protect(mach_port_t task, vm_address_t address, vm_size_t size, bool maximum, vm_prot_t protection)
{
    assert(task == 300 && address == expectedProtectAddress && size == expectedProtectSize && !maximum);
    if (protection == (VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY)) {
        event('W');
        return writableResult;
    }
    assert(protection == (VM_PROT_READ | VM_PROT_EXECUTE));
    event('X');
    return executableResult;
}

static kern_return_t test_vm_write(mach_port_t task, vm_address_t address, vm_offset_t data, mach_msg_type_number_t size)
{
    assert(task == 300 && address == patchAddress && data != 0 && size == patchSize);
    event('C');
    return writeResult;
}

static kern_return_t test_mach_port_mod_refs(mach_port_t task, mach_port_name_t port, mach_port_right_t right, mach_port_delta_t delta)
{
    assert(task == mach_task_self() && port == 300 && right == MACH_PORT_RIGHT_SEND && delta == -1);
    event('D');
    return KERN_SUCCESS;
}

#define extract_task_port test_extract_task_port
#define pid_for_task test_pid_for_task
#define task_suspend test_task_suspend
#define task_resume test_task_resume
#define task_terminate test_task_terminate
#define vm_protect test_vm_protect
#define vm_write test_vm_write
#define mach_port_mod_refs test_mach_port_mod_refs
#include "patch-under-test.h"

static void reset(void)
{
    eventCount = 0;
    events[0] = 0;
    targetPid = getpid() + 1;
    suspendResult = writableResult = writeResult = executableResult = resumeResult = terminateResult = KERN_SUCCESS;
    patchAddress = vm_page_size;
    patchSize = 4;
    expectedProtectAddress = vm_page_size;
    expectedProtectSize = vm_page_size;
}

static int patch(void)
{
    unsigned instruction = 0xd503201f;
    return apply_hook(100, 200, patchAddress, &instruction, patchSize);
}

int main(void)
{
    reset();
    assert(patch() == KERN_SUCCESS);
    assert(strcmp(events, "EPSWCXRD") == 0);
    reset();
    patchAddress = vm_page_size * 2 - 2;
    expectedProtectAddress = vm_page_size;
    expectedProtectSize = vm_page_size * 2;
    assert(patch() == KERN_SUCCESS);
    assert(strcmp(events, "EPSWCXRD") == 0);
    reset();
    suspendResult = KERN_FAILURE;
    assert(patch() == KERN_FAILURE);
    assert(strcmp(events, "EPSD") == 0);
    reset();
    writableResult = KERN_PROTECTION_FAILURE;
    assert(patch() == KERN_PROTECTION_FAILURE);
    assert(strcmp(events, "EPSWRD") == 0);
    reset();
    writeResult = KERN_INVALID_ADDRESS;
    assert(patch() == KERN_INVALID_ADDRESS);
    assert(strcmp(events, "EPSWCXRD") == 0);
    reset();
    executableResult = KERN_PROTECTION_FAILURE;
    assert(patch() == KERN_PROTECTION_FAILURE);
    assert(strcmp(events, "EPSWCXTD") == 0);
    reset();
    executableResult = KERN_PROTECTION_FAILURE;
    terminateResult = KERN_ABORTED;
    assert(patch() == KERN_ABORTED);
    assert(strcmp(events, "EPSWCXTD") == 0);
    reset();
    resumeResult = KERN_ABORTED;
    assert(patch() == KERN_ABORTED);
    assert(strcmp(events, "EPSWCXRD") == 0);
    reset();
    targetPid = getpid();
    assert(patch() == KERN_INVALID_ARGUMENT);
    assert(strcmp(events, "EPD") == 0);
    reset();
    patchAddress = ~(vm_address_t)0 - 1;
    patchSize = 4;
    assert(patch() == KERN_INVALID_ADDRESS);
    assert(events[0] == 0);
    puts("Hookd patch suspension, protection restoration, and error cleanup passed.");
    return 0;
}

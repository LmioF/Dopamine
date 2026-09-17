#include <errno.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <libkern/OSByteOrder.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../BaseBin/libjailbreak/src/codesign.h"

static unsigned failures, cases, rawCalls, trustCalls, diagnostics, allocations;
static int rpcResult, lastStatus;
static bool rawSuccess, checkedIn = true, forceNormalization = true;
static union { max_align_t alignment; uint8_t bytes[128]; } originalBlob;

static void check(bool condition, const char *message)
{
    if (!condition) { fprintf(stderr, "FAIL: %s\n", message); failures++; }
}
static bool jbinfo_is_checked_in(void) { return checkedIn; }
static bool proc_has_bootstrap_port(void) { return true; }
static bool jbinfo_should_force_cs_adhoc(void) { return forceNormalization; }
static bool superblob_is_adhoc_signed(const CS_SuperBlob *blob) { return true; }
static int superblob_find_cdflags_and_team_id(const CS_SuperBlob *blob, off_t *flags, off_t *team)
{
    *flags = sizeof(CS_SuperBlob);
    *team = sizeof(CS_SuperBlob) + sizeof(uint32_t);
    return 0;
}
static kern_return_t fixture_allocate(vm_map_t task, vm_address_t *address, vm_size_t size, int flags)
{
    void *buffer = malloc(size);
    if (!buffer) return KERN_RESOURCE_SHORTAGE;
    allocations++;
    *address = (vm_address_t)buffer;
    return KERN_SUCCESS;
}
static kern_return_t fixture_deallocate(vm_map_t task, vm_address_t address, vm_size_t size)
{
    check(address != 0 && allocations != 0, "release owned signature storage");
    free((void *)address);
    allocations--;
    return KERN_SUCCESS;
}
static CS_SuperBlob *load_signature(int fd, const fsignatures_t *signature)
{
    vm_address_t address = 0;
    if (fixture_allocate(0, &address, signature->fs_blob_size, 0)) return NULL;
    memcpy((void *)address, originalBlob.bytes, signature->fs_blob_size);
    return (CS_SuperBlob *)address;
}
static off_t fixture_lseek(int fd, off_t offset, int whence) { return whence == SEEK_CUR ? 25 : offset; }
static uint64_t msyscall_errno(uint64_t number, ...)
{
    rawCalls++;
    if (rawSuccess || (trustCalls && rpcResult == 0)) return 0;
    errno = EACCES;
    return UINT64_MAX;
}
static int jbclient_mach_trust_file(int fd, struct siginfo *info, bool attach)
{
    trustCalls++;
    check(fd == 7 && info && attach && info->source == SIGNATURE_SOURCE_PROC, "observe normalized attachment request");
    return rpcResult;
}
static int fixture_cerror(int error) { errno = error; return -1; }
static int fixture_dprintf(int fd, const char *format, ...)
{
    va_list arguments;
    va_start(arguments, format);
    lastStatus = va_arg(arguments, int);
    va_end(arguments);
    diagnostics++;
    return 0;
}

#define HOOK(name) fixture_hook
#define vm_allocate fixture_allocate
#define vm_deallocate fixture_deallocate
#define lseek fixture_lseek
#define cerror fixture_cerror
#define _simple_dprintf fixture_dprintf
#undef mach_task_self
#define mach_task_self() ((mach_port_t)99)
#include "implementation.h"

static void run(int command, int status, int expectedError)
{
    cases++;
    rawCalls = trustCalls = diagnostics = 0;
    lastStatus = 0;
    rpcResult = status;
    memset(originalBlob.bytes, 0, sizeof(originalBlob.bytes));
    CS_SuperBlob *blob = (CS_SuperBlob *)originalBlob.bytes;
    blob->length = OSSwapHostToBigInt32(sizeof(originalBlob.bytes));
    fsignatures_t input = {.fs_file_start = 123, .fs_blob_start = command == F_ADDSIGS ? originalBlob.bytes : (void *)(uintptr_t)4096,
        .fs_blob_size = sizeof(originalBlob.bytes), .fs_fsignatures_size = sizeof(input)};
    errno = ENOTTY;
    int result = fixture_hook(7, command, &input, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    if (rawSuccess) {
        check(result == 0 && rawCalls == 1 && !trustCalls && !diagnostics, "preserve original kernel-success fast path");
    } else if (!checkedIn || !forceNormalization) {
        check(result == -1 && errno == EACCES && rawCalls == 1 && !trustCalls, "preserve original failure for skipped normalization");
    } else {
        unsigned expectedCalls = command == F_ADDSIGS ? 0U : 1U;
        if (!status && (command == F_ADDFILESIGS_RETURN || command == F_ADDFILESIGS_INFO)) expectedCalls++;
        check(trustCalls == 1 && rawCalls == expectedCalls, "one normalized request with command-specific kernel output query");
        check(status == 0 ? result == 0 : result == -1 && errno == expectedError, "normalize foreign failure to fcntl -1 and mapped errno");
        if (status) {
            check(input.fs_file_start == 123, "failed attachment does not fabricate output");
            check(diagnostics == 1 && lastStatus == status, "retain raw status in failure diagnostic");
        } else {
            check(!diagnostics, "successful attachment has no failure diagnostic");
        }
    }
    check(allocations == 0, "all signature allocations released");
}

int main(void)
{
    const int commands[] = {F_ADDSIGS, F_ADDFILESIGS, F_ADDFILESIGS_RETURN, F_ADDFILESIGS_INFO};
    const struct { int status, error; } statuses[] = {
        {0, 0}, {KERN_FAILURE, EIO}, {MACH_RCV_TIMED_OUT, ETIMEDOUT}, {MACH_SEND_TIMED_OUT, ETIMEDOUT},
        {KERN_PROTECTION_FAILURE, EACCES}, {KERN_INVALID_ARGUMENT, EINVAL}, {KERN_RESOURCE_SHORTAGE, ENOMEM},
        {KERN_NO_SPACE, ENOMEM}, {MACH_SEND_INVALID_DEST, EPIPE}, {MACH_RCV_PORT_DIED, EPIPE}, {-1, EIO}, {-9, EIO}, {1234567, EIO},
    };
    for (unsigned c = 0; c < sizeof(commands) / sizeof(commands[0]); c++) {
        for (unsigned s = 0; s < sizeof(statuses) / sizeof(statuses[0]); s++) run(commands[c], statuses[s].status, statuses[s].error);
    }
    rawSuccess = true;
    run(F_ADDFILESIGS_RETURN, KERN_FAILURE, 0);
    rawSuccess = false;
    checkedIn = false;
    run(F_ADDFILESIGS_INFO, KERN_FAILURE, EACCES);
    checkedIn = true;
    forceNormalization = false;
    run(F_ADDSIGS, KERN_FAILURE, EACCES);
    printf("%u fcntl status cases, %u failures\n", cases, failures);
    return failures ? 1 : 0;
}

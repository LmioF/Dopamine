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

static const char *scenario;
static unsigned failures, rawCalls, trustCalls, allocations;
static bool attached;
static union { max_align_t alignment; uint8_t bytes[128]; } originalBlob;
static bool is(const char *name) { return !strcmp(scenario, name); }
static void check(bool condition, const char *message)
{
    if (!condition) { fprintf(stderr, "FAIL: %s\n", message); failures++; }
}
static bool jbinfo_is_checked_in(void) { return true; }
static bool proc_has_bootstrap_port(void) { return true; }
static bool jbinfo_should_force_cs_adhoc(void) { return true; }
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
    va_list arguments;
    va_start(arguments, number);
    int fd = va_arg(arguments, int);
    int command = va_arg(arguments, int);
    uint8_t *input = va_arg(arguments, void *);
    va_end(arguments);
    check(fd == 7, "preserve original descriptor");
    if (!attached && !is("initial-kernel-success")) { errno = EACCES; return UINT64_MAX; }
    if (strstr(scenario, "retry-error")) { errno = ENOSPC; return UINT64_MAX; }
    off_t start = 0;
    memcpy(&start, input, sizeof(start));
    check(start == 123, "query output using original slice offset");
    if (command == F_ADDFILESIGS_RETURN || command == F_ADDFILESIGS_INFO) {
        off_t end = 7777;
        memcpy(input, &end, sizeof(end));
    }
    if (command == F_ADDFILESIGS_INFO) {
        size_t advertised = 0;
        memcpy(&advertised, input + offsetof(fsignatures_t, fs_fsignatures_size), sizeof(advertised));
        if (advertised >= sizeof(fsignatures_t)) {
            memset(input + offsetof(fsignatures_t, fs_cdhash), 0x42, USER_FSIGNATURES_CDHASH_LEN);
            int hashType = 3;
            memcpy(input + offsetof(fsignatures_t, fs_hash_type), &hashType, sizeof(hashType));
        }
    }
    return 0;
}
static int jbclient_mach_trust_file(int fd, struct siginfo *info, bool attach)
{
    trustCalls++;
    check(fd == 7 && info && attach && info->source == SIGNATURE_SOURCE_PROC, "normalized attachment request");
    check(info->signature.fs_file_start == 123 && info->signature.fs_blob_size == sizeof(originalBlob.bytes), "preserve requested slice and signature extent");
    if (strstr(scenario, "rpc-error")) return KERN_FAILURE;
    attached = true;
    return 0;
}
static int fixture_cerror(int error) { errno = error; return -1; }
static int fixture_dprintf(int fd, const char *format, ...) { return 0; }

#define HOOK(name) fixture_hook
#define vm_allocate fixture_allocate
#define vm_deallocate fixture_deallocate
#define lseek fixture_lseek
#define cerror fixture_cerror
#define _simple_dprintf fixture_dprintf
#undef mach_task_self
#define mach_task_self() ((mach_port_t)99)
#include "implementation.h"

int main(int argc, const char *argv[])
{
    if (argc != 2) return 2;
    scenario = argv[1];
    int command = !strncmp(scenario, "info-", 5) || is("initial-kernel-success") ? F_ADDFILESIGS_INFO :
        is("proc-legacy") ? F_ADDSIGS : is("file-legacy") ? F_ADDFILESIGS : F_ADDFILESIGS_RETURN;
    size_t capacity = strstr(scenario, "legacy") ? offsetof(fsignatures_t, fs_fsignatures_size) :
        is("info-input-only") || is("info-zero-advertised") || is("info-short-advertised") ? offsetof(fsignatures_t, fs_cdhash) :
        is("info-future") ? sizeof(fsignatures_t) + 16 : sizeof(fsignatures_t);
    uint8_t *input = malloc(capacity);
    uint8_t *expected = malloc(capacity);
    if (!input || !expected) abort();
    memset(input, 0xA5, capacity);
    CS_SuperBlob *blob = (CS_SuperBlob *)originalBlob.bytes;
    blob->length = OSSwapHostToBigInt32(sizeof(originalBlob.bytes));
    fsignatures_t fields = {.fs_file_start = 123, .fs_blob_start = command == F_ADDSIGS ? originalBlob.bytes : (void *)(uintptr_t)4096,
        .fs_blob_size = sizeof(originalBlob.bytes)};
    memcpy(input, &fields, offsetof(fsignatures_t, fs_fsignatures_size));
    size_t advertised = is("info-zero-advertised") ? 0 : is("info-short-advertised") ? 24 : capacity;
    if (command == F_ADDFILESIGS_INFO) memcpy(input + offsetof(fsignatures_t, fs_fsignatures_size), &advertised, sizeof(advertised));
    memcpy(expected, input, capacity);
    bool error = strstr(scenario, "error") != NULL;
    if (!error && (command == F_ADDFILESIGS_RETURN || command == F_ADDFILESIGS_INFO)) {
        off_t end = 7777;
        memcpy(expected, &end, sizeof(end));
    }
    if (!error && command == F_ADDFILESIGS_INFO && advertised >= sizeof(fsignatures_t)) {
        memset(expected + offsetof(fsignatures_t, fs_cdhash), 0x42, USER_FSIGNATURES_CDHASH_LEN);
        int hashType = 3;
        memcpy(expected + offsetof(fsignatures_t, fs_hash_type), &hashType, sizeof(hashType));
    }
    errno = 0;
    int result = fixture_hook(7, command, input, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    check(error ? result == -1 && errno == (strstr(scenario, "rpc-error") ? EIO : ENOSPC) : result == 0, "preserve command completion and error domain");
    check(!memcmp(input, expected, capacity), "exact command-specific outputs with untouched input and extension bytes");
    if (is("initial-kernel-success")) check(rawCalls == 1 && !trustCalls, "original success needs no attachment request");
    else {
        check(trustCalls == 1, "one attachment request");
        unsigned expectedCalls = command == F_ADDSIGS ? 0 : 1;
        if ((command == F_ADDFILESIGS_RETURN || command == F_ADDFILESIGS_INFO) && !strstr(scenario, "rpc-error")) expectedCalls++;
        check(rawCalls == expectedCalls, "query kernel outputs only when required and attached");
    }
    check(!allocations, "temporary signature storage is released");
    free(input);
    free(expected);
    printf("%s: result=%d calls=%u failures=%u\n", scenario, result, rawCalls, failures);
    return failures ? 1 : 0;
}

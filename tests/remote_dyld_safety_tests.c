#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mach-o/loader.h>

typedef int kern_return_t;
typedef unsigned int mach_port_t;
typedef uintptr_t vm_address_t;
typedef uintptr_t vm_offset_t;
typedef size_t vm_size_t;

#ifndef KERN_SUCCESS
#define KERN_SUCCESS 0
#endif
#ifndef VM_PROT_READ
#define VM_PROT_READ 1
#define VM_PROT_WRITE 2
#define VM_PROT_EXECUTE 4
#define VM_PROT_COPY 0x10
#endif

static vm_address_t protected_address[16];
static vm_size_t protected_size[16];
static int protected_prot[16];
static unsigned protected_count;
static unsigned protect_calls, write_calls, copy_calls;
static unsigned fail_protect_call, fail_write_call, fail_copy_call;

static kern_return_t vm_protect(mach_port_t task, vm_address_t address, vm_size_t size, int set_maximum, int protection)
{
    (void)task; (void)set_maximum;
    protect_calls++;
    if (fail_protect_call == protect_calls) return 99;
    if (protected_count >= 16) return 99;
    protected_address[protected_count] = address;
    protected_size[protected_count] = size;
    protected_prot[protected_count] = protection;
    protected_count++;
    return KERN_SUCCESS;
}

static kern_return_t vm_write(mach_port_t task, vm_address_t address, vm_offset_t data, unsigned int size)
{
    (void)task;
    write_calls++;
    if (fail_write_call == write_calls) return 99;
    memcpy((void *)address, (const void *)data, size);
    return KERN_SUCCESS;
}

static kern_return_t vm_copy(mach_port_t task, vm_address_t source, vm_size_t size, vm_address_t dest)
{
    (void)task;
    copy_calls++;
    if (fail_copy_call == copy_calls) return 99;
    memmove((void *)dest, (const void *)source, size);
    return KERN_SUCCESS;
}

static kern_return_t vm_read_overwrite(mach_port_t task, vm_address_t address, vm_size_t size,
                                       vm_address_t data, vm_size_t *out_size)
{
    (void)task;
    memcpy((void *)data, (const void *)address, size);
    if (out_size) *out_size = size;
    return KERN_SUCCESS;
}

static const char *mach_error_string(kern_return_t kr) { (void)kr; return "mock"; }
#define JBLogError(...) do {} while (0)

#include "implementation.h"

static void require(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

static vm_size_t last_rx_size_for(vm_address_t address)
{
    vm_size_t size = 0;
    for (unsigned i = 0; i < protected_count; i++) {
        if (protected_address[i] == address && protected_prot[i] == (VM_PROT_READ | VM_PROT_EXECUTE)) {
            size = protected_size[i];
        }
    }
    return size;
}

static void reset_faults(void)
{
    protected_count = protect_calls = write_calls = copy_calls = 0;
    fail_protect_call = fail_write_call = fail_copy_call = 0;
}

static void test_entry_failure_rollback(void)
{
    uint8_t header[sizeof(struct mach_header_64)];
    uint8_t entry[5 * sizeof(uint32_t)];
    uint8_t original_header[sizeof(header)];
    uint8_t original_entry[sizeof(entry)];
    memset(header, 0x41, sizeof(header));
    memset(entry, 0x52, sizeof(entry));
    memcpy(original_header, header, sizeof(header));
    memcpy(original_entry, entry, sizeof(entry));

    reset_faults();
    fail_protect_call = 2;
    require(hook_dyld_entry(1, (vm_address_t)header, (vm_address_t)entry, 0x3000) != 0,
            "entry hook protection failure was not reported");
    require(memcmp(header, original_header, sizeof(header)) == 0 &&
            memcmp(entry, original_entry, sizeof(entry)) == 0,
            "entry hook protection failure did not restore prior bytes");

    memset(header, 0x41, sizeof(header));
    memset(entry, 0x52, sizeof(entry));
    reset_faults();
    fail_write_call = 2;
    require(hook_dyld_entry(1, (vm_address_t)header, (vm_address_t)entry, 0x3000) != 0,
            "entry hook write failure was not reported");
    require(memcmp(header, original_header, sizeof(header)) == 0 &&
            memcmp(entry, original_entry, sizeof(entry)) == 0,
            "entry hook write failure did not restore prior bytes");

    memset(header, 0x41, sizeof(header));
    memset(entry, 0x52, sizeof(entry));
    reset_faults();
    fail_protect_call = 3;
    require(hook_dyld_entry(1, (vm_address_t)header, (vm_address_t)entry, 0x3000) != 0,
            "entry hook RX failure was not reported");
    require(memcmp(header, original_header, sizeof(header)) == 0 &&
            memcmp(entry, original_entry, sizeof(entry)) == 0,
            "entry hook RX failure did not restore prior bytes");
}

static void test_function_failure_rollback(void)
{
    uint8_t old_function[5 * sizeof(uint32_t)];
    uint8_t trampoline[10 * sizeof(uint32_t)];
    uint8_t original_function[sizeof(old_function)];
    uint8_t original_trampoline[sizeof(trampoline)];
    memset(old_function, 0x63, sizeof(old_function));
    memset(trampoline, 0x74, sizeof(trampoline));
    memcpy(original_function, old_function, sizeof(old_function));
    memcpy(original_trampoline, trampoline, sizeof(trampoline));

    reset_faults();
    fail_protect_call = 3;
    require(hook_dyld_function(1, (vm_address_t)old_function, 0x4000, (vm_address_t)trampoline) != 0,
            "function hook publication failure was not reported");
    require(memcmp(old_function, original_function, sizeof(old_function)) == 0 &&
            memcmp(trampoline, original_trampoline, sizeof(trampoline)) == 0,
            "function hook publication failure did not restore prior bytes");

    memset(old_function, 0x63, sizeof(old_function));
    memset(trampoline, 0x74, sizeof(trampoline));
    reset_faults();
    fail_write_call = 2;
    require(hook_dyld_function(1, (vm_address_t)old_function, 0x4000, (vm_address_t)trampoline) != 0,
            "function hook write failure was not reported");
    require(memcmp(old_function, original_function, sizeof(old_function)) == 0 &&
            memcmp(trampoline, original_trampoline, sizeof(trampoline)) == 0,
            "function hook write failure did not restore prior bytes");

    memset(old_function, 0x63, sizeof(old_function));
    memset(trampoline, 0x74, sizeof(trampoline));
    reset_faults();
    fail_protect_call = 4;
    require(hook_dyld_function(1, (vm_address_t)old_function, 0x4000, (vm_address_t)trampoline) != 0,
            "function hook RX failure was not reported");
    require(memcmp(old_function, original_function, sizeof(old_function)) == 0 &&
            memcmp(trampoline, original_trampoline, sizeof(trampoline)) == 0,
            "function hook RX failure did not restore prior bytes");
}

int main(void)
{
    uint8_t header[sizeof(struct mach_header_64)] = {0};
    uint8_t entry_bytes[5 * sizeof(uint32_t)] = {0};
    uint8_t function_bytes[5 * sizeof(uint32_t)] = {0};
    uint8_t trampoline_bytes[10 * sizeof(uint32_t)] = {0};

    reset_faults();
    vm_address_t entry = (vm_address_t)entry_bytes;
    require(hook_dyld_entry(1, (vm_address_t)header, entry, 0x3000) == 0, "entry hook failed");
    require(last_rx_size_for(entry) == 5 * sizeof(uint32_t), "entry hook did not restore execute over all 20 bytes");

    reset_faults();
    vm_address_t function = (vm_address_t)function_bytes;
    require(hook_dyld_function(1, function, 0x4000, (vm_address_t)trampoline_bytes) == 0, "function hook failed");
    require(last_rx_size_for(function) == 5 * sizeof(uint32_t), "function hook did not restore execute over all 20 bytes");

    test_entry_failure_rollback();
    test_function_failure_rollback();
    puts("remote dyld hook protection ranges passed");
    return 0;
}

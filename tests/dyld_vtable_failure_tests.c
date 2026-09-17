#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int kern_return_t;
typedef uint64_t mach_vm_address_t;
#define mach_task_self_ 1
#define VM_PROT_READ 1
#define VM_PROT_WRITE 2
#define VM_PROT_COPY 4
#define ptrauth_key_process_independent_data 0
#define ptrauth_key_process_independent_code 1
#define ptrauth_key_function_pointer 2
#define ptrauth_auth_data(value, key, discriminator) ((void)(key), (void)(discriminator), (value))
#define ptrauth_auth_and_resign(value, oldkey, olddisc, newkey, newdisc) ((void)(oldkey), (void)(olddisc), (void)(newkey), (void)(newdisc), (value))

static int protect_results[2];
static unsigned protect_calls;
static void *slots[128];
static void *interface_value = slots;
static void **interface_pointer = &interface_value;
static void *original_value;

static int vm_protect(int task, mach_vm_address_t address, size_t size, bool maximum, int protection)
{
    (void)task; (void)address; (void)size; (void)maximum; (void)protection;
    if (protect_calls >= 2) return -99;
    return protect_results[protect_calls++];
}

static void roothide_loader_trace(const char *phase, const char *path, int result)
{
    (void)phase; (void)path; (void)result;
}

#include "implementation.h"

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    slots[14] = (void *)(uintptr_t)0x1234;
    if (!strcmp(argv[1], "writable-failure")) {
        protect_results[0] = 5;
    } else if (!strcmp(argv[1], "restore-failure")) {
        protect_results[0] = 0;
        protect_results[1] = 7;
    } else if (!strcmp(argv[1], "success")) {
        protect_results[0] = protect_results[1] = 0;
    } else return 2;
    int result = HOOK_CALL(interface_pointer, 14, (void *)(uintptr_t)0x5678, &original_value, 0xBF31);
    if (!strcmp(argv[1], "success")) return result == 0 ? 0 : 1;
    return result != 0 ? 0 : 1;
}

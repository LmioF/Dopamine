#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

typedef uint64_t vm_address_t;
static uint32_t template_words[4];
#define hook_trampoline_template template_words
#define hook_trampoline_template_end (template_words + 4)
#define hook_trampoline_template_call (template_words + 1)
#define hook_trampoline_template_jmpback (template_words + 2)
static void hookd_intercept_syscall(void) {}

static int writer_calls;
static int fail_first_write;
static uint32_t arm64_gen_b(vm_address_t origin, vm_address_t target) { (void)origin; (void)target; return 0x14000001; }
static uint32_t arm64_gen_bl(vm_address_t origin, vm_address_t target) { (void)origin; (void)target; return 0x94000001; }
static int litehook_hook_memory(void *target, const void *source, size_t size)
{
    (void)target; (void)source; (void)size;
    writer_calls++;
    if (fail_first_write && writer_calls == 1) return 5;
    return 0;
}

#include "implementation.h"

int main(void)
{
    uint32_t patchpoint[2] = {0};
    uint32_t shellcode[4] = {0};
    size_t emitted = 0;
    fail_first_write = 1;
    int result = emit_hookd_svc_trampoline(patchpoint, shellcode, &emitted);
    if (result == 0) return 1;
    if (writer_calls != 1) return 2;
    if (emitted != 0) return 3;
    puts("ok");
    return 0;
}

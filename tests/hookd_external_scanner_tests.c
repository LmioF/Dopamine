#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint64_t vm_address_t;
typedef uint64_t vm_size_t;
typedef int kern_return_t;
#define KERN_SUCCESS 0
static int mach_task_self(void) { return 1; }

static uint32_t template_words[4];
#define hook_trampoline_template template_words
#define hook_trampoline_template_end (template_words + 4)

static unsigned char trampoline_page[0x4000];
static int emit_calls;
static int emit_fail_at = -1;
static int vm_allocate_nearby(int task, vm_address_t base, vm_size_t size, vm_address_t *out,
                              vm_size_t alloc_size, uint64_t range)
{
    (void)task; (void)base; (void)size; (void)alloc_size; (void)range;
    *out = (vm_address_t)trampoline_page;
    return KERN_SUCCESS;
}
static int emit_hookd_svc_trampoline(uint32_t *patchpoint, uint32_t *shellcode, size_t *emitted)
{
    (void)patchpoint;
    if ((unsigned char *)shellcode < trampoline_page ||
        (unsigned char *)shellcode + 16 > trampoline_page + sizeof(trampoline_page)) return 99;
    int current = emit_calls++;
    if (current == emit_fail_at) return 7;
    *emitted = 4;
    return 0;
}

#include "implementation.h"

int main(int argc, char **argv)
{
    if (argc != 2) return 100;
    size_t count = !strcmp(argv[1], "capacity") ? 1025 : 3;
    uint32_t *text = calloc(count, sizeof(*text));
    if (!text) return 101;
    for (size_t i = 0; i < count; i++) text[i] = 0xd4001001;
    if (!strcmp(argv[1], "emission-fail")) emit_fail_at = 1;

    int result = apply_hookd_syscall_patches(text, count * sizeof(*text));
    free(text);
    if (!strcmp(argv[1], "success")) {
        if (result != 0 || emit_calls != 3) return 1;
    } else {
        if (result == 0) return 2;
    }
    puts("ok");
    return 0;
}

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "../BaseBin/_external/include/libkrw/libkrw_plugin.h"

typedef unsigned mach_port_t;
static bool fixture_modern = true;
static uint64_t fixture_address = 0x100000;
static unsigned surfaces, detachments, legacy_calls;
static mach_port_t IOSurface_kalloc_getSurfacePort_16up(uint64_t size) { surfaces++; return 42; }
static uint64_t IOSurface_port_getSendRight(mach_port_t port) { return 1; }
static uint64_t IOSurfaceSendRight_get_surface(uint64_t right) { return 2; }
static uint64_t IOSurface_get_ranges(uint64_t surface) { return fixture_address; }
static uint64_t IOSurface_get_rangeCount(uint64_t surface) { return 0x1000; }
static void IOSurface_set_ranges(uint64_t surface, uint64_t value) { detachments++; }
static void IOSurface_set_rangeCount(uint64_t surface, uint64_t value) { detachments++; }
static mach_port_t mach_task_self(void) { return 1; }
static int mach_port_deallocate(mach_port_t task, mach_port_t port) { return 0; }
static uint64_t IOSurface_kalloc_15(uint64_t size, bool leak) { legacy_calls++; return fixture_address; }
static struct {
    int (*kalloc_global)(uint64_t *, uint64_t);
    int (*kalloc_local)(uint64_t *, uint64_t);
} gPrimitives;
static void load_primitives_once(void) {}
static int kbase_wrapper(uint64_t *address) { return -1; }
static int kreadbuf(uint64_t from, void *to, size_t size) { return -1; }
static int kwritebuf_wrapper(void *from, uint64_t to, size_t size) { return -1; }
static int kfree(uint64_t address, uint64_t size) { return -1; }

#include "implementation.h"

int main(void)
{
    gPrimitives.kalloc_global = IOSurface_kalloc_global;
    gPrimitives.kalloc_local = IOSurface_kalloc_local;
    struct krw_handlers_s handlers = {0};
    if (krw_initializer(&handlers)) return 2;
    int (*entrypoints[])(uint64_t *, uint64_t) = {
        IOSurface_kalloc_global, IOSurface_kalloc_local, (void *)handlers.kmalloc,
    };
    const uint64_t sizes[] = {16, 65536, 65537, UINT64_MAX};
    int failures = 0;
    int cases = 0;
    for (unsigned entry = 0; entry < 3; entry++) {
        for (unsigned index = 0; index < 4; index++) {
            surfaces = detachments = 0;
            uint64_t address = 123;
            int result = entrypoints[entry](&address, sizes[index]);
            bool success = sizes[index] <= 65536;
            unsigned expected_detachments = success && entry != 1 ? 2 : 0;
            if (result != (success ? 0 : -1) || address != (success ? fixture_address : 123) ||
                surfaces != (unsigned)success || detachments != expected_detachments) {
                fprintf(stderr, "entry=%u size=%llu result=%d address=%llx surfaces=%u detachments=%u\n",
                        entry, (unsigned long long)sizes[index], result, (unsigned long long)address, surfaces, detachments);
                failures++;
            }
            cases++;
        }
    }
    fixture_address = 0;
    for (unsigned entry = 0; entry < 3; entry++) {
        uint64_t address = 123;
        if (entrypoints[entry](&address, 16) != -1 || address != 123) failures++;
        cases++;
    }
    fixture_modern = false;
    fixture_address = 0x200000;
    for (unsigned entry = 0; entry < 2; entry++) {
        uint64_t address = 0;
        if (entrypoints[entry](&address, 65537) != 0 || address != fixture_address) failures++;
        cases++;
    }
    if (legacy_calls != 2) failures++;
    printf("%d allocation result cases, %d failures; IOSurface and memory operations are mocked\n", cases, failures);
    return failures ? 1 : 0;
}

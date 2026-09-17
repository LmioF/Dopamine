#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

enum { BUFFER, CONTAINER, SECTION, MAPPING };
typedef struct Resource {
    int kind;
    bool alive;
    struct Resource *parent;
} Resource;
typedef Resource Fat;
typedef Resource MachO;
typedef Resource PFSection;

static Resource pool[128];
static unsigned allocated, live, invalid, closes;
static int expected_fd = -1;
static Resource *resource(int kind, Resource *parent)
{
    if (allocated >= sizeof(pool) / sizeof(pool[0])) return NULL;
    Resource *result = &pool[allocated++];
    *result = (Resource){kind, true, parent};
    live++;
    return result;
}
static void release_resource(void *pointer, int kind)
{
    if (!pointer) return;
    Resource *object = pointer;
    if (pointer == MAP_FAILED) { invalid++; return; }
    if (!object->alive || object->kind != kind) { invalid++; return; }
    for (unsigned i = 0; i < allocated; i++) {
        if (pool[i].alive && pool[i].parent == object) invalid++;
    }
    object->alive = false;
    live--;
}
static void fixture_free(void *pointer) { release_resource(pointer, BUFFER); }
static void pfsec_free(PFSection *section) { release_resource(section, SECTION); }
static void fat_free(Fat *container) { release_resource(container, CONTAINER); }
static int fixture_munmap(void *pointer, size_t length)
{
    if (length != 4096) invalid++;
    release_resource(pointer, MAPPING);
    return 0;
}
static int fixture_close(int fd)
{
    if (fd != expected_fd || expected_fd < 0 || closes) invalid++;
    closes++;
    return 0;
}

#define free fixture_free
#define munmap fixture_munmap
#define close fixture_close
#include "implementation.h"
#undef free
#undef munmap
#undef close

static void initialize_monitors(unsigned mask)
{
    if (mask & 1) gXPF.decompressedSptm = resource(BUFFER, NULL);
    if (mask & 2) gXPF.sptmContainer = resource(CONTAINER, gXPF.decompressedSptm);
    if (mask & 4) gXPF.sptmTextSection = resource(SECTION, gXPF.sptmContainer);
    if (mask & 8) gXPF.sptmStringSection = resource(SECTION, gXPF.sptmContainer);
    if (mask & 16) gXPF.decompressedTxm = resource(BUFFER, NULL);
    if (mask & 32) gXPF.txmContainer = resource(CONTAINER, gXPF.decompressedTxm);
    if (mask & 64) gXPF.txmTextSection = resource(SECTION, gXPF.txmContainer);
    if (mask & 128) gXPF.txmStringSection = resource(SECTION, gXPF.txmContainer);
    gXPF.sptm = (MachO *)gXPF.sptmContainer;
    gXPF.txm = (MachO *)gXPF.txmContainer;
}
static void reset_fixture(void)
{
    memset(pool, 0, sizeof(pool));
    allocated = live = invalid = closes = 0;
    expected_fd = -1;
    gXPF = (XPF){.kernelFd = -1};
}
static int check_stop(const char *name, unsigned index)
{
    xpf_stop();
    xpf_stop();
    if (live || invalid || closes != (unsigned)(expected_fd >= 0) || gXPF.kernelFd != -1) {
        fprintf(stderr, "%s %u: live=%u invalid=%u closes=%u fd=%d\n",
                name, index, live, invalid, closes, gXPF.kernelFd);
        return 1;
    }
    return 0;
}
int main(void)
{
    int failures = check_stop("initial", 0);
    unsigned cases = 1;
    for (unsigned mask = 0; mask < 256; mask++) {
        reset_fixture();
        initialize_monitors(mask);
        failures += check_stop("monitor-mask", mask);
        cases++;
    }
    for (int selected = -1; selected < KERNEL_SECTION_COUNT; selected++) {
        reset_fixture();
        initialize_kernel(selected);
        initialize_monitors(255);
        expected_fd = 42;
        failures += check_stop("kernel-section", (unsigned)(selected + 1));
        cases++;
    }
    reset_fixture();
    gXPF.mappedKernel = MAP_FAILED;
    gXPF.kernelSize = 4096;
    failures += check_stop("failed-mapping", 0);
    reset_fixture();
    gXPF.kernelFd = expected_fd = 0;
    failures += check_stop("owned-zero-fd", 0);
    cases += 2;
    printf("XPF teardown: %d failures across %u cases; no firmware or real descriptors\n", failures, cases);
    return failures ? 1 : 0;
}

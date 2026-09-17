#import <Foundation/Foundation.h>
#include <mach-o/loader.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uuid/uuid.h>

typedef struct MachO { int unused; } MachO;
static MachO gMacho;
static int gScenario;
static int gFreed;

static MachO *macho_init_for_writing(const char *path)
{
    (void)path;
    return gScenario == 1 ? NULL : &gMacho;
}

static void macho_enumerate_symbols(MachO *macho, void (^block)(const char *, uint8_t, uint64_t, bool *))
{
    (void)macho;
    if (gScenario == 2) return;
    bool stop = false;
    block("__ZN5dyld413ProcessConfig8Security7getAMFIERKNS0_7ProcessERNS_15SyscallDelegateE", 0, 0x1000, &stop);
}

static int macho_write_at_vmaddr(MachO *macho, uint64_t address, size_t size, const void *bytes)
{
    (void)macho; (void)address; (void)size; (void)bytes;
    return gScenario == 3 ? -1 : 0;
}

static void macho_enumerate_load_commands(MachO *macho, void (^block)(struct load_command, uint64_t, void *, bool *))
{
    (void)macho;
    if (gScenario == 4) return;
    struct uuid_command command = { .cmd = LC_UUID, .cmdsize = sizeof(command) };
    bool stop = false;
    block(*(struct load_command *)&command, 0x200, &command, &stop);
}

static int macho_write_at_offset(MachO *macho, uint64_t offset, size_t size, const void *bytes)
{
    (void)macho; (void)offset; (void)size; (void)bytes;
    return gScenario == 5 ? -1 : 0;
}

static void macho_free(MachO *macho)
{
    if (macho) gFreed++;
}

#include "implementation.h"

static void check(bool condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

int main(int argc, const char *argv[])
{
    @autoreleasepool {
        if (argc != 2) return 2;
        gScenario = atoi(argv[1]);
        gFreed = 0;
        int result = apply_dyld_patch(@"/fixture", "DOPA3.0");
        if (gScenario == 1) {
            check(result != 0 && gFreed == 0, "open refusal");
        }
        else if (gScenario >= 2 && gScenario <= 5) {
            check(result != 0, "patch refusal must propagate");
            check(gFreed == 1, "MachO must be released on patch refusal");
        }
        else if (gScenario == 0) {
            check(result == 0 && gFreed == 1, "successful patch");
        }
        else {
            return 2;
        }
        return 0;
    }
}

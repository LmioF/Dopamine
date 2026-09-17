#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <mach-o/loader.h>
#include <mach/machine.h>

#define CPU_SUBTYPE_ARM64E_ABI_V2 0x80000000

typedef struct { struct mach_header header; } MachO;
typedef long dispatch_once_t;
static bool host_arm64e;
static void dispatch_once(dispatch_once_t *token, void (^block)(void)) { if (!*token) { *token = 1; block(); } }
static void host_get_cpu_information(cpu_type_t *type, cpu_subtype_t *subtype)
{
    *type = CPU_TYPE_ARM64;
    *subtype = host_arm64e ? CPU_SUBTYPE_ARM64E : CPU_SUBTYPE_ARM64_ALL;
}
static struct mach_header *macho_get_mach_header(MachO *macho) { return &macho->header; }

#include "implementation.h"

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    host_arm64e = !strcmp(argv[1], "arm64e");
    struct { cpu_type_t type; cpu_subtype_t subtype; uint32_t filetype; bool ordinary, authenticated; } cases[] = {
        {CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, MH_EXECUTE, true, true},
        {CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_V8, MH_DYLIB, true, true},
        {CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E, MH_EXECUTE, false, false},
        {CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E, MH_DYLIB, false, true},
        {CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E, MH_BUNDLE, false, true},
        {CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E | CPU_SUBTYPE_ARM64E_ABI_V2, MH_EXECUTE, false, true},
        {CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E | CPU_SUBTYPE_ARM64E_ABI_V2, MH_DYLIB, false, true},
        {CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, MH_DYLIB, false, false},
    };
    int failures = 0;
    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        MachO macho = {.header = {.cputype = cases[i].type, .cpusubtype = cases[i].subtype, .filetype = cases[i].filetype}};
        bool expected = host_arm64e ? cases[i].authenticated : cases[i].ordinary;
        if (macho_is_mappable(&macho) != expected) { fprintf(stderr, "host=%s case=%u incorrect slice admission\n", argv[1], i); failures++; }
    }
    printf("%s: 8 slice-admission cases, %d failures\n", argv[1], failures);
    return failures ? 1 : 0;
}

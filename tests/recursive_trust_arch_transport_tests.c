#define _DARWIN_C_SOURCE 1
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <xpc/xpc.h>
#include "../BaseBin/libjailbreak/src/jbserver_domains.h"

static const char *mode;
static struct mach_header_64 caller_header;
static struct mach_header_64 main_header;
static unsigned send_calls;
static uint64_t observed_type;
static uint64_t observed_subtype;

static int fixture_dladdr(const void *address, Dl_info *info)
{
    if (!address || strcmp(mode, "caller")) return 0;
    memset(info, 0, sizeof(*info));
    info->dli_fbase = &caller_header;
    return 1;
}

static const struct mach_header *fixture_main_header(uint32_t index)
{
    return index == 0 ? (const struct mach_header *)&main_header : NULL;
}

static bool fixture_shared_cache_contains_path(const char *path) { return false; }
static int fixture_access(const char *path, int mode_arg) { return 0; }
static int fixture_get_executable_path(char *buffer, uint32_t *size)
{
    const char value[] = "/fixture/main";
    if (*size < sizeof(value)) return -1;
    memcpy(buffer, value, sizeof(value));
    return 0;
}
static char *fixture_getcwd(char *buffer, size_t size) { return strdup("/fixture"); }
const char *dyld_image_path_containing_address(const void *address) { return "/fixture/caller.dylib"; }

static xpc_object_t fixture_send(uint64_t domain, uint64_t action, xpc_object_t args)
{
    send_calls++;
    xpc_object_t arches = xpc_dictionary_get_value(args, "preferred-archs");
    if (arches && xpc_get_type(arches) == XPC_TYPE_ARRAY && xpc_array_get_count(arches) == 1) {
        xpc_object_t arch = xpc_array_get_value(arches, 0);
        observed_type = xpc_dictionary_get_uint64(arch, "type");
        observed_subtype = xpc_dictionary_get_uint64(arch, "subtype");
    }
    xpc_object_t reply = xpc_dictionary_create_empty();
    xpc_dictionary_set_int64(reply, "result", 0);
    return reply;
}

#define dladdr fixture_dladdr
#define _dyld_get_image_header fixture_main_header
#define _dyld_shared_cache_contains_path fixture_shared_cache_contains_path
#define access fixture_access
#define _NSGetExecutablePath fixture_get_executable_path
#define getcwd fixture_getcwd
#define jbserver_xpc_send fixture_send
#include "implementation.h"

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    mode = argv[1];
    caller_header = (struct mach_header_64){
        .magic = MH_MAGIC_64,
        .cputype = CPU_TYPE_ARM64,
        .cpusubtype = CPU_SUBTYPE_ARM64E | 0x80000000,
    };
    main_header = (struct mach_header_64){
        .magic = MH_MAGIC_64,
        .cputype = CPU_TYPE_ARM64,
        .cpusubtype = CPU_SUBTYPE_ARM64_ALL,
    };

    void *caller = !strcmp(mode, "caller") ? (void *)0x1234 : NULL;
    int result = jbclient_trust_library_recurse("/fixture/library.dylib", caller);
    uint64_t expected_subtype = (uint32_t)(!strcmp(mode, "caller") ? caller_header.cpusubtype : main_header.cpusubtype);
    unsigned failures = result != 0 || send_calls != 1 || observed_type != CPU_TYPE_ARM64 || observed_subtype != expected_subtype;
    printf("%s: result=%d sends=%u type=%llu subtype=%llu failures=%u\n",
           mode, result, send_calls, observed_type, observed_subtype, failures);
    return failures ? 1 : 0;
}

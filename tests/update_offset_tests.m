#import <Foundation/Foundation.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <xpc/xpc.h>

#define CHECK(value) do { if (!(value)) { fprintf(stderr, "line %d: %s\n", __LINE__, #value); exit(1); } } while (0)

static xpc_object_t merged;
static unsigned stopped, closed, initialized;
static const char *failure;
static const char *xpfError;

static const char *prebootUUIDPath(const char *path) { return path; }
static int mock_access(const char *path, int mode) { (void)path; (void)mode; return -1; }
static void *mock_dlopen(const char *path, int mode) { (void)path; (void)mode; return &closed; }
static int mock_dlclose(void *handle) { CHECK(handle == &closed); closed++; return 0; }
static int mock_start(const char *kernel, const char *sptm, const char *txm)
{
    CHECK(kernel && !sptm && !txm);
    return 0;
}
static const char *mock_error(void) { return xpfError; }
static void mock_stop(void) { stopped++; }
static bool mock_supported(const char *name)
{
    return !strcmp(name, "devmode") || !strcmp(name, "perfkrw");
}
static xpc_object_t mock_construct(const char *sets[])
{
    const char *supported[] = {"translation", "trustcache", "sandbox", "physmap", "struct", "physrw", "IOSurface", "devmode", "perfkrw", NULL};
    for (unsigned i = 0; sets[i]; ++i) {
        bool found = false;
        for (unsigned j = 0; supported[j]; ++j) found |= !strcmp(sets[i], supported[j]);
        if (!found) { xpfError = "unsupported XPF set"; return NULL; }
    }
    xpc_object_t result = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_uint64(result, "kernelStruct.proc.fd", 0x38);
    return result;
}
static void *mock_dlsym(void *handle, const char *symbol)
{
    CHECK(handle == &closed);
    if (!strcmp(symbol, "xpf_start_with_kernel_path")) return mock_start;
    if (!strcmp(symbol, "xpf_get_error")) return mock_error;
    if (!strcmp(symbol, "xpf_stop")) return mock_stop;
    if (!strcmp(symbol, "xpf_set_is_supported")) return mock_supported;
    if (!strcmp(symbol, "xpf_construct_offset_dictionary")) return mock_construct;
    CHECK(false);
    return NULL;
}
static xpc_object_t jbinfo_get_serialized(void)
{
    xpc_object_t result = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_uint64(result, "kernelSymbol.nchashtbl", 0xfffffff00a9b2b48);
    xpc_dictionary_set_uint64(result, "kernelSymbol.nchashmask", 0xfffffff00a9b2b50);
    xpc_dictionary_set_uint64(result, "kernelSymbol.launch_env_logging", 0xfffffff00abf9368);
    xpc_dictionary_set_uint64(result, "kernelSymbol.developer_mode_status", 0xfffffff00abf91d8);
    xpc_dictionary_set_uint64(result, "kernelStruct.proc.fd", 0x30);
    return result;
}
static void jbinfo_initialize_dynamic_offsets(xpc_object_t info) { merged = info; }
static void jbinfo_initialize_hardcoded_offsets(void) { initialized++; }

#define access mock_access
#define dlopen mock_dlopen
#define dlclose mock_dlclose
#define dlsym mock_dlsym
#define abort_with_reason(ns, code, message, flags) do { failure = strdup(message); } while (0)
#include "update-under-test.h"

int main(void)
{
    @autoreleasepool {
        jbupdate_update_system_info();
        if (failure) fprintf(stderr, "Update failed: %s\n", failure);
        CHECK(!failure && merged);
        CHECK(stopped == 1 && closed == 1 && initialized == 1);
        CHECK(xpc_dictionary_get_uint64(merged, "kernelStruct.proc.fd") == 0x38);
        CHECK(xpc_dictionary_get_uint64(merged, "kernelSymbol.nchashtbl") == 0xfffffff00a9b2b48);
        CHECK(xpc_dictionary_get_uint64(merged, "kernelSymbol.nchashmask") == 0xfffffff00a9b2b50);
        CHECK(xpc_dictionary_get_uint64(merged, "kernelSymbol.launch_env_logging") == 0xfffffff00abf9368);
        CHECK(xpc_dictionary_get_uint64(merged, "kernelSymbol.developer_mode_status") == 0xfffffff00abf91d8);
        puts("Hot-update XPF sets and boot-resolved roothide state passed");
    }
    return 0;
}

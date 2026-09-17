#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void *legacy_object[1];
static void *modern_object[1];
static void **legacy_pointer = legacy_object;
static void **modern_pointer = modern_object;
static bool legacy_available;
static bool modern_available;
static bool fail_hook;
static unsigned direct_calls;
static unsigned dispatch_calls;
static void *dyld_dlsym_orig;
static void *dyld_dlsym_hook;

static void *litehook_find_dsc_symbol(const char *image, const char *symbol)
{
    if (strcmp(image, "/usr/lib/system/libdyld.dylib") != 0) return NULL;
    if (!strcmp(symbol, "__ZN5dyld45gDyldE")) return legacy_available ? &legacy_pointer : NULL;
    if (!strcmp(symbol, "__ZN5dyld45gAPIsE")) return modern_available ? &modern_pointer : NULL;
    return NULL;
}

static int dyld_hook_routine(void **object, int slot, void *hook, void **original, uint16_t salt)
{
    (void)hook; (void)original;
    direct_calls++;
    if (object == legacy_object) {
        if (slot != 17 || salt != 0x839D) return -90;
    } else if (object == modern_object) {
        if (slot != 16 || salt != 0x839D) return -91;
    } else return -92;
    return fail_hook ? -7 : 0;
}

static int dyld_hook_dispatch(void ***interface, const char *symbol, unsigned arguments,
                              unsigned slot, void *hook, void **original, uint16_t salt)
{
    (void)hook; (void)original;
    dispatch_calls++;
    if (interface != &modern_pointer || strcmp(symbol, "_dlsym") || arguments != 2 || slot != 16 || salt != 0x839D)
        return -93;
    return fail_hook ? -8 : 0;
}

#include "implementation.h"

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    legacy_available = !strncmp(argv[1], "legacy", 6);
    modern_available = !strncmp(argv[1], "modern", 6);
    fail_hook = strstr(argv[1], "failure") != NULL;
    int result = init_dlsym_hook();
    if (!strcmp(argv[1], "missing")) return result != 0 && direct_calls == 0 && dispatch_calls == 0 ? 0 : 1;
    if (fail_hook && result == 0) return 1;
    if (!fail_hook && result != 0) return 1;
#ifdef __arm64e__
    if (modern_available) return dispatch_calls == 1 && direct_calls == 0 ? 0 : 1;
#endif
    return direct_calls == 1 && dispatch_calls == 0 ? 0 : 1;
}

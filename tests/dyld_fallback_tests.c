#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

#define CHECK(condition) do { if (!(condition)) { fprintf(stderr, "line %d: %s\n", __LINE__, #condition); exit(1); } } while (0)

static bool legacy_available;
static bool modern_available;
static void *legacy_object[1];
static void *modern_object[1];
static void **legacy_pointer = legacy_object;
static void **modern_pointer = modern_object;
static unsigned registration_count;
static unsigned dispatch_count;
static unsigned registration_attempts;
static int fail_attempt = -1;
static struct {
    void **object;
    int slot;
    void *hook;
    void **original;
    uint16_t salt;
} registrations[4];

static unsigned trust_count;
static const char *trusted_path;
static void *trusted_caller;
static void *received_object;
static const char *received_path;
static int received_mode;
static void *received_caller;
static unsigned original_count;
static char result_handle;

static void *litehook_find_dsc_symbol(const char *image, const char *symbol)
{
    CHECK(strcmp(image, "/usr/lib/system/libdyld.dylib") == 0);
    if (strcmp(symbol, "__ZN5dyld45gDyldE") == 0) return legacy_available ? &legacy_pointer : NULL;
    if (strcmp(symbol, "__ZN5dyld45gAPIsE") == 0) return modern_available ? &modern_pointer : NULL;
    CHECK(false);
    return NULL;
}

static int record_registration(void **object, int slot, void *hook, void **original, uint16_t salt)
{
    if ((int)registration_attempts++ == fail_attempt) return -1;
    CHECK(registration_count < 4);
    registrations[registration_count].object = object;
    registrations[registration_count].slot = slot;
    registrations[registration_count].hook = hook;
    registrations[registration_count].original = original;
    registrations[registration_count].salt = salt;
    registration_count++;
    return 0;
}

static int hook_dyld_routine(void **object, int slot, void *hook, void **original, uint16_t salt)
{
#ifdef __arm64e__
    if (object == modern_object) return -1;
#endif
    return record_registration(object, slot, hook, original, salt);
}

int dyld_hook_dispatch(void ***interface, const char *symbol, unsigned arguments,
                       unsigned slot, void *hook, void **original, uint16_t salt)
{
    const char *symbols[] = {"_dlopen", "_dlopen_preflight", "_dlopen_from", "_dlopen_audited"};
    const unsigned counts[] = {2, 1, 3, 2};
    CHECK(interface == &modern_pointer && dispatch_count < 4);
    CHECK(strcmp(symbol, symbols[dispatch_count]) == 0);
    CHECK(arguments == counts[dispatch_count]);
    dispatch_count++;
    return record_registration(*interface, slot, hook, original, salt);
}

static int jbclient_trust_library_recurse(const char *path, void *caller)
{
    trust_count++;
    trusted_path = path;
    trusted_caller = caller;
    return 0;
}

static void roothide_loader_trace(const char *phase, const char *path, int result)
{
    (void)phase;
    (void)path;
    (void)result;
}

/* PRODUCTION_ENTRY_POINTS */

static void *original_open(void *object, const char *path, int mode)
{
    original_count++;
    received_object = object;
    received_path = path;
    received_mode = mode;
    return &result_handle;
}

static void *original_from(void *object, const char *path, int mode, void *caller)
{
    received_caller = caller;
    return original_open(object, path, mode);
}

static bool original_preflight(void *object, const char *path)
{
    original_open(object, path, 0);
    return path != NULL;
}

static void check_registrations(bool modern)
{
    const int legacy_slots[] = {14, 18, 97, 98};
    const int modern_slots[] = {13, 17, 92, 93};
    const uint16_t salts[] = {0xBF31, 0xB1B6, 0xD48C, 0xD2A5};
    void *hooks[] = {dyld_dlopen_hook, dyld_dlopen_preflight_hook, dyld_dlopen_from_hook, dyld_dlopen_audited_hook};
    void **originals[] = {(void **)&dyld_dlopen_orig, (void **)&dyld_dlopen_preflight_orig,
                         (void **)&dyld_dlopen_from_orig, (void **)&dyld_dlopen_audited_orig};
    CHECK(registration_count == 4);
#ifdef __arm64e__
    CHECK(dispatch_count == (modern ? 4 : 0));
#else
    CHECK(dispatch_count == 0);
#endif
    for (unsigned i = 0; i < 4; i++) {
        CHECK(registrations[i].object == (modern ? modern_object : legacy_object));
        CHECK(registrations[i].slot == (modern ? modern_slots[i] : legacy_slots[i]));
        CHECK(registrations[i].salt == salts[i]);
        CHECK(registrations[i].hook == hooks[i]);
        CHECK(registrations[i].original == originals[i]);
    }
}

static void check_wrappers(void)
{
    const char *path = "/fixture/usr/lib/pam/pam_unix.so";
    dyld_dlopen_orig = original_open;
    dyld_dlopen_audited_orig = original_open;
    dyld_dlopen_from_orig = original_from;
    dyld_dlopen_preflight_orig = original_preflight;
    void *(*opens[])(void *, const char *, int) = {dyld_dlopen_hook, dyld_dlopen_audited_hook};
    for (unsigned i = 0; i < 2; i++) {
        trust_count = original_count = 0;
        CHECK(opens[i](legacy_object, path, RTLD_NOW) == &result_handle);
        CHECK(trust_count == 1 && original_count == 1 && trusted_path == path && trusted_caller != NULL);
        CHECK(received_object == legacy_object && received_path == path && received_mode == RTLD_NOW);
        CHECK(opens[i](legacy_object, path, RTLD_NOW | RTLD_NOLOAD) == &result_handle);
        CHECK(trust_count == 1 && original_count == 2 && received_mode == (RTLD_NOW | RTLD_NOLOAD));
        CHECK(opens[i](legacy_object, NULL, RTLD_NOW) == &result_handle);
        CHECK(trust_count == 1 && original_count == 3 && received_path == NULL);
    }
    trust_count = original_count = 0;
    CHECK(dyld_dlopen_from_hook(modern_object, path, RTLD_LAZY, &result_handle) == &result_handle);
    CHECK(trust_count == 1 && original_count == 1 && trusted_caller == &result_handle);
    CHECK(received_caller == &result_handle && received_object == modern_object && received_mode == RTLD_LAZY);
    CHECK(dyld_dlopen_from_hook(modern_object, path, RTLD_NOLOAD, &result_handle) == &result_handle);
    CHECK(trust_count == 1 && original_count == 2);
    CHECK(dyld_dlopen_from_hook(modern_object, NULL, RTLD_NOW, &result_handle) == &result_handle);
    CHECK(trust_count == 1 && original_count == 3);
    CHECK(dyld_dlopen_preflight_hook(modern_object, path));
    CHECK(trust_count == 2 && original_count == 4 && trusted_path == path);
    CHECK(!dyld_dlopen_preflight_hook(modern_object, NULL));
    CHECK(trust_count == 2 && original_count == 5);
}

int main(int argc, char **argv)
{
    CHECK(argc == 2);
    if (strcmp(argv[1], "wrappers") == 0) {
        check_wrappers();
        return 0;
    }
    legacy_available = strcmp(argv[1], "legacy") == 0 || strcmp(argv[1], "both") == 0 || strcmp(argv[1], "legacy-failure") == 0;
    modern_available = strcmp(argv[1], "modern") == 0 || strcmp(argv[1], "both") == 0 || strcmp(argv[1], "modern-failure") == 0;
    if (strstr(argv[1], "failure")) fail_attempt = 1;
    int init_result = init_dyldhooks();
    if (fail_attempt >= 0) {
        CHECK(init_result != 0);
        CHECK(registration_attempts == 4);
        CHECK(registration_count == 3);
    } else if (legacy_available || modern_available) {
        CHECK(init_result == 0);
        check_registrations(!legacy_available);
    } else {
        CHECK(init_result != 0);
        CHECK(registration_count == 0);
    }
    return 0;
}

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <libkern/OSByteOrder.h>

#define CS_OPS_ENTITLEMENTS_BLOB 7
#define CSMAGIC_EMBEDDED_ENTITLEMENTS 0xfade7171
#define XPC_TYPE_DICTIONARY 1

typedef struct { uint32_t magic, length; } CS_GenericBlob;
typedef struct { int type; bool debugger; } FixtureObject;
typedef FixtureObject *xpc_object_t;
static FixtureObject dictionary;
static const char *mode;
static int calls, parse_calls, oversized_allocations, live_allocations;
static size_t parsed_size;

static pid_t getpid(void) { return 42; }
static void *fixture_malloc(size_t size)
{
    if (size > 4096) { oversized_allocations++; return NULL; }
    void *result = malloc(size);
    if (result) live_allocations++;
    return result;
}
static void fixture_free(void *pointer) { if (pointer) live_allocations--; free(pointer); }
static int csops(pid_t pid, unsigned operation, void *buffer, size_t capacity)
{
    calls++;
    if (!strcmp(mode, "header-error") || (calls == 2 && !strcmp(mode, "blob-error"))) { errno = EACCES; return -1; }
    CS_GenericBlob *header = buffer;
    uint32_t length = !strcmp(mode, "empty") ? 8 : !strcmp(mode, "short") ? 4 : 256;
    header->magic = OSSwapHostToBigInt32(CSMAGIC_EMBEDDED_ENTITLEMENTS);
    header->length = OSSwapHostToBigInt32(length);
    if (calls == 1) {
        if (!strncmp(mode, "length-only-", 12)) header->magic = 0;
        errno = ERANGE;
        return -1;
    }
    if (capacity < length) { errno = ERANGE; return -1; }
    memset((char *)buffer + sizeof(*header), 'P', length - sizeof(*header));
    if (!strcmp(mode, "changed-length")) header->length = OSSwapHostToBigInt32(512);
    if (!strcmp(mode, "changed-magic")) header->magic = 0;
    return 0;
}
static xpc_object_t xpc_create_from_plist(const void *plist, size_t length)
{
    parse_calls++; parsed_size = length;
    dictionary.type = !strcmp(mode, "not-dictionary") ? 2 : XPC_TYPE_DICTIONARY;
    dictionary.debugger = !strcmp(mode, "debugger") || !strcmp(mode, "length-only-debugger");
    return &dictionary;
}
static int xpc_get_type(xpc_object_t object) { return object->type; }
static void xpc_release(xpc_object_t object) {}
static bool xpc_dictionary_get_bool(xpc_object_t object, const char *key) { return object->debugger; }

#define malloc fixture_malloc
#define free fixture_free
#include "implementation.h"
#undef malloc
#undef free

int main(void)
{
    const struct {
        const char *name;
        bool parses;
        bool requires;
    } cases[] = {
        {"debugger", true, false},
        {"ordinary", true, true},
        {"empty", false, true},
        {"short", false, true},
        {"header-error", false, true},
        {"blob-error", false, true},
        {"changed-length", false, true},
        {"changed-magic", false, true},
        {"not-dictionary", true, true},
        {"length-only-header", true, true},
        {"length-only-debugger", true, false},
    };
    int failures = 0;
    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        mode = cases[i].name; calls = 0; parse_calls = 0; parsed_size = 0; oversized_allocations = 0;
        bool expected_parse = cases[i].parses;
        bool result = process_requires_hookd();
        if (result != cases[i].requires || parse_calls != (expected_parse ? 1 : 0) ||
            (expected_parse && parsed_size != 248) || oversized_allocations || live_allocations) {
            fprintf(stderr, "%s: requires=%d parses=%d extent=%zu oversized=%d live=%d\n", mode, result, parse_calls, parsed_size, oversized_allocations, live_allocations);
            failures++;
        }
    }
    printf("11 entitlement blob cases, %d failures; csops and parsing are mocked\n", failures);
    return failures ? 1 : 0;
}

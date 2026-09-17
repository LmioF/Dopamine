#include <assert.h>
#include <errno.h>
#include <libkern/OSByteOrder.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <xpc/xpc.h>

#include "declarations.h"

static unsigned query_count;
static uint32_t first_magic, first_extent, returned_extent;
static int query_result, query_errno;

static int observed_csops(pid_t pid, unsigned int operation, void *buffer, size_t capacity)
{
    assert(pid == getpid() && operation == CS_OPS_ENTITLEMENTS_BLOB);
    query_result = csops(pid, operation, buffer, capacity);
    query_errno = errno;
    query_count++;
    if ((query_result == 0 || query_errno == ERANGE) && capacity >= sizeof(CS_GenericBlob)) {
        CS_GenericBlob header;
        memcpy(&header, buffer, sizeof(header));
        uint32_t extent = OSSwapBigToHostInt32(header.length);
        if (query_count == 1) {
            first_magic = OSSwapBigToHostInt32(header.magic);
            first_extent = extent;
        }
        else {
            returned_extent = extent;
            assert(capacity == first_extent);
            assert(extent <= capacity);
        }
    }
    errno = query_errno;
    return query_result;
}

#define csops observed_csops
#include "implementation.h"
#undef csops

int main(int argc, const char *argv[])
{
    if (argc != 2) return 2;
    const char *mode = argv[1];
    if (strcmp(mode, "none") && strcmp(mode, "empty")) return 2;
    xpc_object_t actual = copy_entitlements_xpc();
    if (!strcmp(mode, "none")) {
        if (actual) {
            xpc_release(actual);
            fprintf(stderr, "Unentitled helper unexpectedly returned an entitlement dictionary\n");
            return 1;
        }
        assert(query_count == 1);
    }
    else {
        if (!actual) {
            fprintf(stderr, "%s: no dictionary; queries=%u result=%d errno=%d magic=%08x first=%u returned=%u\n",
                    mode, query_count, query_result, query_errno, first_magic, first_extent, returned_extent);
            return 1;
        }
        xpc_object_t expected = xpc_dictionary_create(NULL, NULL, 0);
        bool equal = xpc_equal(actual, expected);
        xpc_release(expected);
        xpc_release(actual);
        if (!equal) {
            fprintf(stderr, "%s: parsed dictionary differs from the signed fixture\n", mode);
            return 1;
        }
        assert(query_count == 2 && returned_extent > sizeof(CS_GenericBlob));
    }
    printf("%s: real self-process entitlement parsing passed; queries=%u first=%u returned=%u\n",
           mode, query_count, first_extent, returned_extent);
    return 0;
}

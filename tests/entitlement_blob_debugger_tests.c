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

static pid_t target_pid;
static unsigned query_count;
static uint32_t first_extent, returned_extent;

static pid_t observed_getpid(void)
{
    return target_pid;
}

static int observed_csops(pid_t pid, unsigned int operation, void *buffer, size_t capacity)
{
    assert(pid == target_pid && operation == CS_OPS_ENTITLEMENTS_BLOB);
    int result = csops(pid, operation, buffer, capacity);
    int saved_errno = errno;
    query_count++;
    if ((result == 0 || saved_errno == ERANGE) && capacity >= sizeof(CS_GenericBlob)) {
        CS_GenericBlob header;
        memcpy(&header, buffer, sizeof(header));
        uint32_t extent = OSSwapBigToHostInt32(header.length);
        if (query_count & 1) first_extent = extent;
        else returned_extent = extent;
    }
    errno = saved_errno;
    return result;
}

#define getpid observed_getpid
#define csops observed_csops
#include "implementation.h"
#undef csops
#undef getpid

int main(int argc, const char *argv[])
{
    if (argc != 2) return 2;
    target_pid = (pid_t)strtol(argv[1], NULL, 10);
    if (target_pid <= 0) return 2;

    xpc_object_t entitlements = copy_entitlements_xpc();
    if (!entitlements) {
        fprintf(stderr, "debugserver entitlement dictionary was unavailable\n");
        return 1;
    }
    bool debugger = xpc_dictionary_get_bool(entitlements, "com.apple.private.cs.debugger");
    xpc_release(entitlements);
    if (!debugger) {
        fprintf(stderr, "debugserver entitlement dictionary lacked com.apple.private.cs.debugger=true\n");
        return 1;
    }
    if (process_requires_hookd()) {
        fprintf(stderr, "debugger-positive process incorrectly required hookd\n");
        return 1;
    }
    if (query_count != 4 || first_extent <= sizeof(CS_GenericBlob) ||
        returned_extent != first_extent) {
        fprintf(stderr, "unexpected entitlement query contract: queries=%u first=%u returned=%u\n",
                query_count, first_extent, returned_extent);
        return 1;
    }

    printf("debugger entitlement parsing passed; pid=%d queries=%u extent=%u\n",
           target_pid, query_count, returned_extent);
    return 0;
}

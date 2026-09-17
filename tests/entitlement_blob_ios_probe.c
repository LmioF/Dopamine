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
#include "implementation.h"

int main(void)
{
    xpc_object_t entitlements = copy_entitlements_xpc();
    if (!entitlements) {
        fprintf(stderr, "PR028_IOS_FAIL no-entitlement-dictionary\n");
        return 1;
    }

    bool debugger = xpc_dictionary_get_bool(entitlements, "com.apple.private.cs.debugger");
    bool getTaskAllow = xpc_dictionary_get_bool(entitlements, "get-task-allow");
    xpc_release(entitlements);

    bool requiresHookd = process_requires_hookd();
    printf("PR028_IOS_OK debugger=%d get_task_allow=%d requires_hookd=%d\n",
           debugger, getTaskAllow, requiresHookd);

    /* This developer-signed probe is expected to have get-task-allow but not
       Apple's private debugger entitlement, so systemhook must still select
       the privileged hookd path. */
    return (!getTaskAllow || debugger || !requiresHookd) ? 1 : 0;
}

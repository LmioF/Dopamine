#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef JBSERVER_SANDBOX_EXTENSIONS_MAX
#define JBSERVER_SANDBOX_EXTENSIONS_MAX 2000
#endif

#include "implementation.h"

static void require(bool condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

int main(void)
{
    require(validate_sandbox_extensions_for_checkin("a|b|c") == 0, "valid three-token extension set");
    require(validate_sandbox_extensions_for_checkin(NULL) != 0, "null extension set rejected");
    require(validate_sandbox_extensions_for_checkin("") != 0, "empty extension set rejected");
    require(validate_sandbox_extensions_for_checkin("a|b") != 0, "short extension set rejected");
    require(validate_sandbox_extensions_for_checkin("a||c") != 0, "empty token rejected");
    require(validate_sandbox_extensions_for_checkin("a|b|c|d") != 0, "extra token rejected");

    char *oversized = malloc(JBSERVER_SANDBOX_EXTENSIONS_MAX + 1);
    require(oversized != NULL, "allocate oversized fixture");
    memset(oversized, 'x', JBSERVER_SANDBOX_EXTENSIONS_MAX);
    oversized[JBSERVER_SANDBOX_EXTENSIONS_MAX] = '\0';
    oversized[1] = '|';
    oversized[3] = '|';
    require(validate_sandbox_extensions_for_checkin(oversized) == EOVERFLOW, "untransportable extension set rejected");
    free(oversized);
    return 0;
}

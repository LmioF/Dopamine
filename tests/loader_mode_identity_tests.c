#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#define CS_OPS_STATUS 0
#define CS_PLATFORM_BINARY 0x04000000
#define JBLogError(...) ((void)0)
#define JBLogDebug(...) ((void)0)
#define jbinfo(field) mode_state

typedef struct { pid_t pid; uid_t uid; unsigned generation; } audit_token_t;
static bool mode_state, blacklisted;
static uint32_t caller_flags;
static int status_result, token_queries, failures;

static pid_t audit_token_to_pid(audit_token_t token) { return token.pid; }
static uid_t audit_token_to_euid(audit_token_t token) { return token.uid; }
static bool isBlacklistedToken(audit_token_t *token) { return blacklisted; }
static pid_t getpid(void) { return 1; }
static int csops(pid_t pid, unsigned operation, void *output, size_t size)
{
    *(uint32_t *)output = pid == 1 ? CS_PLATFORM_BINARY : caller_flags;
    return status_result;
}
static int csops_audittoken(pid_t pid, unsigned operation, void *output, size_t size, audit_token_t *token)
{
    token_queries++;
    if (pid != token->pid || token->generation != 7) return -1;
    *(uint32_t *)output = caller_flags;
    return status_result;
}

#include "implementation.h"

static void check(const char *label, uid_t uid, uint32_t flags, int query_result, bool deny, unsigned generation, bool permitted)
{
    audit_token_t token = {42, uid, generation};
    mode_state = false; blacklisted = deny; caller_flags = flags;
    status_result = query_result; token_queries = 0;
    int result = roothide_domain_allowed(token) ? roothide_set_dyld_patch(&token, true) : -1;
    if ((result == 0) != permitted || mode_state != permitted) {
        fprintf(stderr, "%s: result=%d mode=%d expected=%d\n", label, result, mode_state, permitted);
        failures++;
    }
    if (uid != 0 && !deny && token_queries != 1) {
        fprintf(stderr, "%s: caller audit token was not checked\n", label);
        failures++;
    }
}

int main(void)
{
    check("root", 0, 0, -1, false, 7, true);
    check("platform", 501, CS_PLATFORM_BINARY, 0, false, 7, true);
    check("ordinary", 501, 0, 0, false, 7, false);
    check("blacklisted-root", 0, CS_PLATFORM_BINARY, 0, true, 7, false);
    check("blacklisted-platform", 501, CS_PLATFORM_BINARY, 0, true, 7, false);
    check("status-refused", 501, CS_PLATFORM_BINARY, -1, false, 7, false);
    check("reused-pid", 501, CS_PLATFORM_BINARY, 0, false, 8, false);
    printf("7 caller-identity cases, %d failures; no actual RPC or mode changes\n", failures);
    return failures ? 1 : 0;
}

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int gConsumeCalls;
static int gReleaseCalls;
static int gFailAt;
static int64_t gNextHandle = 10;

static int64_t fixture_sandbox_extension_consume(const char *token)
{
    if (!token || !token[0]) return -1;
    gConsumeCalls++;
    if (gFailAt == gConsumeCalls) return -1;
    return gNextHandle++;
}

static int fixture_sandbox_extension_release(int64_t handle)
{
    if (handle < 10) return -1;
    gReleaseCalls++;
    return 0;
}

#define sandbox_extension_consume fixture_sandbox_extension_consume
#define sandbox_extension_release fixture_sandbox_extension_release
#include "implementation.h"
#undef sandbox_extension_consume
#undef sandbox_extension_release

static void require(bool condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

int main(int argc, const char *argv[])
{
    if (argc != 2) return 2;
    char buffer[64];
    int expectedResult = -1;
    int expectedConsumes = 0;
    int expectedReleases = 0;

    if (!strcmp(argv[1], "success")) {
        strcpy(buffer, "a|b|c"); expectedResult = 0; expectedConsumes = 3;
    } else if (!strcmp(argv[1], "empty")) {
        buffer[0] = '\0';
    } else if (!strcmp(argv[1], "short")) {
        strcpy(buffer, "a|b");
    } else if (!strcmp(argv[1], "empty-token")) {
        strcpy(buffer, "a||c");
    } else if (!strcmp(argv[1], "long")) {
        strcpy(buffer, "a|b|c|d");
    } else if (!strcmp(argv[1], "fail-first")) {
        strcpy(buffer, "a|b|c"); gFailAt = 1; expectedConsumes = 1;
    } else if (!strcmp(argv[1], "fail-second")) {
        strcpy(buffer, "a|b|c"); gFailAt = 2; expectedConsumes = 2;
    } else if (!strcmp(argv[1], "fail-third")) {
        strcpy(buffer, "a|b|c"); gFailAt = 3; expectedConsumes = 3;
    } else {
        return 2;
    }

    int result = consume_tokenized_sandbox_extensions(buffer);
    require(result == expectedResult, "consumption result");
    require(gConsumeCalls == expectedConsumes, "consume call count");
    require(gReleaseCalls == expectedReleases, "rollback release count");
    require(!strcmp(buffer, !strcmp(argv[1], "empty") ? "" :
                           !strcmp(argv[1], "short") ? "a|b" :
                           !strcmp(argv[1], "empty-token") ? "a||c" :
                           !strcmp(argv[1], "long") ? "a|b|c|d" : "a|b|c"),
            "token buffer restored");
    return 0;
}

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../BaseBin/libjailbreak/src/hookd.h"

static const char *scenario;
static unsigned failures, sends;
static int wantedHooks, wantedFixups;
static bool is(const char *name) { return !strcmp(scenario, name); }
static void check(bool condition, const char *name)
{
    if (!condition) { fprintf(stderr, "FAIL: %s\n", name); failures++; }
}

static int fixture_send(struct hookd_mach_msg *request, struct hookd_mach_msg_reply *reply)
{
    sends++;
    check(request->hdr.msgh_size <= HOOKD_MSG_MAX_SIZE && request->clientPid == 42, "request bounds and caller");
    if (is("transport-error")) return 12345;
    uint64_t hooks = (uint64_t)wantedHooks;
    uint64_t fixups = (uint64_t)wantedFixups;
    if (is("missing-hook")) hooks = 0;
    if (is("missing-fixup")) fixups = 0;
    if (is("extra-hook")) hooks++;
    if (is("extra-fixup")) fixups++;
    if (is("wrong-kind")) { hooks = 0; fixups = 1; }
    if (is("reply-overflow")) hooks = UINT64_MAX / 8 + 1;
    reply->hookResultsCount = hooks;
    reply->fixupResultsCount = fixups;
    reply->hdr.msgh_size = (mach_msg_size_t)(sizeof(*reply) + (hooks + fixups) * sizeof(int64_t));
    if (is("short-reply")) reply->hdr.msgh_size = sizeof(*reply) - 1;
    if (is("long-reply")) reply->hdr.msgh_size = HOOKD_MSG_MAX_SIZE + 8;
    if (hooks + fixups < 20) {
        for (uint64_t i = 0; i < hooks + fixups; i++) {
            int64_t value = is("reply-error") ? 5 : (int64_t)(11 + i);
            if (is("result-overflow")) value = (int64_t)INT_MAX + 1;
            memcpy(reply->data + i * sizeof(value), &value, sizeof(value));
        }
    }
    if (is("odd-payloads")) {
        check(request->hooksStartOff == 0 && request->fixupsStartOff == 37, "packed variable payload offsets");
        struct hookd_encoded_hook first, second;
        memcpy(&first, request->data, sizeof(first));
        memcpy(&second, request->data + sizeof(first) + 3, sizeof(second));
        check(first.address == 0x1000 && first.dataSize == 3 && second.address == 0x2000 && second.dataSize == 2, "unaligned hook headers retain values");
        struct hookd_encoded_fixup fixup;
        memcpy(&fixup, request->data + request->fixupsStartOff, sizeof(fixup));
        check(fixup.address == 0x3000 && fixup.prot == 5, "unaligned fixup retains fields");
    }
    return 0;
}

#define jbclient_mach_hookd_send_msg fixture_send
#define getpid_inline() 42
#undef mach_task_self
#define mach_task_self() ((mach_port_t)99)
#include "implementation.h"

int main(int argc, const char *argv[])
{
    if (argc != 2) return 2;
    scenario = argv[1];
    uint8_t data[] = {1, 2, 3, 4};
    struct hookd_hook hooks[2] = {{0x1000, data, sizeof(data)}, {0x2000, data, 2}};
    struct hookd_encoded_fixup fixups[2] = {{.address = 0x3000, .size = 4, .prot = 5}, {.address = 0x4000, .size = 4, .prot = 1}};
    int hookOutput[4] = {-99, -99, -99, -99};
    int fixupOutput[4] = {-99, -99, -99, -99};
    int *hookOut = hookOutput, *fixupOut = fixupOutput;
    struct hookd_hook *hookInput = hooks;
    struct hookd_encoded_fixup *fixupInput = fixups;
    wantedHooks = is("fixup") || is("missing-fixup") || is("extra-fixup") || is("null-fixups") || is("null-fixup-results") ? 0 : 1;
    wantedFixups = wantedHooks == 0 ? 1 : 0;
    if (is("mixed")) { wantedHooks = 2; wantedFixups = 2; }
    if (is("odd-payloads")) { wantedHooks = 2; wantedFixups = 1; hooks[0].dataSize = 3; }
    if (is("empty")) wantedHooks = wantedFixups = 0;
    if (is("negative-hooks")) wantedHooks = -1;
    if (is("negative-fixups")) wantedFixups = -1;
    if (is("null-hooks")) hookInput = NULL;
    if (is("null-fixups")) fixupInput = NULL;
    if (is("null-hook-results")) hookOut = NULL;
    if (is("null-fixup-results")) fixupOut = NULL;
    if (is("null-data")) hooks[0].data = NULL;
    if (is("huge-data")) hooks[0].dataSize = SIZE_MAX;
    if (is("large-batch")) wantedHooks = INT_MAX;
    if (is("zero-payload")) hooks[0].dataSize = 0;
    int result = hookd_send_requests(99, hookInput, wantedHooks, hookOut, fixupInput, wantedFixups, fixupOut);
    bool valid = is("hook") || is("fixup") || is("mixed") || is("odd-payloads") || is("empty") || is("reply-error");
    check(valid ? result == 0 : result != 0, "reject incomplete, inconsistent or invalid operation batches");
    if (is("transport-error")) check(result == 12345, "preserve transport status");
    if (valid) {
        for (int i = 0; i < wantedHooks; i++) check(hookOut[i] == (is("reply-error") ? 5 : 11 + i), "matching hook results");
        for (int i = 0; i < wantedFixups; i++) check(fixupOut[i] == (is("reply-error") ? 5 : 11 + wantedHooks + i), "matching fixup results");
    } else {
        for (unsigned i = 0; i < 4; i++) check(hookOutput[i] == -99 && fixupOutput[i] == -99, "reject without writing caller outputs");
    }
    bool invalidInput = !strncmp(scenario, "null-", 5) || !strncmp(scenario, "negative-", 9) || is("huge-data") || is("large-batch") || is("zero-payload");
    if (invalidInput) check(!sends, "invalid input never reaches transport");
    printf("%s: result=%d sends=%u failures=%u\n", scenario, result, sends, failures);
    return failures ? 1 : 0;
}

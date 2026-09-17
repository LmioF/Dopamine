#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include "../BaseBin/libjailbreak/src/hookd.h"

static const char *scenario;
static unsigned failures, allocationCalls, receives, sends, destroys, acquisitions, releases;
static unsigned hookCalls, fixupCalls, expectedHooks, expectedFixups, iterations;
static bool validFrame;
static void *allocations[512];
static jmp_buf finished;
static _Alignas(struct hookd_mach_msg) uint8_t input[HOOKD_MSG_MAX_SIZE + MAX_TRAILER_SIZE];

static bool is(const char *name) { return !strcmp(scenario, name); }
static void check(bool condition, const char *name)
{
    if (!condition) { fprintf(stderr, "FAIL: %s\n", name); failures++; }
}

static void *fixture_malloc(size_t size)
{
    allocationCalls++;
    if ((is("buffer-allocation-refused") && allocationCalls == 1) ||
        (is("reply-allocation-refused") && allocationCalls == 2)) return NULL;
    void *result = malloc(size);
    assert(result);
    memset(result, 0xA5, size);
    for (unsigned i = 0; i < 512; i++) {
        if (!allocations[i]) { allocations[i] = result; return result; }
    }
    abort();
}

static void fixture_free(void *pointer)
{
    if (!pointer) return;
    for (unsigned i = 0; i < 512; i++) {
        if (allocations[i] == pointer) {
            allocations[i] = NULL;
            free(pointer);
            return;
        }
    }
    check(false, "only owned allocations are freed once");
}

static void *fixture_realloc(void *pointer, size_t size)
{
    if (!pointer) return fixture_malloc(size);
    for (unsigned i = 0; i < 512; i++) {
        if (allocations[i] == pointer) {
            void *result = realloc(pointer, size);
            assert(result);
            allocations[i] = result;
            return result;
        }
    }
    abort();
}

static void prepare_input(void)
{
    memset(input, 0, sizeof(input));
    struct hookd_mach_msg *message = (struct hookd_mach_msg *)input;
    message->hdr.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
    message->hdr.msgh_remote_port = 55;
    message->hdr.msgh_id = 1000;
    message->clientPid = 42;
    message->taskPortInClient = 99;
    expectedHooks = is("fixup-only") || is("empty") ? 0 : 2;
    expectedFixups = is("hook-only") || is("empty") ? 0 : 1;
    size_t offset = 0;
    for (unsigned i = 0; i < expectedHooks; i++) {
        size_t length = is("odd-payloads") ? 3 - i : 4;
        if (is("zero-hook") && i == 1) length = 0;
        struct hookd_encoded_hook hook = {.address = 0x1000 + i * 0x1000, .dataSize = length};
        if (is("long-hook") && i == 1) hook.dataSize = UINT64_MAX;
        memcpy(message->data + offset, &hook, sizeof(hook));
        offset += sizeof(hook);
        memset(message->data + offset, 0x31 + i, length);
        offset += length;
    }
    if (is("short-hook")) offset += 3;
    message->fixupsStartOff = offset;
    if (expectedFixups) {
        struct hookd_encoded_fixup fixup = {.address = 0x3000, .size = 16, .set_maximum = false, .prot = 5};
        size_t size = sizeof(fixup) - (is("partial-fixup") ? 1 : 0);
        memcpy(message->data + offset, &fixup, size);
        offset += size;
    }
    message->hdr.msgh_size = (mach_msg_size_t)(sizeof(*message) + offset);
    if (is("short-message")) message->hdr.msgh_size = sizeof(*message) - 1;
    if (is("long-message")) message->hdr.msgh_size = HOOKD_MSG_MAX_SIZE + 1;
    if (is("complex-message")) message->hdr.msgh_bits |= MACH_MSGH_BITS_COMPLEX;
    if (is("offset-outside")) message->fixupsStartOff = UINT64_MAX;
    if (is("reversed-offsets")) message->hooksStartOff = message->fixupsStartOff + 1;
    size_t trailerOffset = (message->hdr.msgh_size + sizeof(natural_t) - 1) & ~(sizeof(natural_t) - 1);
    assert(trailerOffset + sizeof(mach_msg_audit_trailer_t) <= sizeof(input));
    mach_msg_audit_trailer_t trailer = {0};
    trailer.msgh_trailer_type = is("wrong-trailer") ? 1 : MACH_MSG_TRAILER_FORMAT_0;
    trailer.msgh_trailer_size = sizeof(trailer);
    trailer.msgh_audit.val[5] = is("wrong-caller") ? 502 : 1;
    if (is("short-trailer")) trailer.msgh_trailer_size = sizeof(mach_msg_trailer_t);
    if (is("long-trailer")) trailer.msgh_trailer_size = sizeof(input) + 1;
    memcpy(input + trailerOffset, &trailer, sizeof(trailer));
    validFrame = is("mixed") || is("hook-only") || is("fixup-only") || is("odd-payloads") ||
        is("empty") || is("repeated") || is("send-error");
}

static mach_msg_return_t fixture_receive(mach_msg_header_t *message, mach_msg_option_t options,
                                        mach_msg_size_t sendSize, mach_msg_size_t receiveSize,
                                        mach_port_name_t receivePort, mach_msg_timeout_t timeout,
                                        mach_port_name_t notifyPort)
{
    if (receives == iterations) longjmp(finished, 1);
    receives++;
    check(message != NULL && receiveSize == sizeof(input), "receive buffer exists with full trailer capacity");
    check(receivePort == 77 && sendSize == 0, "receive invocation preserves routing");
    if (is("receive-error")) return MACH_RCV_INTERRUPTED;
    memcpy(message, input, sizeof(input));
    return KERN_SUCCESS;
}

static kern_return_t fixture_task_for_pid(mach_port_t task, pid_t pid, mach_port_t *result)
{
    acquisitions++;
    check(task == 88 && pid == 42, "caller task request preserves identity");
    if (is("task-error")) { *result = MACH_PORT_NULL; return KERN_FAILURE; }
    *result = 66;
    return KERN_SUCCESS;
}

static kern_return_t fixture_mod_refs(mach_port_t task, mach_port_name_t name, mach_port_right_t right, mach_port_delta_t delta)
{
    check(task == 88 && name == 66 && right == MACH_PORT_RIGHT_SEND && delta == -1, "release the acquired task right once");
    releases++;
    return KERN_SUCCESS;
}

static int fixture_hook(mach_port_t client, mach_port_t target, vm_address_t address, const void *data, vm_size_t size)
{
    unsigned index = expectedHooks ? hookCalls % expectedHooks : 0;
    hookCalls++;
    check(validFrame, "malformed or unallocated requests never reach operation callbacks");
    check(client == 66 && target == 99 && address == 0x1000 + index * 0x1000, "decoded hook identity and address");
    size_t expectedSize = is("odd-payloads") ? 3 - index : 4;
    check(size == expectedSize && data != NULL, "decoded payload extent");
    if (size == expectedSize && data) {
        for (size_t i = 0; i < size; i++) check(((const uint8_t *)data)[i] == 0x31 + index, "decoded payload bytes");
    }
    return (int)(11 + index);
}

static int fixture_fixup(mach_port_t client, mach_port_t target, vm_address_t address, vm_size_t size, bool maximum, vm_prot_t protection)
{
    fixupCalls++;
    check(validFrame, "invalid requests never reach fixup callbacks");
    check(client == 66 && target == 99 && address == 0x3000 && size == 16 && !maximum && protection == 5, "decoded fixup fields");
    return -17;
}

static mach_msg_return_t fixture_send(mach_msg_header_t *header)
{
    sends++;
    struct hookd_mach_msg_reply *reply = (struct hookd_mach_msg_reply *)header;
    check(validFrame, "invalid requests do not send successful partial replies");
    check(reply->hookResultsCount == expectedHooks && reply->fixupResultsCount == expectedFixups, "reply cardinality");
    check(header->msgh_size == sizeof(*reply) + (expectedHooks + expectedFixups) * sizeof(int64_t), "reply extent");
    check(header->msgh_remote_port == 55 && header->msgh_id == 1100, "reply routing");
    if (reply->hookResultsCount == expectedHooks && reply->fixupResultsCount == expectedFixups) {
        for (unsigned i = 0; i < expectedHooks + expectedFixups; i++) {
            int64_t result;
            memcpy(&result, reply->data + i * sizeof(result), sizeof(result));
            check(result == (i < expectedHooks ? (int64_t)(11 + i) : -17), "raw operation result preserved");
        }
    }
    return is("send-error") ? MACH_SEND_INVALID_DEST : KERN_SUCCESS;
}

static void fixture_destroy(mach_msg_header_t *message)
{
    destroys++;
    bool sent = validFrame && !is("send-error");
    check(message->msgh_remote_port == (sent ? 0 : 55), "input owns reply right until send succeeds");
}

#define malloc fixture_malloc
#define realloc fixture_realloc
#define free fixture_free
#define mach_msg fixture_receive
#define mach_msg_send fixture_send
#define mach_msg_destroy fixture_destroy
#define task_for_pid fixture_task_for_pid
#define mach_port_mod_refs fixture_mod_refs
#undef mach_task_self
#define mach_task_self() ((mach_port_t)88)
#define audit_token_to_pid(token) ((pid_t)(token).val[5])
#define apply_hook fixture_hook
#define apply_fixup fixture_fixup
#include "implementation.h"
#undef malloc
#undef realloc
#undef free

int main(int argc, const char *argv[])
{
    if (argc != 2) return 2;
    scenario = argv[1];
    iterations = is("repeated") ? 32 : 1;
    prepare_input();
    if (setjmp(finished) == 0) server_loop(77);
    check(sends == (validFrame ? iterations : 0), "expected send count");
    check(hookCalls == (validFrame ? expectedHooks * iterations : 0), "expected hook callback count");
    check(fixupCalls == (validFrame ? expectedFixups * iterations : 0), "expected fixup callback count");
    unsigned expectedReceives = is("buffer-allocation-refused") ? 0 : iterations;
    check(receives == expectedReceives, "allocation refusal stops before receive");
    check(destroys == (is("receive-error") ? 0 : expectedReceives), "destroy every received request");
    check(releases == acquisitions - (is("task-error") ? acquisitions : 0), "balanced acquired task rights");
    unsigned live = 0;
    for (unsigned i = 0; i < 512; i++) {
        if (allocations[i]) { live++; free(allocations[i]); }
    }
    check(live == (is("buffer-allocation-refused") ? 0 : 1), "only the server receive buffer remains allocated");
    printf("%s: sends=%u callbacks=%u/%u live=%u failures=%u\n", scenario, sends, hookCalls, fixupCalls, live, failures);
    return failures ? 1 : 0;
}

#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static struct { uint32_t ngroups, groups; } offsets;
#define koffsetof(type, field) offsets.field
static unsigned char memory[128];
static const uint64_t credential = UINT64_C(0x100000);
static unsigned reads, fail_at, failures, scenarios, forwarded_count, forwarded_calls;
static size_t group_read_size;
static gid_t forwarded_groups[NGROUPS_MAX];
static uint64_t proc_ucred(uint64_t proc) { return proc == 7 ? credential : 0; }
static int kreadbuf(uint64_t address, void *output, size_t length)
{
    if (++reads == fail_at) { memset(output, 0x77, length); return -1; }
    if (address < credential || address - credential > sizeof(memory) || length > sizeof(memory) - (address - credential)) {
        failures++;
        return -1;
    }
    if (address == credential + offsets.ngroups && length != sizeof(uint16_t)) failures++;
    if (address == credential + offsets.groups) group_read_size = length;
    memcpy(output, memory + (address - credential), length);
    return 0;
}
static int proc_ucred_update_content_counted(uint64_t proc, const char *path, uid_t uid, gid_t gid,
                                            uid_t ruid, gid_t rgid, const gid_t *groups, uint32_t count)
{
    forwarded_count = count;
    forwarded_calls++;
    memcpy(forwarded_groups, groups, count * sizeof(gid_t));
    return 37;
}

#include "implementation.h"

static void check(bool condition, const char *message)
{
    if (!condition) { fprintf(stderr, "FAIL: %s\n", message); failures++; }
}
static void initialize(uint16_t count)
{
    scenarios++;
    offsets.ngroups = 12;
    offsets.groups = 16;
    memset(memory, 0xa5, sizeof(memory));
    memcpy(memory + offsets.ngroups, &count, sizeof(count));
    for (unsigned i = 0; i < NGROUPS_MAX; i++) {
        gid_t group = i ? 19 + i : 501;
        memcpy(memory + offsets.groups + i * sizeof(group), &group, sizeof(group));
    }
    reads = fail_at = forwarded_calls = forwarded_count = 0;
    group_read_size = 0;
}
static void read_case(uint16_t count, unsigned fail_read, int invalid)
{
    initialize(count);
    fail_at = fail_read;
    gid_t groups[NGROUPS_MAX];
    memset(groups, 0x55, sizeof(groups));
    uint32_t observed = UINT32_MAX;
    uint64_t source = credential;
    if (invalid == 1) offsets.ngroups = 0;
    if (invalid == 2) offsets.groups = 0;
    if (invalid == 3) source = 0;
    if (invalid == 4) source = UINT64_MAX - 16;
    if (invalid == 5) {
        gid_t bad = (gid_t)-1;
        memcpy(memory + offsets.groups, &bad, sizeof(bad));
    }
    int result = ucred_read_groups(source, groups, &observed);
    bool valid = count > 0 && count <= NGROUPS_MAX && !fail_read && !invalid;
    if (valid) {
        check(result == 0 && observed == count, "read the 16-bit authoritative count despite nonzero padding");
        check(group_read_size == count * sizeof(gid_t), "read only counted group entries");
        check(groups[0] == 501, "preserve primary group");
        for (unsigned i = 1; i < count; i++) check(groups[i] == 19 + i, "preserve supplementary membership");
        for (unsigned i = count; i < NGROUPS_MAX; i++) check(groups[i] == 0, "unused output slots do not inherit stale groups");
    } else {
        check(result == -1 && observed == 0, "invalid or failed reads do not publish a count");
        for (unsigned i = 0; i < NGROUPS_MAX; i++) check(groups[i] == 0, "failed reads do not publish partially copied groups");
        if (count == 0 || count > NGROUPS_MAX || fail_read == 1 || (invalid && invalid != 5)) {
            check(group_read_size == 0, "invalid count prevents group-array reads");
        }
    }
}
int main(void)
{
    read_case(1, 0, 0);
    read_case(2, 0, 0);
    read_case(NGROUPS_MAX, 0, 0);
    read_case(0, 0, 0);
    read_case(NGROUPS_MAX + 1, 0, 0);
    read_case(UINT16_MAX, 0, 0);
    read_case(2, 1, 0);
    read_case(2, 2, 0);
    for (int invalid = 1; invalid <= 5; invalid++) read_case(2, 0, invalid);
    initialize(1);
    uint32_t count = 99;
    gid_t groups[NGROUPS_MAX] = {501};
    check(ucred_read_groups(credential, NULL, &count) == -1 && !reads, "null output rejected before access");
    check(ucred_read_groups(credential, groups, NULL) == -1 && !reads, "null count rejected before access");
    initialize(2);
    groups[1] = 20;
    check(proc_ucred_update_content(7, "/fixture", 501, 501, 501, 501, groups) == 37,
          "legacy public entry point propagates the counted implementation result");
    check(forwarded_calls == 1 && forwarded_count == 2 && forwarded_groups[1] == 20,
          "legacy public entry point obtains count from metadata, not zero or sentinel padding");
    initialize(0);
    check(proc_ucred_update_content(7, "/fixture", 501, 501, 501, 501, groups) == -1 && !forwarded_calls,
          "legacy entry point rejects missing authoritative group count");
    printf("Credential group reader: %u scenarios, %u failures\n", scenarios, failures);
    return failures ? 1 : 0;
}

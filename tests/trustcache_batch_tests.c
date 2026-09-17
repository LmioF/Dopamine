#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uuid/uuid.h>
#include "../BaseBin/XPF/external/ChOma/src/CodeDirectory.h"

static unsigned char caches[96][0x4000];
static unsigned cache_count, invalid_accesses, writes;
static int fail_grow_at, fail_read, fail_write;
static void _jb_trustcache_enumerate(void (^block)(uint64_t, bool *));
static uint64_t _jb_trustcache_grow(void);
static uint32_t kread32(uint64_t address);
static int kreadbuf(uint64_t address, void *buffer, size_t size);
static int kwritebuf(uint64_t address, const void *buffer, size_t size);

#include "implementation.h"

static bool valid_range(uint64_t address, size_t size)
{
    for (unsigned i = 0; i < cache_count; i++) {
        uintptr_t base = (uintptr_t)caches[i];
        if (address >= base && size <= sizeof(caches[i]) && address - base <= sizeof(caches[i]) - size) return true;
    }
    return false;
}
static int kreadbuf(uint64_t address, void *buffer, size_t size)
{
    if (!valid_range(address, size)) {
        invalid_accesses++;
        memset(buffer, 0, size);
        return -1;
    }
    if ((fail_read == 1 && size == sizeof(uint32_t)) || (fail_read == 2 && size == JB_TRUSTCACHE_SIZE)) {
        memset(buffer, 0, size);
        return fail_read == 1 ? -7 : -9;
    }
    memcpy(buffer, (void *)(uintptr_t)address, size);
    if (fail_read == 3 && size == sizeof(uint32_t)) *(uint32_t *)buffer = JB_TRUSTCACHE_ENTRY_COUNT + 1;
    if (fail_read == 4 && size == JB_TRUSTCACHE_SIZE) ((jb_trustcache *)buffer)->file.length++;
    return 0;
}
static uint32_t kread32(uint64_t address)
{
    uint32_t result = 0;
    kreadbuf(address, &result, sizeof(result));
    return result;
}
static int kwritebuf(uint64_t address, const void *buffer, size_t size)
{
    if (!valid_range(address, size)) { invalid_accesses++; return -1; }
    if (fail_write) return -11;
    writes++;
    memcpy((void *)(uintptr_t)address, buffer, size);
    return 0;
}
static void _jb_trustcache_enumerate(void (^block)(uint64_t, bool *))
{
    for (unsigned i = 0; i < cache_count; i++) {
        bool stop = false;
        block((uintptr_t)caches[i], &stop);
        if (stop) break;
    }
}
static uint64_t _jb_trustcache_grow(void)
{
    if ((int)cache_count == fail_grow_at || cache_count == 96) return 0;
    jb_trustcache *cache = (void *)caches[cache_count++];
    memset(cache, 0, JB_TRUSTCACHE_SIZE);
    cache->file.version = 1;
    return (uintptr_t)cache;
}
static void seed(unsigned length)
{
    jb_trustcache *cache = (void *)(uintptr_t)_jb_trustcache_grow();
    cache->file.length = length;
    for (unsigned i = 0; i < length; i++) memset(&cache->file.entries[i], 0xff, sizeof(trustcache_entry_v1));
}
static int run_case(const char *name, unsigned initial, unsigned count, int growth_failure, int read_failure, int write_failure)
{
    cache_count = invalid_accesses = writes = 0;
    fail_grow_at = -1;
    fail_read = fail_write = 0;
    if (initial) seed(initial);
    fail_grow_at = growth_failure;
    fail_read = read_failure;
    fail_write = write_failure;
    trustcache_entry_v1 *entries = calloc(count ? count : 1, sizeof(*entries));
    unsigned *occurrences = calloc(count ? count : 1, sizeof(*occurrences));
    if (!entries || !occurrences) exit(2);
    for (uint32_t i = 0; i < count; i++) {
        memcpy(entries[i].hash, &i, sizeof(i));
        entries[i].hash_type = 1;
    }
    int result = jb_trustcache_add_entries(entries, count);
    bool expect_failure = growth_failure >= 0 || read_failure || write_failure;
    unsigned old_entries = 0;
    unsigned mismatches = 0;
    if (!expect_failure) {
        for (unsigned c = 0; c < cache_count; c++) {
            jb_trustcache *cache = (void *)caches[c];
            if (cache->file.length > JB_TRUSTCACHE_ENTRY_COUNT) { mismatches++; continue; }
            for (unsigned i = 0; i < cache->file.length; i++) {
                uint32_t index;
                trustcache_entry_v1 *entry = &cache->file.entries[i];
                memcpy(&index, entry->hash, sizeof(index));
                if (index == UINT32_MAX) { old_entries++; continue; }
                if (index >= count || memcmp(entry, &entries[index], sizeof(*entry))) { mismatches++; continue; }
                occurrences[index]++;
            }
        }
        for (unsigned i = 0; i < count; i++) if (occurrences[i] != 1) mismatches++;
        if (old_entries != initial) mismatches++;
    }
    int expected_result = growth_failure >= 0 ? -1 : read_failure == 1 ? -7 : read_failure == 2 ? -9 :
                          read_failure ? -1 : write_failure ? -11 : 0;
    bool failed = result != expected_result || invalid_accesses || mismatches;
    if (failed) fprintf(stderr, "%s: result=%d expected_failure=%d caches=%u invalid=%u mismatches=%u writes=%u\n",
                        name, result, expect_failure, cache_count, invalid_accesses, mismatches, writes);
    free(entries);
    free(occurrences);
    return failed;
}
int main(void)
{
    unsigned capacity = JB_TRUSTCACHE_ENTRY_COUNT;
    int failures = 0;
    failures += run_case("empty", 0, 0, -1, 0, 0);
    failures += run_case("single", 0, 1, -1, 0, 0);
    failures += run_case("exact", 0, capacity, -1, 0, 0);
    failures += run_case("partial-boundary", capacity - 1, 2, -1, 0, 0);
    failures += run_case("full-boundary", capacity, capacity + 1, -1, 0, 0);
    failures += run_case("new-boundary", 0, capacity + 1, -1, 0, 0);
    failures += run_case("many-caches", capacity - 1, capacity * 70 + 3, -1, 0, 0);
    failures += run_case("initial-allocation-refusal", 0, 1, 0, 0, 0);
    failures += run_case("later-allocation-refusal", capacity - 1, 2, 1, 0, 0);
    failures += run_case("metadata-read-refusal", 1, 1, -1, 1, 0);
    failures += run_case("cache-read-refusal", 1, 1, -1, 2, 0);
    failures += run_case("cache-write-refusal", 1, 1, -1, 0, 1);
    failures += run_case("oversized-metadata", 1, 1, -1, 3, 0);
    failures += run_case("changed-metadata", 1, 1, -1, 4, 0);
    printf("14 trustcache batch cases, %d failures; only fixture-owned memory is accessed\n", failures);
    return failures ? 1 : 0;
}

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <uuid/uuid.h>

#define CS_CDHASH_LEN 20

typedef uint8_t cdhash_t[CS_CDHASH_LEN];
typedef struct trustcache_entry_v1
{
    cdhash_t hash;
    uint8_t hash_type;
    uint8_t flags;
} __attribute__((__packed__)) trustcache_entry_v1;

typedef struct s_trustcache_file_v1
{
    uint32_t version;
    uuid_t uuid;
    uint32_t length;
    trustcache_entry_v1 entries[];
} __attribute__((__packed__)) trustcache_file_v1;

#define ksizeof(x) ((uint64_t)sizeof(x))
#define koffsetof(t, f) ((uint64_t)offsetof(t, f))

typedef struct trustcache { uint64_t next; uint64_t fileptr; uint64_t size; uint64_t type; } trustcache;

static uint64_t old_tc_addr = 0x1000;
static uint64_t old_file_addr = 0x2000;
static uint32_t old_length = 1;
static int removed;
static int old_freed;
static int new_freed;
static int old_inserted;
static int new_inserted;
static int alloc_fail = 1;
static int new_insert_fail;

static void _trustcache_list_enumerate(void (^block)(uint64_t, bool *))
{
    bool stop = false;
    block(old_tc_addr, &stop);
}

static uint64_t kread64(uint64_t addr)
{
    if (addr == old_tc_addr + offsetof(trustcache, fileptr)) return old_file_addr;
    return 0;
}

static uint32_t kread32(uint64_t addr)
{
    if (addr == old_file_addr + offsetof(trustcache_file_v1, length)) return old_length;
    return 0;
}

static void kreadbuf(uint64_t addr, void *buf, size_t size)
{
    memset(buf, 0, size);
    if (addr == old_file_addr + offsetof(trustcache_file_v1, uuid)) {
        memset(buf, 0x42, size);
    }
}

static int _is_jb_trustcache(uint64_t addr) { (void)addr; return 0; }
static int trustcache_list_remove(uint64_t addr) { (void)addr; removed++; return 0; }
static int trustcache_list_insert(uint64_t addr)
{
    if (addr == old_tc_addr) {
        old_inserted++;
        return 0;
    }
    new_inserted++;
    return new_insert_fail ? -1 : 0;
}
static int kalloc(uint64_t *addr, uint64_t size) { (void)size; if (alloc_fail) return -1; *addr = 0x3000; return 0; }
static void kfree(uint64_t addr, uint64_t size)
{
    (void)size;
    if (addr == old_tc_addr) old_freed++;
    if (addr == 0x3000) new_freed++;
}
static void kwritebuf(uint64_t addr, const void *buf, size_t size) { (void)addr; (void)buf; (void)size; }
static void kwrite64(uint64_t addr, uint64_t value) { (void)addr; (void)value; }

#include "implementation.h"

int main(void)
{
    size_t size = sizeof(trustcache_file_v1) + 2 * sizeof(trustcache_entry_v1);
    trustcache_file_v1 *replacement = calloc(1, size);
    if (!replacement) return 10;
    memset(replacement->uuid, 0x42, sizeof(replacement->uuid));
    replacement->length = 2;

    int result = trustcache_file_upload(replacement);
    if (result == 0) return 1;
    if (removed != 0) return 2;
    if (old_freed != 0 || new_freed != 0) return 3;
    if (old_inserted != 0 || new_inserted != 0) return 4;

    alloc_fail = 0;
    new_insert_fail = 1;
    removed = old_freed = new_freed = old_inserted = new_inserted = 0;
    result = trustcache_file_upload(replacement);

    if (result == 0) return 5;
    if (removed != 1) return 6;
    if (new_inserted != 1) return 7;
    if (old_inserted != 1) return 8;
    if (old_freed != 0) return 9;
    if (new_freed != 1) return 10;

    new_insert_fail = 0;
    removed = old_freed = new_freed = old_inserted = new_inserted = 0;
    result = trustcache_file_upload(replacement);
    if (result != 0) return 11;
    if (removed != 1) return 12;
    if (new_inserted != 1 || old_inserted != 0) return 13;
    if (old_freed != 1 || new_freed != 0) return 14;
    free(replacement);
    puts("ok");
    return 0;
}

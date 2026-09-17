#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define XPC_TYPE_DICTIONARY 1
#define XPC_TYPE_ARRAY 2
#define XPC_TYPE_STRING 3
#define XPC_TYPE_INT64 4

typedef struct fixture_object {
    atomic_int references;
    int type;
    const char *string;
    size_t count;
    struct fixture_object *values[2];
    struct fixture_object *next;
} *xpc_object_t;

static const char *scenario;
static char configPath[1024];
static pthread_mutex_t objectsLock = PTHREAD_MUTEX_INITIALIZER;
static xpc_object_t objects;
static atomic_uint failures, descriptors, parses;
static _Thread_local unsigned readCalls;
static bool failDup;
static bool is(const char *name) { return !strcmp(scenario, name); }
static void check(bool condition, const char *name)
{
    if (!condition) { fprintf(stderr, "FAIL: %s\n", name); atomic_fetch_add(&failures, 1); }
}

static void require_live(xpc_object_t object)
{
    if (!object || atomic_load(&object->references) <= 0) {
        fprintf(stderr, "FAIL: accessed missing or released configuration value\n");
        exit(3);
    }
}

static xpc_object_t object_create(int type)
{
    xpc_object_t object = calloc(1, sizeof(*object));
    if (!object) abort();
    object->type = type;
    atomic_init(&object->references, 1);
    pthread_mutex_lock(&objectsLock);
    object->next = objects;
    objects = object;
    pthread_mutex_unlock(&objectsLock);
    return object;
}

static xpc_object_t xpc_retain(xpc_object_t object)
{
    require_live(object);
    atomic_fetch_add(&object->references, 1);
    return object;
}

static void xpc_release(xpc_object_t object)
{
    require_live(object);
    if (atomic_fetch_sub(&object->references, 1) == 1) {
        for (size_t i = 0; i < object->count; i++) xpc_release(object->values[i]);
    }
}

static int xpc_get_type(xpc_object_t object) { require_live(object); return object->type; }
static xpc_object_t xpc_dictionary_get_value(xpc_object_t object, const char *key)
{
    require_live(object);
    if (object->type != XPC_TYPE_DICTIONARY) {
        fprintf(stderr, "FAIL: dictionary accessor used on non-dictionary\n");
        exit(3);
    }
    return !strcmp(key, "ProcessBlacklist") && object->count ? object->values[0] : NULL;
}

static size_t xpc_array_get_count(xpc_object_t object) { require_live(object); return object->count; }
static xpc_object_t xpc_array_get_value(xpc_object_t object, size_t index)
{
    require_live(object);
    return index < object->count ? object->values[index] : NULL;
}
static const char *xpc_string_get_string_ptr(xpc_object_t object)
{
    require_live(object);
    return object->type == XPC_TYPE_STRING ? object->string : NULL;
}
static const char *xpc_array_get_string(xpc_object_t object, size_t index)
{
    xpc_object_t value = xpc_array_get_value(object, index);
    return value ? xpc_string_get_string_ptr(value) : NULL;
}

static xpc_object_t xpc_create_from_plist(const void *data, size_t size)
{
    atomic_fetch_add(&parses, 1);
    if (!size || *(const char *)data == '!') return NULL;
    char marker = *(const char *)data;
    xpc_object_t array = object_create(XPC_TYPE_ARRAY);
    if (marker == 'T') return array;
    xpc_object_t value = object_create(marker == 'N' ? XPC_TYPE_INT64 : XPC_TYPE_STRING);
    value->string = marker == 'B' ? "/fixture/B" : "/fixture/A";
    array->count = 1;
    array->values[0] = value;
    xpc_object_t dictionary = object_create(XPC_TYPE_DICTIONARY);
    dictionary->count = 1;
    dictionary->values[0] = array;
    return dictionary;
}

static void publish(char marker, const struct timespec *mtime)
{
    char temporary[1100];
    snprintf(temporary, sizeof(temporary), "%s.next", configPath);
    int fd = open(temporary, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0 || (marker && write(fd, &marker, 1) != 1)) abort();
    if (mtime) {
        struct timespec times[2] = {*mtime, *mtime};
        if (futimens(fd, times)) abort();
    }
    if (close(fd) || rename(temporary, configPath)) abort();
}

static int fixture_open(const char *path, int flags, ...)
{
    int fd = open(path, flags);
    if (fd >= 0) atomic_fetch_add(&descriptors, 1);
    return fd;
}
static int fixture_close(int fd)
{
    int result = close(fd);
    if (!result) atomic_fetch_sub(&descriptors, 1);
    return result;
}
static void *fixture_mmap(void *address, size_t size, int prot, int flags, int fd, off_t offset)
{
    if (is("mapping-failure")) { errno = ENOMEM; return MAP_FAILED; }
    return mmap(address, size, prot, flags, fd, offset);
}
static ssize_t fixture_read(int fd, void *data, size_t size)
{
    readCalls++;
    if (is("interrupted-read") && readCalls == 1) { errno = EINTR; return -1; }
    if (is("partial-read") && size > 1) size = 1;
    ssize_t received = read(fd, data, size);
    if (is("changed-during-read") && readCalls == 1) {
        int writer = open(configPath, O_WRONLY | O_APPEND);
        if (writer < 0 || write(writer, "B", 1) != 1 || close(writer)) abort();
    }
    return received;
}
static char *fixture_strdup(const char *string)
{
    if (failDup) return NULL;
    return strdup(string);
}

static const char *fixture_config_path(void) { return configPath; }
#define JBROOT_PATH(path) fixture_config_path()
#define open fixture_open
#define close fixture_close
#define mmap fixture_mmap
#define read fixture_read
#define strdup fixture_strdup
#include "implementation.h"
#undef open
#undef close
#undef mmap
#undef read
#undef strdup

static void release_value(xpc_object_t value)
{
#if CONFIG_COPY_OWNED
    if (value) xpc_release(value);
#else
    (void)value;
#endif
}

static bool allows(const char *path)
{
    return spawn_config_for_executable(path, NULL) == (kSpawnConfigInject | kSpawnConfigTrust);
}

static void *reader(void *unused)
{
    for (unsigned i = 0; i < 100; i++) {
        xpc_object_t value = config_value("ProcessBlacklist");
        check(value != NULL && xpc_get_type(value) == XPC_TYPE_ARRAY, "concurrent reader gets a live snapshot");
        if (value) {
            check(atomic_load(&value->references) >= 2, "caller owns retained snapshot value");
            release_value(value);
        }
    }
    return NULL;
}

int main(int argc, const char *argv[])
{
    if (argc != 3) return 2;
    scenario = argv[1];
    snprintf(configPath, sizeof(configPath), "%s/config-%s", argv[2], scenario);
    if (is("nested") || is("stop") || is("null-string") || is("allocation-refusal")) {
        __block unsigned outer = 0, inner = 0;
        failDup = is("allocation-refusal");
        string_enumerate_components(is("null-string") ? NULL : ":first::second:", ":", ^(const char *part, bool *stop) {
            outer++;
            if (is("nested")) string_enumerate_components("a:b", ":", ^(const char *nested, bool *nestedStop) { inner++; });
            if (is("stop")) *stop = true;
        });
        check(outer == (is("null-string") || failDup ? 0U : is("stop") ? 1U : 2U), "enumeration preserves outer state and stop/null/allocation semantics");
        if (is("nested")) check(inner == 4, "nested enumeration is independent");
    } else {
        char marker = is("initial-invalid") ? '!' : is("empty") ? 0 : is("not-dictionary") ? 'T' : is("non-string-entry") ? 'N' : 'A';
        publish(marker, NULL);
        if (is("partial-read")) {
            int fd = open(configPath, O_WRONLY | O_APPEND);
            if (fd < 0 || write(fd, "AAA", 3) != 3 || close(fd)) abort();
        }
        if (is("missing-file")) unlink(configPath);
        if (is("initial-invalid") || is("empty") || is("not-dictionary") || is("non-string-entry") || is("missing-file")) {
            check(allows("/fixture/A"), "invalid or absent optional configuration uses defaults");
        } else if (is("mapping-failure") || is("changed-during-read")) {
            xpc_object_t value = config_value("ProcessBlacklist");
            if (is("changed-during-read")) check(value == NULL, "changed file is not published as a complete snapshot");
            release_value(value);
        } else if (is("concurrent-readers")) {
            pthread_t threads[8];
            for (unsigned i = 0; i < 8; i++) if (pthread_create(&threads[i], NULL, reader, NULL)) abort();
            for (unsigned i = 0; i < 8; i++) if (pthread_join(threads[i], NULL)) abort();
            for (xpc_object_t object = objects; object; object = object->next) check(atomic_load(&object->references) == 0, "thread exit releases its cached configuration");
        } else {
            xpc_object_t before = config_value("ProcessBlacklist");
            check(before != NULL, "valid dictionary loads");
            if (is("retained-value")) check(atomic_load(&before->references) >= 2, "returned value has independent ownership");
            bool replace = is("preserve-on-failed-reload") || is("retry-failed-reload") || is("same-timestamp-replacement") || is("older-timestamp-replacement") || is("retained-value");
            if (replace) {
                struct stat status;
                if (stat(configPath, &status)) abort();
                struct timespec timestamp = status.st_mtimespec;
                if (is("older-timestamp-replacement")) timestamp.tv_sec--;
                bool failedReload = is("preserve-on-failed-reload") || is("retry-failed-reload");
                publish(failedReload ? '!' : 'B', &timestamp);
                check(!allows(failedReload ? "/fixture/A" : "/fixture/B"), "publish replacement or retain last valid snapshot after parse refusal");
                if (is("retry-failed-reload")) {
                    publish('B', &timestamp);
                    check(!allows("/fixture/B"), "failed reload does not suppress later retry");
                }
                if (is("retained-value")) check(!strcmp(xpc_array_get_string(before, 0), "/fixture/A"), "retained value survives replacement");
            } else {
                check(!allows("/fixture/A") && allows("/fixture/B"), "valid blacklist changes only matching executable");
                check(atomic_load(&parses) == 1, "unchanged file uses cached snapshot");
            }
            release_value(before);
        }
    }
    check(atomic_load(&descriptors) == 0, "file descriptors are balanced");
    unlink(configPath);
    unsigned result = atomic_load(&failures);
    printf("%s: parses=%u failures=%u\n", scenario, atomic_load(&parses), result);
    return result ? 1 : 0;
}

#include <errno.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <ptrauth.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define CHECK(condition) do { if (!(condition)) { fprintf(stderr, "line %d: %s (errno=%d)\n", __LINE__, #condition, errno); exit(1); } } while (0)

static bool fail_write;
static bool fail_restore;
static unsigned protection_count;
static vm_prot_t protections[4];
static char old_target, new_target, original_sentinel;

static kern_return_t test_vm_protect(vm_map_t task, vm_address_t address, vm_size_t size, boolean_t maximum, vm_prot_t protection)
{
    CHECK(protection_count < 4);
    CHECK(!maximum);
    CHECK(!(protection & VM_PROT_EXECUTE));
    protections[protection_count++] = protection;
    if (fail_write && (protection & VM_PROT_WRITE)) return KERN_PROTECTION_FAILURE;
    if (fail_restore && protection == VM_PROT_READ) return KERN_PROTECTION_FAILURE;
    return vm_protect(task, address, size, maximum, protection);
}

static void roothide_loader_trace(const char *phase, const char *path, int result)
{
    (void)phase;
    (void)path;
    (void)result;
}

#undef ptrauth_auth_data
#undef ptrauth_auth_and_resign
#define ptrauth_auth_data(pointer, key, discriminator) (pointer)
#define ptrauth_auth_and_resign(pointer, old_key, old_discriminator, new_key, new_discriminator) (pointer)
#define vm_protect test_vm_protect

/* PRODUCTION_PATCHERS */

#undef vm_protect

typedef int (*patcher_t)(void **, int, void *, void **, uint16_t);

static void check_readonly(vm_address_t address)
{
    vm_size_t size = 0;
    mach_port_t object = MACH_PORT_NULL;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    CHECK(vm_region_64(mach_task_self(), &address, &size, VM_REGION_BASIC_INFO_64,
                      (vm_region_info_t)&info, &count, &object) == KERN_SUCCESS);
    CHECK(info.protection == VM_PROT_READ);
    if (MACH_PORT_VALID(object)) mach_port_deallocate(mach_task_self(), object);
}

int main(int argc, char **argv)
{
    CHECK(argc == 3);
    patcher_t patch = strcmp(argv[1], "roothide") == 0 ? hook_dyld_routine : dyld_hook_routine;
    void *original = &original_sentinel;
    void *object[1] = {NULL};

    if (strcmp(argv[2], "null") == 0) {
        CHECK(patch(NULL, 13, &new_target, &original, 0xBF31) == -1);
        CHECK(patch(object, 13, &new_target, &original, 0xBF31) == -1);
        CHECK(protection_count == 0 && original == &original_sentinel);
        return 0;
    }

    char path[] = "/tmp/roothide-vtable-XXXXXX";
    int fd = mkstemp(path);
    CHECK(fd >= 0);
    size_t page_size = (size_t)getpagesize();
    CHECK(ftruncate(fd, (off_t)page_size) == 0);
    void *target = &old_target;
    CHECK(pwrite(fd, &target, sizeof(target), 13 * sizeof(target)) == sizeof(target));
    CHECK(close(fd) == 0);
    fd = open(path, O_RDONLY);
    CHECK(fd >= 0);
    CHECK(unlink(path) == 0);
    int flags = strcmp(argv[2], "private") == 0 ? MAP_PRIVATE : MAP_SHARED;
    void **table = mmap(NULL, page_size, PROT_READ, flags, fd, 0);
    void **observer = mmap(NULL, page_size, PROT_READ, MAP_SHARED, fd, 0);
    CHECK(table != MAP_FAILED && observer != MAP_FAILED);
    CHECK(close(fd) == 0);
    object[0] = table;
    fail_write = strcmp(argv[2], "failure") == 0;
    fail_restore = strcmp(argv[2], "restore-failure") == 0;

    int result = patch(object, 13, &new_target, &original, 0xBF31);
    if (fail_write) {
        CHECK(result == -1);
        CHECK(original == &original_sentinel && table[13] == &old_target);
        CHECK(protection_count == 1);
    } else if (fail_restore) {
        CHECK(result == -1);
        CHECK(original == &old_target && table[13] == &old_target);
        CHECK(protection_count >= 2);
    } else {
        CHECK(result == 0);
        CHECK(original == &old_target && table[13] == &new_target);
        CHECK(protection_count == 2);
        CHECK(protections[0] == (VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY));
        CHECK(protections[1] == VM_PROT_READ);
    }
    CHECK(observer[13] == &old_target);
    check_readonly((vm_address_t)table);
    CHECK(munmap(table, page_size) == 0);
    CHECK(munmap(observer, page_size) == 0);
    return 0;
}

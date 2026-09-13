#include <assert.h>
#include <mach/mach.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static mach_port_t gHookdPort;
static kern_return_t test_allocate(mach_port_t task, mach_port_right_t right, mach_port_t *port)
{
    (void)task; (void)right;
    *port = 40;
    return KERN_SUCCESS;
}
static kern_return_t test_insert(mach_port_t task, mach_port_t name, mach_port_t right, mach_msg_type_name_t type)
{
    (void)task; (void)name; (void)right; (void)type;
    return KERN_SUCCESS;
}
static int test_attr_init(posix_spawnattr_t *attr) { *attr = NULL; return 0; }
static int test_registered(posix_spawnattr_t *attr, mach_port_t *ports, uint32_t count)
{
    (void)attr;
    assert(count == 3 && ports[2] == 40);
    return 0;
}
static int test_spawn(pid_t *pid, const char *path, const posix_spawn_file_actions_t *actions,
    const posix_spawnattr_t *attr, char *const argv[], char *const envp[])
{
    (void)path; (void)actions; (void)attr; (void)argv; (void)envp;
    *pid = 50;
    return 0;
}
static kern_return_t test_receive(mach_msg_header_t *message, mach_msg_option_t option,
    mach_msg_size_t sendSize, mach_msg_size_t receiveSize, mach_port_t port,
    mach_msg_timeout_t timeout, mach_port_t notify)
{
    (void)timeout; (void)notify;
    assert(option == MACH_RCV_MSG && sendSize == 0 && port == 40);
    assert(receiveSize >= sizeof(*message) + sizeof(mach_msg_trailer_t));
    memset((uint8_t *)message + sizeof(*message), 0, sizeof(mach_msg_trailer_t));
    message->msgh_remote_port = 60;
    message->msgh_size = sizeof(*message);
    return KERN_SUCCESS;
}
static kern_return_t test_refs(mach_port_t task, mach_port_t port, mach_port_right_t right, mach_port_delta_t delta)
{
    (void)task; (void)port; (void)right; (void)delta;
    return KERN_SUCCESS;
}
static void test_destroy(mach_msg_header_t *message) { assert(message->msgh_remote_port == 60); }
static kern_return_t test_deallocate(mach_port_t task, mach_port_t port)
{
    (void)task;
    assert(port == 40);
    return KERN_SUCCESS;
}
#define JBROOT_PATH(path) (path)
#define mach_port_allocate test_allocate
#define mach_port_insert_right test_insert
#define posix_spawnattr_init test_attr_init
#define posix_spawnattr_set_registered_ports_np test_registered
#define posix_spawn test_spawn
#define mach_msg test_receive
#define mach_port_mod_refs test_refs
#define mach_msg_destroy test_destroy
#define mach_port_deallocate test_deallocate
#include "checkin-under-test.h"

int main(void)
{
    pid_t pid = 0;
    assert(hookd_start(&pid, &gHookdPort) == 0);
    assert(pid == 50 && gHookdPort == 60);
    puts("Hookd check-in receive buffer includes the Mach trailer.");
    return 0;
}

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int mach_port_t;
typedef unsigned int mach_msg_type_number_t;
#define MACH_PORT_NULL 0

static int acquire_result;
static int done_result;
static int done_calls;

static int mach_task_self(void) { return 1; }
static int mach_ports_lookup(int task, mach_port_t **ports, mach_msg_type_number_t *count)
{
    static mach_port_t registered[3] = {0, 0, 9};
    (void)task;
    *ports = registered;
    *count = 3;
    return 0;
}
static int mach_ports_register(int task, mach_port_t *ports, mach_msg_type_number_t count)
{
    (void)task; (void)ports; (void)count;
    return 0;
}
static void jbclient_xpc_set_custom_port(mach_port_t port) { (void)port; }
static int is_kcall_available(void) { return 0; }
static int jbclient_initialize_primitives_internal(bool pte) { (void)pte; return acquire_result; }
static int jbclient_boomerang_done(void) { done_calls++; return done_result; }
static int fake_waitpid(int pid, int *status, int options) { (void)pid; (void)status; (void)options; return pid; }
static void roothide_bootlog(const char *message) { (void)message; }

#define waitpid fake_waitpid
#include "implementation.h"
#undef waitpid

int main(int argc, char **argv)
{
    if (argc != 2) return 100;
    if (!strcmp(argv[1], "acquire-fail")) acquire_result = -1;
    else if (!strcmp(argv[1], "done-fail")) done_result = -1;

    int result = boomerang_recoverPrimitives(true, true);
    if (!strcmp(argv[1], "acquire-fail")) {
        if (result == 0 || done_calls != 0) return 1;
    } else if (!strcmp(argv[1], "done-fail")) {
        if (result == 0 || done_calls != 1) return 2;
    } else {
        if (result != 0 || done_calls != 1) return 3;
    }
    puts("ok");
    return 0;
}

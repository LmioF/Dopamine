#include <sys/types.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <time.h>
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

static const char *scenario;
static struct observations { unsigned calls, invalid, aborts, allocations, live, reads, writes; uint64_t address, size; } *observed;
static bool is_case(const char *value) { return !strcmp(scenario, value); }
static uint64_t now_ns(void)
{
    struct timespec value;
    clock_gettime(CLOCK_MONOTONIC, &value);
    return (uint64_t)value.tv_sec * 1000000000ULL + value.tv_nsec;
}
static uid_t fixture_uid(void) { return 0; }
static kern_return_t fixture_task_for_pid(mach_port_t task, int pid, mach_port_t *result) { *result = 7; return KERN_SUCCESS; }
static uint64_t fixture_slide(void) { return UINT64_C(0x123456789abc); }
static void fixture_abort(void) { observed->aborts++; }
static kern_return_t fixture_mach_read(task_t task, mach_vm_address_t address, mach_vm_size_t size,
                                       mach_vm_address_t output, mach_vm_size_t *actual)
{
    observed->calls++;
    observed->address = address;
    observed->size = size;
    if (size > 1024 * 1024 || (size && !output)) { observed->invalid++; *actual = 0; return KERN_INVALID_ARGUMENT; }
    if (is_case("mach-read-failed")) { *actual = 0; return KERN_FAILURE; }
    *actual = is_case("partial-mach-read") ? size / 2 : size;
    for (size_t i = 0; i < *actual; i++) ((unsigned char *)(uintptr_t)output)[i] = (unsigned char)(address + i);
    return KERN_SUCCESS;
}
static kern_return_t fixture_mach_write(task_t task, mach_vm_address_t address, mach_vm_address_t input,
                                        mach_msg_type_number_t size)
{
    observed->calls++;
    observed->address = address;
    observed->size = size;
    if (size > 1024 * 1024 || (size && !input)) { observed->invalid++; return KERN_INVALID_ARGUMENT; }
    for (size_t i = 0; i < size; i++) if (((unsigned char *)(uintptr_t)input)[i] != (unsigned char)(address + i)) {
        observed->invalid++;
        return KERN_FAILURE;
    }
    return KERN_SUCCESS;
}
static void *fixture_malloc(size_t size)
{
    observed->allocations++;
    if (is_case("allocation-refused") || size > 1024 * 1024) { errno = ENOMEM; return NULL; }
    void *result = malloc(size ? size : 1);
    if (result) observed->live++;
    return result;
}
static void *fixture_calloc(size_t count, size_t size)
{
    if (size && count > SIZE_MAX / size) { errno = ENOMEM; return NULL; }
    void *result = fixture_malloc(count * size);
    if (result) memset(result, 0, count * size);
    return result;
}
static void fixture_free(void *allocation)
{
    if (allocation) observed->live--;
    free(allocation);
}
static ssize_t fixture_read(int fd, void *buffer, size_t size)
{
    unsigned call = observed->reads++;
    if (is_case("interrupted-input") && call < 2) { errno = EINTR; return -1; }
    if (is_case("short-input") && size > 1) size = 1;
    return read(fd, buffer, size);
}
static ssize_t fixture_write(int fd, const void *buffer, size_t size)
{
    unsigned call = observed->writes++;
    if (is_case("interrupted-output") && call < 2) { errno = EINTR; return -1; }
    if (is_case("short-output") && size > 1) size = 1;
    return write(fd, buffer, size);
}
#define SYSLOG(...) ((void)0)
#define getuid fixture_uid
#define task_for_pid fixture_task_for_pid
#define getkslide fixture_slide
#define mach_vm_read_overwrite fixture_mach_read
#define mach_vm_write fixture_mach_write
#define abort fixture_abort
#define malloc fixture_malloc
#define calloc fixture_calloc
#define free fixture_free
#define read fixture_read
#define write fixture_write

#include "implementation.h"

#undef malloc
#undef calloc
#undef free
#undef read
#undef write

static int peer_io(int fd, void *buffer, size_t size, bool writing)
{
    uint64_t deadline = now_ns() + 450000000ULL;
    size_t done = 0;
    while (done < size) {
        if (now_ns() >= deadline) return -1;
        struct pollfd descriptor = {.fd = fd, .events = writing ? POLLOUT : POLLIN};
        int ready = poll(&descriptor, 1, 20);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) return -1;
        if (!ready) continue;
        ssize_t result = writing ? write(fd, (char *)buffer + done, size - done) : read(fd, (char *)buffer + done, size - done);
        if (result > 0) done += (size_t)result;
        else if (result < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        else return -1;
    }
    return 0;
}
static int wait_child(pid_t pid, bool *forced)
{
    uint64_t deadline = now_ns() + 450000000ULL;
    int status = 0;
    for (;;) {
        pid_t result = waitpid(pid, &status, WNOHANG);
        if (result == pid) return status;
        if (result < 0 && errno != EINTR) return -1;
        if (now_ns() >= deadline) break;
        usleep(1000);
    }
    *forced = true;
    kill(pid, SIGKILL);
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    return status;
}

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    scenario = argv[1];
    observed = mmap(NULL, sizeof(*observed), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
    if (observed == MAP_FAILED) return 2;
    int input[2], output[2];
    if (pipe(input) || pipe(output) || fcntl(input[1], F_SETNOSIGPIPE, 1) || fcntl(output[1], F_SETNOSIGPIPE, 1)) return 2;
    pid_t child = fork();
    if (child < 0) return 2;
    if (child == 0) {
        int child_input = fcntl(input[0], F_DUPFD_CLOEXEC, 10);
        int child_output = fcntl(output[1], F_DUPFD_CLOEXEC, 10);
        if (child_input < 0 || child_output < 0) _exit(90);
        close(input[0]); close(input[1]); close(output[0]); close(output[1]);
        if (dup2(child_input, SERVER_INPUT_FD) < 0 || dup2(child_output, SERVER_OUTPUT_FD) < 0) _exit(91);
        close(child_input); close(child_output);
        char *arguments[] = {"fixture-server", "server", NULL};
        int result = fixture_server_main(2, arguments);
        _exit(result ? 1 : 0);
    }
    close(input[0]);
    close(output[1]);
    unsigned failures = 0;
    uint64_t address = is_case("address-wrap") ? UINT64_MAX - 7 : UINT64_C(0x12345670);
    size_t size = is_case("oversized") ? 1024 * 1024 + 1 : is_case("zero-size") ? 0 : 32;
    unsigned char payload[32];
    for (size_t i = 0; i < sizeof(payload); i++) payload[i] = (unsigned char)(address + i);
    bool writing = is_case("write") || is_case("payload-truncated");
    bool invalid = is_case("header-truncated") || is_case("payload-truncated") || is_case("allocation-refused") ||
                   is_case("oversized") || is_case("address-wrap") || is_case("unknown") || is_case("partial-command-stall");
    uint32_t command = writing ? KWRITE_BUF : KREAD_BUF;
    if (is_case("unknown")) command = 99;
    if (is_case("reply-closed")) {
        close(output[0]);
        output[0] = -1;
        command = GET_KSLIDE;
    }
    if (is_case("idle")) usleep(300000);
    if (!is_case("eof")) {
        if (is_case("partial-command-stall")) {
            failures += peer_io(input[1], &command, 1, true) != 0;
            struct pollfd descriptor = {.fd = output[0], .events = POLLIN};
            int ready = poll(&descriptor, 1, 350);
            char byte;
            failures += ready <= 0 || read(output[0], &byte, 1) != 0;
        } else {
            failures += peer_io(input[1], &command, sizeof(command), true) != 0;
            if (command == KREAD_BUF || command == KWRITE_BUF) {
                failures += peer_io(input[1], &address, is_case("header-truncated") ? 4 : sizeof(address), true) != 0;
                if (!is_case("header-truncated")) {
                    failures += peer_io(input[1], &size, sizeof(size), true) != 0;
                    if (writing) failures += peer_io(input[1], payload, is_case("payload-truncated") ? size / 2 : size, true) != 0;
                }
            }
            if (!invalid && !is_case("reply-closed")) {
                int result = -1;
                if (!writing && size) {
                    memset(payload, 0xcc, sizeof(payload));
                    failures += peer_io(output[0], payload, size, false) != 0;
                }
                failures += peer_io(output[0], &result, sizeof(result), false) != 0;
                bool failed_read = is_case("partial-mach-read") || is_case("mach-read-failed");
                failures += failed_read ? result == KERN_SUCCESS : result != KERN_SUCCESS;
                if (!writing && !failed_read) {
                    for (size_t i = 0; i < size; i++) failures += payload[i] != (unsigned char)(address + i);
                }
                if (is_case("mach-read-failed")) for (size_t i = 0; i < size; i++) failures += payload[i] != 0;
                command = EXIT_SERVER;
                peer_io(input[1], &command, sizeof(command), true);
            }
        }
    }
    close(input[1]);
    if (output[0] >= 0) close(output[0]);
    bool forced = false;
    int status = wait_child(child, &forced);
    failures += forced || !WIFEXITED(status) || observed->aborts || observed->invalid || observed->live;
    if (invalid || is_case("eof") || is_case("reply-closed") || is_case("zero-size")) failures += observed->calls != 0;
    else failures += observed->calls != 1 || observed->address != address || observed->size != size;
    if (is_case("eof")) failures += !WIFEXITED(status) || WEXITSTATUS(status) != 0;
    printf("%s: operations=%u invalid=%u aborts=%u live=%u forced=%d failures=%u\n",
           scenario, observed->calls, observed->invalid, observed->aborts, observed->live, forced, failures);
    munmap(observed, sizeof(*observed));
    return failures ? 1 : 0;
}

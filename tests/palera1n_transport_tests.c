#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <spawn.h>
#include <poll.h>
#include <signal.h>
#include <time.h>
#include <dispatch/dispatch.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

extern char **environ;
static const char *scenario;
static _Atomic unsigned io_calls, write_calls, read_calls, wait_calls;
static unsigned attribute_live, spawn_calls;
static pid_t last_spawned_pid = -1;
static bool is_case(const char *value) { return !strcmp(scenario, value); }
static uint64_t fixture_now(void)
{
    struct timespec value;
    clock_gettime(CLOCK_MONOTONIC, &value);
    return (uint64_t)value.tv_sec * 1000000000ULL + value.tv_nsec;
}
static ssize_t fixture_write(int fd, const void *buffer, size_t size)
{
    io_calls++;
    unsigned call = write_calls++;
    if (is_case("write-interrupted") && call == 0) { errno = EINTR; return -1; }
    if (is_case("zero-write") && call == 0) return 0;
    if (is_case("partial-write-error") && call > 0) { errno = EIO; return -1; }
    if (is_case("write-short") || is_case("concurrent") || is_case("partial-write-error")) {
        if (size > 2) size = 2;
    }
    ssize_t result = write(fd, buffer, size);
    if (is_case("concurrent")) usleep(200);
    return result;
}
static ssize_t fixture_read(int fd, void *buffer, size_t size)
{
    io_calls++;
    unsigned call = read_calls++;
    if (is_case("read-interrupted") && call == 0) { errno = EINTR; return -1; }
    if (is_case("read-short") && size > 2) size = 2;
    return read(fd, buffer, size);
}
static pid_t fixture_waitpid(pid_t pid, int *status, int options)
{
    if (is_case("stop-interrupted") && wait_calls++ < 2) { errno = EINTR; return -1; }
    return waitpid(pid, status, options);
}
static int fixture_attr_init(posix_spawnattr_t *attribute)
{
    if (is_case("check-init-refused")) return ENOMEM;
    int result = posix_spawnattr_init(attribute);
    if (!result) attribute_live++;
    return result;
}
static int fixture_attr_destroy(posix_spawnattr_t *attribute)
{
    int result = posix_spawnattr_destroy(attribute);
    if (!result) attribute_live--;
    return result;
}
static int fixture_persona(const posix_spawnattr_t *attribute, uid_t uid, uint32_t flags)
{
    return is_case("check-persona-refused") ? EPERM : 0;
}
static int fixture_persona_uid(const posix_spawnattr_t *attribute, uid_t uid) { return 0; }
static int fixture_persona_gid(const posix_spawnattr_t *attribute, uid_t gid) { return 0; }
static int fixture_spawn(pid_t *pid, const char *path, const posix_spawn_file_actions_t *actions,
                         const posix_spawnattr_t *attribute, char *const argv[], char *const envp[])
{
    spawn_calls++;
    if (!attribute_live) return EINVAL;
    if (is_case("check-spawn-refused")) return EACCES;
    if (is_case("check-invalid-pid")) { *pid = -1; return 0; }
    int result = posix_spawn(pid, path, actions, attribute, argv, envp);
    if (!result) last_spawned_pid = *pid;
    return result;
}
static void fixture_log(const char *format, ...) {}
#define SYSLOG fixture_log
#define POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE 1
#define read fixture_read
#define write fixture_write
#define waitpid fixture_waitpid
#define posix_spawnattr_init fixture_attr_init
#define posix_spawnattr_destroy fixture_attr_destroy
#define posix_spawnattr_set_persona_np fixture_persona
#define posix_spawnattr_set_persona_uid_np fixture_persona_uid
#define posix_spawnattr_set_persona_gid_np fixture_persona_gid
#define posix_spawn fixture_spawn

#include "implementation.h"

#undef read
#undef write
#undef waitpid
#undef posix_spawnattr_init
#undef posix_spawnattr_destroy
#undef posix_spawn

static int peer_io(int fd, void *data, size_t size, bool writing)
{
    size_t done = 0;
    while (done < size) {
        struct pollfd descriptor = {.fd = fd, .events = writing ? POLLOUT : POLLIN};
        int ready = poll(&descriptor, 1, 300);
        if (ready < 0 && errno == EINTR) continue;
        if (ready <= 0) return -1;
        ssize_t result = writing ? write(fd, (char *)data + done, size - done)
                                 : read(fd, (char *)data + done, size - done);
        if (result > 0) done += (size_t)result;
        else if (result < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        else return -1;
    }
    return 0;
}
static void peer_main(int input, int output)
{
    if (is_case("read-eof")) _exit(0);
    if (is_case("stall") || is_case("slide-stall") || is_case("stop-stall")) {
        usleep(600000);
        _exit(0);
    }
    unsigned requests = 0;
    for (;;) {
        uint32_t command = 0;
        if (peer_io(input, &command, sizeof(command), false)) _exit(0);
        if (command == EXIT_SERVER) _exit(0);
        if (command == GET_KSLIDE) {
            uint64_t slide = UINT64_C(0x123456789abc);
            size_t size = is_case("slide-short") ? 4 : sizeof(slide);
            peer_io(output, &slide, size, true);
            if (is_case("slide-short")) _exit(0);
            continue;
        }
        if (command != KREAD_BUF && command != KWRITE_BUF) _exit(71);
        uint64_t address = 0;
        size_t size = 0;
        if (peer_io(input, &address, sizeof(address), false) || peer_io(input, &size, sizeof(size), false)) _exit(72);
        if (size > 1024 * 1024) _exit(73);
        unsigned char *buffer = malloc(size ? size : 1);
        if (!buffer) _exit(74);
        int result = is_case("server-error") && requests++ == 0 ? 17 : 0;
        if (command == KREAD_BUF) {
            for (size_t i = 0; i < size; i++) buffer[i] = (unsigned char)(address + i);
            if (is_case("payload-short") || is_case("read-after-error")) {
                peer_io(output, buffer, size / 2, true);
                free(buffer);
                _exit(0);
            }
            if (peer_io(output, buffer, size, true)) { free(buffer); _exit(0); }
        } else {
            if (peer_io(input, buffer, size, false)) { free(buffer); _exit(0); }
            for (size_t i = 0; i < size; i++) if (buffer[i] != (unsigned char)(address + i)) result = 18;
        }
        free(buffer);
        size_t result_size = is_case("result-short") || is_case("write-result-short") ? 2 : sizeof(result);
        if (peer_io(output, &result, result_size, true)) _exit(0);
        if (result_size != sizeof(result)) _exit(0);
    }
}
static void reap_fixture_child(pid_t pid)
{
    if (pid <= 1) return;
    int status;
    pid_t result = waitpid(pid, &status, WNOHANG);
    if (result == 0) {
        kill(pid, SIGKILL);
        while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    }
}
static unsigned setup_peer(pid_t *pid)
{
    int input[2], output[2];
    if (pipe(input) || pipe(output)) return 1;
    if (fcntl(input[1], F_SETNOSIGPIPE, 1) || fcntl(output[1], F_SETNOSIGPIPE, 1)) return 1;
    *pid = fork();
    if (*pid < 0) return 1;
    if (*pid == 0) {
        close(input[1]);
        close(output[0]);
        peer_main(input[0], output[1]);
        _exit(75);
    }
    close(input[0]);
    close(output[1]);
    serverInputPipe[0] = serverOutputPipe[1] = -1;
    serverInputPipe[1] = input[1];
    serverOutputPipe[0] = output[0];
    serverPid = *pid;
    return 0;
}
static bool payload_matches(const unsigned char *buffer, uint64_t address, size_t size)
{
    for (size_t i = 0; i < size; i++) if (buffer[i] != (unsigned char)(address + i)) return false;
    return true;
}
struct thread_request { uint64_t address; unsigned char payload[32]; int result; };
static void *concurrent_request(void *context)
{
    struct thread_request *request = context;
    request->result = temp_kreadbuf(request->address, request->payload, sizeof(request->payload));
    return NULL;
}

int main(int argc, char **argv)
{
    if (argc == 3 && !strcmp(argv[1], "--check-child")) {
        if (!strcmp(argv[2], "stall")) { usleep(600000); return 0; }
        return 6;
    }
    if (argc != 2) return 2;
    scenario = argv[1];
    unsigned failures = 0;
    uint64_t began = fixture_now();
    if (!strncmp(scenario, "check-", 6)) {
        char *arguments[] = {argv[0], "--check-child", is_case("check-stall") ? "stall" : "6", NULL};
        errno = 0;
        int result = check_server(argv[0], arguments, environ);
        int saved_errno = errno;
        int expected = is_case("check-persona-refused") ? EPERM : is_case("check-init-refused") ? ENOMEM :
                       is_case("check-spawn-refused") ? EACCES : is_case("check-invalid-pid") ? ECHILD : 6;
        if (is_case("check-stall")) failures += result == 0 || saved_errno != ETIMEDOUT;
        else failures += result != expected;
        failures += attribute_live != 0;
        if (is_case("check-persona-refused") || is_case("check-init-refused")) failures += spawn_calls != 0;
        if (is_case("check-stall")) failures += fixture_now() - began > 450000000ULL;
        reap_fixture_child(last_spawned_pid);
        printf("%s: result=%d errno=%d live_attributes=%u failures=%u\n", scenario, result, saved_errno, attribute_live, failures);
        return failures ? 1 : 0;
    }
    pid_t child = -1;
    if (setup_peer(&child)) return 2;
    began = fixture_now();
    errno = 0;
    if (!strncmp(scenario, "stop-", 5)) {
        int result = stop_server();
        int saved_errno = errno;
        if (is_case("stop-stall")) failures += result == 0 || saved_errno != ETIMEDOUT || fixture_now() - began > 450000000ULL;
        else failures += result != 0;
        failures += serverInputPipe[1] != -1 || serverOutputPipe[0] != -1 || serverPid != -1;
    } else if (!strncmp(scenario, "slide-", 6)) {
        uint64_t slide = getkslide();
        if (is_case("slide-full")) failures += slide != UINT64_C(0x123456789abc);
        else failures += slide != 0 || errno == 0;
        if (is_case("slide-stall")) failures += fixture_now() - began > 450000000ULL;
    } else if (is_case("concurrent")) {
        struct thread_request first = {.address = 0x11111111}, second = {.address = 0x22222222};
        pthread_t a, b;
        if (pthread_create(&a, NULL, concurrent_request, &first) || pthread_create(&b, NULL, concurrent_request, &second)) return 2;
        pthread_join(a, NULL);
        pthread_join(b, NULL);
        failures += first.result || second.result || !payload_matches(first.payload, first.address, sizeof(first.payload)) ||
                    !payload_matches(second.payload, second.address, sizeof(second.payload));
    } else {
        size_t size = is_case("large-read") || is_case("large-write") ? 2 * 1024 * 1024 + 17 : 32;
        uint64_t address = is_case("address-wrap") ? UINT64_MAX - 7 : UINT64_C(0x12345670);
        unsigned char *buffer = malloc(size);
        if (!buffer) return 2;
        bool writing = !strncmp(scenario, "write-", 6) || is_case("large-write");
        for (size_t i = 0; i < size; i++) buffer[i] = writing ? (unsigned char)(address + i) : 0;
        unsigned before = io_calls;
        int result;
        if (is_case("zero-length")) result = temp_kreadbuf(address, NULL, 0);
        else if (is_case("bad-buffer")) result = temp_kreadbuf(address, NULL, size);
        else result = writing ? temp_kwritebuf(address, buffer, size) : temp_kreadbuf(address, buffer, size);
        int saved_errno = errno;
        bool transport_failure = is_case("read-eof") || is_case("payload-short") || is_case("result-short") ||
                                 is_case("write-result-short") || is_case("partial-write-error") || is_case("zero-write") ||
                                 is_case("stall") || is_case("read-after-error");
        if (transport_failure) failures += result == 0 || saved_errno == 0;
        else if (is_case("bad-buffer") || is_case("address-wrap")) failures += result == 0 || io_calls != before;
        else if (is_case("zero-length")) failures += result != 0 || io_calls != before;
        else if (is_case("server-error")) {
            failures += result != 17;
            result = temp_kreadbuf(address, buffer, size);
            failures += result != 0 || !payload_matches(buffer, address, size);
        } else failures += result != 0 || (!writing && !payload_matches(buffer, address, size));
        if (writing && !transport_failure) failures += getkslide() != UINT64_C(0x123456789abc);
        if (is_case("read-after-error")) {
            unsigned calls = io_calls;
            result = temp_kreadbuf(address, buffer, size);
            failures += result == 0 || io_calls != calls;
        }
        if (is_case("stall")) failures += fixture_now() - began > 450000000ULL || saved_errno != ETIMEDOUT;
        free(buffer);
    }
    if (serverInputPipe[1] >= 0) close(serverInputPipe[1]);
    if (serverOutputPipe[0] >= 0) close(serverOutputPipe[0]);
    reap_fixture_child(child);
    printf("%s: io_calls=%u elapsed_ms=%llu failures=%u\n", scenario, (unsigned)io_calls,
           (unsigned long long)((fixture_now() - began) / 1000000ULL), failures);
    return failures ? 1 : 0;
}

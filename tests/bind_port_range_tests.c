#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

enum { EXHAUST, FIRST, LAST, REFUSE, EXPLICIT };
static int mode, calls, invalid_calls;
static int fixture_bind(int fd, const struct sockaddr *address, socklen_t length)
{
    calls++;
    if (fd != 1234) invalid_calls++;
    if (address->sa_family == AF_UNIX) { errno = EAFNOSUPPORT; return -1; }
    unsigned port;
    if (address->sa_family == AF_INET) {
        if (length != sizeof(struct sockaddr_in)) invalid_calls++;
        port = ntohs(((const struct sockaddr_in *)address)->sin_port);
    } else {
        if (length != sizeof(struct sockaddr_in6)) invalid_calls++;
        port = ntohs(((const struct sockaddr_in6 *)address)->sin6_port);
    }
    if (mode == EXPLICIT) {
        if (port != 12345) invalid_calls++;
        return 0;
    }
    if (port < IPPORT_HIFIRSTAUTO || port > IPPORT_HILASTAUTO) {
        invalid_calls++;
        errno = EIO;
        return -1;
    }
    if (mode == FIRST || (mode == LAST && port == IPPORT_HILASTAUTO)) return 0;
    errno = mode == REFUSE ? EACCES : EADDRINUSE;
    return -1;
}
static int (*orig_bind)(int, const struct sockaddr *, socklen_t) = fixture_bind;

#include "implementation.h"

int main(void)
{
    const int families[] = {AF_INET, AF_INET6};
    int failures = 0;
    for (unsigned i = 0; i < 2; i++) {
        for (mode = EXHAUST; mode <= EXPLICIT; mode++) {
            struct sockaddr_storage storage = {0};
            storage.ss_family = families[i];
            socklen_t length;
            if (families[i] == AF_INET) {
                struct sockaddr_in *address = (struct sockaddr_in *)&storage;
                address->sin_port = htons(mode == EXPLICIT ? 12345 : 0);
                length = sizeof(*address);
            } else {
                struct sockaddr_in6 *address = (struct sockaddr_in6 *)&storage;
                address->sin6_port = htons(mode == EXPLICIT ? 12345 : 0);
                length = sizeof(*address);
            }
            struct sockaddr_storage original = storage;
            calls = invalid_calls = errno = 0;
            int result = new_bind(1234, (const struct sockaddr *)&storage, length);
            int expected_result = mode == EXHAUST || mode == REFUSE ? -1 : 0;
            int expected_calls = mode == EXHAUST || mode == LAST ? IPPORT_HILASTAUTO - IPPORT_HIFIRSTAUTO + 1 : 1;
            int expected_errno = mode == EXHAUST ? EADDRINUSE : mode == REFUSE ? EACCES : 0;
            if (result != expected_result || calls != expected_calls || invalid_calls ||
                (expected_result < 0 && errno != expected_errno) || memcmp(&storage, &original, sizeof(storage))) {
                fprintf(stderr, "family=%d mode=%d result=%d errno=%d calls=%d invalid=%d\n",
                        families[i], mode, result, errno, calls, invalid_calls);
                failures++;
            }
        }
    }
    struct sockaddr other = {.sa_family = AF_UNIX};
    calls = invalid_calls = errno = 0;
    if (new_bind(1234, &other, sizeof(other)) != -1 || errno != EAFNOSUPPORT || calls != 1 || invalid_calls) failures++;
    printf("11 bind range cases, %d failures; no sockets opened\n", failures);
    return failures ? 1 : 0;
}

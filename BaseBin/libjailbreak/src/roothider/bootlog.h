#ifndef ROOTHIDE_BOOTLOG_H
#define ROOTHIDE_BOOTLOG_H

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/time.h>
#include <unistd.h>

#ifndef ROOTHIDE_BOOTLOG_PATH
#define ROOTHIDE_BOOTLOG_PATH "/var/mobile/Library/Logs/CrashReporter/Dopamine-boot.log"
#endif

static inline void roothide_bootlog(const char *phase)
{
    int savedErrno = errno;
    int fd = open(ROOTHIDE_BOOTLOG_PATH, O_WRONLY | O_APPEND | O_CLOEXEC);
    if (fd >= 0) {
        struct timeval now = {0};
        gettimeofday(&now, NULL);
        char line[256];
        int length = snprintf(line, sizeof(line), "%lld.%06ld pid=%d %s\n",
            (long long)now.tv_sec, (long)now.tv_usec, getpid(), phase);
        if (length > 0) {
            if ((size_t)length >= sizeof(line)) length = sizeof(line) - 1;
            line[length - 1] = '\n';
            size_t written = 0;
            while (written < (size_t)length) {
                ssize_t count = write(fd, line + written, (size_t)length - written);
                if (count > 0) written += (size_t)count;
                else if (count < 0 && errno == EINTR) continue;
                else break;
            }
            // A userspace failure can otherwise lose the last diagnostic phase.
            fsync(fd);
        }
        close(fd);
    }
    errno = savedErrno;
}

#endif

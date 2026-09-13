#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static const char *bootlog_path;
#define ROOTHIDE_BOOTLOG_PATH bootlog_path
#include "../BaseBin/libjailbreak/src/roothider/bootlog.h"

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    bootlog_path = argv[1];
    unlink(bootlog_path);
    errno = EDOM;
    roothide_bootlog("disabled");
    assert(errno == EDOM);
    assert(access(bootlog_path, F_OK) == -1);

    int fd = open(bootlog_path, O_CREAT | O_EXCL | O_WRONLY, 0600);
    assert(fd >= 0);
    close(fd);
    errno = ERANGE;
    roothide_bootlog("phase one");
    assert(errno == ERANGE);
    roothide_bootlog("phase two");
    assert(errno == ERANGE);

    char buffer[1024] = {0};
    fd = open(bootlog_path, O_RDONLY);
    assert(fd >= 0);
    ssize_t size = read(fd, buffer, sizeof(buffer) - 1);
    assert(size > 0);
    close(fd);
    assert(strstr(buffer, "phase one\n"));
    assert(strstr(buffer, "phase two\n"));
    assert(!strstr(buffer, "disabled"));
    assert(strstr(buffer, "pid="));
    assert(unlink(bootlog_path) == 0);
    puts("Boot-phase diagnostics: opt-in, append, and errno preservation passed.");
    return 0;
}

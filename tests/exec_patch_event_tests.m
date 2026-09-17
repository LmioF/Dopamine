#import <Foundation/Foundation.h>
#include <dispatch/dispatch.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <unistd.h>

static dispatch_queue_t gExecPatchDataQueue = nil;
static NSMutableDictionary *gExecPatchArray = nil;
static int gScenario;
static int gKeventCalls;

static int fixture_kevent(int kq, const struct kevent *changelist, int nchanges,
                         struct kevent *eventlist, int nevents,
                         const struct timespec *timeout)
{
    (void)kq;
    (void)changelist;
    (void)nchanges;
    (void)nevents;
    (void)timeout;
    gKeventCalls++;
    if (gKeventCalls == 1) {
        errno = (gScenario == 0) ? EINTR : EIO;
        return -1;
    }
    if (gKeventCalls == 2) {
        memset(eventlist, 0, sizeof(*eventlist));
        eventlist->ident = 42;
        eventlist->filter = EVFILT_PROC;
        eventlist->fflags = NOTE_EXIT;
        return 1;
    }
    _Exit(0);
}

static int fixture_roothide_patch_proc(pid_t pid)
{
    (void)pid;
    return 0;
}

static int fixture_kill(pid_t pid, int sig)
{
    (void)pid;
    (void)sig;
    return 0;
}

#define kevent(...) fixture_kevent(__VA_ARGS__)
#define roothide_patch_proc fixture_roothide_patch_proc
#define kill fixture_kill
#define JBLogError(...) ((void)0)
#define JBLogDebug(...) ((void)0)

#include "implementation.h"

#undef kevent
#undef roothide_patch_proc
#undef kill

int main(int argc, const char *argv[])
{
    @autoreleasepool {
        if (argc != 2) return 2;
        if (!strcmp(argv[1], "eintr")) gScenario = 0;
        else if (!strcmp(argv[1], "error")) gScenario = 1;
        else return 2;

        gExecPatchDataQueue = dispatch_queue_create("fixture.execpatch", DISPATCH_QUEUE_SERIAL);
        gExecPatchArray = [NSMutableDictionary dictionaryWithObject:@NO forKey:@42];
        event_handler(7);
        return 3;
    }
}

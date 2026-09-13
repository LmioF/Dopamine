#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include "hookd.h"
#include "mach_msg_exchange.h"

static pid_t gHookdPid = 1;
static mach_port_t gHookdPort = MACH_PORT_NULL;

static int waitpid_inline(pid_t pid, int *status, int options)
{
    assert(pid == gHookdPid && options == WNOHANG);
    *status = 0;
    return 0;
}

static int hookd_start(pid_t *pid, mach_port_t *port)
{
    (void)pid;
    (void)port;
    return EIO;
}

#include "transport-under-test.h"

static void *reply_thread(void *unused)
{
    (void)unused;
    for (unsigned i = 0; i < 3; ++i) {
        _Alignas(8) unsigned char storage[HOOKD_MSG_MAX_SIZE + MAX_TRAILER_SIZE] = {0};
        struct hookd_mach_msg *request = (void *)storage;
        assert(mach_msg(&request->hdr, MACH_RCV_MSG, 0, sizeof(storage),
            gHookdPort, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL) == KERN_SUCCESS);
        assert(request->hdr.msgh_id == 0x40000000);
        assert(request->clientPid == getpid());

        usleep(5000);
        struct hookd_mach_msg_reply reply = {0};
        reply.hdr.msgh_size = sizeof(reply);
        reply.hdr.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
        reply.hdr.msgh_remote_port = request->hdr.msgh_remote_port;
        reply.hdr.msgh_id = request->hdr.msgh_id + 100;
        reply.hookResultsCount = 100 + i;
        assert(mach_msg_send(&reply.hdr) == KERN_SUCCESS);
        request->hdr.msgh_remote_port = MACH_PORT_NULL;
        mach_msg_destroy(&request->hdr);
    }
    return NULL;
}

int main(void)
{
    assert(mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE,
        &gHookdPort) == KERN_SUCCESS);
    assert(mach_port_insert_right(mach_task_self(), gHookdPort, gHookdPort,
        MACH_MSG_TYPE_MAKE_SEND) == KERN_SUCCESS);
    pthread_t server;
    assert(pthread_create(&server, NULL, reply_thread, NULL) == 0);

    for (unsigned i = 0; i < 3; ++i) {
        struct hookd_mach_msg request = {0};
        request.hdr.msgh_size = sizeof(request);
        request.clientPid = getpid();
        _Alignas(8) unsigned char storage[HOOKD_MSG_MAX_SIZE + MAX_TRAILER_SIZE] = {0};
        struct hookd_mach_msg_reply *reply = (void *)storage;
        reply->hdr.msgh_size = sizeof(storage);
        assert(launchd_hookd_send_msg(&request, reply) == KERN_SUCCESS);
        assert(reply->hdr.msgh_size == sizeof(*reply));
        assert(reply->hdr.msgh_id == 0x40000000 + 100);
        assert(reply->hookResultsCount == 100 + i);
    }
    assert(pthread_join(server, NULL) == 0);
    assert(mach_port_deallocate(mach_task_self(), gHookdPort) == KERN_SUCCESS);
    assert(mach_port_mod_refs(mach_task_self(), gHookdPort, MACH_PORT_RIGHT_RECEIVE, -1) == KERN_SUCCESS);
    gHookdPort = MACH_PORT_DEAD;
    struct hookd_mach_msg request = {0};
    request.hdr.msgh_size = sizeof(request);
    _Alignas(8) unsigned char storage[HOOKD_MSG_MAX_SIZE + MAX_TRAILER_SIZE] = {0};
    struct hookd_mach_msg_reply *reply = (void *)storage;
    reply->hdr.msgh_size = sizeof(storage);
    assert(launchd_hookd_send_msg(&request, reply) == MACH_SEND_INVALID_DEST);
    puts("Hookd transport: three delayed roundtrips and send failure passed.");
    return 0;
}

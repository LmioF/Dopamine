#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "jbserver.h"
#include "mach_msg_exchange.h"

static mach_port_t serverPort = MACH_PORT_NULL;

static mach_port_t jbclient_mach_get_launchd_port(void)
{
    if (MACH_PORT_VALID(serverPort)) {
        kern_return_t result = mach_port_mod_refs(mach_task_self(), serverPort, MACH_PORT_RIGHT_SEND, 1);
        if (result != KERN_SUCCESS) {
            assert(mach_port_mod_refs(mach_task_self(), serverPort, MACH_PORT_RIGHT_DEAD_NAME, 1) == KERN_SUCCESS);
        }
    }
    return serverPort;
}

#include "transport-under-test.h"

static void *reply_thread(void *unused)
{
    (void)unused;
    for (unsigned i = 0; i < 3; ++i) {
        _Alignas(8) unsigned char storage[4096 + MAX_TRAILER_SIZE] = {0};
        struct jbserver_mach_msg *request = (void *)storage;
        assert(mach_msg(&request->hdr, MACH_RCV_MSG, 0, sizeof(storage), serverPort,
            MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL) == KERN_SUCCESS);
        assert(request->hdr.msgh_id == (0x40000000 | 206));
        assert(request->magic == JBSERVER_MACH_MAGIC);
        usleep(5000);
        struct jbserver_mach_msg_reply reply = {0};
        reply.msg.hdr.msgh_size = sizeof(reply);
        reply.msg.hdr.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
        reply.msg.hdr.msgh_remote_port = request->hdr.msgh_remote_port;
        reply.msg.hdr.msgh_id = request->hdr.msgh_id + 100;
        reply.msg.magic = request->magic;
        reply.msg.action = request->action;
        reply.status = 20 + i;
        assert(mach_msg_send(&reply.msg.hdr) == KERN_SUCCESS);
        request->hdr.msgh_remote_port = MACH_PORT_NULL;
        mach_msg_destroy(&request->hdr);
    }
    return NULL;
}

int main(void)
{
    assert(mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &serverPort) == KERN_SUCCESS);
    assert(mach_port_insert_right(mach_task_self(), serverPort, serverPort, MACH_MSG_TYPE_MAKE_SEND) == KERN_SUCCESS);
    pthread_t server;
    assert(pthread_create(&server, NULL, reply_thread, NULL) == 0);
    for (unsigned i = 0; i < 3; ++i) {
        _Alignas(8) unsigned char outgoing[512] = {0};
        struct jbserver_mach_msg *request = (void *)outgoing;
        request->hdr.msgh_size = i == 1 ? sizeof(outgoing) : sizeof(*request);
        request->magic = JBSERVER_MACH_MAGIC;
        request->action = JBSERVER_MACH_HOOKD_SEND_MSG;
        _Alignas(8) unsigned char storage[4096 + MAX_TRAILER_SIZE] = {0};
        struct jbserver_mach_msg_reply *reply = (void *)storage;
        reply->msg.hdr.msgh_size = i == 1 ? sizeof(*reply) + MAX_TRAILER_SIZE : sizeof(storage);
        assert(jbclient_mach_send_msg(&request->hdr, reply) == KERN_SUCCESS);
        assert(reply->status == 20 + i);
        assert(reply->msg.magic == JBSERVER_MACH_MAGIC);
        assert(reply->msg.action == request->action);
        mach_port_urefs_t references = 0;
        assert(mach_port_get_refs(mach_task_self(), serverPort, MACH_PORT_RIGHT_SEND, &references) == KERN_SUCCESS);
        assert(references == 1);
    }
    assert(pthread_join(server, NULL) == 0);
    assert(mach_port_mod_refs(mach_task_self(), serverPort, MACH_PORT_RIGHT_RECEIVE, -1) == KERN_SUCCESS);
    struct jbserver_mach_msg request = {0};
    struct jbserver_mach_msg_reply reply = {0};
    request.hdr.msgh_size = sizeof(request);
    reply.msg.hdr.msgh_size = sizeof(reply);
    assert(jbclient_mach_send_msg(&request.hdr, &reply) == MACH_SEND_INVALID_DEST);
    mach_port_urefs_t references = 0;
    assert(mach_port_get_refs(mach_task_self(), serverPort, MACH_PORT_RIGHT_DEAD_NAME, &references) == KERN_SUCCESS);
    assert(references == 1);
    assert(mach_port_deallocate(mach_task_self(), serverPort) == KERN_SUCCESS);
    serverPort = MACH_PORT_NULL;
    assert(jbclient_mach_send_msg(&request.hdr, &reply) == KERN_FAILURE);
    puts("Mach client roundtrips and send failure passed.");
    return 0;
}

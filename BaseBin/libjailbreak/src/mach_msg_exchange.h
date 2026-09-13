#ifndef JB_MACH_MSG_EXCHANGE_H
#define JB_MACH_MSG_EXCHANGE_H

#include <mach/mach.h>
#include <stdint.h>
#include <string.h>

static inline kern_return_t jb_mach_msg_exchange(mach_msg_header_t *request,
    mach_msg_header_t *reply, mach_port_t replyPort)
{
    mach_msg_size_t sendSize = request->msgh_size;
    mach_msg_size_t receiveSize = reply->msgh_size;
    if (sendSize < sizeof(*request) || receiveSize < sizeof(*reply)) return KERN_INVALID_ARGUMENT;
    mach_msg_size_t capacity = sendSize > receiveSize ? sendSize : receiveSize;
    _Alignas(8) uint8_t storage[capacity];
    mach_msg_header_t *exchange = (mach_msg_header_t *)storage;
    memcpy(exchange, request, sendSize);

    // iOS 15's self-contained dyldhook exposes mach_msg, not mach_msg_overwrite.
    kern_return_t result = mach_msg(exchange, MACH_SEND_MSG | MACH_RCV_MSG,
        sendSize, receiveSize, replyPort, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (result == KERN_SUCCESS) memcpy(reply, exchange, exchange->msgh_size);
    return result;
}

#endif

#pragma once

#include <xpc/xpc.h>

extern __typeof__(xpc_dictionary_create_reply) *orig_xpc_dictionary_create_reply;
XPC_RETURNS_RETAINED
xpc_object_t new_xpc_dictionary_create_reply(xpc_object_t original);
extern int (*orig_xpc_pipe_routine_reply)(xpc_object_t reply);
int new_xpc_pipe_routine_reply(xpc_object_t reply);

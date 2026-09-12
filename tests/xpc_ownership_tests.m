#include "../BaseBin/libjailbreak/src/roothider/xpc_hook.h"

_Static_assert(__builtin_types_compatible_p(
    __typeof__(orig_xpc_dictionary_create_reply),
    __typeof__(&xpc_dictionary_create_reply)),
    "Original XPC function pointer must preserve SDK return ownership");

_Static_assert(__builtin_types_compatible_p(
    __typeof__(&new_xpc_dictionary_create_reply),
    __typeof__(&xpc_dictionary_create_reply)),
    "Replacement XPC function must preserve SDK return ownership");

void check_xpc_reply_ownership(void)
{
    orig_xpc_dictionary_create_reply = xpc_dictionary_create_reply;
    orig_xpc_dictionary_create_reply = new_xpc_dictionary_create_reply;
}

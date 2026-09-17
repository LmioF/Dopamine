#ifndef ROOTHIDE_DYLD_DISPATCH_H
#define ROOTHIDE_DYLD_DISPATCH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool dyld_dispatch_offset(const uint32_t *instructions, size_t count, uintptr_t address,
                          uintptr_t interface, unsigned arguments, unsigned slot,
                          uint16_t salt, size_t *offset);
int dyld_hook_dispatch(void ***interface, const char *symbol, unsigned arguments,
                       unsigned slot, void *hook, void **original, uint16_t salt);

#endif

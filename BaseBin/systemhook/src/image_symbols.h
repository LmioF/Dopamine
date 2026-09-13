#pragma once

#include <mach-o/loader.h>

void *systemhook_find_image_symbol(const struct mach_header_64 *header, const char *symbolName);

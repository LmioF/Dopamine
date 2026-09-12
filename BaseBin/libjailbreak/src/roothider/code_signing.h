#ifndef ROOTHIDE_CODE_SIGNING_H
#define ROOTHIDE_CODE_SIGNING_H

#include <choma/CodeDirectory.h>

int roothide_refresh_first_code_slot(CS_DecodedBlob *destination, CS_DecodedBlob *source);
bool roothide_calculate_page_hash(const CS_CodeDirectory *directory, MachO *macho, uint32_t slot, uint8_t *output);

#endif

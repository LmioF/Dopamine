#include "image_symbols.h"
#include <mach-o/nlist.h>
#include <stdint.h>
#include <string.h>

void *_litehook_sign_if_executable(void *pointer);

void *systemhook_find_image_symbol(const struct mach_header_64 *header, const char *symbolName)
{
    if (!header || header->magic != MH_MAGIC_64 || !symbolName) return NULL;

    const struct segment_command_64 *text = NULL;
    const struct segment_command_64 *linkedit = NULL;
    const struct symtab_command *symtab = NULL;
    const uint8_t *commands = (const uint8_t *)(header + 1);
    uint32_t offset = 0;
    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (offset > header->sizeofcmds || header->sizeofcmds - offset < sizeof(struct load_command)) return NULL;
        const struct load_command *command = (const void *)(commands + offset);
        if (command->cmdsize < sizeof(*command) || command->cmdsize > header->sizeofcmds - offset) return NULL;
        if (command->cmd == LC_SEGMENT_64 && command->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *segment = (const void *)command;
            if (!strncmp(segment->segname, "__TEXT", sizeof(segment->segname))) text = segment;
            if (!strncmp(segment->segname, "__LINKEDIT", sizeof(segment->segname))) linkedit = segment;
        }
        else if (command->cmd == LC_SYMTAB && command->cmdsize >= sizeof(struct symtab_command)) {
            symtab = (const void *)command;
        }
        offset += command->cmdsize;
    }
    if (!text || !linkedit || !symtab) return NULL;

    // Cached dyld has nonzero preferred addresses; adding the header would relocate it twice.
    uintptr_t slide = (uintptr_t)header - text->vmaddr;
    uintptr_t linkeditBase = slide + linkedit->vmaddr - linkedit->fileoff;
    const struct nlist_64 *symbols = (const void *)(linkeditBase + symtab->symoff);
    const char *strings = (const void *)(linkeditBase + symtab->stroff);
    for (uint32_t i = 0; i < symtab->nsyms; i++) {
        const struct nlist_64 *symbol = &symbols[i];
        uint32_t stringOffset = symbol->n_un.n_strx;
        if (!stringOffset || stringOffset >= symtab->strsize ||
            (symbol->n_type & N_STAB) || (symbol->n_type & N_TYPE) != N_SECT) continue;
        const char *name = strings + stringOffset;
        if (!memchr(name, '\0', symtab->strsize - stringOffset)) continue;
        if (!strcmp(name, symbolName)) {
            return _litehook_sign_if_executable((void *)(slide + symbol->n_value));
        }
    }
    return NULL;
}

#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void *systemhook_find_image_symbol(const struct mach_header_64 *, const char *);

void *_litehook_sign_if_executable(void *pointer)
{
    return pointer;
}

static void require(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

static void invalid_read(int signal_number)
{
    const char message[] = "Symbol lookup accessed an unrelocated Mach-O address.\n";
    write(STDERR_FILENO, message, sizeof(message) - 1);
    _exit(1);
}

static struct mach_header_64 *make_image(uint64_t preferred_base)
{
    struct mach_header_64 *header = calloc(1, 4096);
    require(header != NULL, "Allocating the image fixture failed");
    header->magic = MH_MAGIC_64;
    header->ncmds = 3;
    header->sizeofcmds = 2 * sizeof(struct segment_command_64) + sizeof(struct symtab_command);
    struct segment_command_64 *text = (void *)(header + 1);
    *text = (struct segment_command_64){
        .cmd = LC_SEGMENT_64, .cmdsize = sizeof(*text),
        .vmaddr = preferred_base, .vmsize = 1024, .filesize = 1024,
    };
    memcpy(text->segname, "__TEXT", 7);
    struct segment_command_64 *linkedit = text + 1;
    *linkedit = (struct segment_command_64){
        .cmd = LC_SEGMENT_64, .cmdsize = sizeof(*linkedit),
        .vmaddr = preferred_base + 1024, .vmsize = 3072,
        .fileoff = 1024, .filesize = 3072,
    };
    memcpy(linkedit->segname, "__LINKEDIT", 11);
    struct symtab_command *symtab = (void *)(linkedit + 1);
    *symtab = (struct symtab_command){
        .cmd = LC_SYMTAB, .cmdsize = sizeof(*symtab),
        .symoff = 1024, .nsyms = 3, .stroff = 1088, .strsize = 32,
    };
    struct nlist_64 *symbols = (void *)((uint8_t *)header + symtab->symoff);
    symbols[0] = (struct nlist_64){ .n_un.n_strx = 100, .n_type = N_SECT };
    symbols[1] = (struct nlist_64){ .n_un.n_strx = 1, .n_type = N_UNDF };
    symbols[2] = (struct nlist_64){
        .n_un.n_strx = 1, .n_type = N_SECT, .n_value = preferred_base + 512,
    };
    memcpy((uint8_t *)header + symtab->stroff + 1, "_fixture_function", 18);
    return header;
}

int main(void)
{
    signal(SIGSEGV, invalid_read);
    signal(SIGBUS, invalid_read);
    const uint64_t preferred_bases[] = {0, 0x180000000ULL, 0x100000000ULL};
    for (unsigned i = 0; i < sizeof(preferred_bases) / sizeof(*preferred_bases); i++) {
        struct mach_header_64 *header = make_image(preferred_bases[i]);
        require(systemhook_find_image_symbol(header, "_fixture_function") == (uint8_t *)header + 512,
                "Symbol lookup must relocate both LINKEDIT and n_value by the full-width slide");
        require(systemhook_find_image_symbol(header, "_missing") == NULL, "Absent symbols must return NULL");
        free(header);
    }
    require(systemhook_find_image_symbol(NULL, "_fixture_function") == NULL, "A missing image must return NULL");
    struct mach_header_64 *header = make_image(0x180000000ULL);
    require(systemhook_find_image_symbol(header, NULL) == NULL, "A missing symbol name must return NULL");
    struct segment_command_64 *text = (void *)(header + 1);
    struct symtab_command *symtab = (void *)(text + 2);
    memset((uint8_t *)header + symtab->stroff, 'x', symtab->strsize);
    require(systemhook_find_image_symbol(header, "_fixture_function") == NULL, "Unterminated names must be ignored");
    text->cmdsize = 0;
    require(systemhook_find_image_symbol(header, "_fixture_function") == NULL, "Invalid load commands must return NULL");
    free(header);
    puts("Loaded-image symbols: zero/nonzero preferred addresses, full-width slide, and invalid-input checks passed.");
    return 0;
}

#include "code_signing.h"
#include <CommonCrypto/CommonDigest.h>
#include <stddef.h>
#include <limits.h>
#include <string.h>

static size_t digest_size(uint8_t type)
{
    switch (type) {
        case CS_HASHTYPE_SHA160_160:
        case CS_HASHTYPE_SHA256_160: return 20;
        case CS_HASHTYPE_SHA256_256: return 32;
        case CS_HASHTYPE_SHA384_384: return 48;
        default: return 0;
    }
}

static bool read_directory(CS_DecodedBlob *blob, CS_CodeDirectory *directory)
{
    size_t size = csd_blob_get_size(blob);
    if (size < offsetof(CS_CodeDirectory, scatterOffset)) return false;
    memset(directory, 0, sizeof(*directory));
    if (csd_blob_read(blob, 0, size < sizeof(*directory) ? size : sizeof(*directory), directory) != 0) return false;
    CODE_DIRECTORY_APPLY_BYTE_ORDER(directory, BIG_TO_HOST_APPLIER);
    if (directory->magic != CSMAGIC_CODEDIRECTORY || directory->length > size) return false;
    if (directory->hashSize != digest_size(directory->hashType) || !directory->hashSize) return false;
    return directory->codeLimit > 0 && directory->nCodeSlots > 0 && directory->hashOffset <= directory->length &&
        directory->hashSize <= directory->length - directory->hashOffset;
}

int roothide_refresh_first_code_slot(CS_DecodedBlob *destination, CS_DecodedBlob *source)
{
    CS_CodeDirectory current, fresh;
    if (!destination || !source || !read_directory(destination, &current) || !read_directory(source, &fresh)) return -1;
    if (current.hashType != fresh.hashType || current.hashSize != fresh.hashSize ||
        current.pageSize != fresh.pageSize || current.codeLimit != fresh.codeLimit ||
        current.nCodeSlots != fresh.nCodeSlots) return -1;
    uint8_t digest[CC_SHA384_DIGEST_LENGTH];
    if (csd_blob_read(source, fresh.hashOffset, fresh.hashSize, digest) != 0) return -1;
    return csd_blob_write(destination, current.hashOffset, current.hashSize, digest);
}

bool roothide_calculate_page_hash(const CS_CodeDirectory *directory, MachO *macho, uint32_t slot, uint8_t *output)
{
    if (!directory || !macho || !output || slot >= directory->nCodeSlots) return false;
    if (!digest_size(directory->hashType) || directory->hashSize != digest_size(directory->hashType)) return false;
    if (directory->pageSize >= 32 || (directory->version >= 0x20100 && directory->scatterOffset)) return false;
    uint64_t limit = directory->codeLimit;
    uint64_t pageSize = directory->pageSize ? 1ULL << directory->pageSize : limit;
    uint64_t offset = (uint64_t)slot * pageSize;
    if (!limit || offset >= limit || limit > memory_stream_get_size(macho_get_stream(macho))) return false;
    uint64_t length = limit - offset < pageSize ? limit - offset : pageSize;
    if (!length || length > UINT32_MAX) return false;
    uint8_t *page = malloc((size_t)length);
    if (!page) return false;
    if (macho_read_at_offset(macho, offset, (size_t)length, page) != 0) {
        free(page);
        return false;
    }
    uint8_t digest[CC_SHA384_DIGEST_LENGTH];
    switch (directory->hashType) {
        case CS_HASHTYPE_SHA160_160: CC_SHA1(page, (CC_LONG)length, digest); break;
        case CS_HASHTYPE_SHA256_256:
        case CS_HASHTYPE_SHA256_160: CC_SHA256(page, (CC_LONG)length, digest); break;
        case CS_HASHTYPE_SHA384_384: CC_SHA384(page, (CC_LONG)length, digest); break;
        default: free(page); return false;
    }
    memcpy(output, digest, directory->hashSize);
    free(page);
    return true;
}

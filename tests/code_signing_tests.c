#include <CommonCrypto/CommonDigest.h>
#include <stdio.h>
#include <string.h>
#include <choma/Host.h>
#include "../BaseBin/libjailbreak/src/roothider/code_signing.h"

static void require(bool condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

static CS_DecodedBlob *directory(uint32_t flags, uint8_t fill, uint8_t hashSize)
{
    size_t size = sizeof(CS_CodeDirectory) + hashSize;
    CS_CodeDirectory header = {
        .magic = CSMAGIC_CODEDIRECTORY, .length = (uint32_t)size, .version = 0x20200,
        .flags = flags, .hashOffset = sizeof(CS_CodeDirectory), .nCodeSlots = 1,
        .codeLimit = 32, .hashSize = hashSize, .hashType = CS_HASHTYPE_SHA256_256, .pageSize = 12,
    };
    CODE_DIRECTORY_APPLY_BYTE_ORDER(&header, HOST_TO_BIG_APPLIER);
    void *data = malloc(size);
    require(data != NULL, "Allocation failed");
    memcpy(data, &header, sizeof(header));
    memset((char *)data + sizeof(header), fill, hashSize);
    CS_DecodedBlob *blob = csd_blob_init(CSSLOT_CODEDIRECTORY, data);
    free(data);
    require(blob != NULL, "CodeDirectory creation failed");
    return blob;
}

int main(int argc, const char **argv)
{
    require(argc == 2, "Expected a Mach-O fixture path");
    CS_DecodedBlob *caller = directory(0, 0x11, 32);
    CS_DecodedBlob *disk = directory(2, 0x22, 32);
    CS_DecodedBlob *malformed = directory(2, 0x33, 31);
    require(roothide_refresh_first_code_slot(caller, disk) == 0, "Compatible signatures must refresh");
    require(csd_code_directory_get_flags(caller) == 0, "Caller TXM flags must survive refresh");
    require(csd_code_directory_get_flags(disk) == 2, "The source signature must remain unchanged");
    uint8_t actual[48] = {0};
    require(csd_blob_read(caller, sizeof(CS_CodeDirectory), 32, actual) == 0, "Reading the refreshed hash failed");
    for (unsigned i = 0; i < 32; i++) require(actual[i] == 0x22, "First-page hash was not refreshed");
    require(roothide_refresh_first_code_slot(caller, malformed) != 0, "Invalid SHA256 hash length must be rejected");
    require(roothide_refresh_first_code_slot(NULL, disk) != 0, "A missing destination must be rejected");
    csd_blob_free(caller);
    csd_blob_free(disk);
    csd_blob_free(malformed);

    Fat *fat = fat_init_from_path(argv[1]);
    require(fat != NULL, "Opening the Mach-O fixture failed");
    MachO *macho = fat_find_preferred_slice(fat);
    require(macho != NULL, "Selecting the fixture slice failed");
    uint32_t codeLimit = 0, signatureSize = 0;
    require(macho_find_code_signature_bounds(macho, &codeLimit, &signatureSize) == 0 && codeLimit > 4096, "The fixture needs at least two signed pages");
    uint8_t page[4096], expected[48];
    require(macho_read_at_offset(macho, 0, sizeof(page), page) == 0, "Reading the fixture page failed");
    const uint8_t types[] = {CS_HASHTYPE_SHA160_160, CS_HASHTYPE_SHA256_256, CS_HASHTYPE_SHA256_160, CS_HASHTYPE_SHA384_384};
    const uint8_t sizes[] = {20, 32, 20, 48};
    for (unsigned i = 0; i < 4; i++) {
        CS_CodeDirectory header = {.version = 0x20200, .codeLimit = codeLimit, .nCodeSlots = (codeLimit + 4095) / 4096, .pageSize = 12, .hashSize = sizes[i], .hashType = types[i]};
        memset(actual, 0, sizeof(actual));
        if (i == 0) CC_SHA1(page, sizeof(page), expected);
        else if (i == 3) CC_SHA384(page, sizeof(page), expected);
        else CC_SHA256(page, sizeof(page), expected);
#ifdef TEST_LEGACY_PAGE_HASH
        extern bool code_directory_calculate_page_hash(CS_CodeDirectory *, MachO *, int, uint8_t *);
        require(code_directory_calculate_page_hash(&header, macho, 0, actual), "Legacy hash calculation failed");
#else
        require(roothide_calculate_page_hash(&header, macho, 0, actual), "Page hashing failed");
#endif
        require(memcmp(actual, expected, sizes[i]) == 0, "Page digest does not match the declared hash algorithm");
        require(!roothide_calculate_page_hash(&header, macho, header.nCodeSlots, actual), "An out-of-range code slot must be rejected");
    }
    fat_free(fat);
    puts("Signature refresh, TXM flag preservation, four digest algorithms, and invalid-layout checks passed");
    return 0;
}

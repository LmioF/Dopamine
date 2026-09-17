#include <errno.h>
#include <copyfile.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <choma/MachO.h>
#include <choma/Host.h>
#include "../BaseBin/libjailbreak/src/info.h"
#include "../BaseBin/libjailbreak/src/signatures.h"
#include "../BaseBin/libjailbreak/src/roothider/code_signing.h"

struct system_info gSystemInfo;
static cdhash_t cachedHashes[8];
static unsigned cachedCount;
static unsigned attachmentCount;
static bool rejectAttachments;
static bool rejectTrustcache;
static const void *remoteSignatureBytes;
static size_t remoteSignatureSize;
static unsigned remoteReadCount;

static void require(bool condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "%s (errno=%d, attachment calls=%u)\n", message, errno, attachmentCount);
        exit(1);
    }
}

bool isRemovableBundlePath(const char *path) { return false; }
bool hasTrollstoreLiteMarker(const char *path) { return false; }
bool string_has_prefix(const char *string, const char *prefix)
{
    return strncmp(string, prefix, strlen(prefix)) == 0;
}

bool is_cdhash_trustcached(cdhash_t hash)
{
    for (unsigned i = 0; i < cachedCount; i++) {
        if (memcmp(hash, cachedHashes[i], sizeof(cdhash_t)) == 0) return true;
    }
    return false;
}

int jb_trustcache_add_cdhashes(cdhash_t *hashes, uint32_t count)
{
    if (rejectTrustcache) {
        errno = ENOMEM;
        return -1;
    }
    require(cachedCount + count <= 8, "Unexpected number of trust-cache entries");
    memcpy(cachedHashes + cachedCount, hashes, count * sizeof(cdhash_t));
    cachedCount += count;
    return 0;
}

int fd_attach_signature(int fd, fsignatures_t *signature)
{
    attachmentCount++;
    if (rejectAttachments) {
        errno = EBADEXEC;
        return -1;
    }
    require(signature && signature->fs_blob_start && signature->fs_blob_size, "An attached signature must own its bytes");
    return 0;
}

uint64_t proc_find(pid_t pid)
{
    require(pid == 4242, "Remote signature fixture used an unexpected pid");
    return 1;
}

int proc_vreadbuf(uint64_t process, const void *address, void *output, size_t size)
{
    require(process == 1, "Remote signature fixture used an unexpected process handle");
    require(address == remoteSignatureBytes && size == remoteSignatureSize,
            "Remote signature fixture requested the wrong range");
    memcpy(output, remoteSignatureBytes, size);
    remoteReadCount++;
    return 0;
}

static CS_DecodedSuperBlob *decode(CS_SuperBlob *blob)
{
    require(blob != NULL, "Signature read failed");
    CS_DecodedSuperBlob *decoded = csd_superblob_decode(blob);
    free(blob);
    require(decoded != NULL, "Signature decode failed");
    return decoded;
}

static void check_cached_directory(CS_DecodedSuperBlob *decoded)
{
    CS_DecodedBlob *directory = csd_superblob_find_best_code_directory(decoded);
    cdhash_t hash;
    require(directory && csd_code_directory_calculate_hash(directory, hash) == 0, "Signature hash calculation failed");
    require(is_cdhash_trustcached(hash), "The updated code directory must match the published trust-cache hash");
}

static void set_team_presence(CS_DecodedBlob *directory, bool present)
{
    uint32_t teamOffset = 0;
    char *team = csd_code_directory_copy_team_id(directory, &teamOffset);
    if (present) {
        if (!team) require(csd_code_directory_set_team_id(directory, "RH-TXM-TEAM") == 0,
                           "Adding a fixture TeamID failed");
    }
    else if (team) {
        CS_CodeDirectory header;
        require(csd_blob_read(directory, 0, sizeof(header), &header) == 0,
                "Reading the fixture CodeDirectory failed");
        CODE_DIRECTORY_APPLY_BYTE_ORDER(&header, BIG_TO_HOST_APPLIER);
        header.teamOffset = 0;
        CODE_DIRECTORY_APPLY_BYTE_ORDER(&header, HOST_TO_BIG_APPLIER);
        require(csd_blob_write(directory, 0, sizeof(header), &header) == 0,
                "Clearing the fixture TeamID failed");
    }
    free(team);
}

static void configure_txm_combination(CS_DecodedSuperBlob *decoded, bool adhoc, bool team)
{
    CS_DecodedBlob *directory = csd_superblob_find_best_code_directory(decoded);
    require(directory != NULL, "Fixture is missing a CodeDirectory");
    set_team_presence(directory, team);
    uint32_t flags = csd_code_directory_get_flags(directory);
    csd_code_directory_set_flags(directory, adhoc ? (flags | 2U) : (flags & ~2U));
}

static const char *source_name(signature_source_t source)
{
    switch (source) {
        case SIGNATURE_SOURCE_ALLOCATION: return "allocation";
        case SIGNATURE_SOURCE_FILE: return "file";
        case SIGNATURE_SOURCE_PROC: return "proc";
    }
    return "unknown";
}

static void run_txm_source_case(const char *fixture, const char *directoryPath,
                                signature_source_t source, bool adhoc, bool team)
{
    char path[PATH_MAX];
    require(snprintf(path, sizeof(path), "%s/txm-%s-%d-%d", directoryPath,
                     source_name(source), adhoc, team) < sizeof(path), "TXM fixture path too long");
    require(copyfile(fixture, path, NULL, COPYFILE_DATA | COPYFILE_STAT) == 0,
            "TXM fixture copy failed");
    int fd = open(path, O_RDWR);
    require(fd >= 0, "Opening the TXM fixture failed");

    Fat *fat = fat_init_from_path(path);
    require(fat != NULL, "Opening the TXM fixture Mach-O failed");
    MachO *slice = fat_find_preferred_slice(fat);
    require(slice != NULL, "Selecting the TXM fixture slice failed");
    uint64_t sliceOffset = slice->archDescriptor.offset;
    CS_SuperBlob *diskBlob = macho_read_code_signature(slice);
    require(diskBlob != NULL, "Reading the TXM fixture signature failed");
    CS_DecodedSuperBlob *decoded = csd_superblob_decode(diskBlob);
    free(diskBlob);
    require(decoded != NULL, "Decoding the TXM fixture signature failed");
    configure_txm_combination(decoded, adhoc, team);
    CS_DecodedBlob *inputDirectory = csd_superblob_find_best_code_directory(decoded);
    cdhash_t inputHash;
    require(csd_code_directory_calculate_hash(inputDirectory, inputHash) == 0,
            "Hashing the TXM fixture signature failed");
    CS_SuperBlob *customBlob = csd_superblob_encode(decoded);
    csd_superblob_free(decoded);
    fat_free(fat);
    require(customBlob != NULL, "Encoding the TXM fixture signature failed");
    size_t customSize = OSSwapBigToHostInt32(customBlob->length);

    cachedCount = 1;
    memcpy(cachedHashes[0], inputHash, sizeof(inputHash));
    attachmentCount = 0;
    rejectAttachments = false;
    rejectTrustcache = false;
    remoteReadCount = 0;
    remoteSignatureBytes = NULL;
    remoteSignatureSize = 0;
    gSystemInfo.kernelSymbol.SPTMArgs = 1;

    struct siginfo signature = {
        .source = source,
        .signature = {
            .fs_file_start = sliceOffset,
            .fs_blob_size = customSize,
        },
    };
    int pid = getpid();
    bool customOwnedBySignature = false;
    if (source == SIGNATURE_SOURCE_ALLOCATION) {
        signature.signature.fs_blob_start = customBlob;
        customOwnedBySignature = true;
    }
    else if (source == SIGNATURE_SOURCE_FILE) {
        off_t appendOffset = lseek(fd, 0, SEEK_END);
        require(appendOffset >= 0 && (uint64_t)appendOffset >= sliceOffset,
                "Finding the TXM file-signature fixture offset failed");
        require(write(fd, customBlob, customSize) == (ssize_t)customSize,
                "Writing the TXM file-signature fixture failed");
        signature.signature.fs_blob_start = (void *)(uintptr_t)((uint64_t)appendOffset - sliceOffset);
    }
    else {
        pid = 4242;
        remoteSignatureBytes = customBlob;
        remoteSignatureSize = customSize;
        signature.signature.fs_blob_start = customBlob;
    }

    int result = trust_signatures(pid, fd, &signature, 1);
    bool originallyValid = adhoc != team;
    require(result == 0, "Every TXM source/flag/TeamID combination must use the shared trust contract");
    require(attachmentCount == (originallyValid ? 0U : 1U),
            "TXM normalization used the wrong detached-attachment policy");
    require(cachedCount == (originallyValid ? 1U : 2U),
            "TXM normalization published an unexpected trust-cache hash count");
    if (!originallyValid) {
        require(signature.source == SIGNATURE_SOURCE_ALLOCATION,
                "A normalized remote/file signature must become owned attachment bytes");
    }
    if (source == SIGNATURE_SOURCE_PROC) require(remoteReadCount >= 1, "Remote signature source was not read");

    CS_DecodedSuperBlob *resultDecoded = decode(siginfo_resolve_superblob(&signature, pid, fd));
    CS_DecodedBlob *resultDirectory = csd_superblob_find_best_code_directory(resultDecoded);
    char *resultTeam = csd_code_directory_copy_team_id(resultDirectory, NULL);
    bool resultHasTeam = resultTeam != NULL;
    bool resultAdhoc = (csd_code_directory_get_flags(resultDirectory) & 2U) != 0;
    free(resultTeam);
    require(resultHasTeam == team, "TXM normalization must preserve TeamID presence");
    require(resultAdhoc == (originallyValid ? adhoc : !team),
            "TXM normalization produced the wrong CS_ADHOC state");
    require(resultAdhoc != resultHasTeam, "TXM output must have exactly one of CS_ADHOC and TeamID");
    csd_superblob_free(resultDecoded);

    if (signature.source == SIGNATURE_SOURCE_ALLOCATION) free(signature.signature.fs_blob_start);
    if (!customOwnedBySignature) free(customBlob);
    remoteSignatureBytes = NULL;
    remoteSignatureSize = 0;
    require(close(fd) == 0, "Closing the TXM fixture failed");
    require(unlink(path) == 0, "Removing the TXM fixture failed");
}

static void run_txm_source_matrix(const char *fixture, const char *directoryPath)
{
    signature_source_t sources[] = {
        SIGNATURE_SOURCE_ALLOCATION,
        SIGNATURE_SOURCE_FILE,
        SIGNATURE_SOURCE_PROC,
    };
    for (size_t sourceIndex = 0; sourceIndex < sizeof(sources) / sizeof(sources[0]); sourceIndex++) {
        for (unsigned adhoc = 0; adhoc <= 1; adhoc++) {
            for (unsigned team = 0; team <= 1; team++) {
                run_txm_source_case(fixture, directoryPath, sources[sourceIndex], adhoc != 0, team != 0);
            }
        }
    }
}

static void run_case(const char *fixture, const char *path, bool txm)
{
    require(copyfile(fixture, path, NULL, COPYFILE_DATA | COPYFILE_STAT) == 0, "Fixture copy failed");
    int fd = open(path, O_RDONLY);
    require(fd >= 0, "Fixture open failed");
    struct siginfo *signatures = NULL;
    uint32_t count = 0;
    file_collect_signatures(fd, &signatures, &count);
    require(count == 1, "Expected one compatible bootstrap signature");
    require(signatures[0].source == SIGNATURE_SOURCE_ALLOCATION, "The collector must own a copy of the file signature");

    uint32_t memoryFlags = 0;
    if (txm) {
        CS_DecodedSuperBlob *decoded = decode(siginfo_resolve_superblob(&signatures[0], getpid(), fd));
        CS_DecodedBlob *directory = csd_superblob_find_best_code_directory(decoded);
        char *team = csd_code_directory_copy_team_id(directory, NULL);
        uint32_t flags = csd_code_directory_get_flags(directory) | 0x10000;
        flags = team ? flags | 2 : flags & ~2U;
        memoryFlags = team ? flags & ~2U : flags | 2;
        free(team);
        csd_code_directory_set_flags(directory, flags);
        CS_SuperBlob *encoded = csd_superblob_encode(decoded);
        csd_superblob_free(decoded);
        require(encoded != NULL, "Memory signature encoding failed");
        free(signatures[0].signature.fs_blob_start);
        signatures[0].source = SIGNATURE_SOURCE_ALLOCATION;
        signatures[0].signature.fs_blob_start = encoded;
        signatures[0].signature.fs_blob_size = OSSwapBigToHostInt32(encoded->length);
    }

    cachedCount = 0;
    attachmentCount = 0;
    rejectAttachments = !txm;
    rejectTrustcache = false;
    gSystemInfo.kernelSymbol.SPTMArgs = txm ? 1 : 0;
    int result = trust_signatures(getpid(), fd, signatures, count);
    require(result == 0, txm ? "TXM flag correction must remain supported" : "On-disk branding must not use detached F_ADDSIGS attachment");
    require(attachmentCount == (txm ? 1 : 0), "Unexpected signature attachment policy");
    require(signatures[0].source == SIGNATURE_SOURCE_ALLOCATION, "Signature ownership must remain valid");

    CS_DecodedSuperBlob *decoded = decode(siginfo_resolve_superblob(&signatures[0], getpid(), fd));
    check_cached_directory(decoded);
    if (txm) {
        require(csd_code_directory_get_flags(csd_superblob_find_best_code_directory(decoded)) == memoryFlags, "Caller flags must survive roothide signature refresh");
    }
    csd_superblob_free(decoded);
    require(cachedCount == 1, "Expected one updated trust-cache hash");

    if (!txm) {
        Fat *fat = fat_init_from_path(path);
        require(fat != NULL, "Opening the branded file failed");
        MachO *slice = fat_find_preferred_slice(fat);
        require(slice != NULL, "Selecting the branded slice failed");
        CS_DecodedSuperBlob *disk = decode(macho_read_code_signature(slice));
        check_cached_directory(disk);
        CS_DecodedBlob *directory = csd_superblob_find_best_code_directory(disk);
        CS_CodeDirectory header;
        require(csd_blob_read(directory, 0, sizeof(header), &header) == 0, "Reading the branded directory failed");
        CODE_DIRECTORY_APPLY_BYTE_ORDER(&header, BIG_TO_HOST_APPLIER);
        uint8_t actual[48], expected[48];
        require(roothide_calculate_page_hash(&header, slice, 0, actual), "Hashing the branded code page failed");
        require(csd_blob_read(directory, header.hashOffset, header.hashSize, expected) == 0, "Reading the branded code slot failed");
        require(memcmp(actual, expected, header.hashSize) == 0, "On-disk code and its signature must remain consistent");
        csd_superblob_free(disk);
        fat_free(fat);
        require(trust_signatures(getpid(), fd, signatures, count) == 0, "Repeated file trust must succeed");
        require(attachmentCount == 0 && cachedCount == 1, "Repeated file trust must not attach or duplicate the cached hash");
    }
    if (signatures[0].source == SIGNATURE_SOURCE_ALLOCATION) free(signatures[0].signature.fs_blob_start);
    free(signatures);
    close(fd);
    require(unlink(path) == 0, "Fixture cleanup failed");
}

static void run_trustcache_failure_case(const char *fixture, const char *path)
{
    require(copyfile(fixture, path, NULL, COPYFILE_DATA | COPYFILE_STAT) == 0, "Fixture copy failed");
    int fd = open(path, O_RDONLY);
    require(fd >= 0, "Fixture open failed");
    struct siginfo *signatures = NULL;
    uint32_t count = 0;
    file_collect_signatures(fd, &signatures, &count);
    require(count == 1, "Expected one compatible bootstrap signature");

    cachedCount = 0;
    attachmentCount = 0;
    rejectAttachments = false;
    rejectTrustcache = true;
    gSystemInfo.kernelSymbol.SPTMArgs = 0;
    int result = trust_signatures(getpid(), fd, signatures, count);
    require(result != 0, "Trust-cache publication failure must fail signature preparation");
    require(cachedCount == 0, "Rejected trust-cache publication must not publish a hash");
    require(attachmentCount == 0, "Trust-cache failure must not continue into detached attachment");

    rejectTrustcache = false;
    if (signatures[0].source == SIGNATURE_SOURCE_ALLOCATION) free(signatures[0].signature.fs_blob_start);
    free(signatures);
    close(fd);
    require(unlink(path) == 0, "Fixture cleanup failed");
}

int main(int argc, const char **argv)
{
    require(argc == 3, "Expected bootstrap fixture and project-local build directory");
    char directory[PATH_MAX];
    require(snprintf(directory, sizeof(directory), "%s/trust-signatures-XXXXXX", argv[2]) < sizeof(directory), "Build path too long");
    require(mkdtemp(directory) != NULL, "Temporary fixture directory creation failed");
    char path[PATH_MAX];
    require(snprintf(path, sizeof(path), "%s/fixture", directory) < sizeof(path), "Fixture path too long");
    gSystemInfo.jailbreakInfo.jbrand = 0x1122334455667700ULL;
    run_case(argv[1], path, false);
    run_case(argv[1], path, true);
    run_trustcache_failure_case(argv[1], path);
    run_txm_source_matrix(argv[1], directory);
    require(rmdir(directory) == 0, "Temporary directory cleanup failed");
    puts("On-disk branding, repeated trust, and TXM source/normalization attachment regressions passed.");
    return 0;
}

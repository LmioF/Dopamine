#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <choma/MachO.h>
#include <choma/Fat.h>
#include <choma/MemoryStream.h>
#include <choma/FileStream.h>
#include <choma/CSBlob.h>
#include <choma/CodeDirectory.h>
#include <choma/Util.h>
#include <choma/Host.h>
#include <mach-o/dyld.h>
#include <libkern/OSByteOrder.h>
#include "trustcache.h"
#include "util.h"
#include "kernel.h"
#include "primitives.h"
#include "codesign.h"

#include "roothider.h"
#include "roothider/code_signing.h"

bool macho_is_mappable(MachO *macho)
{
	// Determine if there is any case in which the macho could be mapped

	static cpu_type_t hostCpuType;
	static cpu_subtype_t hostCpuSubtype;
	static dispatch_once_t onceToken = 0;
	dispatch_once(&onceToken, ^{
		host_get_cpu_information(&hostCpuType, &hostCpuSubtype);
	});

	bool hostIsArm64e = (hostCpuType == CPU_TYPE_ARM64) && ((hostCpuSubtype & ~0xff000000) == CPU_SUBTYPE_ARM64E);

	struct mach_header *header = macho_get_mach_header(macho);

	cpu_type_t cputype = header->cputype;
	cpu_subtype_t cpusubtype = header->cpusubtype;
	bool isLibrary = (header->filetype == MH_EXECUTE);

	if (cputype != CPU_TYPE_ARM64) return false;

	if (hostIsArm64e) {
		if (cpusubtype == (CPU_SUBTYPE_ARM64E | CPU_SUBTYPE_ARM64E_ABI_V2)) {
			// New arm64e ABI always mappable on arm64e
			return true;
		}
		else if (cpusubtype == CPU_SUBTYPE_ARM64E && isLibrary) {
			// Old arm64e ABI only mappable for libraries on arm64e iOS 14.6+
			return true;
		}
	}

	// Anything arm64 is always mappable on all dvices
	if ((cpusubtype == CPU_SUBTYPE_ARM64_V8) || (cpusubtype == CPU_SUBTYPE_ARM64_ALL)) return true;

	return false;
}

bool csd_superblob_is_adhoc_signed(CS_DecodedSuperBlob *superblob)
{
	CS_DecodedBlob *wrapperBlob = csd_superblob_find_blob(superblob, CSSLOT_SIGNATURESLOT, NULL);
	if (wrapperBlob) {
		if (csd_blob_get_size(wrapperBlob) > 8) {
			return false;
		}
	}
	return true;
}

bool code_signature_calculate_adhoc_cdhash(CS_SuperBlob *superblob, cdhash_t cdhashOut)
{
	bool isAdhocSigned = false;

	CS_DecodedSuperBlob *decodedSuperblob = csd_superblob_decode(superblob);
	if (decodedSuperblob) {
		if (csd_superblob_is_adhoc_signed(decodedSuperblob)) {
			if (csd_superblob_calculate_best_cdhash(decodedSuperblob, cdhashOut, NULL) == 0) {
				isAdhocSigned = true;
			}
		}
		csd_superblob_free(decodedSuperblob);
	}

	return isAdhocSigned;
}

bool macho_parse_code_signature(MachO *macho, cdhash_t cdhashOut)
{
	bool isAdhocSigned = false;

	CS_SuperBlob *superblob = macho_read_code_signature(macho);
	if (superblob) {
		isAdhocSigned = code_signature_calculate_adhoc_cdhash(superblob, cdhashOut);
		free(superblob);
	}

	return isAdhocSigned;
}

void fat_collect_untrusted_cdhashes_for_path(Fat *fat, const char *filepath, cdhash_t **cdhashesOut, uint32_t *cdhashCountOut)
{
	*cdhashesOut = NULL;
	*cdhashCountOut = 0;
	if (filepath && (string_has_prefix(filepath, "/private/preboot/Cryptexes/") ||
		(isRemovableBundlePath(filepath) && !hasTrollstoreLiteMarker(filepath)))) {
		return;
	}
	__block cdhash_t *cdhashes = NULL;
	__block uint32_t cdhashCount = 0;
	fat_enumerate_slices(fat, ^(MachO *macho, bool *stop) {
		if (macho_is_mappable(macho)) {
			cdhash_t cdhash;
			if (macho_parse_code_signature(macho, cdhash)) {
				if (!is_cdhash_trustcached(cdhash)) {


					if (filepath && ensure_randomized_cdhash_for_slice(filepath, macho->archDescriptor.offset, cdhash) != 0) {
						JBLogError("Failed to ensure randomized cdhash for %s", filepath);
						return;
					}


					cdhashCount++;
					cdhashes = realloc(cdhashes, cdhashCount * sizeof(cdhash_t));
					memcpy(cdhashes[cdhashCount-1], cdhash, sizeof(cdhash));
				}
			}
		}
	});

	*cdhashesOut = cdhashes;
	*cdhashCountOut = cdhashCount;
}

void fat_collect_untrusted_cdhashes(Fat *fat, cdhash_t **cdhashesOut, uint32_t *cdhashCountOut)
{
	fat_collect_untrusted_cdhashes_for_path(fat, NULL, cdhashesOut, cdhashCountOut);
}

void file_collect_untrusted_cdhashes(int fd, cdhash_t **cdhashesOut, uint32_t *cdhashCountOut)
{
	*cdhashesOut = NULL;
	*cdhashCountOut = 0;
	char filepath[PATH_MAX];
	if (fcntl(fd, F_GETPATH, filepath) != 0) {
		JBLogError("Failed to get file path for fd %d", fd);
		return;
	}

	MemoryStream *s = file_stream_init_from_file_descriptor(fd, 0, FILE_STREAM_SIZE_AUTO, 0);
	if (!s) return;

	Fat *fat = fat_init_from_memory_stream(s);
	if (!fat) {
		memory_stream_free(s);
		return;
	}

	fat_collect_untrusted_cdhashes_for_path(fat, filepath, cdhashesOut, cdhashCountOut);

	fat_free(fat);
}

void file_collect_untrusted_cdhashes_by_path(const char *path, cdhash_t **cdhashesOut, uint32_t *cdhashCountOut)
{
	int fd = open(path, O_RDONLY);
	if (fd < 0) return;
	file_collect_untrusted_cdhashes(fd, cdhashesOut, cdhashCountOut);
	close(fd);
}

void fat_collect_signatures(Fat *fat, struct siginfo **sigInfosOut, uint32_t *sigInfoCountOut)
{
	__block struct siginfo *sigInfos = NULL;
	__block uint32_t sigInfoCount = 0;
	fat_enumerate_slices(fat, ^(MachO *macho, bool *stop) {
		if (macho_is_mappable(macho)) {
			CS_SuperBlob *superblob = macho_read_code_signature(macho);
			if (superblob) {
				sigInfoCount++;
				sigInfos = realloc(sigInfos, sigInfoCount * sizeof(struct siginfo));
				struct siginfo *curSigInfo = &sigInfos[sigInfoCount-1];

				curSigInfo->source = SIGNATURE_SOURCE_ALLOCATION;
				curSigInfo->signature.fs_file_start = macho->archDescriptor.offset;
				curSigInfo->signature.fs_blob_start = superblob;
				curSigInfo->signature.fs_blob_size = OSSwapBigToHostInt32(superblob->length);
			}
		}
	});

	if (sigInfosOut) *sigInfosOut = sigInfos;
	if (sigInfoCountOut) *sigInfoCountOut = sigInfoCount;
}

void file_collect_signatures(int fd, struct siginfo **sigInfosOut, uint32_t *sigInfoCountOut)
{
	MemoryStream *s = file_stream_init_from_file_descriptor(fd, 0, FILE_STREAM_SIZE_AUTO, 0);
	if (!s) return;

	Fat *fat = fat_init_from_memory_stream(s);
	if (!fat) {
		memory_stream_free(s);
		return;
	}

	fat_collect_signatures(fat, sigInfosOut, sigInfoCountOut);

	fat_free(fat);
}


CS_SuperBlob *siginfo_resolve_superblob(struct siginfo *siginfo, int pid, int fd)
{
	if (!siginfo) return NULL;
	if (siginfo->signature.fs_blob_size == 0) return NULL;

	size_t superblobSize = siginfo->signature.fs_blob_size;
	CS_SuperBlob *superblob = malloc(superblobSize);
	if (!superblob) return NULL;

	bool success = false;

	switch (siginfo->source) {
		case SIGNATURE_SOURCE_ALLOCATION: {
			memcpy(superblob, siginfo->signature.fs_blob_start, superblobSize);
			success = true;
			break;
		}
		case SIGNATURE_SOURCE_FILE: {
			uintptr_t superblobStart = siginfo->signature.fs_file_start + (uintptr_t)siginfo->signature.fs_blob_start;
			uintptr_t superblobEnd   = superblobStart + superblobSize;
			struct stat st = {};

        	if (fstat(fd, &st) != 0) break;
			if (superblobEnd > st.st_size) break;
			if (lseek(fd, superblobStart, SEEK_SET) != superblobStart) break;
			if (read(fd, superblob, superblobSize) != superblobSize) break;

			success = true;
			break;
		}
		case SIGNATURE_SOURCE_PROC: {
			uint64_t proc = proc_find(pid);

			if (!proc) break;
			if (proc_vreadbuf(proc, siginfo->signature.fs_blob_start, superblob, superblobSize) != 0) break;

			success = true;
			break;
		}
	}

	if (!success) {
		free(superblob);
		superblob = NULL;
	}

	return superblob;
}

static int refresh_roothide_signature(const char *path, struct siginfo *signature, CS_DecodedSuperBlob *decoded, CS_DecodedBlob *directory)
{
	cdhash_t randomizedHash;
	if (ensure_randomized_cdhash_for_slice(path, signature->signature.fs_file_start, randomizedHash) != 0) return -1;
	Fat *fat = fat_init_from_path(path);
	if (!fat) return -1;
	__block MachO *slice = NULL;
	fat_enumerate_slices(fat, ^(MachO *candidate, bool *stop) {
		if (candidate->archDescriptor.offset == signature->signature.fs_file_start) {
			slice = candidate;
			*stop = true;
		}
	});
	CS_SuperBlob *diskBlob = slice ? macho_read_code_signature(slice) : NULL;
	CS_DecodedSuperBlob *diskDecoded = diskBlob ? csd_superblob_decode(diskBlob) : NULL;
	CS_DecodedBlob *diskDirectory = diskDecoded ? csd_superblob_find_best_code_directory(diskDecoded) : NULL;
	int result = diskDirectory ? roothide_refresh_first_code_slot(directory, diskDirectory) : -1;
	if (diskDecoded) csd_superblob_free(diskDecoded);
	free(diskBlob);
	fat_free(fat);
	if (result != 0) return result;

	// The caller may have adjusted TXM flags in a remote signature; only the changed code-page hash comes from disk.
	CS_SuperBlob *updated = csd_superblob_encode(decoded);
	if (!updated) return -1;
	if (signature->source == SIGNATURE_SOURCE_ALLOCATION) free(signature->signature.fs_blob_start);
	signature->source = SIGNATURE_SOURCE_ALLOCATION;
	signature->signature.fs_blob_start = updated;
	signature->signature.fs_blob_size = OSSwapBigToHostInt32(updated->length);
	return 0;
}

int trust_signatures(int pid, int fd, struct siginfo *sigInfos, uint32_t sigInfoCount)
{
	if (sigInfoCount == 0) return 0;
	char path[PATH_MAX];
	if (fcntl(fd, F_GETPATH, path) != 0) return -1;

    cdhash_t *cdhashes = malloc(sizeof(cdhash_t) * sigInfoCount);
	if (!cdhashes) return -2;
    uint32_t cdhashesCount = 0;

	struct siginfo **sigInfosToAttach = malloc(sizeof(struct siginfo *) * sigInfoCount);
	if (!sigInfosToAttach) {
		free(cdhashes);
		return -2;
	}
	uint32_t sigInfosToAttachCount = 0;

	for (uint32_t i = 0; i < sigInfoCount; i++) {
		struct siginfo *curSigInfo = &sigInfos[i];
		CS_SuperBlob *superblob = siginfo_resolve_superblob(curSigInfo, pid, fd);
		if (superblob) {
			CS_DecodedSuperBlob *decodedSuperblob = csd_superblob_decode(superblob);
			free(superblob);

			if (decodedSuperblob) {
				if (csd_superblob_is_adhoc_signed(decodedSuperblob)) {
					CS_DecodedBlob *bestCDBlob = csd_superblob_find_best_code_directory(decodedSuperblob);
					if (bestCDBlob) {
						bool needsAttach = false;
						cdhash_t originalHash;
						if (csd_code_directory_calculate_hash(bestCDBlob, originalHash) != 0 ||
							(!is_cdhash_trustcached(originalHash) &&
							 refresh_roothide_signature(path, curSigInfo, decodedSuperblob, bestCDBlob) != 0)) {
							csd_superblob_free(decodedSuperblob);
							free(cdhashes);
							free(sigInfosToAttach);
							return -1;
						}
							// Branding updates the embedded signature; only TXM-only mutations need detached attachment.
						if (ksymbol(SPTMArgs)) {
							uint32_t flags = csd_code_directory_get_flags(bestCDBlob);
							bool hasTeamId = false;
							char *teamId = csd_code_directory_copy_team_id(bestCDBlob, NULL);
							if (teamId) {
								free(teamId);
								hasTeamId = true;
							}

							if (!!(flags & CS_ADHOC) == hasTeamId) {
								// According to TXM, either CS_ADHOC or TeamID is fine
								// Both or neither are not
								// Neither: We give it CS_ADHOC
								// Both: We strip CS_ADHOC

								if (curSigInfo->source == SIGNATURE_SOURCE_ALLOCATION) {
									if (hasTeamId) {
										// Has both TeamID and CS_ADHOC, strip CS_ADHOC
										csd_code_directory_set_flags(bestCDBlob, flags & ~CS_ADHOC);
									}
									else {
										// Has neither TeamID or CS_ADHOC, add CS_ADHOC
										csd_code_directory_set_flags(bestCDBlob, flags | CS_ADHOC);
									}

									free(curSigInfo->signature.fs_blob_start);
									superblob = csd_superblob_encode(decodedSuperblob);
									curSigInfo->signature.fs_blob_start = superblob;
									curSigInfo->signature.fs_blob_size = OSSwapBigToHostInt32(superblob->length);

									needsAttach = true;
								}
								else {
									// If the signature does not reside inside our own address space, there is nothing we can do
									// Such a signature should have been caught by dyldhook so in reality this code path will probably never fire
									csd_superblob_free(decodedSuperblob);
									free(cdhashes);
									free(sigInfosToAttach);
									return -1;
								}
							}
						}

						cdhash_t cdhash;
						csd_code_directory_calculate_hash(bestCDBlob, &cdhash);
						if (!is_cdhash_trustcached(cdhash)) {
							memcpy(&cdhashes[cdhashesCount++], &cdhash, sizeof(cdhash_t));
						}
						if (needsAttach) sigInfosToAttach[sigInfosToAttachCount++] = curSigInfo;
					}
				}
				csd_superblob_free(decodedSuperblob);
			}
		}
	}

	if (cdhashesCount > 0) {
		jb_trustcache_add_cdhashes(cdhashes, cdhashesCount);
	}

	int r = 0;
	if (sigInfosToAttachCount > 0) {
		// For every signature we have modified, we need to attach them to fd now
		for (uint32_t i = 0; i < sigInfosToAttachCount; i++) {
			struct siginfo *curSigInfo = sigInfosToAttach[i];
			int fd_r = fd_attach_signature(fd, &curSigInfo->signature);
			if (fd_r != 0) r = fd_r;
		}
	}
	
	free(sigInfosToAttach);
	free(cdhashes);
	return r;
}

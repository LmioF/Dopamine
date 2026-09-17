#import "libjailbreak.h"
#import "carboncopy.h"
#import "codesign.h"
#import "util.h"
#import "roothider/bootlog.h"
#import <Foundation/Foundation.h>
#import <sys/sysctl.h>


NSString *dyldhook_dylib_for_platform(void)
{
	cpu_subtype_t cpusubtype = 0;
	size_t len = sizeof(cpusubtype);
	if (sysctlbyname("hw.cpusubtype", &cpusubtype, &len, NULL, 0) == -1) { return nil; }
	if ((cpusubtype & ~CPU_SUBTYPE_MASK) == CPU_SUBTYPE_ARM64E) {
		if (@available(iOS 18.0, *)) {
			return @"dyldhook_merge.arm64e.iOS18+.dylib"; 
		}
		else if (@available(iOS 16.0, *)) {
			return @"dyldhook_merge.arm64e.iOS16-17.dylib"; 
		}
		else {
			return @"dyldhook_merge.arm64e.iOS15.dylib"; 
		}
	}
	else {
		if (@available(iOS 18.0, *)) {
			return @"dyldhook_merge.arm64.iOS18+.dylib"; 
		}
		else if (@available(iOS 16.0, *)) {
			return @"dyldhook_merge.arm64.iOS16-17.dylib"; 
		}
		else {
			return @"dyldhook_merge.arm64.iOS15.dylib"; 
		}
	}
}

int apply_dyld_patch(NSString *dyldPath, const char *newUUIDPrefix)
{
	MachO *dyldMacho = macho_init_for_writing(dyldPath.fileSystemRepresentation);
	if (!dyldMacho) return -1;

	__block int r = 0;

	// Make AMFI flags always be `0xff`, allows DYLD_* variables to always work
	__block uint64_t getAMFIAddr = 0;
	macho_enumerate_symbols(dyldMacho, ^(const char *name, uint8_t type, uint64_t vmaddr, bool *stop){
		if (!strcmp(name, "__ZN5dyld413ProcessConfig8Security7getAMFIERKNS0_7ProcessERNS_15SyscallDelegateE")) {
			getAMFIAddr = vmaddr;
		}
	});
	uint32_t getAMFIPatch[] = {
		0xd2801fe0, // mov x0, 0xff
		0xd65f03c0  // ret
	};

	if (getAMFIAddr == 0) {
	        printf("Error: Failed patchfinding getAMFI\n");
		macho_free(dyldMacho);
	        return -1;
	    }

	if (macho_write_at_vmaddr(dyldMacho, getAMFIAddr, sizeof(getAMFIPatch), getAMFIPatch) != 0) {
		macho_free(dyldMacho);
		return -1;
	}

	// iOS 16+: Change LC_UUID to prevent the kernel from using the in-cache dyld
	__block bool foundUUID = false;
	macho_enumerate_load_commands(dyldMacho, ^(struct load_command loadCommand, uint64_t offset, void *cmd, bool *stop) {
			if (loadCommand.cmd == LC_UUID) {
				foundUUID = true;
            // The new UUID will look like this:
            // DOPA<dopamine version>\0<rest of original UUID>
            // This way we ensure:
            // - The version it was patched on and it being patched by Dopamine is identifiable later
            // - The UUID is still unique based on the source dyld that was patched

	            size_t newUUIDPrefixLen = strlen(newUUIDPrefix) + 1;
	            if (newUUIDPrefixLen <= sizeof(uuid_t)) {
	                // Also write null byte here, because otherwise it's impossible to know where the version string ends
	                if (macho_write_at_offset(dyldMacho, offset + offsetof(struct uuid_command, uuid), newUUIDPrefixLen, newUUIDPrefix) != 0) {
					r = -1;
				}
	            }
            else {
				r = -1;
                printf("Error: Failed to write identifier to LC_UUID, too long (%zu)\n", newUUIDPrefixLen);
            }
			*stop = true;
			}
		});
	if (!foundUUID) r = -1;

	macho_free(dyldMacho);
	return r;
}

int merge_dyldhook(NSString *originalDyldPath, NSString *dyldhookMergeDylibPath, NSString *outPath)
{
	roothide_bootlog("generator: starting MachOMerger");
	int r = exec_cmd(JBROOT_PATH("/basebin/MachOMerger"), originalDyldPath.fileSystemRepresentation, dyldhookMergeDylibPath.fileSystemRepresentation, outPath.fileSystemRepresentation, NULL);
	roothide_bootlog("generator: MachOMerger returned");
	if (r == 0) {
		r = chmod(outPath.fileSystemRepresentation, 0755);
	}
	return r;
}

int basebin_generate_internal(NSString *originUsrLibPath, NSString *basebinPath, NSString *targetBasebinPath, bool comingFromJBUpdate)
{
	roothide_bootlog("generator: selecting linker variant");
	NSString *dyldhookMergeDylibName = dyldhook_dylib_for_platform();
	if (!dyldhookMergeDylibName) {
		printf("Error: Failed to locate dyldhook.dylib\n");
		return -1;
	}

	NSString *dyldPath               = [originUsrLibPath stringByAppendingPathComponent:@"dyld"];

	NSString *genPath                = [basebinPath stringByAppendingPathComponent:@"gen"];
	NSString *fakelibPath            = [basebinPath stringByAppendingPathComponent:@".fakelib"];
	NSString *versionPath            = [basebinPath stringByAppendingPathComponent:@".version"];
	NSString *dyldhookMergeDylibPath = [basebinPath stringByAppendingPathComponent:dyldhookMergeDylibName];

	NSString *fakelibDyldPath        = [fakelibPath stringByAppendingPathComponent:@"dyld"];
	NSString *fakelibSystemHookPath  = [fakelibPath stringByAppendingPathComponent:@"systemhook.dylib"];

	NSString *dyldOrigPath           = [genPath stringByAppendingPathComponent:@"dyld.orig"];
	NSString *dyldInflightPath       = [genPath stringByAppendingPathComponent:@"dyld.inflight"];
	NSString *dyldOldPath            = [genPath stringByAppendingPathComponent:@"dyld.old"];
	NSString *dyldPatchedPath        = [genPath stringByAppendingPathComponent:@"dyld"];

	NSString *targetDyldPath         = [targetBasebinPath stringByAppendingPathComponent:@"gen/dyld"];
	NSString *targetSystemhookPath   = [targetBasebinPath stringByAppendingPathComponent:@"systemhook.dylib"];
	
	NSString *dopamineVersion = [NSString stringWithContentsOfFile:versionPath encoding:NSUTF8StringEncoding error:nil];
	if (!dopamineVersion) return 1;

		if (![[NSFileManager defaultManager] createDirectoryAtPath:genPath withIntermediateDirectories:YES attributes:nil error:nil]) return 5;
	roothide_bootlog("generator: generation directory prepared");

	if (!comingFromJBUpdate) {
		// Copy /usr/lib to /var/jb/basebin/.fakelib
			if ([[NSFileManager defaultManager] fileExistsAtPath:fakelibPath] &&
				![[NSFileManager defaultManager] removeItemAtPath:fakelibPath error:nil]) return 6;
			if (![[NSFileManager defaultManager] createDirectoryAtPath:fakelibPath withIntermediateDirectories:YES attributes:nil error:nil]) return 7;
			roothide_bootlog("generator: copying system libraries");
			if (carbonCopy(originUsrLibPath, fakelibPath) != 0) return 8;
		roothide_bootlog("generator: system libraries copied");

		// Delete the dyld inside .fakelib
			if ([[NSFileManager defaultManager] fileExistsAtPath:fakelibDyldPath] &&
				![[NSFileManager defaultManager] removeItemAtPath:fakelibDyldPath error:nil]) return 9;

		// Symlink .fakelib/dyld -> /var/jb/basebin/gen/dyld
			if (![[NSFileManager defaultManager] createSymbolicLinkAtPath:fakelibDyldPath withDestinationPath:targetDyldPath error:nil]) return 10;

		// Symlink .fakelib/systemhook.dylib -> /var/jb/basebin/systemhook.dylib
			if (![[NSFileManager defaultManager] createSymbolicLinkAtPath:fakelibSystemHookPath withDestinationPath:targetSystemhookPath error:nil]) return 11;

		// Backup original dyld
			if (carbonCopy(dyldPath, dyldOrigPath) != 0) return 12;
		roothide_bootlog("generator: original linker copied");
	}

		if (carbonCopy(dyldOrigPath, dyldInflightPath) != 0) return 13;
	roothide_bootlog("generator: inflight linker copied");

	NSString *dyldUUIDPrefix = [@"DOPA" stringByAppendingString:dopamineVersion];
	if (apply_dyld_patch(dyldInflightPath, dyldUUIDPrefix.UTF8String) != 0) return 2;
	roothide_bootlog("generator: linker policy patched");
	if (merge_dyldhook(dyldInflightPath, dyldhookMergeDylibPath, dyldInflightPath) != 0) return 3;
	roothide_bootlog("generator: signing linker");
	if (resign_file(dyldInflightPath, @"com.apple.dyld", YES) != 0) return 4;
	roothide_bootlog("generator: linker signed");

	if (comingFromJBUpdate) {
		// We cannot delete dyld as this point because it's still in use
		// If we did this, we'd panic the system
		// So we will move the past patched dyld to dyld.old to keep the vnode alive
		// If there is another dyld.old at this point, we will remove it now
		// since it is guaranteed to not be in use at this point
			if ([[NSFileManager defaultManager] fileExistsAtPath:dyldOldPath]) {
				if (![[NSFileManager defaultManager] removeItemAtPath:dyldOldPath error:nil]) return 14;
			}
			if (![[NSFileManager defaultManager] moveItemAtPath:dyldPatchedPath toPath:dyldOldPath error:nil]) return 15;
		}

		if (![[NSFileManager defaultManager] moveItemAtPath:dyldInflightPath toPath:dyldPatchedPath error:nil]) return 16;
	roothide_bootlog("generator: linker published");
	return 0;
}

int basebin_generate(bool comingFromJBUpdate)
{
	return basebin_generate_internal(@"/usr/lib", JBROOT_PATH(@"/basebin"), JBROOT_PATH(@"/basebin"), comingFromJBUpdate);
}

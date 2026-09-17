#include "info.h"
#import <Foundation/Foundation.h>
#import "util.h"
#import <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

bool is_dopamine_app(const char *pathC)
{
	if (!jbinfo(appIdentifier)) return false;

	// Make sure the prefix is sane
	const char wantedPrefixC[] = "/private/var/containers/Bundle/Application/";
	if (strncmp(pathC, wantedPrefixC, (sizeof(wantedPrefixC) - 1)) != 0) return false;

	// Make sure there are no path traversals
	if (strstr(pathC, "/../")) return false;

	// Stricly enforce the number of slashes (8)
	// /private/var/containers/Bundle/Application/*/*.app/*
	// ^       ^   ^          ^      ^           ^ ^     ^
	uint64_t slashNum = 0;
	uint64_t idx = 0;
	while (pathC[idx] != 0) {
		if (pathC[idx++] == '/') {
			slashNum++;
		}
	}
	if (slashNum != 8) return false;

	@autoreleasepool {
		NSString *path = [NSString stringWithUTF8String:pathC];
		NSString *infoPlistPath = [[path stringByDeletingLastPathComponent] stringByAppendingPathComponent:@"Info.plist"];
		if (![[NSFileManager defaultManager] fileExistsAtPath:infoPlistPath]) return false;

		NSDictionary *infoPlist = [NSDictionary dictionaryWithContentsOfFile:infoPlistPath];
		NSString *bundleIdentifier = infoPlist[@"CFBundleIdentifier"];
		if (!bundleIdentifier) return false;

		return !strcmp(bundleIdentifier.UTF8String, jbinfo(appIdentifier));
	}
}

NSString *NSPrebootUUIDPath(NSString *relativePath)
{
	@autoreleasepool {
		return [NSString stringWithUTF8String:prebootUUIDPath(relativePath.UTF8String)];
	}
}

static void _JBFixMobilePermissionsOfDescriptor(int fd, BOOL recursive, dev_t rootDevice)
{
	if (fd < 0) return;
	struct stat s;
	if (fstat(fd, &s) != 0 || s.st_dev != rootDevice ||
		(!S_ISDIR(s.st_mode) && !S_ISREG(s.st_mode)) ||
		(S_ISREG(s.st_mode) && s.st_nlink != 1)) {
		close(fd);
		return;
	}
	if (s.st_uid != 501 || s.st_gid != 501) fchown(fd, 501, 501);
	if (!recursive || !S_ISDIR(s.st_mode)) {
		close(fd);
		return;
	}
	DIR *directory = fdopendir(fd);
	if (!directory) {
		close(fd);
		return;
	}
	struct dirent *entry;
	while ((entry = readdir(directory))) {
		if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
		struct stat candidate;
		if (fstatat(fd, entry->d_name, &candidate, AT_SYMLINK_NOFOLLOW) != 0 ||
			candidate.st_dev != rootDevice ||
			(!S_ISDIR(candidate.st_mode) && !S_ISREG(candidate.st_mode))) continue;
		int flags = O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK;
		if (S_ISDIR(candidate.st_mode)) flags |= O_DIRECTORY;
		_JBFixMobilePermissionsOfDescriptor(openat(fd, entry->d_name, flags), YES, rootDevice);
	}
	closedir(directory);
}

void JBFixMobilePermissions(void)
{
	@autoreleasepool {
		NSString *primaryPath = JBROOT_PATH(@"/");
		while (primaryPath.length > 1 && [primaryPath hasSuffix:@"/"]) {
			primaryPath = [primaryPath substringToIndex:primaryPath.length - 1];
		}
		const char *rootName = primaryPath.lastPathComponent.UTF8String;
		if (!rootName || strlen(rootName) != 24 || strncmp(rootName, ".jbroot-", 8) ||
			strspn(rootName + 8, "0123456789abcdefABCDEF") != 16) return;
		const int directoryFlags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC;
		int primary = open(primaryPath.fileSystemRepresentation, directoryFlags);
		if (primary < 0) return;
		NSString *containerPath = @"/var/mobile/Containers/Shared/AppGroup";
		int container = open(containerPath.fileSystemRepresentation, directoryFlags);
		int secondary = container < 0 ? -1 : openat(container, rootName, directoryFlags);
		if (container >= 0) close(container);
		int var = secondary < 0 ? -1 : openat(secondary, "var", directoryFlags);
		if (secondary >= 0) close(secondary);
		struct stat expected, linked;
		// Only the known primary-to-secondary link may cross the traversal boundary.
		BOOL matches = var >= 0 && fstat(var, &expected) == 0 &&
			fstatat(primary, "var", &linked, 0) == 0 &&
			S_ISDIR(linked.st_mode) && expected.st_dev == linked.st_dev && expected.st_ino == linked.st_ino;
		close(primary);
		if (!matches) {
			if (var >= 0) close(var);
			return;
		}
		int mobile = openat(var, "mobile", directoryFlags);
		close(var);
		if (mobile < 0) return;
		int library = openat(mobile, "Library", directoryFlags);
		if (library >= 0) {
			const char *directories[] = {"SplashBoard", "Application Support", "Preferences"};
			for (size_t i = 0; i < sizeof(directories) / sizeof(directories[0]); i++) {
				_JBFixMobilePermissionsOfDescriptor(openat(library, directories[i], directoryFlags), YES, expected.st_dev);
			}
			_JBFixMobilePermissionsOfDescriptor(library, NO, expected.st_dev);
		}
		_JBFixMobilePermissionsOfDescriptor(mobile, NO, expected.st_dev);
	}
}

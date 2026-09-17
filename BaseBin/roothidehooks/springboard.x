#import <Foundation/Foundation.h>
#include <roothide.h>
#import <fcntl.h>
#include "common.h"
#include "request_scope.h"

static int fcntlCommandTakesArgument(int cmd)
{
	switch (cmd) {
		case F_GETFD:
#ifdef F_GETFL
		case F_GETFL:
#endif
#ifdef F_GETOWN
		case F_GETOWN:
#endif
#ifdef F_FULLFSYNC
		case F_FULLFSYNC:
#endif
#ifdef F_FREEZE_FS
		case F_FREEZE_FS:
#endif
#ifdef F_THAW_FS
		case F_THAW_FS:
#endif
#ifdef F_GETPROTECTIONCLASS
		case F_GETPROTECTIONCLASS:
#endif
#ifdef F_GETNOSIGPIPE
		case F_GETNOSIGPIPE:
#endif
#ifdef F_GETPROTECTIONLEVEL
		case F_GETPROTECTIONLEVEL:
#endif
#ifdef F_BARRIERFSYNC
		case F_BARRIERFSYNC:
#endif
			return 0;
		default:
			return 1;
	}
}

%hookf(int, fcntl, int fildes, int cmd, ...) {
	if (cmd == F_SETPROTECTIONCLASS) {
		char filePath[PATH_MAX];
		if (fcntl(fildes, F_GETPATH, filePath) != -1) {
			// Skip setting protection class on jailbreak apps, this doesn't work and causes snapshots to not be saved correctly
			if (isSubPathOf(filePath, jbroot("/var/mobile/Library/SplashBoard/Snapshots/"))) {
				return 0;
			}
		}
	}

		if (!fcntlCommandTakesArgument(cmd)) {
			return %orig(fildes, cmd);
		}

		va_list a;
		va_start(a, cmd);
		uintptr_t arg = va_arg(a, uintptr_t);
		va_end(a);
		return %orig(fildes, cmd, arg);
	}

@interface XBSnapshotContainerIdentity : NSObject
@property NSString* bundleIdentifier;
@end

%hook XBSnapshotContainerIdentity

/*
-(id)_initWithBundleIdentifier:(id)arg1 bundlePath:(id)arg2 dataContainerPath:(id)arg3 bundleContainerPath:(id)arg4 
{
    NSLog(@"snapshot init, id=%@, bundlePath=%@, dataContainerPath=%@, bundleContainerPath=%@", arg1, arg2, arg3, arg4);

    return %orig;
}
*/

-(NSString *)snapshotContainerPath {
    NSString* path = %orig;

    if([path hasPrefix:@"/var/mobile/Library/SplashBoard/Snapshots/"] && (![self.bundleIdentifier hasPrefix:@"com.apple."] || is_apple_internal_identifier(self.bundleIdentifier.UTF8String))) {
        NSLog(@"snapshotContainerPath redirect %@ : %@", self.bundleIdentifier, path);
        path = jbroot(path);
    }

    return path;
}

%end

static const void *kDenyQueryTagKey = &kDenyQueryTagKey;

%hook FBSApplicationLibrary
-(id)applicationInfoForBundleIdentifier:(NSString*)bundleIdentifier
{
	id result = %orig; //SBApplicationInfo
	NSURL* executableURL = [result performSelector:@selector(executableURL)];
	NSLog(@"FBSApplicationLibrary applicationInfoForBundleIdentifier %@ : %@, %@", bundleIdentifier, result, executableURL);

	if(rhAssociatedFlagIsActive(bundleIdentifier, kDenyQueryTagKey)) {

		if(is_sensitive_app_identifier(bundleIdentifier.UTF8String)) {
			NSLog(@"FBSApplicationLibrary deny query %@", bundleIdentifier);
			return nil;
		}

		if(result && executableURL && isJailbreakBundlePath(executableURL.path.fileSystemRepresentation)) {
			NSLog(@"FBSApplicationLibrary deny query %@", bundleIdentifier);
			return nil;
		}
	}

	return result;
}
%end

%hook FBSystemService
-(void*)openApplication:(NSString*)bundleIdentifier withOptions:(id)options originator:(id)originator requestID:(void*)requestID completion:(void*)completion
{
	NSLog(@"openApplication %@ withOptions:%@ originator:%@ requestID:%@ completion:%p", bundleIdentifier, options, originator, requestID, completion);

	Class serviceConnectionClass = NSClassFromString(@"BSServiceConnection");
	id currentContext = [serviceConnectionClass respondsToSelector:@selector(currentContext)] ? [serviceConnectionClass performSelector:@selector(currentContext)] : nil;
	id remoteProcess = [currentContext respondsToSelector:@selector(remoteProcess)] ? [currentContext performSelector:@selector(remoteProcess)] : nil; //BSProcessHandle

	NSNumber* _pid = nil;
	NSString* _bundleID = nil;
	@try {
		_pid = [remoteProcess valueForKey:@"_pid"];
		_bundleID = [remoteProcess valueForKey:@"_bundleID"]; //may be nil
	} @catch(NSException *exception) {
		NSLog(@"openApplication request context unavailable: %@", exception);
	}

	pid_t pid = _pid.intValue;

	NSLog(@"openApplication %@ from pid=%d bundleID=%@", bundleIdentifier, pid, _bundleID);

	BOOL denyQueryScope = NO;
	if(pid > 0 && jbclient_blacklist_check_pid(pid)==true) {
		NSLog(@"openApplication deny request from %@", _bundleID);
		rhAssociatedFlagScopeBegin(bundleIdentifier, kDenyQueryTagKey);
		denyQueryScope = YES;
	}

	void *result = NULL;
	@try {
		result = %orig;
	} @finally {
		if(denyQueryScope) rhAssociatedFlagScopeEnd(bundleIdentifier, kDenyQueryTagKey);
	}
	return result;
}
%end

void sbInit(void)
{
	NSLog(@"sbInit...");
	%init();
}

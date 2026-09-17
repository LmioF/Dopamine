#import <Foundation/Foundation.h>
#import "NSString+Version.h"
#include <stdio.h>

static NSString *gStatusPath;
#define JBROOT_PATH(path) gStatusPath

@interface DOBootstrapper : NSObject
- (NSString *)installedVersionForPackageWithIdentifier:(NSString *)identifier;
- (BOOL)shouldInstallPackage:(NSString *)identifier;
@end

#include "implementation.h"

static unsigned failures;
static unsigned cases;

static void check(BOOL condition, const char *name)
{
    cases++;
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", name);
        failures++;
    }
}

static void writeStatus(NSString *status)
{
    NSError *error = nil;
    if (![status writeToFile:gStatusPath atomically:YES encoding:NSUTF8StringEncoding error:&error]) {
        fprintf(stderr, "status fixture: %s\n", error.description.UTF8String);
        exit(2);
    }
}

static void checkVersion(DOBootstrapper *bootstrapper, NSString *left, NSString *right, NSComparisonResult expected)
{
    writeStatus([NSString stringWithFormat:@"Package: fixture\nStatus: install ok installed\nVersion: %@\n", left]);
    gBundledPackages = @{@"fixture": right};
    BOOL upgrade = [bootstrapper shouldInstallPackage:@"fixture"];
    writeStatus([NSString stringWithFormat:@"Package: fixture\nStatus: install ok installed\nVersion: %@\n", right]);
    gBundledPackages = @{@"fixture": left};
    BOOL reverse = [bootstrapper shouldInstallPackage:@"fixture"];
    check(upgrade == (expected == NSOrderedAscending) && reverse == (expected == NSOrderedDescending),
          [NSString stringWithFormat:@"Debian ordering %@ vs %@", left, right].UTF8String);
}

int main(int argc, const char *argv[])
{
    @autoreleasepool {
        if (argc != 2) return 2;
        gStatusPath = @(argv[1]);
        DOBootstrapper *bootstrapper = [DOBootstrapper new];
        writeStatus(@"Package: libkrw0-dopamine\nStatus: install ok installed\nVersion: 2.0.4\n");
        check([bootstrapper shouldInstallPackage:@"libkrw0-dopamine"], "legacy 2.0.4 provider is upgraded across ABI transition");
        writeStatus([NSString stringWithFormat:@"Package: libkrw0-dopamine\nStatus: install ok installed\nVersion: %@\n", LIBKRW_DOPAMINE_BUNDLED_VERSION]);
        check(![bootstrapper shouldInstallPackage:@"libkrw0-dopamine"], "current provider version is retained");
        checkVersion(bootstrapper, @"1.0~rc1", @"1.0", NSOrderedAscending);
        checkVersion(bootstrapper, @"1.0~~", @"1.0~", NSOrderedAscending);
        checkVersion(bootstrapper, @"1.0a", @"1.0b", NSOrderedAscending);
        checkVersion(bootstrapper, @"1.0A", @"1.0a", NSOrderedAscending);
        checkVersion(bootstrapper, @"1.0z", @"1.0+", NSOrderedAscending);
        checkVersion(bootstrapper, @"1:1.1.1-2+dp3.1~rc1", @"1:1.1.1-2+dp3.1", NSOrderedAscending);
        checkVersion(bootstrapper, @"1:0.1", @"999.9", NSOrderedDescending);
        checkVersion(bootstrapper, @"0:1.0", @"1.0", NSOrderedSame);
        checkVersion(bootstrapper, @"1.0", @"1.0-0", NSOrderedSame);
        checkVersion(bootstrapper, @"1.0-1", @"1.0-2", NSOrderedAscending);
        checkVersion(bootstrapper, @"1.0-1~1", @"1.0-1", NSOrderedAscending);
        checkVersion(bootstrapper, @"1.0-foo-2", @"1.0-foo-10", NSOrderedAscending);
        checkVersion(bootstrapper, @"2.00000000000000000000009", @"2.10", NSOrderedAscending);
        checkVersion(bootstrapper, @"2.999999999999999999999999", @"2.1000000000000000000000000", NSOrderedAscending);
        checkVersion(bootstrapper, @"2.01", @"2.1", NSOrderedSame);
        checkVersion(bootstrapper, @"2.0.3", @"2.0.4", NSOrderedAscending);
        checkVersion(bootstrapper, @"1.0+git1", @"1.0+git2", NSOrderedAscending);
        checkVersion(bootstrapper, @"1.0", @"1.0.0", NSOrderedAscending);

        gBundledPackages = @{@"fixture": @"2.0.4"};
        writeStatus(@"Package: fixture-extra\nStatus: install ok installed\nVersion: 99\n\nPackage: fixture\nStatus: install ok installed\nVersion: 2.0.3\n");
        check([[bootstrapper installedVersionForPackageWithIdentifier:@"fixture"] isEqualToString:@"2.0.3"], "exact package name");
        writeStatus(@"Version: 2.0.4\nStatus: hold ok installed\nPackage: fixture\n");
        check([[bootstrapper installedVersionForPackageWithIdentifier:@"fixture"] isEqualToString:@"2.0.4"], "field order and held installation");
        for (NSString *status in @[@"deinstall ok config-files", @"install ok unpacked", @"install reinstreq installed", @"install ok half-configured", @"install ok not-installed"]) {
            writeStatus([NSString stringWithFormat:@"Package: fixture\nStatus: %@\nVersion: 2.0.4\n", status]);
            check([bootstrapper shouldInstallPackage:@"fixture"], [@"incomplete state " stringByAppendingString:status].UTF8String);
        }
        writeStatus(@"Package: fixture\nVersion: 2.0.4\n");
        check([bootstrapper shouldInstallPackage:@"fixture"], "missing status");
        writeStatus(@"Package: fixture\nStatus: install ok installed\nVersion: \n");
        check([bootstrapper shouldInstallPackage:@"fixture"], "empty version");
        writeStatus(@"Package: fixture\nStatus: install ok installed\n");
        check([bootstrapper shouldInstallPackage:@"fixture"], "missing version");
        writeStatus(@"Package: other\nStatus: install ok installed\nVersion: 99\n");
        check([bootstrapper shouldInstallPackage:@"fixture"], "missing package");
        check(![bootstrapper shouldInstallPackage:@"unbundled"], "unbundled package");
        writeStatus(@"Package: fixture\r\nStatus: install ok installed\r\nVersion: 2.0.4\r\n\r\nPackage: other\r\nVersion: 99\r\n");
        check([[bootstrapper installedVersionForPackageWithIdentifier:@"fixture"] isEqualToString:@"2.0.4"], "CRLF stanza boundaries");
        [[NSFileManager defaultManager] removeItemAtPath:gStatusPath error:nil];
        check([bootstrapper shouldInstallPackage:@"fixture"], "unreadable status");
        printf("%u package selection cases, %u failures\n", cases, failures);
        return failures ? 1 : 0;
    }
}

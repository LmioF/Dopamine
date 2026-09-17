#import <Foundation/Foundation.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

static NSString *gRoot;
static int gScenario;

static NSString *JBRootPath(NSString *path)
{
    NSString *relative = [path hasPrefix:@"/"] ? [path substringFromIndex:1] : path;
    return [gRoot stringByAppendingPathComponent:relative];
}

#define JBROOT_PATH(path) JBRootPath(path)

static int libarchive_unarchive(const char *archive, const char *destination)
{
    (void)archive;
    NSString *basebin = [@(destination) stringByAppendingPathComponent:@"basebin"];
    NSFileManager *fm = NSFileManager.defaultManager;
    if (![fm createDirectoryAtPath:basebin withIntermediateDirectories:YES attributes:nil error:nil]) return 1;
    if (![@"tc" writeToFile:[basebin stringByAppendingPathComponent:@"basebin.tc"] atomically:YES encoding:NSUTF8StringEncoding error:nil]) return 1;
    if (![@"3.1" writeToFile:[basebin stringByAppendingPathComponent:@".version"] atomically:YES encoding:NSUTF8StringEncoding error:nil]) return 1;
    NSString *payload = [basebin stringByAppendingPathComponent:@"payload"];
    if (![@"new" writeToFile:payload atomically:YES encoding:NSUTF8StringEncoding error:nil]) return 1;
    if (gScenario == 1) chmod(payload.fileSystemRepresentation, 0000);
    return 0;
}

static int randomizeAndLoadBasebinTrustcache(const char *path)
{
    (void)path;
    return 0;
}

#include "implementation.h"

static void require(BOOL condition, NSString *message)
{
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message.UTF8String);
        exit(1);
    }
}

static void prepareRoot(void)
{
    gRoot = [NSTemporaryDirectory() stringByAppendingPathComponent:NSUUID.UUID.UUIDString];
    NSString *basebin = JBRootPath(@"/basebin");
    require([NSFileManager.defaultManager createDirectoryAtPath:basebin withIntermediateDirectories:YES attributes:nil error:nil], @"create old basebin");
    require([@"3.0" writeToFile:[basebin stringByAppendingPathComponent:@".version"] atomically:YES encoding:NSUTF8StringEncoding error:nil], @"write old version");
    require([@"old" writeToFile:[basebin stringByAppendingPathComponent:@"payload"] atomically:YES encoding:NSUTF8StringEncoding error:nil], @"write old payload");
}

int main(int argc, const char *argv[])
{
    @autoreleasepool {
        if (argc != 2) return 2;
        gScenario = atoi(argv[1]);
        prepareRoot();
        NSString *archive = [gRoot stringByAppendingPathComponent:@"basebin.tar"];
        require([@"fixture" writeToFile:archive atomically:YES encoding:NSUTF8StringEncoding error:nil], @"write archive");

        if (gScenario == 2) chmod(JBRootPath(@"/basebin").fileSystemRepresentation, 0555);
        int result = jbupdate_basebin(archive.fileSystemRepresentation);
        if (gScenario == 2) chmod(JBRootPath(@"/basebin").fileSystemRepresentation, 0755);

        if (gScenario == 0) {
            require(result == 0, @"successful update");
            require([[NSString stringWithContentsOfFile:JBRootPath(@"/basebin/payload") encoding:NSUTF8StringEncoding error:nil] isEqualToString:@"new"], @"new payload published");
            require([[NSString stringWithContentsOfFile:JBRootPath(@"/basebin/.version") encoding:NSUTF8StringEncoding error:nil] isEqualToString:@"3.1"], @"new version published");
        }
        else {
            require(result != 0, @"filesystem publication refusal must not report success");
        }

        [NSFileManager.defaultManager removeItemAtPath:gRoot error:nil];
        return 0;
    }
}

#import <Foundation/Foundation.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

static int gCarbonCopyResult;

static NSString *dyldhook_dylib_for_platform(void)
{
    return @"dyldhook.fixture.dylib";
}

static int carbonCopy(NSString *source, NSString *destination)
{
    if (gCarbonCopyResult != 0) return gCarbonCopyResult;
    NSError *error = nil;
    [[NSFileManager defaultManager] removeItemAtPath:destination error:nil];
    return [[NSFileManager defaultManager] copyItemAtPath:source toPath:destination error:&error] ? 0 : 1;
}

static int apply_dyld_patch(NSString *path, const char *prefix)
{
    (void)path;
    (void)prefix;
    return 0;
}

static int merge_dyldhook(NSString *original, NSString *hook, NSString *output)
{
    (void)original;
    (void)hook;
    (void)output;
    return 0;
}

static int resign_file(NSString *path, NSString *identifier, bool preserve)
{
    (void)path;
    (void)identifier;
    (void)preserve;
    return 0;
}

#define roothide_bootlog(...) ((void)0)

#include "implementation.h"

static void must(BOOL value, NSString *message)
{
    if (!value) {
        fprintf(stderr, "FAIL: %s\n", message.UTF8String);
        exit(1);
    }
}

static NSString *prepareBasebin(BOOL includePublishedDyld)
{
    NSString *root = [NSTemporaryDirectory() stringByAppendingPathComponent:NSUUID.UUID.UUIDString];
    NSString *gen = [root stringByAppendingPathComponent:@"gen"];
    NSFileManager *fm = NSFileManager.defaultManager;
    must([fm createDirectoryAtPath:gen withIntermediateDirectories:YES attributes:nil error:nil], @"create gen");
    must([@"3.0.9" writeToFile:[root stringByAppendingPathComponent:@".version"] atomically:YES encoding:NSUTF8StringEncoding error:nil], @"write version");
    must([@"orig" writeToFile:[gen stringByAppendingPathComponent:@"dyld.orig"] atomically:YES encoding:NSUTF8StringEncoding error:nil], @"write dyld.orig");
    if (includePublishedDyld) {
        must([@"old" writeToFile:[gen stringByAppendingPathComponent:@"dyld"] atomically:YES encoding:NSUTF8StringEncoding error:nil], @"write current dyld");
    }
    return root;
}

int main(int argc, const char *argv[])
{
    @autoreleasepool {
        if (argc != 2) return 2;
        NSString *scenario = @(argv[1]);
        BOOL needsCurrent = ![scenario isEqualToString:@"missing-current"];
        NSString *basebin = prepareBasebin(needsCurrent);

        if ([scenario isEqualToString:@"copy-failure"]) {
            gCarbonCopyResult = 17;
            must(basebin_generate_internal(@"/unused", basebin, basebin, true) != 0,
                 @"inflight copy refusal must fail generation");
        }
        else if ([scenario isEqualToString:@"missing-current"]) {
            gCarbonCopyResult = 0;
            must(basebin_generate_internal(@"/unused", basebin, basebin, true) != 0,
                 @"hot update without current dyld must fail before publication");
        }
        else if ([scenario isEqualToString:@"success"]) {
            gCarbonCopyResult = 0;
            must(basebin_generate_internal(@"/unused", basebin, basebin, true) == 0,
                 @"valid hot-update publication");
            NSString *published = [NSString stringWithContentsOfFile:[basebin stringByAppendingPathComponent:@"gen/dyld"] encoding:NSUTF8StringEncoding error:nil];
            NSString *old = [NSString stringWithContentsOfFile:[basebin stringByAppendingPathComponent:@"gen/dyld.old"] encoding:NSUTF8StringEncoding error:nil];
            must([published isEqualToString:@"orig"], @"new dyld published");
            must([old isEqualToString:@"old"], @"old dyld retained");
        }
        else {
            return 2;
        }

        [NSFileManager.defaultManager removeItemAtPath:basebin error:nil];
        return 0;
    }
}

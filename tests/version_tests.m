#import <Foundation/Foundation.h>
#import "../Application/Dopamine/Extensions/NSString+Version.h"

static void require(BOOL condition, NSString *message)
{
    if (!condition) {
        fprintf(stderr, "%s\n", message.UTF8String);
        exit(1);
    }
}

int main(void)
{
    @autoreleasepool {
        require([@"3.0.9.0" compareVersion:@"2.4.9.27"] == NSOrderedDescending, @"A 2.x revision must not outrank 3.x");
        require([@"3.0.9.27" compareVersion:@"3.0.9.9"] == NSOrderedDescending, @"Revision comparison must be numeric");
        require([@"3.0.9.256" compareVersion:@"3.0.10.0"] == NSOrderedAscending, @"Revisions must not overlap patch components");
        require([@"v3.0.9" compareVersion:@"3.0.9.0\n"] == NSOrderedSame, @"Missing revisions are zero");
        require([@"3.00.009.01" compareVersion:@"3.0.9.1"] == NSOrderedSame, @"Leading zeros must not change ordering");
        require([@"3.1" compareVersion:@"3.0.99.99"] == NSOrderedDescending, @"Minor versions precede patch versions");
        require([@"3.0.9" isQualifiedVersion], @"Upstream release tags must be accepted");
        require([@"v3.0.9.1" isQualifiedVersion], @"Roothide release tags must be accepted");
        require(![@"27" isQualifiedVersion], @"Legacy revision-only tags must not be interpreted as major versions");
        require(![@"3.0.9-beta1" isQualifiedVersion], @"Prerelease tags must not enter stable updates");
        puts("10 version checks passed");
    }
    return 0;
}

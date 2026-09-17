#import <Foundation/Foundation.h>
#import <sys/stat.h>
#import <unistd.h>
#import "../Application/Dopamine/Jailbreak/DOBootstrapTransaction.h"

static void require(BOOL condition, NSString *message)
{
    if (!condition) {
        fprintf(stderr, "%s\n", message.UTF8String);
        exit(1);
    }
}

static NSString *readlinkString(NSString *path)
{
    char buffer[PATH_MAX + 1] = {0};
    ssize_t length = readlink(path.fileSystemRepresentation, buffer, PATH_MAX);
    if (length < 0) return nil;
    buffer[length] = 0;
    return @(buffer);
}

static void makeInitialLayout(NSFileManager *fm, NSString *primaryParent, NSString *secondaryParent, uint64_t brand)
{
    NSString *name = RHBootstrapRootName(brand);
    NSString *primary = [primaryParent stringByAppendingPathComponent:name];
    NSString *secondary = [secondaryParent stringByAppendingPathComponent:name];
    require([fm createDirectoryAtPath:[primary stringByAppendingPathComponent:@"private"] withIntermediateDirectories:YES attributes:nil error:nil], @"primary creation failed");
    require([fm createDirectoryAtPath:[secondary stringByAppendingPathComponent:@"var"] withIntermediateDirectories:YES attributes:nil error:nil], @"secondary creation failed");
    require([@"1" writeToFile:[primary stringByAppendingPathComponent:@".installed_dopamine"] atomically:YES encoding:NSUTF8StringEncoding error:nil], @"marker creation failed");
    require(symlink([secondary stringByAppendingPathComponent:@"var"].fileSystemRepresentation,
                    [primary stringByAppendingPathComponent:@"private/var"].fileSystemRepresentation) == 0, @"primary var symlink failed");
    require(symlink(primary.fileSystemRepresentation,
                    [secondary stringByAppendingPathComponent:@".jbroot"].fileSystemRepresentation) == 0, @"secondary backlink failed");
}

static void verifyFinalLayout(NSFileManager *fm, NSString *primaryParent, NSString *secondaryParent, uint64_t oldBrand, uint64_t newBrand)
{
    NSString *oldName = RHBootstrapRootName(oldBrand);
    NSString *newName = RHBootstrapRootName(newBrand);
    NSString *primary = [primaryParent stringByAppendingPathComponent:newName];
    NSString *secondary = [secondaryParent stringByAppendingPathComponent:newName];
    require(!RHBootstrapPathExistsNoFollow([primaryParent stringByAppendingPathComponent:oldName]), @"old primary survived");
    require(!RHBootstrapPathExistsNoFollow([secondaryParent stringByAppendingPathComponent:oldName]), @"old secondary survived");
    require([fm fileExistsAtPath:[primary stringByAppendingPathComponent:@".installed_dopamine"]], @"installed marker lost");
    require([[secondary stringByAppendingPathComponent:@"var"] isEqualToString:readlinkString([primary stringByAppendingPathComponent:@"private/var"])], @"primary var link incorrect");
    require([primary isEqualToString:readlinkString([secondary stringByAppendingPathComponent:@".jbroot"])], @"secondary backlink incorrect");
}

static void runFailureRecovery(NSString *base, NSString *failureStep)
{
    NSFileManager *fm = NSFileManager.defaultManager;
    NSString *root = [base stringByAppendingPathComponent:failureStep];
    NSString *primaryParent = [root stringByAppendingPathComponent:@"primary"];
    NSString *secondaryParent = [root stringByAppendingPathComponent:@"secondary"];
    require([fm createDirectoryAtPath:primaryParent withIntermediateDirectories:YES attributes:nil error:nil], @"primary parent failed");
    require([fm createDirectoryAtPath:secondaryParent withIntermediateDirectories:YES attributes:nil error:nil], @"secondary parent failed");
    const uint64_t oldBrand = 0x1111111111111111ULL;
    const uint64_t newBrand = 0x2222222222222222ULL;
    makeInitialLayout(fm, primaryParent, secondaryParent, oldBrand);
    NSString *journal = [secondaryParent stringByAppendingPathComponent:@".dopamine-rerandomize.plist"];
    NSError *error = nil;
    BOOL result = RHBootstrapBeginRerandomization(fm, primaryParent, secondaryParent, oldBrand, newBrand, journal,
        ^BOOL(NSString *step) { return [step isEqualToString:failureStep]; }, &error);
    require(!result, [NSString stringWithFormat:@"%@ did not inject failure", failureStep]);

    BOOL recovered = NO;
    error = nil;
    require(RHBootstrapRecoverRerandomization(fm, primaryParent, secondaryParent, journal, &recovered, &error),
            [NSString stringWithFormat:@"%@ recovery failed: %@", failureStep, error]);
    verifyFinalLayout(fm, primaryParent, secondaryParent, oldBrand, newBrand);
    require(!RHBootstrapPathExistsNoFollow(journal), @"journal survived successful recovery");
}

static void runLegacyPairRecovery(NSString *base)
{
    NSFileManager *fm = NSFileManager.defaultManager;
    NSString *primaryParent = [base stringByAppendingPathComponent:@"legacy-primary"];
    NSString *secondaryParent = [base stringByAppendingPathComponent:@"legacy-secondary"];
    require([fm createDirectoryAtPath:primaryParent withIntermediateDirectories:YES attributes:nil error:nil], @"legacy primary parent failed");
    require([fm createDirectoryAtPath:secondaryParent withIntermediateDirectories:YES attributes:nil error:nil], @"legacy secondary parent failed");
    const uint64_t primaryBrand = 0x3333333333333333ULL;
    const uint64_t secondaryBrand = 0x4444444444444444ULL;
    makeInitialLayout(fm, primaryParent, secondaryParent, primaryBrand);
    NSString *primaryName = RHBootstrapRootName(primaryBrand);
    NSString *secondaryName = RHBootstrapRootName(secondaryBrand);
    NSString *matchingSecondary = [secondaryParent stringByAppendingPathComponent:primaryName];
    NSString *mismatchedSecondary = [secondaryParent stringByAppendingPathComponent:secondaryName];
    require([fm moveItemAtPath:matchingSecondary toPath:mismatchedSecondary error:nil], @"legacy mismatch setup failed");

    BOOL repaired = NO;
    NSError *error = nil;
    require(RHBootstrapRepairLegacyPair(fm, primaryParent, secondaryParent, &repaired, &error), error.description ?: @"legacy repair failed");
    require(repaired, @"legacy mismatch was not reported repaired");
    require(RHBootstrapPathExistsNoFollow(matchingSecondary), @"legacy secondary not renamed to installed brand");
    NSString *primary = [primaryParent stringByAppendingPathComponent:primaryName];
    require([[matchingSecondary stringByAppendingPathComponent:@"var"] isEqualToString:readlinkString([primary stringByAppendingPathComponent:@"private/var"])], @"legacy primary link not repaired");
    require([primary isEqualToString:readlinkString([matchingSecondary stringByAppendingPathComponent:@".jbroot"])], @"legacy backlink not repaired");
}

int main(void)
{
    @autoreleasepool {
        NSString *base = [NSTemporaryDirectory() stringByAppendingPathComponent:NSUUID.UUID.UUIDString];
        require([NSFileManager.defaultManager createDirectoryAtPath:base withIntermediateDirectories:YES attributes:nil error:nil], @"base creation failed");
        for (NSString *step in @[@"journal-write", @"primary-rename", @"secondary-rename", @"primary-var-link", @"secondary-root-link", @"journal-clear"]) {
            runFailureRecovery(base, step);
        }
        runLegacyPairRecovery(base);
        require([NSFileManager.defaultManager removeItemAtPath:base error:nil], @"cleanup failed");
        puts("bootstrap transaction fault-injection scenarios passed");
    }
    return 0;
}

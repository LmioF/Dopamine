#import <Foundation/Foundation.h>
#import <sys/stat.h>
#import <unistd.h>

static NSString *const RHBootstrapTransactionOldBrandKey = @"oldBrand";
static NSString *const RHBootstrapTransactionNewBrandKey = @"newBrand";

typedef BOOL (^RHBootstrapTransactionFailureInjector)(NSString *step);

static NSString *RHBootstrapRootName(uint64_t brand)
{
    return [NSString stringWithFormat:@".jbroot-%016llX", brand];
}

static BOOL RHBootstrapPathExistsNoFollow(NSString *path)
{
    struct stat st = {0};
    return path && lstat(path.fileSystemRepresentation, &st) == 0;
}

static BOOL RHBootstrapSetError(NSError **error, NSString *description)
{
    if (error) {
        *error = [NSError errorWithDomain:@"BootstrapRootTransaction" code:1
                                 userInfo:@{NSLocalizedDescriptionKey: description ?: @"Bootstrap root transaction failed"}];
    }
    return NO;
}

static BOOL RHBootstrapInjectedFailure(RHBootstrapTransactionFailureInjector injector,
                                       NSString *step,
                                       NSError **error)
{
    if (injector && injector(step)) {
        return RHBootstrapSetError(error, [NSString stringWithFormat:@"Injected failure after %@", step]);
    }
    return YES;
}

static BOOL RHBootstrapMoveIfNeeded(NSFileManager *fm, NSString *source, NSString *destination, NSError **error)
{
    BOOL sourceExists = RHBootstrapPathExistsNoFollow(source);
    BOOL destinationExists = RHBootstrapPathExistsNoFollow(destination);
    if (!sourceExists && destinationExists) return YES;
    if (!sourceExists && !destinationExists) {
        return RHBootstrapSetError(error, [NSString stringWithFormat:@"Neither transaction path exists: %@ / %@", source, destination]);
    }
    if (sourceExists && destinationExists) {
        return RHBootstrapSetError(error, [NSString stringWithFormat:@"Both transaction generations exist: %@ / %@", source, destination]);
    }
    NSError *moveError = nil;
    if (![fm moveItemAtPath:source toPath:destination error:&moveError]) {
        if (error) *error = moveError;
        return NO;
    }
    return YES;
}

static BOOL RHBootstrapReplaceSymlink(NSString *path, NSString *destination, NSError **error)
{
    struct stat st = {0};
    if (lstat(path.fileSystemRepresentation, &st) == 0) {
        if (!S_ISLNK(st.st_mode)) {
            return RHBootstrapSetError(error, [NSString stringWithFormat:@"Refusing to replace non-symlink transaction path %@", path]);
        }
        char existing[PATH_MAX + 1] = {0};
        ssize_t length = readlink(path.fileSystemRepresentation, existing, PATH_MAX);
        if (length >= 0) {
            existing[length] = 0;
            if ([destination isEqualToString:@(existing)]) return YES;
        }
    }
    else if (errno != ENOENT) {
        return RHBootstrapSetError(error, [NSString stringWithFormat:@"Unable to inspect transaction symlink %@: %s", path, strerror(errno)]);
    }

    NSString *temporary = [path stringByAppendingFormat:@".dopamine-tmp-%@", NSUUID.UUID.UUIDString];
    unlink(temporary.fileSystemRepresentation);
    if (symlink(destination.fileSystemRepresentation, temporary.fileSystemRepresentation) != 0) {
        return RHBootstrapSetError(error, [NSString stringWithFormat:@"Creating transaction symlink %@ failed: %s", temporary, strerror(errno)]);
    }
    if (rename(temporary.fileSystemRepresentation, path.fileSystemRepresentation) != 0) {
        int savedErrno = errno;
        unlink(temporary.fileSystemRepresentation);
        return RHBootstrapSetError(error, [NSString stringWithFormat:@"Publishing transaction symlink %@ failed: %s", path, strerror(savedErrno)]);
    }
    return YES;
}

static BOOL RHBootstrapCompleteRerandomization(NSFileManager *fm,
                                               NSString *primaryParent,
                                               NSString *secondaryParent,
                                               uint64_t oldBrand,
                                               uint64_t newBrand,
                                               NSString *journalPath,
                                               RHBootstrapTransactionFailureInjector injector,
                                               NSError **error)
{
    NSString *oldName = RHBootstrapRootName(oldBrand);
    NSString *newName = RHBootstrapRootName(newBrand);
    NSString *oldPrimary = [primaryParent stringByAppendingPathComponent:oldName];
    NSString *newPrimary = [primaryParent stringByAppendingPathComponent:newName];
    NSString *oldSecondary = [secondaryParent stringByAppendingPathComponent:oldName];
    NSString *newSecondary = [secondaryParent stringByAppendingPathComponent:newName];

    if (!RHBootstrapMoveIfNeeded(fm, oldPrimary, newPrimary, error)) return NO;
    if (!RHBootstrapInjectedFailure(injector, @"primary-rename", error)) return NO;
    if (!RHBootstrapMoveIfNeeded(fm, oldSecondary, newSecondary, error)) return NO;
    if (!RHBootstrapInjectedFailure(injector, @"secondary-rename", error)) return NO;

    NSString *primaryVar = [newPrimary stringByAppendingPathComponent:@"private/var"];
    NSString *secondaryVar = [newSecondary stringByAppendingPathComponent:@"var"];
    if (!RHBootstrapReplaceSymlink(primaryVar, secondaryVar, error)) return NO;
    if (!RHBootstrapInjectedFailure(injector, @"primary-var-link", error)) return NO;

    NSString *secondaryBacklink = [newSecondary stringByAppendingPathComponent:@".jbroot"];
    if (!RHBootstrapReplaceSymlink(secondaryBacklink, newPrimary, error)) return NO;
    if (!RHBootstrapInjectedFailure(injector, @"secondary-root-link", error)) return NO;

    if (RHBootstrapPathExistsNoFollow(journalPath)) {
        NSError *removeError = nil;
        if (![fm removeItemAtPath:journalPath error:&removeError]) {
            if (error) *error = removeError;
            return NO;
        }
    }
    return RHBootstrapInjectedFailure(injector, @"journal-clear", error);
}

static BOOL RHBootstrapBeginRerandomization(NSFileManager *fm,
                                            NSString *primaryParent,
                                            NSString *secondaryParent,
                                            uint64_t oldBrand,
                                            uint64_t newBrand,
                                            NSString *journalPath,
                                            RHBootstrapTransactionFailureInjector injector,
                                            NSError **error)
{
    if (!fm || !primaryParent || !secondaryParent || !journalPath || oldBrand == newBrand) {
        return RHBootstrapSetError(error, @"Invalid bootstrap rerandomization transaction arguments");
    }
    NSDictionary *journal = @{
        RHBootstrapTransactionOldBrandKey: @(oldBrand),
        RHBootstrapTransactionNewBrandKey: @(newBrand),
    };
    if (![journal writeToFile:journalPath atomically:YES]) {
        return RHBootstrapSetError(error, [NSString stringWithFormat:@"Writing bootstrap transaction journal %@ failed", journalPath]);
    }
    if (!RHBootstrapInjectedFailure(injector, @"journal-write", error)) return NO;
    return RHBootstrapCompleteRerandomization(fm, primaryParent, secondaryParent, oldBrand, newBrand,
                                              journalPath, injector, error);
}

static BOOL RHBootstrapRecoverRerandomization(NSFileManager *fm,
                                              NSString *primaryParent,
                                              NSString *secondaryParent,
                                              NSString *journalPath,
                                              BOOL *didRecover,
                                              NSError **error)
{
    if (didRecover) *didRecover = NO;
    if (!RHBootstrapPathExistsNoFollow(journalPath)) return YES;

    NSDictionary *journal = [NSDictionary dictionaryWithContentsOfFile:journalPath];
    NSNumber *oldBrand = [journal isKindOfClass:[NSDictionary class]] ? journal[RHBootstrapTransactionOldBrandKey] : nil;
    NSNumber *newBrand = [journal isKindOfClass:[NSDictionary class]] ? journal[RHBootstrapTransactionNewBrandKey] : nil;
    if (![oldBrand isKindOfClass:[NSNumber class]] || ![newBrand isKindOfClass:[NSNumber class]] ||
        oldBrand.unsignedLongLongValue == newBrand.unsignedLongLongValue) {
        return RHBootstrapSetError(error, [NSString stringWithFormat:@"Invalid bootstrap transaction journal %@", journalPath]);
    }

    if (!RHBootstrapCompleteRerandomization(fm, primaryParent, secondaryParent,
                                            oldBrand.unsignedLongLongValue, newBrand.unsignedLongLongValue,
                                            journalPath, nil, error)) return NO;
    if (didRecover) *didRecover = YES;
    return YES;
}

static BOOL RHBootstrapRootNameIsValid(NSString *name)
{
    if (![name hasPrefix:@".jbroot-"] || name.length != 24) return NO;
    NSString *hex = [name substringFromIndex:8];
    NSScanner *scanner = [NSScanner scannerWithString:hex];
    unsigned long long value = 0;
    return [scanner scanHexLongLong:&value] && scanner.isAtEnd;
}

static BOOL RHBootstrapRepairLegacyPair(NSFileManager *fm,
                                        NSString *primaryParent,
                                        NSString *secondaryParent,
                                        BOOL *didRepair,
                                        NSError **error)
{
    if (didRepair) *didRepair = NO;
    NSError *listError = nil;
    NSArray<NSString *> *primaryItems = [fm contentsOfDirectoryAtPath:primaryParent error:&listError];
    if (!primaryItems) {
        if (error) *error = listError;
        return NO;
    }
    NSArray<NSString *> *secondaryItems = [fm contentsOfDirectoryAtPath:secondaryParent error:&listError];
    if (!secondaryItems) {
        if (error) *error = listError;
        return NO;
    }

    NSMutableArray<NSString *> *installedPrimaryNames = [NSMutableArray array];
    for (NSString *name in primaryItems) {
        if (!RHBootstrapRootNameIsValid(name)) continue;
        NSString *root = [primaryParent stringByAppendingPathComponent:name];
        if ([fm fileExistsAtPath:[root stringByAppendingPathComponent:@".installed_dopamine"]]) {
            [installedPrimaryNames addObject:name];
        }
    }
    if (installedPrimaryNames.count != 1) return YES;

    NSString *primaryName = installedPrimaryNames.firstObject;
    NSString *primary = [primaryParent stringByAppendingPathComponent:primaryName];
    NSString *matchingSecondary = [secondaryParent stringByAppendingPathComponent:primaryName];
    if (!RHBootstrapPathExistsNoFollow(matchingSecondary)) {
        NSMutableArray<NSString *> *secondaryRootNames = [NSMutableArray array];
        for (NSString *name in secondaryItems) {
            if (RHBootstrapRootNameIsValid(name)) [secondaryRootNames addObject:name];
        }
        if (secondaryRootNames.count != 1) {
            return RHBootstrapSetError(error, @"Installed bootstrap has no uniquely recoverable secondary root");
        }
        NSString *oldSecondary = [secondaryParent stringByAppendingPathComponent:secondaryRootNames.firstObject];
        NSError *moveError = nil;
        if (![fm moveItemAtPath:oldSecondary toPath:matchingSecondary error:&moveError]) {
            if (error) *error = moveError;
            return NO;
        }
        if (didRepair) *didRepair = YES;
    }

    if (!RHBootstrapReplaceSymlink([primary stringByAppendingPathComponent:@"private/var"],
                                   [matchingSecondary stringByAppendingPathComponent:@"var"], error)) return NO;
    if (!RHBootstrapReplaceSymlink([matchingSecondary stringByAppendingPathComponent:@".jbroot"], primary, error)) return NO;
    return YES;
}

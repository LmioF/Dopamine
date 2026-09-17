#import <Foundation/Foundation.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static NSString *gPrimary, *gSecondaryContainer, *gRoot, *gRacePath;
static NSMutableSet<NSString *> *gExpected, *gTouched;
static NSMutableSet<NSNumber *> *gOpened;
static const char *gScenario;
static bool gRaceTriggered;
static unsigned gFailures;

static bool scenario(const char *name) { return !strcmp(gScenario, name); }

static void check(bool condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message);
        gFailures++;
    }
}

static NSString *child(NSString *parent, NSString *name)
{
    return [parent stringByAppendingPathComponent:name];
}

static void makeDirectory(NSString *path)
{
    NSError *error = nil;
    if (![[NSFileManager defaultManager] createDirectoryAtPath:path withIntermediateDirectories:YES attributes:nil error:&error]) {
        fprintf(stderr, "fixture directory: %s\n", error.description.UTF8String);
        exit(2);
    }
}

static void removePath(NSString *path)
{
    NSError *error = nil;
    if (![[NSFileManager defaultManager] removeItemAtPath:path error:&error]) {
        fprintf(stderr, "fixture remove: %s\n", error.description.UTF8String);
        exit(2);
    }
}

static void movePath(NSString *from, NSString *to)
{
    NSError *error = nil;
    if (![[NSFileManager defaultManager] moveItemAtPath:from toPath:to error:&error]) {
        fprintf(stderr, "fixture move: %s\n", error.description.UTF8String);
        exit(2);
    }
}

static void makeLink(NSString *path, NSString *target)
{
    if (symlink(target.fileSystemRepresentation, path.fileSystemRepresentation) != 0) {
        perror("fixture symlink");
        exit(2);
    }
}

static void makeFile(NSString *path)
{
    makeDirectory(path.stringByDeletingLastPathComponent);
    if (![[NSData dataWithBytes:"fixture" length:7] writeToFile:path atomically:NO]) exit(2);
}

static void omitExpectedTree(NSString *path)
{
    for (NSString *entry in gExpected.copy) {
        if ([entry isEqualToString:path] || [entry hasPrefix:[path stringByAppendingString:@"/"]]) {
            [gExpected removeObject:entry];
        }
    }
}

static NSString *fixtureRoot(NSString *path)
{
    NSString *relative = [path stringByTrimmingCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"/"]];
    return relative.length ? child(gPrimary, relative) : gPrimary;
}

static void changeBeforeLookup(const char *path)
{
    if (!scenario("replacement-race") || gRaceTriggered || !path) return;
    if (strcmp(path, "raced") && strcmp(path, gRacePath.fileSystemRepresentation)) return;
    gRaceTriggered = true;
    movePath(gRacePath, child(gRoot, @"saved-race-file"));
    makeLink(gRacePath, child(gRoot, @"outside/keep"));
}

static int recordOwnership(const char *path, uid_t uid, gid_t gid)
{
    check(uid == 501 && gid == 501, "preserve requested mobile ownership");
    char *resolved = realpath(path, NULL);
    if (!resolved) { perror("fixture ownership path"); return -1; }
    NSString *actual = [NSString stringWithUTF8String:resolved];
    free(resolved);
    if (![gExpected containsObject:actual]) {
        fprintf(stderr, "FAIL: ownership requested outside permitted entries: %s\n", actual.UTF8String);
        gFailures++;
    }
    [gTouched addObject:actual];
    if (scenario("ownership-refusal")) { errno = EPERM; return -1; }
    return 0;
}

static int fixture_chown(const char *path, uid_t uid, gid_t gid)
{
    changeBeforeLookup(path);
    return recordOwnership(path, uid, gid);
}

static int fixture_fchown(int fd, uid_t uid, gid_t gid)
{
    char path[PATH_MAX];
    if (fcntl(fd, F_GETPATH, path) != 0) {
        check(false, "ownership descriptor remains open");
        return -1;
    }
    return recordOwnership(path, uid, gid);
}

static void fixtureOwner(struct stat *state)
{
    state->st_uid = state->st_gid = scenario("already-owned") ? 501 : 0;
}

static int fixture_stat(const char *path, struct stat *state)
{
    int result = stat(path, state);
    if (!result) fixtureOwner(state);
    return result;
}

static int fixture_fstat(int fd, struct stat *state)
{
    if (scenario("metadata-refusal")) { errno = EIO; return -1; }
    int result = fstat(fd, state);
    if (!result) fixtureOwner(state);
    if (!result && (scenario("opened-file-stat-refusal") || scenario("different-device-after-open"))) {
        char path[PATH_MAX];
        if (fcntl(fd, F_GETPATH, path) == 0 && !strcmp(strrchr(path, '/'), "/item")) {
            if (scenario("opened-file-stat-refusal")) { errno = EIO; return -1; }
            state->st_dev ^= 1;
        }
    }
    return result;
}

static int fixture_fstatat(int fd, const char *path, struct stat *state, int flags)
{
    if ((scenario("link-query-refusal") && !strcmp(path, "var")) ||
        (scenario("child-stat-refusal") && !strcmp(path, "item"))) { errno = EIO; return -1; }
    int result = fstatat(fd, path, state, flags);
    if (!result) fixtureOwner(state);
    if (!result && scenario("different-device") && !strcmp(path, "item")) state->st_dev ^= 1;
    return result;
}

static int fixture_open(const char *path, int flags, ...)
{
    check(!(flags & O_CREAT), "permission repair does not create files");
    if ((scenario("primary-open-refusal") && !strcmp(path, gPrimary.fileSystemRepresentation)) ||
        (scenario("container-open-refusal") && !strcmp(path, gSecondaryContainer.fileSystemRepresentation))) {
        errno = EACCES;
        return -1;
    }
    int fd = open(path, flags);
    if (fd >= 0) [gOpened addObject:@(fd)];
    return fd;
}

static int fixture_openat(int parent, const char *path, int flags, ...)
{
    check(!(flags & O_CREAT), "permission repair does not create relative files");
    changeBeforeLookup(path);
    if (scenario("directory-open-refusal") && !strcmp(path, "Library")) { errno = EACCES; return -1; }
    if ((scenario("secondary-open-refusal") && !strncmp(path, ".jbroot-", 8)) ||
        (scenario("var-open-refusal") && !strcmp(path, "var")) ||
        (scenario("mobile-open-refusal") && !strcmp(path, "mobile")) ||
        (scenario("file-open-refusal") && !strcmp(path, "item"))) { errno = EACCES; return -1; }
    int fd = openat(parent, path, flags);
    if (fd >= 0) [gOpened addObject:@(fd)];
    if (fd >= 0 && scenario("replacement-after-open") && !strcmp(path, "item")) {
        gRaceTriggered = true;
        movePath(gRacePath, child(gRoot, @"saved-open-file"));
        makeLink(gRacePath, child(gRoot, @"outside/keep"));
    }
    return fd;
}

static DIR *fixture_fdopendir(int fd)
{
    if (scenario("enumeration-refusal")) { errno = ENOMEM; return NULL; }
    return fdopendir(fd);
}

#define JBROOT_PATH(path) fixtureRoot(path)
#define stat(path, state) fixture_stat(path, state)
#define fstat fixture_fstat
#define fstatat fixture_fstatat
#define chown fixture_chown
#define fchown fixture_fchown
#define open fixture_open
#define openat fixture_openat
#define fdopendir fixture_fdopendir
#include "implementation.h"
#undef stat
#undef fstat
#undef fstatat
#undef chown
#undef fchown
#undef open
#undef openat
#undef fdopendir

int main(int argc, const char *argv[])
{
    @autoreleasepool {
        if (argc != 3) return 2;
        gScenario = argv[1];
        char *resolved = realpath(argv[2], NULL);
        if (!resolved) return 2;
        gRoot = [NSString stringWithUTF8String:resolved];
        free(resolved);
        gExpected = [NSMutableSet set];
        gTouched = [NSMutableSet set];
        gOpened = [NSMutableSet set];
        gPrimary = child(gRoot, @"primary/.jbroot-0123456789ABCDEF");
        gSecondaryContainer = child(gRoot, @"secondary");
        NSString *secondary = child(gSecondaryContainer, gPrimary.lastPathComponent);
        NSString *var = child(secondary, @"var");
        NSString *mobile = child(var, @"mobile");
        NSString *library = child(mobile, @"Library");
        NSString *snapshots = child(library, @"SplashBoard");
        NSString *nested = child(snapshots, @"nested");
        NSString *item = child(nested, @"item");
        NSString *support = child(library, @"Application Support");
        NSString *preferences = child(library, @"Preferences");
        NSString *outside = child(gRoot, @"outside");
        makeDirectory(child(gPrimary, @"private"));
        makeDirectory(nested);
        makeDirectory(support);
        makeDirectory(preferences);
        makeFile(item);
        makeFile(child(support, @"data"));
        makeFile(child(preferences, @"prefs"));
        makeFile(child(mobile, @"not-selected"));
        makeFile(child(library, @"not-selected"));
        makeFile(child(outside, @"keep"));
        makeLink(child(gPrimary, @"var"), @"private/var");
        makeLink(child(gPrimary, @"private/var"), var);
        [gExpected addObjectsFromArray:@[mobile, library, snapshots, nested, item, support, child(support, @"data"), preferences, child(preferences, @"prefs")]];

        if (scenario("mobile-link") || scenario("library-link") || scenario("selected-link") || scenario("nested-link")) {
            NSString *path = scenario("mobile-link") ? mobile : scenario("library-link") ? library : scenario("selected-link") ? snapshots : nested;
            NSString *destination = child(outside, @"moved-directory");
            movePath(path, destination);
            makeLink(path, destination);
            omitExpectedTree(path);
        } else if (scenario("file-link") || scenario("dangling-link") || scenario("link-cycle")) {
            removePath(item);
            makeLink(item, scenario("file-link") ? child(outside, @"keep") : scenario("dangling-link") ? child(outside, @"absent") : item);
            [gExpected removeObject:item];
        } else if (scenario("wrong-var")) {
            NSString *other = child(outside, @"other-var");
            if (![[NSFileManager defaultManager] copyItemAtPath:var toPath:other error:nil]) return 2;
            removePath(child(gPrimary, @"private/var"));
            makeLink(child(gPrimary, @"private/var"), other);
            [gExpected removeAllObjects];
        } else if (scenario("secondary-link") || scenario("secondary-var-link") || scenario("primary-link")) {
            NSString *path = scenario("secondary-link") ? secondary : scenario("secondary-var-link") ? var : gPrimary;
            NSString *destination = child(outside, @"moved-root");
            movePath(path, destination);
            makeLink(path, destination);
            [gExpected removeAllObjects];
        } else if (scenario("invalid-root-name")) {
            NSString *renamed = child(gRoot, @"primary/not-a-bootstrap");
            movePath(gPrimary, renamed);
            gPrimary = renamed;
            [gExpected removeAllObjects];
        } else if (scenario("hardlink")) {
            removePath(item);
            if (link(child(outside, @"keep").fileSystemRepresentation, item.fileSystemRepresentation) != 0) return 2;
            [gExpected removeObject:item];
        } else if (scenario("fifo")) {
            removePath(item);
            if (mkfifo(item.fileSystemRepresentation, 0600) != 0) return 2;
            [gExpected removeObject:item];
        } else if (scenario("already-owned")) {
            [gExpected removeAllObjects];
        } else if (scenario("directory-open-refusal")) {
            omitExpectedTree(library);
        } else if (scenario("enumeration-refusal")) {
            omitExpectedTree(nested);
            [gExpected removeObject:child(support, @"data")];
            [gExpected removeObject:child(preferences, @"prefs")];
        } else if (scenario("replacement-race")) {
            gRacePath = child(snapshots, @"raced");
            makeFile(gRacePath);
        } else if (scenario("missing-var")) {
            removePath(var);
            [gExpected removeAllObjects];
        } else if (scenario("primary-open-refusal") || scenario("container-open-refusal") ||
                   scenario("secondary-open-refusal") || scenario("var-open-refusal") ||
                   scenario("mobile-open-refusal") || scenario("metadata-refusal") || scenario("link-query-refusal")) {
            [gExpected removeAllObjects];
        } else if (scenario("child-stat-refusal") || scenario("file-open-refusal") ||
                   scenario("opened-file-stat-refusal") || scenario("different-device") || scenario("different-device-after-open")) {
            [gExpected removeObject:item];
        } else if (scenario("non-directory-mobile")) {
            removePath(mobile);
            makeFile(mobile);
            [gExpected removeAllObjects];
        } else if (scenario("replacement-after-open")) {
            gRacePath = item;
            [gExpected removeObject:item];
            [gExpected addObject:child(gRoot, @"saved-open-file")];
        }

        if (scenario("descriptor-zero")) close(STDIN_FILENO);
        unsigned repeats = scenario("repeated") ? 40 : 1;
        for (unsigned run = 0; run < repeats; run++) {
            [gTouched removeAllObjects];
            [gOpened removeAllObjects];
            JBFixMobilePermissions();
            check([gTouched isEqualToSet:gExpected], "repair exactly the intended reachable entries");
            for (NSNumber *number in gOpened) {
                errno = 0;
                check(fcntl(number.intValue, F_GETFD) == -1 && errno == EBADF, "release every operation-owned descriptor");
            }
        }
        if (scenario("replacement-race")) check(gRaceTriggered, "exercise replacement during the lookup boundary");
        if (scenario("replacement-after-open")) check(gRaceTriggered, "keep the opened object after its name is replaced");
        if (scenario("descriptor-zero")) check(fcntl(STDIN_FILENO, F_GETFD) == -1, "close an owned descriptor zero");
        if (gFailures) return 1;
        printf("%s: permission confinement passed\n", gScenario);
        return 0;
    }
}

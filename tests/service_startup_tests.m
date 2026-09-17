#import <Foundation/Foundation.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static bool hasPanic, nullPanic, skipCache, alertFailure;
static int bootstrapResult, cacheResult;
static unsigned operations, bootstrapOrder, cacheOrder, queryOrder, alertOrder, failures, cases;

static void check(bool condition, const char *message)
{
    if (!condition) { fprintf(stderr, "FAIL: %s\n", message); failures++; }
}

static int fixture_command(const char *path, ...)
{
    va_list arguments;
    va_start(arguments, path);
    const char *first = va_arg(arguments, const char *);
    int result;
    if (!strcmp(path, "/usr/bin/launchctl")) {
        bootstrapOrder = ++operations;
        check(!strcmp(first, "bootstrap"), "keep daemon bootstrap command");
        check(!strcmp(va_arg(arguments, const char *), "system"), "keep system domain");
        check(!strcmp(va_arg(arguments, const char *), "/Library/LaunchDaemons"), "keep RootHide launchctl path semantics");
        result = bootstrapResult;
    } else {
        cacheOrder = ++operations;
        check(!strcmp(path, "/usr/bin/uicache") && !strcmp(first, "-a"), "keep application refresh command");
        check(bootstrapOrder != 0 && !bootstrapResult, "application refresh follows successful service bootstrap");
        result = cacheResult;
    }
    check(va_arg(arguments, const char *) == NULL, "terminate command arguments");
    va_end(arguments);
    return result;
}

static int fixture_access(const char *path, int mode)
{
    check(!strcmp(path, "/.disable_auto_uicache") && mode == F_OK, "preserve explicit cache-refresh opt-out");
    return skipCache ? 0 : -1;
}

static int fixture_panic(char **message)
{
    queryOrder = ++operations;
    check(bootstrapOrder != 0 && !bootstrapResult, "recover services before querying diagnostics");
    *message = hasPanic && !nullPanic ? strdup("fixture watchdog message") : NULL;
    return hasPanic ? 0 : -1;
}

static SInt32 fixture_alert(CFTimeInterval timeout, CFOptionFlags flags, CFURLRef icon, CFURLRef sound,
    CFURLRef localization, CFStringRef header, CFStringRef message, CFStringRef primary,
    CFStringRef alternate, CFStringRef other, CFOptionFlags *response)
{
    alertOrder = ++operations;
    check(bootstrapOrder != 0 && !bootstrapResult && (skipCache || cacheOrder != 0), "notification never gates required startup work");
    check(timeout > 0, "unanswered diagnostic notification does not retain startup job forever");
    check(message != NULL, "show meaningful panic text");
    return alertFailure ? -1 : 0;
}

#define JBROOT_PATH(path) path
#define JBLogDebug(...) ((void)0)
#define exec_cmd fixture_command
#define access fixture_access
#define jbclient_watchdog_get_last_userspace_panic fixture_panic
#define CFUserNotificationDisplayAlert fixture_alert
#include "implementation.h"

static void run(bool panic, bool noMessage, bool disabled, int bootstrap, int cache, bool refusedAlert)
{
    cases++;
    operations = bootstrapOrder = cacheOrder = queryOrder = alertOrder = 0;
    hasPanic = panic;
    nullPanic = noMessage;
    skipCache = disabled;
    bootstrapResult = bootstrap;
    cacheResult = cache;
    alertFailure = refusedAlert;
    int result = run_startup();
    int expected = bootstrap ? bootstrap : disabled ? 0 : cache;
    check(result == expected, "return required operation failure or successful completion");
    check(bootstrapOrder == 1, "service recovery is first");
    if (bootstrap) check(!cacheOrder && !alertOrder, "failed bootstrap is not reported as completed startup");
    if (disabled) check(!cacheOrder, "cache-refresh opt-out does not skip service bootstrap");
    if (!expected && panic && !noMessage) check(alertOrder > bootstrapOrder && queryOrder > bootstrapOrder, "panic notification remains available after recovery");
    if (!panic || noMessage) check(!alertOrder, "do not display absent diagnostics");
}

int main(void)
{
    @autoreleasepool {
        run(false, false, false, 0, 0, false);
        run(true, false, false, 0, 0, false);
        run(true, false, true, 0, 0, false);
        run(true, false, false, 0, 0, true);
        run(true, false, false, 17, 0, false);
        run(false, false, false, 23, 0, false);
        run(false, false, false, 0, 31, false);
        run(true, false, false, 0, 31, false);
        run(true, true, false, 0, 0, false);
        run(false, false, true, 0, 99, false);
        printf("%u startup cases, %u failures\n", cases, failures);
        return failures ? 1 : 0;
    }
}

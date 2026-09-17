#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

static uid_t realUID, effectiveUID, savedUID;
static gid_t realGID, effectiveGID, savedGID;
static unsigned operation, failAt, failures, cases;
static int installedGroupCount;
static gid_t installedGroups[NGROUPS_MAX];

static bool permitted_operation(void)
{
    if (++operation == failAt) { errno = EIO; return false; }
    return true;
}
static int fixture_setuid(uid_t uid)
{
    if (!permitted_operation()) return -1;
    if (effectiveUID == 0) { realUID = effectiveUID = savedUID = uid; return 0; }
    if (uid == realUID || uid == savedUID) { effectiveUID = uid; return 0; }
    errno = EPERM;
    return -1;
}
static int fixture_setreuid(uid_t real, uid_t effective)
{
    if (!permitted_operation()) return -1;
    bool setReal = real != (uid_t)-1, setEffective = effective != (uid_t)-1;
    if (effectiveUID != 0 && ((setReal && real != realUID && real != savedUID) ||
        (setEffective && effective != effectiveUID && effective != realUID && effective != savedUID))) {
        errno = EPERM;
        return -1;
    }
    uid_t oldReal = realUID;
    if (setReal) realUID = real;
    if (setEffective) effectiveUID = effective;
    if (setReal || (setEffective && effective != oldReal)) savedUID = effectiveUID;
    return 0;
}
static int fixture_setgid(gid_t gid)
{
    if (!permitted_operation()) return -1;
    if (effectiveUID == 0) { realGID = effectiveGID = savedGID = gid; return 0; }
    if (gid == realGID || gid == savedGID) { effectiveGID = gid; return 0; }
    errno = EPERM;
    return -1;
}
static int fixture_setregid(gid_t real, gid_t effective)
{
    if (!permitted_operation()) return -1;
    bool setReal = real != (gid_t)-1, setEffective = effective != (gid_t)-1;
    if (effectiveUID != 0 && ((setReal && real != realGID && real != savedGID) ||
        (setEffective && effective != effectiveGID && effective != realGID && effective != savedGID))) {
        errno = EPERM;
        return -1;
    }
    gid_t oldReal = realGID;
    if (setReal) realGID = real;
    if (setEffective) effectiveGID = effective;
    if (setReal || (setEffective && effective != oldReal)) savedGID = effectiveGID;
    return 0;
}
static int fixture_setgroups(int count, const gid_t *groups)
{
    if (!permitted_operation()) return -1;
    if (effectiveUID != 0 || count < 0 || count > NGROUPS_MAX) { errno = EPERM; return -1; }
    installedGroupCount = count;
    memcpy(installedGroups, groups, count * sizeof(gid_t));
    if (count) effectiveGID = groups[0];
    return 0;
}

#define setuid fixture_setuid
#define setreuid fixture_setreuid
#define setgid fixture_setgid
#define setregid fixture_setregid
#define setgroups fixture_setgroups
#include "implementation.h"

static void check(bool condition, const char *message)
{
    if (!condition) { fprintf(stderr, "FAIL: %s\n", message); failures++; }
}
static void run(uid_t real, uid_t effective, gid_t realGroup, gid_t effectiveGroup, unsigned failedOperation)
{
    cases++;
    realUID = effectiveUID = savedUID = 0;
    realGID = effectiveGID = savedGID = 0;
    installedGroupCount = 0;
    operation = 0;
    failAt = failedOperation;
    gid_t groups[NGROUPS_MAX];
    for (unsigned i = 0; i < NGROUPS_MAX; i++) groups[i] = (gid_t)-1;
    groups[0] = effectiveGroup;
    groups[1] = 20;
    int result = configure_identity(effective, real, effectiveGroup, realGroup, groups, 2);
    if (failedOperation) {
        check(result != 0, "failed identity operation never produces donor success");
    } else {
        check(result == 0, "privileged donor can construct requested identity");
        check(realUID == real && effectiveUID == effective && savedUID == effective, "real effective and saved UIDs match intended donor identity");
        check(realGID == realGroup && effectiveGID == effectiveGroup && savedGID == effectiveGroup, "groups are configured before dropping UID privilege");
        check(installedGroupCount == 2 && installedGroups[0] == effectiveGroup && installedGroups[1] == 20, "preserve explicitly counted nonempty group input");
    }
}

int main(void)
{
    run(501, 502, 501, 502, 0);
    run(501, 0, 501, 0, 0);
    run(501, 501, 501, 501, 0);
    run(0, 501, 0, 501, 0);
    run(0, 0, 0, 0, 0);
    run(1000, 502, 20, 30, 0);
    for (unsigned i = 1; i <= 5; i++) run(501, 502, 501, 502, i);
    printf("%u donor identity cases, %u failures\n", cases, failures);
    return failures ? 1 : 0;
}

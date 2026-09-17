#include <errno.h>
#include <limits.h>
#include <math.h>
#include <mach/mach.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "../BaseBin/systemhook/src/common/private.h"

static const char *scenario;
static const char *HOOK_DYLIB_PATH = "/fixture/systemhook.dylib";
static bool fixtureModern = true;
static unsigned failures, spawnCalls, personaCalls, resumeCalls, killCalls, waitCalls, allocationCalls, allocationRefusal, allocationsLive;
static unsigned depth;
static void *allocations[8];
static struct _posix_spawn_args_desc originalDescriptor;
static struct _posix_spawn_persona_info originalPersona, personaBefore;
static union { max_align_t alignment; uint8_t bytes[0xE0]; } originalAttributes;
static uint8_t attributesBefore[0xE0];
static double multiplier = 3;
static bool is(const char *name) { return !strcmp(scenario, name); }

static void check(bool condition, const char *message)
{
    if (!condition) { fprintf(stderr, "FAIL: %s\n", message); failures++; }
}

static void *fixture_malloc(size_t size)
{
    if (++allocationCalls == allocationRefusal) return NULL;
    void *pointer = malloc(size);
    if (!pointer) abort();
    for (unsigned i = 0; i < 8; i++) if (!allocations[i]) { allocations[i] = pointer; allocationsLive++; return pointer; }
    abort();
}

static void fixture_free(void *pointer)
{
    if (!pointer) return;
    for (unsigned i = 0; i < 8; i++) if (allocations[i] == pointer) { allocations[i] = NULL; allocationsLive--; free(pointer); return; }
    abort();
}

static int fixture_getflags(const posix_spawnattr_t *attr, short *flags)
{
    if (is("getflags-failure")) return EINVAL;
    *flags = 0;
    if (*attr) memcpy(flags, *attr, sizeof(*flags));
    return 0;
}
static int fixture_setflags(posix_spawnattr_t *attr, short flags)
{
    if (is("flags-failure")) return EINVAL;
    if (!*attr) return EINVAL;
    memcpy(*attr, &flags, sizeof(flags));
    return 0;
}
static int fixture_processtype(const posix_spawnattr_t *attr, int *type) { *type = 0; return 0; }
static int fixture_access(const char *path, int mode) { return 0; }
static uid_t fixture_uid(void) { return is("already-root") ? 0 : 501; }
static bool allowInjectWithSafeMode(const char *path) { return true; }
static const char *envbuf_getenv(const char **env, const char *key) { return !strcmp(key, "DYLD_INSERT_LIBRARIES") ? HOOK_DYLIB_PATH : NULL; }
static char **envbuf_mutcopy(const char **env) { abort(); }
static void envbuf_setenv(char ***env, const char *key, const char *value) { abort(); }
static void envbuf_unsetenv(char ***env, const char *key) { abort(); }
static void envbuf_free(char **env) { abort(); }
static void string_enumerate_components(const char *text, const char *separator, void (^callback)(const char *, bool *))
{
    bool stop = false;
    callback(text, &stop);
}
static int fixture_persona(pid_t pid, uid_t uid, gid_t gid)
{
    personaCalls++;
    check(pid == 42 && uid == 0 && gid == 0, "preserve original requested persona identity");
    return is("persona-failure") ? -1 : 0;
}
static int fixture_kill(pid_t pid, int signal)
{
    check(pid == 42, "only the created child is signalled");
    if (signal == SIGCONT) { resumeCalls++; if (is("resume-failure")) { errno = ESRCH; return -1; } }
    else if (signal == SIGKILL) killCalls++;
    else check(false, "unexpected signal");
    return 0;
}
static pid_t fixture_wait(pid_t pid, int *status, int flags) { waitCalls++; check(pid == 42, "only created child is reaped"); return pid; }
static int fixture_trust(const char *path) { return 0; }
static int fixture_debug(uint64_t pid, bool fully) { check(is("caller-suspended") && pid == 42, "debug only caller-requested suspension"); return 0; }
static int invoke(void);

static int fixture_spawn(pid_t *pid, const char *path, struct _posix_spawn_args_desc *desc, char *const argv[], char *const env[])
{
    spawnCalls++;
    check(!memcmp(originalAttributes.bytes, attributesBefore, sizeof(attributesBefore)) && !memcmp(&originalPersona, &personaBefore, sizeof(personaBefore)), "caller attributes remain immutable during the operation");
    if (!path) { if (pid) *pid = 42; return 0; }
    check(desc != &originalDescriptor && desc->attrp != originalDescriptor.attrp, "each operation owns its descriptor and attribute snapshot");
    check(desc->file_actions == originalDescriptor.file_actions && desc->file_actions_size == originalDescriptor.file_actions_size, "preserve unrelated descriptor fields");
    int active = 0;
    memcpy(&active, (uint8_t *)desc->attrp + POSIX_SPAWNATTR_OFF_MEMLIMIT_ACTIVE, sizeof(active));
    check(active == (is("jetsam-overflow") || is("jetsam-infinite") ? INT_MAX : 300), "scale limits exactly once with bounded conversion");
    short flags = 0;
    fixture_getflags(&desc->attrp, &flags);
    bool personaExpected = fixtureModern && !is("already-root") && !is("no-persona") && !is("setexec");
    if (personaExpected) {
        struct _posix_spawn_persona_info *persona = NULL;
        memcpy(&persona, (uint8_t *)desc->attrp + POSIX_SPAWNATTR_OFF_PERSONA, sizeof(persona));
        check(persona && persona != &originalPersona && persona->pspi_uid == 501 && persona->pspi_gid == 501, "private mobile persona in attribute snapshot");
        check(desc->persona_info && desc->persona_info != originalDescriptor.persona_info, "kernel descriptor references private persona");
        struct _posix_spawn_persona_info *kernelPersona = desc->persona_info;
        check(kernelPersona->pspi_uid == 501 && kernelPersona->pspi_gid == 501, "kernel-facing persona matches temporary attribute persona");
        check((flags & POSIX_SPAWN_START_SUSPENDED) != 0, "identity repair runs before child execution");
    }
    if (is("interleaved") && depth == 0) {
        depth++;
        check(invoke() == 0, "nested call succeeds with same caller-owned attributes");
        depth--;
        int after = 0;
        memcpy(&after, (uint8_t *)desc->attrp + POSIX_SPAWNATTR_OFF_MEMLIMIT_ACTIVE, sizeof(after));
        check(after == active, "interleaved call leaves the first snapshot unchanged");
    }
    if (is("spawn-failure")) return EAGAIN;
    if (pid) *pid = 42;
    return 0;
}
static int fixture_exec(const char *path, char *const argv[], char *const env[]) { return -7; }

#define malloc fixture_malloc
#define free fixture_free
#define access fixture_access
#define getuid fixture_uid
#define kill fixture_kill
#define waitpid fixture_wait
#define posix_spawnattr_getflags fixture_getflags
#define posix_spawnattr_setflags fixture_setflags
#define posix_spawnattr_getprocesstype_np fixture_processtype
#define jbclient_persona_fix fixture_persona
#define spawn_config_for_executable(path, argv) 3
#include "implementation.h"
#undef malloc
#undef free

static int invoke(void)
{
    pid_t pid = -1;
    char *arguments[] = {"fixture", NULL};
    char *environment[] = {NULL};
    return posix_spawn_hook_shared(&pid, is("null-path") ? NULL : "/fixture/program", &originalDescriptor,
        arguments, environment, fixture_spawn, fixture_trust, fixture_debug, multiplier);
}

int main(int argc, const char *argv[])
{
    if (argc != 2) return 2;
    scenario = argv[1];
    fixtureModern = !is("legacy");
    short flags = is("caller-suspended") ? POSIX_SPAWN_START_SUSPENDED : is("setexec") ? POSIX_SPAWN_SETEXEC : 0;
    int limit = is("jetsam-overflow") ? INT_MAX : 100;
    int inactive = -1;
    memcpy(originalAttributes.bytes, &flags, sizeof(flags));
    memcpy(originalAttributes.bytes + POSIX_SPAWNATTR_OFF_MEMLIMIT_ACTIVE, &limit, sizeof(limit));
    memcpy(originalAttributes.bytes + POSIX_SPAWNATTR_OFF_MEMLIMIT_INACTIVE, &inactive, sizeof(inactive));
    originalPersona = (struct _posix_spawn_persona_info){.pspi_id = 99, .pspi_flags = POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE | POSIX_SPAWN_PERSONA_UID | POSIX_SPAWN_PERSONA_GID};
    struct _posix_spawn_persona_info *personaPointer = is("no-persona") || is("descriptor-persona") ? NULL : &originalPersona;
    memcpy(originalAttributes.bytes + POSIX_SPAWNATTR_OFF_PERSONA, &personaPointer, sizeof(personaPointer));
    originalDescriptor = (struct _posix_spawn_args_desc){
        .attr_size = sizeof(originalAttributes.bytes), .attrp = (posix_spawnattr_t)originalAttributes.bytes,
        .file_actions_size = 8, .file_actions = (void *)(uintptr_t)123,
        .persona_info_size = is("no-persona") ? 0 : sizeof(originalPersona),
        .persona_info = is("no-persona") ? NULL : &originalPersona,
    };
    if (is("short-attributes")) originalDescriptor.attr_size = 1;
    if (is("short-persona")) originalDescriptor.persona_info_size = 2;
    if (is("allocation-one")) allocationRefusal = 1;
    if (is("allocation-two")) allocationRefusal = 2;
    if (is("jetsam-infinite")) multiplier = INFINITY;
    memcpy(attributesBefore, originalAttributes.bytes, sizeof(attributesBefore));
    personaBefore = originalPersona;
    bool expectedFailure = strstr(scenario, "failure") || allocationRefusal || is("short-attributes") || is("short-persona");
    if (is("execve")) {
        char *arguments[] = {"fixture", NULL};
        char *environment[] = {NULL};
        check(execve_hook_shared("/fixture/program", arguments, environment, fixture_exec, fixture_trust) == -7, "preserve execve result");
    } else {
        unsigned repeat = is("reused") ? 2 : 1;
        for (unsigned i = 0; i < repeat; i++) {
            int result = invoke();
            check(expectedFailure ? result != 0 : result == 0, "preserve failure or successful spawn result");
            check(!memcmp(originalAttributes.bytes, attributesBefore, sizeof(attributesBefore)) && !memcmp(&originalPersona, &personaBefore, sizeof(personaBefore)), "caller attributes remain immutable after the operation");
        }
        bool personaExpected = !expectedFailure && !is("null-path") && fixtureModern && !is("already-root") && !is("no-persona") && !is("setexec");
        if (personaExpected) check(personaCalls == spawnCalls && resumeCalls == (is("caller-suspended") ? 0 : spawnCalls), "every reused/interleaved spawn receives identity repair and correct resume ownership");
        if (is("spawn-failure")) check(!personaCalls && !resumeCalls && !killCalls, "failed spawn does not touch a child");
        if (allocationRefusal || is("short-attributes") || is("short-persona") || is("flags-failure") || is("getflags-failure")) check(!spawnCalls, "invalid setup does not spawn");
    }
    check(!allocationsLive, "release per-call attribute and persona copies");
    for (unsigned i = 0; i < 8; i++) free(allocations[i]);
    printf("%s: spawns=%u personas=%u resumes=%u failures=%u\n", scenario, spawnCalls, personaCalls, resumeCalls, failures);
    return failures ? 1 : 0;
}

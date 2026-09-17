#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/proc_info.h>
#include <libproc.h>
#include <bsm/libbsm.h>
#include <mach/mach.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

static const char *scenario;
static char original_path[PATH_MAX], replacement_path[PATH_MAX], alias_path[PATH_MAX];
static int caller_fd = -1;
static unsigned queries, opens, trusts, attachments, wrong_object, failures;
static struct stat original_stat;
struct siginfo;
static bool is_case(const char *value) { return !strcmp(scenario, value); }
static pid_t fixture_token_pid(audit_token_t token) { return 4242; }
static bool string_has_prefix(const char *string, const char *prefix) { return !strncmp(string, prefix, strlen(prefix)); }
static bool isRemovableBundlePath(const char *path) { return false; }
static bool hasTrollstoreLiteMarker(const char *path) { return false; }
static int fixture_query(pid_t pid, int fd, int flavor, void *buffer, int size)
{
    queries++;
    if (pid != 4242 || fd != caller_fd || flavor != PROC_PIDFDVNODEPATHINFO || size != sizeof(struct vnode_fdinfowithpath)) failures++;
    if (is_case("query-failed") || (is_case("recheck-failed") && queries > 1)) { errno = ESRCH; return -1; }
    struct vnode_fdinfowithpath *info = buffer;
    memset(info, 0, sizeof(*info));
    strcpy(info->pvip.vip_path, is_case("hardlink") ? alias_path : original_path);
    struct stat status;
    if (fstat(caller_fd, &status)) abort();
    info->pvip.vip_vi.vi_stat.vst_dev = status.st_dev;
    info->pvip.vip_vi.vi_stat.vst_ino = status.st_ino;
    info->pvip.vip_vi.vi_stat.vst_gen = status.st_gen;
    if (is_case("device-mismatch")) info->pvip.vip_vi.vi_stat.vst_dev++;
    if (is_case("inode-mismatch") || (is_case("descriptor-reused") && queries > 1)) info->pvip.vip_vi.vi_stat.vst_ino++;
    if (is_case("generation-mismatch")) info->pvip.vip_vi.vi_stat.vst_gen++;
    if (is_case("path-unterminated")) memset(info->pvip.vip_path, 'x', sizeof(info->pvip.vip_path));
    if (queries == 1 && !strncmp(scenario, "replaced", 8) && rename(replacement_path, original_path)) abort();
    if (queries == 1 && is_case("removed") && unlink(original_path)) abort();
    return is_case("query-short") ? sizeof(*info) - 1 : sizeof(*info);
}
static int fixture_open(const char *path, int flags, ...)
{
    opens++;
    if (is_case("path-unterminated")) { errno = ENAMETOOLONG; return -1; }
    return open(path, flags);
}
static int fixture_fstat(int fd, struct stat *status)
{
    if (is_case("stat-failed")) { errno = EIO; return -1; }
    return fstat(fd, status);
}
static int fixture_statfs(int fd, struct statfs *status)
{
    memset(status, 0, sizeof(*status));
    strcpy(status->f_mntonname, "/fixture-volume");
    return 0;
}
static void observe_object(int fd)
{
    struct stat status;
    if (fstat(fd, &status) || status.st_dev != original_stat.st_dev || status.st_ino != original_stat.st_ino) wrong_object++;
}
static int fixture_fcntl(int fd, int command, ...)
{
    va_list arguments;
    va_start(arguments, command);
    void *argument = va_arg(arguments, void *);
    va_end(arguments);
    if (command == F_GETPATH) return fcntl(fd, F_GETPATH, argument);
    if (command == F_ADDSIGS) { attachments++; observe_object(fd); return 0; }
    failures++;
    errno = EINVAL;
    return -1;
}
static void file_collect_signatures(int fd, struct siginfo **signatures, uint32_t *count);
static int trust_signatures(int pid, int fd, struct siginfo *signatures, uint32_t count);
static void *siginfo_resolve_superblob(struct siginfo *signature, int pid, int fd);
#define audit_token_to_pid fixture_token_pid
#define proc_pidfdinfo fixture_query
#define open fixture_open
#define fstat fixture_fstat
#define fstatfs fixture_statfs
#define fcntl fixture_fcntl

#include "implementation.h"

#undef open
#undef fstat
#undef fcntl

static void file_collect_signatures(int fd, struct siginfo **signatures, uint32_t *count)
{
    *signatures = calloc(1, sizeof(**signatures));
    if (!*signatures) abort();
    (*signatures)->source = SIGNATURE_SOURCE_FILE;
    *count = 1;
}
static int trust_signatures(int pid, int fd, struct siginfo *signatures, uint32_t count)
{
    trusts++;
    observe_object(fd);
    return 0;
}
static void *siginfo_resolve_superblob(struct siginfo *signature, int pid, int fd)
{
    return calloc(1, 16);
}
static int descriptor_count(void)
{
    int result = 0;
    for (int fd = 0; fd < 256; fd++) if (fcntl(fd, F_GETFD) != -1) result++;
    return result;
}

int main(int argc, char **argv)
{
    if (argc != 3) return 2;
    scenario = argv[1];
    snprintf(original_path, sizeof(original_path), "%s/original", argv[2]);
    snprintf(replacement_path, sizeof(replacement_path), "%s/replacement", argv[2]);
    snprintf(alias_path, sizeof(alias_path), "%s/alias", argv[2]);
    caller_fd = open(original_path, O_RDWR | O_CREAT | O_EXCL, 0600);
    int replacement = open(replacement_path, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (caller_fd < 0 || replacement < 0 || fstat(caller_fd, &original_stat)) return 2;
    if (write(caller_fd, "original", 8) != 8 || write(replacement, "replacement", 11) != 11 || close(replacement)) return 2;
    if (is_case("hardlink") && link(original_path, alias_path)) return 2;
    int descriptors = descriptor_count();
    audit_token_t token = {{0}};
    bool local = is_case("local-duplicate");
    bool valid = is_case("unchanged") || is_case("hardlink") || local || is_case("without-attachment") || !strncmp(scenario, "source-", 7);
    bool attach = !is_case("without-attachment");
    struct siginfo signature = {.source = SIGNATURE_SOURCE_FILE};
    bool supplied = !strncmp(scenario, "source-", 7) || !strncmp(scenario, "replaced-", 9);
    if (strstr(scenario, "proc")) signature.source = SIGNATURE_SOURCE_PROC;
    if (strstr(scenario, "allocation")) {
        signature.source = SIGNATURE_SOURCE_ALLOCATION;
        signature.signature.fs_blob_start = calloc(1, 16);
        if (!signature.signature.fs_blob_start) return 2;
    }
    int result = systemwide_trust_file(local ? NULL : &token, caller_fd,
                                      supplied ? &signature : NULL, supplied ? sizeof(signature) : 0, attach);
    if (!trusts && signature.source == SIGNATURE_SOURCE_ALLOCATION) free(signature.signature.fs_blob_start);
    failures += valid ? result != 0 || trusts != 1 || attachments != (unsigned)attach : result == 0 || trusts || attachments;
    failures += wrong_object != 0 || descriptor_count() != descriptors;
    if (local) failures += queries != 0 || opens != 0;
    if (is_case("query-short") || is_case("query-failed") || is_case("path-unterminated")) failures += opens != 0;
    printf("%s: result=%d queries=%u opens=%u trusts=%u attachments=%u wrong_object=%u failures=%u\n",
           scenario, result, queries, opens, trusts, attachments, wrong_object, failures);
    close(caller_fd);
    return failures ? 1 : 0;
}

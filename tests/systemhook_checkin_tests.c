#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include "jbclient_mach.h"

static char *JB_RootPath;
static char *JB_BootUUID;
static char *JB_SandboxExtensions;
static bool gFullyDebugged;
static int checkinResult;
static unsigned checkinCalls;

int jbclient_mach_process_checkin(char *root, char *uuid, char *extensions, bool *debugged, bool *adhoc)
{
    ++checkinCalls;
    if (checkinResult) return checkinResult;
    strcpy(root, "/private/var/containers/Bundle/Application/.jbroot-test");
    strcpy(uuid, "01234567-89AB-CDEF-0123-456789ABCDEF");
    strcpy(extensions, "read-token|exec-token");
    *debugged = true;
    if (adhoc) *adhoc = false;
    return 0;
}

#include "checkin-under-test.h"

int main(void)
{
    checkinResult = EACCES;
    assert(systemhook_checkin() == EACCES);
    assert(JB_RootPath == NULL && JB_BootUUID == NULL && JB_SandboxExtensions == NULL);
    assert(!gFullyDebugged);
    checkinResult = 0;
    assert(systemhook_checkin() == 0);
    assert(checkinCalls == 2);
    assert(strcmp(JB_RootPath, "/private/var/containers/Bundle/Application/.jbroot-test") == 0);
    assert(strcmp(JB_BootUUID, "01234567-89AB-CDEF-0123-456789ABCDEF") == 0);
    assert(strcmp(JB_SandboxExtensions, "read-token|exec-token") == 0);
    assert(gFullyDebugged);
    JB_SandboxExtensions[10] = '\0';
    assert(strcmp(JB_SandboxExtensions, "read-token") == 0);
    JB_SandboxExtensions[10] = '|';
    puts("Mach check-in outputs and failure preservation passed.");
    return 0;
}

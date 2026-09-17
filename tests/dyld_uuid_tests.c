#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "dyld_jbinfo.h"

typedef unsigned char uuid_t[16];
struct mach_header { int unused; };
struct mach_header_64 { int unused; };
static struct mach_header_64 image;
static struct dyld_jbinfo info;
static uuid_t fixture_uuid;
static bool has_header = true, has_uuid = true, has_section = true;
static const struct mach_header_64 *get_dyld_mach_header(void) { return has_header ? &image : NULL; }
static bool _dyld_get_image_uuid(const struct mach_header *header, uuid_t result)
{
    if (!has_uuid) return false;
    memcpy(result, fixture_uuid, sizeof(fixture_uuid));
    return true;
}
static void *getsectiondata(const struct mach_header_64 *header, const char *segment, const char *section, size_t *size)
{
    *size = sizeof(info);
    return has_section ? &info : NULL;
}

#include "implementation.h"

int main(void)
{
    int failures = 0;
    memset(fixture_uuid, 0xAB, sizeof(fixture_uuid));
    if (parse_dyldhook_jbinfo(NULL, NULL, NULL, NULL) != -3) failures++;
    fixture_uuid[3] = 0;
    if (parse_dyldhook_jbinfo(NULL, NULL, NULL, NULL) != -3) failures++;
    memset(fixture_uuid, 0xAB, sizeof(fixture_uuid));
    memcpy(fixture_uuid, "DOPA", 4);
    info.state = DYLD_STATE_CHECKED_IN;
    info.jbRootPath = "/fixture/root"; info.bootUUID = "fixture-boot"; info.sandboxExtensions = "fixture-capability";
    info.fullyDebugged = true;
    char *root = NULL, *boot = NULL, *extensions = NULL;
    bool debugged = false;
    if (parse_dyldhook_jbinfo(&root, &boot, &extensions, &debugged) != 0 ||
        root != info.jbRootPath || boot != info.bootUUID || extensions != info.sandboxExtensions || !debugged) failures++;
    has_header = false;
    if (parse_dyldhook_jbinfo(NULL, NULL, NULL, NULL) != -1) failures++;
    has_header = true; has_uuid = false;
    if (parse_dyldhook_jbinfo(NULL, NULL, NULL, NULL) != -2) failures++;
    has_uuid = true; has_section = false;
    if (parse_dyldhook_jbinfo(NULL, NULL, NULL, NULL) != -4) failures++;
    has_section = true; info.state = 0;
    if (parse_dyldhook_jbinfo(NULL, NULL, NULL, NULL) != -5) failures++;
    printf("7 binary UUID/check-in parsing cases, %d failures\n", failures);
    return failures ? 1 : 0;
}

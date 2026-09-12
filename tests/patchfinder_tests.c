#include <stdio.h>
#include <xpf/xpf.h>
#include "../Application/Dopamine/Jailbreak/DORoothidePatchfinder.h"

int main(int argc, const char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s /path/to/kernelcache\n", argv[0]);
        return 2;
    }
    int result = xpf_start_with_kernel_path(argv[1], NULL, NULL);
    if (result == 0) {
        printf("%s\n", gXPF.kernelVersionString);
        xpc_object_t offsets = xpc_dictionary_create(NULL, NULL, 0);
        result = roothide_add_kernel_offsets(offsets);
        if (result == 0) {
            xpc_dictionary_apply(offsets, ^bool(const char *key, xpc_object_t value) {
                printf("%s = 0x%016llx\n", key, xpc_uint64_get_value(value));
                return true;
            });
        }
        xpc_release(offsets);
    }
    if (result != 0) fprintf(stderr, "Patchfinding failed: %s\n", xpf_get_error() ?: "unknown error");
    xpf_stop();
    return result == 0 ? 0 : 1;
}

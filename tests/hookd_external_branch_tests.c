#include <stdint.h>
#include <stdio.h>

typedef uint64_t vm_address_t;

#include "implementation.h"

int main(void)
{
    vm_address_t origin = 0x100000000ULL;
    if (arm64_gen_b(origin, origin + (16ULL << 30)) != 0) return 1;
    if (arm64_gen_bl(origin, origin + (16ULL << 30)) != 0) return 2;
    if (arm64_gen_b(origin, origin + (128ULL << 20)) != 0) return 3;
    if (arm64_gen_b(origin, origin + (128ULL << 20) - 4) == 0) return 4;
    if (arm64_gen_b(origin, origin - (128ULL << 20)) == 0) return 5;
    if (arm64_gen_b(origin, origin - (128ULL << 20) - 4) != 0) return 6;
    puts("ok");
    return 0;
}

#include <limits.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    if (strcmp(argv[1], "overflow") == 0) {
        volatile int value = INT_MAX;
        volatile int result = value + 1;
        (void)result;
    }
    else if (strcmp(argv[1], "clean") != 0) {
        return 2;
    }
    puts("fixture completed");
    return 0;
}

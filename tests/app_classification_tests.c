#include <stdbool.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *app_root;
static bool preference;
#define JBROOT_PATH(suffix) app_root
#define jbsetting(name) preference

#include "implementation.h"

int main(int argc, char **argv)
{
    if (argc != 18) return 2;
    app_root = argv[1];
    int cases = 0;
    int failures = 0;
    for (int i = 2; i < argc; i += 2) {
        for (int enabled = 0; enabled <= 1; enabled++) {
            preference = enabled != 0;
            bool expected = preference && atoi(argv[i + 1]) != 0;
            bool result = fixture_fully_debugged(argv[i]);
            cases++;
            if (result != expected) {
                fprintf(stderr, "%s: preference=%d result=%d expected=%d\n",
                        argv[i], preference, result, expected);
                failures++;
            }
        }
    }
    printf("%d app classification cases, %d failures; no process or credential operations\n", cases, failures);
    return failures ? 1 : 0;
}

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define koffsetof(type, field) 0
static int unavailable, writer_result, task_queries, write_calls, failures;
static const void *expected_address, *expected_input;
static size_t expected_length;

static uint64_t proc_task(uint64_t proc)
{
    task_queries++;
    return proc == 11 && unavailable != 1 ? 22 : 0;
}
static uint64_t kread_ptr(uint64_t address)
{
    if (address == 22) return unavailable == 2 ? 0 : 33;
    if (address == 33) return unavailable == 3 ? 0 : 44;
    return 0;
}
static uint64_t kread64(uint64_t address) { return address == 44 && unavailable != 4 ? 55 : 0; }
static int vwritebuf(uint64_t table, const void *address, const void *input, size_t length)
{
    write_calls++;
    if (table != 55 || address != expected_address || input != expected_input || length != expected_length) failures++;
    return writer_result;
}

#include "implementation.h"

int main(void)
{
    char input[8] = {0}, destination[8] = {0};
    expected_input = input; expected_address = destination; expected_length = sizeof(input);
    for (int missing = 0; missing <= 4; missing++) {
        for (int result = 0; result >= -9; result -= 9) {
            unavailable = missing; writer_result = result; task_queries = 0; write_calls = 0;
            int actual = proc_vwritebuf(11, destination, input, sizeof(input));
            int expected = missing ? -1 : result;
            if (actual != expected || task_queries != 1 || write_calls != (missing ? 0 : 1)) {
                fprintf(stderr, "missing=%d writer=%d actual=%d task_queries=%d write_calls=%d\n", missing, result, actual, task_queries, write_calls);
                failures++;
            }
        }
    }
    printf("10 process-write dispatch cases, %d failures; memory operations are mocked\n", failures);
    return failures ? 1 : 0;
}

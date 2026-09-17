#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static int live_allocations, allocation_failure, create_failure, create_calls, scans;
static int calls_a, calls_b, argument_failures, immediate;
static uintptr_t tpidr;
static int argument_a, argument_b, result_a, result_b;
static void *(*queued_routines[4])(void *);
static void *queued_arguments[4];
static unsigned queued;
static void *immediate_result;
static void *fixture_malloc(size_t size)
{
    if (allocation_failure) return NULL;
    void *result = malloc(size);
    if (result) live_allocations++;
    return result;
}
static void fixture_free(void *pointer)
{
    if (pointer) live_allocations--;
    free(pointer);
}
static uintptr_t get_tpidrr0_el0(void) { return tpidr; }
static int find_frida_text(void (^handler)(uint32_t *, size_t)) { scans++; return 0; }
static int apply_hookd_syscall_patches(uint32_t *text, size_t size) { return 0; }

#define malloc fixture_malloc
#define free fixture_free
#include "implementation.h"
#undef malloc
#undef free

static void *routine_a(void *arg)
{
    calls_a++;
    argument_failures += arg != &argument_a;
    return &result_a;
}
static void *routine_b(void *arg)
{
    calls_b++;
    argument_failures += arg != &argument_b;
    return &result_b;
}
static int fixture_create(pthread_t *restrict thread, const pthread_attr_t *restrict attr,
                          void *(*routine)(void *), void *restrict arg, uint32_t whatever)
{
    create_calls++;
    if (whatever != 123) argument_failures++;
    if (create_failure) return create_failure;
    if (immediate) immediate_result = routine(arg);
    else {
        if (queued == 4) exit(2);
        queued_routines[queued] = routine;
        queued_arguments[queued++] = arg;
    }
    return 0;
}
static void reset_fixture(void)
{
    if (live_allocations) exit(2);
    queued = 0;
    create_calls = scans = calls_a = calls_b = argument_failures = 0;
    allocation_failure = create_failure = immediate = 0;
    tpidr = 0;
    immediate_result = NULL;
    _pthread_create_orig = fixture_create;
}
static void *start_queued(unsigned index) { return queued_routines[index](queued_arguments[index]); }
int main(void)
{
    pthread_t thread;
    int failures = 0;
    for (unsigned reverse = 0; reverse < 2; reverse++) {
        reset_fixture();
        int a = _pthread_create_hook(&thread, NULL, routine_a, &argument_a, 123);
        int b = _pthread_create_hook(&thread, NULL, routine_b, &argument_b, 123);
        if (a || b || queued != 2) return 2;
        void *first = start_queued(reverse ? 1 : 0);
        void *second = start_queued(reverse ? 0 : 1);
        if (first != (reverse ? &result_b : &result_a) || second != (reverse ? &result_a : &result_b) ||
            calls_a != 1 || calls_b != 1 || argument_failures || live_allocations || scans != 2) {
            fprintf(stderr, "delayed reverse=%u: A=%d B=%d arguments=%d live=%d scans=%d\n",
                    reverse, calls_a, calls_b, argument_failures, live_allocations, scans);
            failures++;
        }
    }
    reset_fixture();
    immediate = 1;
    if (_pthread_create_hook(&thread, NULL, routine_a, &argument_a, 123) || immediate_result != &result_a ||
        calls_a != 1 || argument_failures || live_allocations || scans != 1) failures++;
    reset_fixture();
    create_failure = EAGAIN;
    if (_pthread_create_hook(&thread, NULL, routine_a, &argument_a, 123) != EAGAIN ||
        create_calls != 1 || queued || live_allocations || scans) failures++;
    reset_fixture();
    allocation_failure = 1;
    int allocation_result = _pthread_create_hook(&thread, NULL, routine_a, &argument_a, 123);
    if (allocation_result != ENOMEM || create_calls || queued || live_allocations || scans) {
        fprintf(stderr, "allocation refusal: result=%d creates=%d queued=%u live=%d\n",
                allocation_result, create_calls, queued, live_allocations);
        failures++;
    }
    for (unsigned i = 0; i < queued; i++) start_queued(i);
    reset_fixture();
    tpidr = 1;
    allocation_failure = 1;
    if (_pthread_create_hook(&thread, NULL, routine_b, &argument_b, 123) || queued != 1 ||
        queued_routines[0] != routine_b || queued_arguments[0] != &argument_b) return 2;
    if (start_queued(0) != &result_b || calls_b != 1 || argument_failures || scans || live_allocations) failures++;
    reset_fixture();
    tpidr = 1;
    create_failure = EINVAL;
    if (_pthread_create_hook(&thread, NULL, routine_a, &argument_a, 123) != EINVAL ||
        create_calls != 1 || queued || live_allocations || scans) failures++;
    printf("7 thread-start ownership cases, %d failures; no target threads or patches\n", failures);
    return failures ? 1 : 0;
}

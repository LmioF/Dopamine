#import <Foundation/Foundation.h>
#include <stdio.h>
#include <stdlib.h>
#include "request_scope.h"

static void require(BOOL condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

int main(void)
{
    @autoreleasepool {
        static const void *key = &key;
        NSObject *first = [NSObject new];
        NSObject *second = [NSObject new];

        require(!rhAssociatedFlagIsActive(first, key), "fresh object must not be tagged");
        rhAssociatedFlagScopeBegin(first, key);
        require(rhAssociatedFlagIsActive(first, key), "first scope must activate the tag");
        require(!rhAssociatedFlagIsActive(second, key), "tag must be object-local");
        rhAssociatedFlagScopeBegin(first, key);
        rhAssociatedFlagScopeEnd(first, key);
        require(rhAssociatedFlagIsActive(first, key), "nested scope must keep outer tag active");
        rhAssociatedFlagScopeEnd(first, key);
        require(!rhAssociatedFlagIsActive(first, key), "final scope exit must clear reusable object state");

        __thread static pid_t currentPid;
        currentPid = 11;
        RHPidScope outer = rhPidScopeBegin(&currentPid, 22);
        require(currentPid == 22, "outer pid scope must publish the current client");
        RHPidScope inner = rhPidScopeBegin(&currentPid, 33);
        require(currentPid == 33, "inner pid scope must override the outer client");
        rhPidScopeEnd(&currentPid, inner);
        require(currentPid == 22, "inner pid scope must restore the outer client");
        rhPidScopeEnd(&currentPid, outer);
        require(currentPid == 11, "outer pid scope must restore preexisting thread state");
    }
    return 0;
}

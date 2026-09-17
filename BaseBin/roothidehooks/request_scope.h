#pragma once

#import <Foundation/Foundation.h>
#include <sys/types.h>

typedef struct {
    pid_t previous;
} RHPidScope;

RHPidScope rhPidScopeBegin(pid_t *slot, pid_t value);
void rhPidScopeEnd(pid_t *slot, RHPidScope scope);

void rhAssociatedFlagScopeBegin(id object, const void *key);
void rhAssociatedFlagScopeEnd(id object, const void *key);
BOOL rhAssociatedFlagIsActive(id object, const void *key);

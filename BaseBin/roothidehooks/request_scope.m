#import "request_scope.h"
#import <objc/runtime.h>

RHPidScope rhPidScopeBegin(pid_t *slot, pid_t value)
{
    RHPidScope scope = { .previous = slot ? *slot : 0 };
    if (slot) *slot = value;
    return scope;
}

void rhPidScopeEnd(pid_t *slot, RHPidScope scope)
{
    if (slot) *slot = scope.previous;
}

void rhAssociatedFlagScopeBegin(id object, const void *key)
{
    if (!object || !key) return;
    @synchronized (object) {
        NSNumber *count = objc_getAssociatedObject(object, key);
        objc_setAssociatedObject(object, key, @(count.unsignedIntegerValue + 1), OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    }
}

void rhAssociatedFlagScopeEnd(id object, const void *key)
{
    if (!object || !key) return;
    @synchronized (object) {
        NSNumber *count = objc_getAssociatedObject(object, key);
        NSUInteger value = count.unsignedIntegerValue;
        if (value <= 1) {
            objc_setAssociatedObject(object, key, nil, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        } else {
            objc_setAssociatedObject(object, key, @(value - 1), OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        }
    }
}

BOOL rhAssociatedFlagIsActive(id object, const void *key)
{
    if (!object || !key) return NO;
    @synchronized (object) {
        NSNumber *count = objc_getAssociatedObject(object, key);
        return count.unsignedIntegerValue > 0;
    }
}

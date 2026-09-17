#import <Foundation/Foundation.h>
#include <stdio.h>
#include <stdlib.h>
#include "implementation.h"

@interface ThrowingKVC : NSObject
@end
@implementation ThrowingKVC
- (id)valueForKey:(NSString *)key { @throw [NSException exceptionWithName:@"Fixture" reason:key userInfo:nil]; }
- (void)setValue:(id)value forKey:(NSString *)key { @throw [NSException exceptionWithName:@"Fixture" reason:key userInfo:nil]; }
@end

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
        NSIndexSet *removed = [NSIndexSet indexSetWithIndexesInRange:NSMakeRange(1, 1)];
        NSArray *immutable = @[@1, @2, @3];
        NSArray *filtered = rhArrayByRemovingIndexes(immutable, removed, 3);
        require([filtered isEqualToArray:@[@1, @3]], "immutable input must be filtered through a copy");
        require([immutable isEqualToArray:@[@1, @2, @3]], "source array must remain unchanged");
        require(rhArrayByRemovingIndexes(immutable, removed, 2) == nil, "mismatched correlated arrays must be rejected");
        require(rhArrayByRemovingIndexes(@[@1], removed, 1) == nil, "out-of-range removal must be rejected");
        require(rhArrayByRemovingIndexes(@"not-an-array", removed, 0) == nil, "wrong-type query data must be rejected");

        ThrowingKVC *throwing = [ThrowingKVC new];
        require(rhSafeValueForKey(throwing, @"missing") == nil, "KVC read exceptions must degrade to nil");
        require(!rhSafeSetValueForKey(throwing, @"missing", @[]), "KVC write exceptions must degrade without escaping");
    }
    return 0;
}

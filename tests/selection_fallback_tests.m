#import <Foundation/Foundation.h>

typedef NS_ENUM(NSUInteger, ExploitType) { EXPLOIT_TYPE_KERNEL, EXPLOIT_TYPE_PAC, EXPLOIT_TYPE_PPL, EXPLOIT_TYPE_COUNT };
@interface DOExploit : NSObject
@property NSString *identifier;
@end
@implementation DOExploit
@end

@interface DOPreferenceManager : NSObject
@property NSMutableDictionary *values;
+ (instancetype)sharedManager;
- (id)preferenceValueForKey:(NSString *)key;
@end
@implementation DOPreferenceManager
+ (instancetype)sharedManager
{
    static DOPreferenceManager *manager;
    if (!manager) { manager = [self new]; manager.values = [NSMutableDictionary new]; }
    return manager;
}
- (id)preferenceValueForKey:(NSString *)key { return self.values[key]; }
@end

@interface DOExploitManager : NSObject
@property NSArray<NSSet<DOExploit *> *> *available;
@property NSArray<DOExploit *> *defaults;
- (NSSet<DOExploit *> *)availableExploitsForType:(ExploitType)type;
- (DOExploit *)_findExploitWithIdentifier:(NSString *)identifier andType:(ExploitType)type;
- (DOExploit *)preferredKernelExploit;
- (DOExploit *)preferredPACBypass;
- (DOExploit *)preferredPPLBypass;
- (DOExploit *)selectedKernelExploit;
- (DOExploit *)selectedPACBypass;
- (DOExploit *)selectedPPLBypass;
@end
@implementation DOExploitManager
- (NSSet<DOExploit *> *)availableExploitsForType:(ExploitType)type { return self.available[type]; }
- (DOExploit *)preferredKernelExploit { return self.defaults[0]; }
- (DOExploit *)preferredPACBypass { return self.defaults[1]; }
- (DOExploit *)preferredPPLBypass { return self.defaults[2]; }
#include "implementation.h"
@end

int main(void)
{
    @autoreleasepool {
        DOExploitManager *manager = [DOExploitManager new];
        NSMutableArray *defaults = [NSMutableArray new];
        NSMutableArray *available = [NSMutableArray new];
        NSMutableArray *chosen = [NSMutableArray new];
        for (NSUInteger type = 0; type < EXPLOIT_TYPE_COUNT; type++) {
            DOExploit *fallback = [DOExploit new]; fallback.identifier = @"default";
            DOExploit *choice = [DOExploit new]; choice.identifier = @"chosen";
            [defaults addObject:fallback]; [chosen addObject:choice];
            [available addObject:[NSSet setWithObjects:fallback, choice, nil]];
        }
        manager.defaults = defaults; manager.available = available;
        NSArray *keys = @[@"selectedKernelExploit", @"selectedPACBypass", @"selectedPPLBypass"];
        int failures = 0, checks = 0;
        for (NSUInteger type = 0; type < EXPLOIT_TYPE_COUNT; type++) {
            for (id value in @[[NSNull null], @"chosen", @"removed", @"unsupported", @123]) {
                NSMutableDictionary *preferences = [DOPreferenceManager sharedManager].values;
                [preferences removeAllObjects];
                if (value != [NSNull null]) preferences[keys[type]] = value;
                DOExploit *expected = [value isEqual:@"chosen"] ? chosen[type] : defaults[type];
                checks++;
                @try {
                    DOExploit *actual = type == 0 ? manager.selectedKernelExploit : type == 1 ? manager.selectedPACBypass : manager.selectedPPLBypass;
                    if (actual != expected) { fprintf(stderr, "type=%lu preference=%s lost fallback\n", (unsigned long)type, [[value description] UTF8String]); failures++; }
                } @catch (NSException *exception) {
                    fprintf(stderr, "type=%lu preference raised %s\n", (unsigned long)type, exception.name.UTF8String); failures++;
                }
            }
        }
        printf("%d preference checks, %d failures; no exploit code loaded or executed\n", checks, failures);
        return failures ? 1 : 0;
    }
}

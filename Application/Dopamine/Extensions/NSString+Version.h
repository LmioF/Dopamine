//
//  NSString+Version.h
//  Dopamine
//
//  Created by Lars Fröder on 12.06.24.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface NSString (Version)

- (NSInteger)numericalVersionRepresentation;
- (NSComparisonResult)compareVersion:(NSString *)other;
- (BOOL)isQualifiedVersion;

@end

NS_ASSUME_NONNULL_END

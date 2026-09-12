//
//  NSString+Version.h
//  Dopamine
//
//  Created by Lars Fröder on 12.06.24.
//

#import <Foundation/Foundation.h>

@implementation NSString (Version)

- (BOOL)isQualifiedVersion
{
    NSString *version = [self stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    NSRange match = [version rangeOfString:@"^v?[0-9]+(?:\\.[0-9]+){2,3}$" options:NSRegularExpressionSearch];
    return match.location == 0 && match.length == version.length && version.length > 0;
}

- (NSComparisonResult)compareVersion:(NSString *)other
{
    NSCharacterSet *separators = NSCharacterSet.decimalDigitCharacterSet.invertedSet;
    NSPredicate *nonempty = [NSPredicate predicateWithFormat:@"SELF != ''"];
    NSArray<NSString *> *left = [[self componentsSeparatedByCharactersInSet:separators] filteredArrayUsingPredicate:nonempty];
    NSArray<NSString *> *right = [[other componentsSeparatedByCharactersInSet:separators] filteredArrayUsingPredicate:nonempty];
    for (NSUInteger index = 0; index < MAX(left.count, right.count); index++) {
        NSString *a = index < left.count ? left[index] : @"0";
        NSString *b = index < right.count ? right[index] : @"0";
        NSComparisonResult result = [a compare:b options:NSNumericSearch];
        if (result != NSOrderedSame) return result;
    }
    return NSOrderedSame;
}

- (NSInteger)numericalVersionRepresentation
{
    NSInteger numericalRepresentation = 0;

    NSArray *components = [self componentsSeparatedByCharactersInSet:[[NSCharacterSet decimalDigitCharacterSet] invertedSet]];
    
    components = [components filteredArrayUsingPredicate:[NSPredicate predicateWithFormat:@"SELF != ''"]];
    assert(components.count <= 3);
    
    while (components.count < 3)
        components = [components arrayByAddingObject:@"0"];

    numericalRepresentation |= [components[0] integerValue] << 16;
    numericalRepresentation |= [components[1] integerValue] << 8;
    numericalRepresentation |= [components[2] integerValue];
    return numericalRepresentation;
}

@end

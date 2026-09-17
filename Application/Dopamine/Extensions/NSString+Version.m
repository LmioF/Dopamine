//
//  NSString+Version.h
//  Dopamine
//
//  Created by Lars Fröder on 12.06.24.
//

#import <Foundation/Foundation.h>

static BOOL DOVersionIsDigit(unsigned char character)
{
    return character >= '0' && character <= '9';
}

static int DODebianVersionOrder(unsigned char character)
{
    if (character == '~') return -1;
    if (!character || DOVersionIsDigit(character)) return 0;
    if ((character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z')) return character;
    return character + 256;
}

static NSComparisonResult DOCompareDebianPart(NSString *left, NSString *right)
{
    const unsigned char *a = (const unsigned char *)left.UTF8String;
    const unsigned char *b = (const unsigned char *)right.UTF8String;
    while (*a || *b) {
        while ((*a && !DOVersionIsDigit(*a)) || (*b && !DOVersionIsDigit(*b))) {
            int difference = DODebianVersionOrder(*a) - DODebianVersionOrder(*b);
            if (difference) return difference < 0 ? NSOrderedAscending : NSOrderedDescending;
            if (*a) a++;
            if (*b) b++;
        }
        while (*a == '0') a++;
        while (*b == '0') b++;
        int difference = 0;
        while (DOVersionIsDigit(*a) && DOVersionIsDigit(*b)) {
            if (!difference) difference = *a - *b;
            a++;
            b++;
        }
        if (DOVersionIsDigit(*a)) return NSOrderedDescending;
        if (DOVersionIsDigit(*b)) return NSOrderedAscending;
        if (difference) return difference < 0 ? NSOrderedAscending : NSOrderedDescending;
    }
    return NSOrderedSame;
}

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

- (NSComparisonResult)compareDebianVersion:(NSString *)other
{
    NSString *left = self;
    NSString *right = other;
    NSRange leftColon = [left rangeOfString:@":"];
    NSRange rightColon = [right rangeOfString:@":"];
    NSString *leftEpoch = leftColon.location == NSNotFound ? @"0" : [left substringToIndex:leftColon.location];
    NSString *rightEpoch = rightColon.location == NSNotFound ? @"0" : [right substringToIndex:rightColon.location];
    NSComparisonResult result = DOCompareDebianPart(leftEpoch, rightEpoch);
    if (result != NSOrderedSame) return result;
    if (leftColon.location != NSNotFound) left = [left substringFromIndex:NSMaxRange(leftColon)];
    if (rightColon.location != NSNotFound) right = [right substringFromIndex:NSMaxRange(rightColon)];

    NSRange leftHyphen = [left rangeOfString:@"-" options:NSBackwardsSearch];
    NSRange rightHyphen = [right rangeOfString:@"-" options:NSBackwardsSearch];
    NSString *leftRevision = leftHyphen.location == NSNotFound ? @"0" : [left substringFromIndex:NSMaxRange(leftHyphen)];
    NSString *rightRevision = rightHyphen.location == NSNotFound ? @"0" : [right substringFromIndex:NSMaxRange(rightHyphen)];
    if (leftHyphen.location != NSNotFound) left = [left substringToIndex:leftHyphen.location];
    if (rightHyphen.location != NSNotFound) right = [right substringToIndex:rightHyphen.location];
    result = DOCompareDebianPart(left, right);
    return result == NSOrderedSame ? DOCompareDebianPart(leftRevision, rightRevision) : result;
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

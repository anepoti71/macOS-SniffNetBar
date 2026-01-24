//
//  IPAddressUtilities.m
//  SniffNetBar
//

#import "IPAddressUtilities.h"
#import <arpa/inet.h>

@implementation IPAddressUtilities

#pragma mark - Basic Validation

+ (BOOL)isValidIPv4:(NSString *)ipAddress {
    if (!ipAddress || ipAddress.length == 0) {
        return NO;
    }

    NSArray<NSString *> *octets = [ipAddress componentsSeparatedByString:@"."];
    if (octets.count != 4) {
        return NO;
    }

    NSCharacterSet *nonDigits = [[NSCharacterSet decimalDigitCharacterSet] invertedSet];
    for (NSString *octet in octets) {
        if (octet.length == 0 || [octet rangeOfCharacterFromSet:nonDigits].location != NSNotFound) {
            return NO;
        }
        NSInteger value = [octet integerValue];
        if (value < 0 || value > 255) {
            return NO;
        }
    }

    return YES;
}

+ (BOOL)isValidIPv6:(NSString *)ipAddress {
    if (!ipAddress || ipAddress.length == 0) {
        return NO;
    }

    // Use inet_pton for robust IPv6 validation
    struct in6_addr addr;
    return inet_pton(AF_INET6, [ipAddress UTF8String], &addr) == 1;
}

#pragma mark - Private/Local Address Detection

+ (BOOL)isPrivateIPv4Address:(NSString *)ipAddress {
    if (![self isValidIPv4:ipAddress]) {
        return NO;
    }

    NSArray<NSString *> *octets = [ipAddress componentsSeparatedByString:@"."];
    NSInteger first = [octets[0] integerValue];
    NSInteger second = [octets[1] integerValue];

    // RFC 1918 private ranges
    if (first == 10) {  // 10.0.0.0/8
        return YES;
    }
    if (first == 172 && second >= 16 && second <= 31) {  // 172.16.0.0/12
        return YES;
    }
    if (first == 192 && second == 168) {  // 192.168.0.0/16
        return YES;
    }

    // Loopback
    if (first == 127) {  // 127.0.0.0/8
        return YES;
    }

    // Link-local (APIPA)
    if (first == 169 && second == 254) {  // 169.254.0.0/16
        return YES;
    }

    return NO;
}

+ (BOOL)isPrivateIPv6Address:(NSString *)ipAddress {
    if (![self isValidIPv6:ipAddress]) {
        return NO;
    }

    NSString *lowerIP = [ipAddress lowercaseString];

    // Loopback (::1)
    if ([lowerIP isEqualToString:@"::1"] || [lowerIP hasPrefix:@"::1/"]) {
        return YES;
    }

    // Link-local (fe80::/10)
    if ([lowerIP hasPrefix:@"fe80:"]) {
        return YES;
    }

    // Unique Local Addresses (fc00::/7 - includes fc00::/8 and fd00::/8)
    if ([lowerIP hasPrefix:@"fc"] || [lowerIP hasPrefix:@"fd"]) {
        return YES;
    }

    // Unspecified address (::)
    if ([lowerIP isEqualToString:@"::"]) {
        return YES;
    }

    return NO;
}

+ (BOOL)isPrivateIPAddress:(NSString *)ipAddress {
    if (!ipAddress || ipAddress.length == 0) {
        return NO;
    }

    if ([ipAddress containsString:@"."]) {
        return [self isPrivateIPv4Address:ipAddress];
    } else if ([ipAddress containsString:@":"]) {
        return [self isPrivateIPv6Address:ipAddress];
    }

    return NO;
}

#pragma mark - Public Address Detection

+ (BOOL)isPublicIPAddress:(NSString *)ipAddress {
    if (!ipAddress || ipAddress.length == 0) {
        return NO;
    }

    // IPv4
    if ([ipAddress containsString:@"."]) {
        if (![self isValidIPv4:ipAddress]) {
            return NO;
        }

        // Check if it's private/local
        if ([self isPrivateIPv4Address:ipAddress]) {
            return NO;
        }

        NSArray<NSString *> *octets = [ipAddress componentsSeparatedByString:@"."];
        NSInteger first = [octets[0] integerValue];

        // Multicast (224.0.0.0/4)
        if (first >= 224 && first <= 239) {
            return NO;
        }

        // Reserved/experimental (240.0.0.0/4)
        if (first >= 240) {
            return NO;
        }

        // "This network" (0.0.0.0/8)
        if (first == 0) {
            return NO;
        }

        return YES;
    }

    // IPv6
    if ([ipAddress containsString:@":"]) {
        if (![self isValidIPv6:ipAddress]) {
            return NO;
        }

        // Check if it's private/local
        if ([self isPrivateIPv6Address:ipAddress]) {
            return NO;
        }

        NSString *lowerIP = [ipAddress lowercaseString];

        // Multicast (ff00::/8)
        if ([lowerIP hasPrefix:@"ff"]) {
            return NO;
        }

        return YES;
    }

    return NO;
}

#pragma mark - Special Address Ranges

+ (BOOL)isLoopbackAddress:(NSString *)ipAddress {
    if (!ipAddress || ipAddress.length == 0) {
        return NO;
    }

    if ([ipAddress containsString:@"."]) {
        if (![self isValidIPv4:ipAddress]) {
            return NO;
        }
        NSArray<NSString *> *octets = [ipAddress componentsSeparatedByString:@"."];
        return [octets[0] integerValue] == 127;
    }

    if ([ipAddress containsString:@":"]) {
        NSString *lowerIP = [ipAddress lowercaseString];
        return [lowerIP isEqualToString:@"::1"] || [lowerIP hasPrefix:@"::1/"];
    }

    return NO;
}

+ (BOOL)isMulticastAddress:(NSString *)ipAddress {
    if (!ipAddress || ipAddress.length == 0) {
        return NO;
    }

    if ([ipAddress containsString:@"."]) {
        if (![self isValidIPv4:ipAddress]) {
            return NO;
        }
        NSArray<NSString *> *octets = [ipAddress componentsSeparatedByString:@"."];
        NSInteger first = [octets[0] integerValue];
        return first >= 224 && first <= 239;
    }

    if ([ipAddress containsString:@":"]) {
        NSString *lowerIP = [ipAddress lowercaseString];
        return [lowerIP hasPrefix:@"ff"];
    }

    return NO;
}

+ (BOOL)isLinkLocalAddress:(NSString *)ipAddress {
    if (!ipAddress || ipAddress.length == 0) {
        return NO;
    }

    if ([ipAddress containsString:@"."]) {
        if (![self isValidIPv4:ipAddress]) {
            return NO;
        }
        NSArray<NSString *> *octets = [ipAddress componentsSeparatedByString:@"."];
        NSInteger first = [octets[0] integerValue];
        NSInteger second = [octets[1] integerValue];
        return first == 169 && second == 254;
    }

    if ([ipAddress containsString:@":"]) {
        NSString *lowerIP = [ipAddress lowercaseString];
        return [lowerIP hasPrefix:@"fe80:"];
    }

    return NO;
}

@end

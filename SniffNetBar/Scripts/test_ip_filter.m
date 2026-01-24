//
//  test_ip_filter.m
//  SniffNetBar
//
//  Test IP address filtering for threat intelligence
//

#import <Foundation/Foundation.h>

BOOL isPublicIPAddress(NSString *ipAddress) {
    // Skip private, local, and loopback IP addresses
    // Only send public IPs to threat intelligence providers

    if (!ipAddress || ipAddress.length == 0) {
        return NO;
    }

    // Check for IPv4 private ranges
    if ([ipAddress containsString:@"."]) {
        // Split into octets
        NSArray *octets = [ipAddress componentsSeparatedByString:@"."];
        if (octets.count != 4) {
            return NO;
        }

        NSInteger first = [octets[0] integerValue];
        NSInteger second = [octets[1] integerValue];

        // 127.0.0.0/8 - Loopback
        if (first == 127) return NO;

        // 10.0.0.0/8 - Private
        if (first == 10) return NO;

        // 172.16.0.0/12 - Private
        if (first == 172 && second >= 16 && second <= 31) return NO;

        // 192.168.0.0/16 - Private
        if (first == 192 && second == 168) return NO;

        // 169.254.0.0/16 - Link-local
        if (first == 169 && second == 254) return NO;

        // 224.0.0.0/4 - Multicast
        if (first >= 224 && first <= 239) return NO;

        // 240.0.0.0/4 - Reserved
        if (first >= 240) return NO;

        // 0.0.0.0/8 - Current network
        if (first == 0) return NO;

        return YES; // Public IPv4
    }

    // Check for IPv6 private/local ranges
    if ([ipAddress containsString:@":"]) {
        NSString *lowerIP = [ipAddress lowercaseString];

        // ::1 - Loopback
        if ([lowerIP isEqualToString:@"::1"] || [lowerIP hasPrefix:@"::1/"]) return NO;

        // fe80::/10 - Link-local
        if ([lowerIP hasPrefix:@"fe80:"]) return NO;

        // fc00::/7 - Unique local (private)
        if ([lowerIP hasPrefix:@"fc"] || [lowerIP hasPrefix:@"fd"]) return NO;

        // ff00::/8 - Multicast
        if ([lowerIP hasPrefix:@"ff"]) return NO;

        // :: - Unspecified
        if ([lowerIP isEqualToString:@"::"]) return NO;

        return YES; // Public IPv6
    }

    return NO; // Unknown format
}

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        printf("=== Testing IP Address Filtering ===\n\n");

        NSArray *testCases = @[
            // Private IPv4 addresses (should be filtered)
            @{@"ip": @"192.168.1.1", @"expected": @NO, @"description": @"Private (192.168.x.x)"},
            @{@"ip": @"10.0.0.1", @"expected": @NO, @"description": @"Private (10.x.x.x)"},
            @{@"ip": @"172.16.0.1", @"expected": @NO, @"description": @"Private (172.16-31.x.x)"},
            @{@"ip": @"172.31.255.255", @"expected": @NO, @"description": @"Private (172.16-31.x.x)"},
            @{@"ip": @"127.0.0.1", @"expected": @NO, @"description": @"Loopback"},
            @{@"ip": @"169.254.1.1", @"expected": @NO, @"description": @"Link-local"},
            @{@"ip": @"224.0.0.1", @"expected": @NO, @"description": @"Multicast"},
            @{@"ip": @"0.0.0.0", @"expected": @NO, @"description": @"Current network"},

            // Public IPv4 addresses (should be sent to threat intel)
            @{@"ip": @"8.8.8.8", @"expected": @YES, @"description": @"Public (Google DNS)"},
            @{@"ip": @"1.1.1.1", @"expected": @YES, @"description": @"Public (Cloudflare DNS)"},
            @{@"ip": @"93.184.216.34", @"expected": @YES, @"description": @"Public (example.com)"},
            @{@"ip": @"172.15.0.1", @"expected": @YES, @"description": @"Public (172.15 is public)"},
            @{@"ip": @"172.32.0.1", @"expected": @YES, @"description": @"Public (172.32 is public)"},

            // IPv6 addresses
            @{@"ip": @"::1", @"expected": @NO, @"description": @"IPv6 Loopback"},
            @{@"ip": @"fe80::1", @"expected": @NO, @"description": @"IPv6 Link-local"},
            @{@"ip": @"fc00::1", @"expected": @NO, @"description": @"IPv6 Unique local"},
            @{@"ip": @"fd00::1", @"expected": @NO, @"description": @"IPv6 Unique local"},
            @{@"ip": @"2001:4860:4860::8888", @"expected": @YES, @"description": @"IPv6 Public (Google DNS)"},
        ];

        int passed = 0;
        int failed = 0;

        for (NSDictionary *test in testCases) {
            NSString *ip = test[@"ip"];
            BOOL expected = [test[@"expected"] boolValue];
            NSString *desc = test[@"description"];

            BOOL result = isPublicIPAddress(ip);

            if (result == expected) {
                printf("✓ PASS: %-30s %s -> %s\n",
                       [ip UTF8String],
                       [desc UTF8String],
                       result ? "PUBLIC" : "PRIVATE/LOCAL");
                passed++;
            } else {
                printf("✗ FAIL: %-30s %s -> Expected %s, got %s\n",
                       [ip UTF8String],
                       [desc UTF8String],
                       expected ? "PUBLIC" : "PRIVATE/LOCAL",
                       result ? "PUBLIC" : "PRIVATE/LOCAL");
                failed++;
            }
        }

        printf("\n=== Results ===\n");
        printf("Passed: %d/%d\n", passed, passed + failed);
        printf("Failed: %d/%d\n", failed, passed + failed);

        return failed > 0 ? 1 : 0;
    }
}

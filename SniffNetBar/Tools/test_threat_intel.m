//
//  test_threat_intel.m
//  SniffNetBar
//
//  Test utility for threat intelligence functionality
//

#import <Foundation/Foundation.h>
#import "../ThreatIntel/ThreatIntelFacade.h"
#import "../ThreatIntel/ThreatIntelModels.h"
#import "../Tests/ThreatIntel/MockThreatIntelProvider.h"

void testMockThreatIntel() {
    NSLog(@"=== Testing Threat Intelligence with Mock Provider ===\n");

    // Create facade
    ThreatIntelFacade *facade = [[ThreatIntelFacade alloc] init];
    facade.enabled = YES;

    // Create mock provider
    MockThreatIntelProvider *mockProvider = [[MockThreatIntelProvider alloc] initWithName:@"MockProvider"];

    // Configure known malicious IPs for testing
    NSArray *maliciousIPs = @[
        @"1.2.3.4",      // Simulated malicious
        @"5.6.7.8",      // Simulated suspicious
        @"198.51.100.1"  // Test IP (RFC 5737)
    ];

    // Set mock scores (0-100, where >50 is malicious)
    [mockProvider setMockScore:95 forIndicatorValue:maliciousIPs[0]]; // Malicious
    [mockProvider setMockScore:60 forIndicatorValue:maliciousIPs[1]]; // Suspicious
    [mockProvider setMockScore:10 forIndicatorValue:maliciousIPs[2]]; // Clean

    // Add provider to facade
    [facade addProvider:mockProvider];

    NSLog(@"Configured mock provider with %lu test IPs\n", (unsigned long)maliciousIPs.count);

    // Test each IP
    dispatch_group_t group = dispatch_group_create();

    for (NSString *ip in maliciousIPs) {
        dispatch_group_enter(group);

        NSLog(@"Testing IP: %@", ip);
        [facade enrichIP:ip completion:^(TIEnrichmentResponse *response, NSError *error) {
            if (error) {
                NSLog(@"  ❌ Error for %@: %@", ip, error.localizedDescription);
            } else if (response) {
                for (TIResult *result in response.providerResults) {
                    NSString *verdictStr = result.verdict.hit ? @"THREAT" : @"Clean";
                    NSInteger confidence = result.verdict.confidence;

                    NSLog(@"  %@ %@ (confidence: %ld%%)",
                          result.verdict.hit ? @"⚠️" : @"✓",
                          verdictStr,
                          (long)confidence);

                    if (result.verdict.categories.count > 0) {
                        NSLog(@"    Categories: %@", [result.verdict.categories componentsJoinedByString:@", "]);
                    }
                }
            }
            NSLog(@"");
            dispatch_group_leave(group);
        }];
    }

    // Wait with timeout for all enrichments to complete
    long result = dispatch_group_wait(group, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC));
    if (result != 0) {
        NSLog(@"⚠️  Timeout waiting for enrichment responses");
    }

    // Show cache stats
    NSDictionary *stats = [facade cacheStats];
    NSLog(@"Cache Stats: %@\n", stats);

    NSLog(@"=== Test Complete ===");
}

int main(int argc __unused, const char * argv[] __unused) {
    @autoreleasepool {
        testMockThreatIntel();

        // Allow time for async operations to complete
        [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.5]];
    }
    return 0;
}

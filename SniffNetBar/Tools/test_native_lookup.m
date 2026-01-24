//
//  test_native_lookup.m
//  Test the native process lookup implementation
//

#import <Foundation/Foundation.h>
#import "ProcessLookup.h"
#import "Logger.h"

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        if (argc < 5) {
            printf("Usage: %s <source_ip> <source_port> <dest_ip> <dest_port>\n", argv[0]);
            printf("Example: %s 192.168.0.203 54321 93.184.216.34 443\n", argv[0]);
            return 1;
        }

        NSString *sourceIP = [NSString stringWithUTF8String:argv[1]];
        NSInteger sourcePort = atoi(argv[2]);
        NSString *destIP = [NSString stringWithUTF8String:argv[3]];
        NSInteger destPort = atoi(argv[4]);

        printf("\n=== Testing Native Process Lookup ===\n");
        printf("Looking for: %s:%ld -> %s:%ld\n\n",
               sourceIP.UTF8String, (long)sourcePort,
               destIP.UTF8String, (long)destPort);

        // Test native lookup
        printf("--- Native API Lookup ---\n");
        ProcessInfo *nativeResult = [ProcessLookup lookupUsingNativeAPIForSource:sourceIP
                                                                       sourcePort:sourcePort
                                                                      destination:destIP
                                                                  destinationPort:destPort];
        if (nativeResult) {
            printf("✓ Found: %s (PID %d)\n", nativeResult.processName.UTF8String, nativeResult.pid);
            if (nativeResult.executablePath) {
                printf("  Path: %s\n", nativeResult.executablePath.UTF8String);
            }
        } else {
            printf("✗ Not found\n");
        }

        // Test lsof lookup for comparison
        printf("\n--- lsof Lookup (for comparison) ---\n");
        ProcessInfo *lsofResult = [ProcessLookup lookupUsingLsofForSource:sourceIP
                                                               sourcePort:sourcePort
                                                              destination:destIP
                                                          destinationPort:destPort];
        if (lsofResult) {
            printf("✓ Found: %s (PID %d)\n", lsofResult.processName.UTF8String, lsofResult.pid);
        } else {
            printf("✗ Not found\n");
        }

        printf("\n");
    }
    return 0;
}

//
//  test_process_lookup.m
//  SniffNetBar
//
//  Test utility for process lookup functionality
//

#import <Foundation/Foundation.h>
#import "../Utils/ProcessLookup.h"

int main(int argc __unused, const char * argv[] __unused) {
    @autoreleasepool {
        NSLog(@"=== Testing Process Lookup ===\n");

        // Try to find the current process (this test tool itself)
        // Get local address
        NSString *localAddress = @"127.0.0.1";

        NSLog(@"Looking up process for connection...");
        NSLog(@"Note: Process lookup requires active network connections.");
        NSLog(@"For real testing, run SniffNetBar and generate some network traffic.\n");

        // Test with a known connection (if any)
        // This is just a demonstration - in real use, the connection info comes from packet capture

        ProcessInfo *info = [ProcessLookup lookupProcessForConnectionWithSource:localAddress
                                                                      sourcePort:12345
                                                                     destination:@"8.8.8.8"
                                                                 destinationPort:80];

        if (info) {
            NSLog(@"Found process:");
            NSLog(@"  PID: %d", info.pid);
            NSLog(@"  Name: %@", info.processName);
            if (info.executablePath) {
                NSLog(@"  Path: %@", info.executablePath);
            }
        } else {
            NSLog(@"No process found for the test connection (expected - connection doesn't exist)");
        }

        NSLog(@"\n=== Test Complete ===");
        NSLog(@"To see real process information:");
        NSLog(@"1. Run SniffNetBar: sudo ./build/SniffNetBar.app/Contents/MacOS/SniffNetBar");
        NSLog(@"2. Generate network traffic (e.g., open a web browser)");
        NSLog(@"3. Check the TOP CONNECTIONS section in the menu");
    }
    return 0;
}

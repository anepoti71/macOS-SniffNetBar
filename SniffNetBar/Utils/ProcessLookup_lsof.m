//
//  ProcessLookup_lsof.m
//  SniffNetBar
//
//  Alternative process lookup using lsof (more reliable but slightly slower)
//

#import "ProcessLookup.h"
#import "Logger.h"

// Alternative implementation using lsof
@implementation ProcessLookup (Lsof)

+ (nullable ProcessInfo *)lookupUsingLsofForSource:(NSString *)sourceAddress
                                        sourcePort:(NSInteger)sourcePort
                                       destination:(NSString *)destinationAddress
                                   destinationPort:(NSInteger)destinationPort {

    SNBLogInfo("ProcessLookup(lsof): Looking for connection %@:%ld -> %@:%ld",
          sourceAddress, (long)sourcePort, destinationAddress, (long)destinationPort);

    // Security: Validate port is within valid TCP range to prevent any unexpected behavior
    if (sourcePort < 0 || sourcePort > 65535) {
        SNBLogWarn("ProcessLookup(lsof): Invalid source port %ld", (long)sourcePort);
        return nil;
    }

    // Use NSTask instead of popen for better security (no shell interpretation)
    NSTask *task = [[NSTask alloc] init];
    task.executableURL = [NSURL fileURLWithPath:@"/usr/sbin/lsof"];
    task.arguments = @[@"-i", [NSString stringWithFormat:@"TCP:%ld", (long)sourcePort], @"-n", @"-P"];
    task.standardOutput = [NSPipe pipe];
    task.standardError = [NSFileHandle fileHandleWithNullDevice];

    NSError *launchError = nil;
    if (![task launchAndReturnError:&launchError]) {
        SNBLogInfo("ProcessLookup(lsof): Failed to run lsof: %@", launchError.localizedDescription);
        return nil;
    }

    NSFileHandle *outputHandle = [task.standardOutput fileHandleForReading];
    NSData *outputData = [outputHandle readDataToEndOfFile];
    [task waitUntilExit];

    if (task.terminationStatus != 0 || outputData.length == 0) {
        SNBLogInfo("ProcessLookup(lsof): lsof returned no data or failed");
        return nil;
    }

    NSString *output = [[NSString alloc] initWithData:outputData encoding:NSUTF8StringEncoding];
    if (!output) {
        SNBLogInfo("ProcessLookup(lsof): Failed to decode lsof output");
        return nil;
    }

    NSArray<NSString *> *lines = [output componentsSeparatedByString:@"\n"];
    if (lines.count < 2) {
        // No data lines (only header or empty)
        return nil;
    }

    ProcessInfo *result = nil;

    // Parse output lines (skip header at index 0)
    for (NSUInteger i = 1; i < lines.count; i++) {
        NSString *line = lines[i];
        if (line.length == 0) continue;

        // Format: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
        // Example: curl 12345 user 3u IPv4 0x123456 0t0 TCP 192.168.1.10:54321->93.184.216.34:80 (ESTABLISHED)
        char command[256] = {0};
        pid_t pid = 0;
        char name[512] = {0};

        // Parse the line
        if (sscanf(line.UTF8String, "%255s %d %*s %*s %*s %*s %*s %*s %511[^\n]", command, &pid, name) >= 2) {
            // Check if this connection matches our criteria
            NSString *nameStr = [NSString stringWithUTF8String:name];

            // Look for the connection pattern: localIP:localPort->remoteIP:remotePort
            NSString *expectedPattern = [NSString stringWithFormat:@"%@:%ld->%@:%ld",
                                        sourceAddress, (long)sourcePort,
                                        destinationAddress, (long)destinationPort];

            // Also check for IPv6 format or other variations
            if ([nameStr rangeOfString:expectedPattern].location != NSNotFound ||
                [nameStr rangeOfString:[NSString stringWithFormat:@":%ld->", (long)sourcePort]].location != NSNotFound) {

                result = [[ProcessInfo alloc] init];
                result.pid = pid;
                result.processName = [NSString stringWithUTF8String:command];

                SNBLogInfo("ProcessLookup(lsof): ✓ Found %@ (PID %d)", result.processName, result.pid);
                break;
            }
        }
    }

    if (!result) {
        SNBLogInfo("ProcessLookup(lsof): ✗ No matching process found");
    }

    return result;
}

@end

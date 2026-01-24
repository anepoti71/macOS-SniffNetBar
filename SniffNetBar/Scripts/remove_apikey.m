//
//  remove_apikey.m
//  SniffNetBar
//
//  Command-line tool to remove API keys from keychain
//

#import <Foundation/Foundation.h>
#import "KeychainManager.h"
#import "ConfigurationManager.h"

extern NSString * const kVirusTotalAPIKeyIdentifier;
extern NSString * const kAbuseIPDBAPIKeyIdentifier;
extern NSString * const kGreyNoiseAPIKeyIdentifier;
extern NSString * const kShodanAPIKeyIdentifier;
extern NSString * const kIpInfoAPITokenIdentifier;

static BOOL deleteWithSecurityCLI(NSString *identifier) {
    NSTask *task = [[NSTask alloc] init];
    task.launchPath = @"/usr/bin/security";
    task.arguments = @[@"delete-generic-password",
                       @"-s", @"com.sniffnetbar.api-keys",
                       @"-a", identifier];

    NSPipe *pipe = [NSPipe pipe];
    task.standardOutput = pipe;
    task.standardError = pipe;

    @try {
        [task launch];
        [task waitUntilExit];
    } @catch (NSException *exception) {
        return NO;
    }

    return (task.terminationStatus == 0);
}

void printUsage(const char *progName) {
    printf("Usage: %s <provider>\n", progName);
    printf("\nProviders:\n");
    printf("  virustotal    Remove VirusTotal API key\n");
    printf("  abuseipdb     Remove AbuseIPDB API key\n");
    printf("  greynoise     Remove GreyNoise API key\n");
    printf("  shodan        Remove Shodan API key\n");
    printf("  ipinfo        Remove ipinfo.io API token\n");
    printf("  all           Remove all API keys\n");
    printf("\nExamples:\n");
    printf("  %s virustotal\n", progName);
    printf("  %s abuseipdb\n", progName);
    printf("  %s greynoise\n", progName);
    printf("  %s shodan\n", progName);
    printf("  %s all\n", progName);
}

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        [KeychainManager requestKeychainAccessWithError:nil];
        if (argc != 2) {
            printUsage(argv[0]);
            return 1;
        }

        NSString *provider = [NSString stringWithUTF8String:argv[1]];
        NSArray<NSString *> *identifiers = nil;

        // Determine which identifiers to remove
        if ([provider isEqualToString:@"virustotal"]) {
            identifiers = @[kVirusTotalAPIKeyIdentifier];
        } else if ([provider isEqualToString:@"abuseipdb"]) {
            identifiers = @[kAbuseIPDBAPIKeyIdentifier];
        } else if ([provider isEqualToString:@"greynoise"]) {
            identifiers = @[kGreyNoiseAPIKeyIdentifier];
        } else if ([provider isEqualToString:@"shodan"]) {
            identifiers = @[kShodanAPIKeyIdentifier];
        } else if ([provider isEqualToString:@"ipinfo"]) {
            identifiers = @[kIpInfoAPITokenIdentifier];
        } else if ([provider isEqualToString:@"all"]) {
            identifiers = @[kVirusTotalAPIKeyIdentifier, kAbuseIPDBAPIKeyIdentifier, kGreyNoiseAPIKeyIdentifier, kShodanAPIKeyIdentifier, kIpInfoAPITokenIdentifier];
        } else {
            printf("Error: Unknown provider '%s'\n", [provider UTF8String]);
            printf("Valid providers: virustotal, abuseipdb, greynoise, shodan, ipinfo, all\n");
            return 1;
        }

        // Remove from keychain
        BOOL allSuccess = YES;
        for (NSString *identifier in identifiers) {
            NSError *error = nil;
            BOOL success = [KeychainManager deleteAPIKeyForIdentifier:identifier
                                                                 error:&error];

            if (success) {
                printf("✓ API key for %s removed from keychain\n", [identifier UTF8String]);
            } else {
                NSString *description = error.localizedDescription ?: @"Unknown error";
                BOOL fallbackSuccess = NO;
                if ([description containsString:@"-25244"]) {
                    fallbackSuccess = deleteWithSecurityCLI(identifier);
                }

                if (fallbackSuccess) {
                    printf("✓ API key for %s removed via security tool\n", [identifier UTF8String]);
                } else {
                    printf("✗ Failed to remove API key for %s: %s\n",
                           [identifier UTF8String],
                           [description UTF8String]);
                    allSuccess = NO;
                }
            }
        }

        return allSuccess ? 0 : 1;
    }
}

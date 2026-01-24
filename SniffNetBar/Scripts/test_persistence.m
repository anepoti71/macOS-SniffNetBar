//
//  test_persistence.m
//  SniffNetBar
//
//  Test program to verify keychain persistence
//

#import <Foundation/Foundation.h>
#import "KeychainManager.h"
#import "Logger.h"

extern NSString * const kVirusTotalAPIKeyIdentifier;
extern NSString * const kAbuseIPDBAPIKeyIdentifier;
extern NSString * const kGreyNoiseAPIKeyIdentifier;

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        SNB_LOG(SNBLogLevelInfo, SNB_LOG_CATEGORY_CORE, "=== Testing Keychain Persistence ===\n");

        // Store test keys
        NSString *persistVTKey = @"persistent_virustotal_key_abc123";
        NSString *persistAbuseKey = @"persistent_abuseipdb_key_xyz789";
        NSString *persistGreyNoiseKey = @"persistent_greynoise_key_456def";

        SNB_LOG(SNBLogLevelInfo, SNB_LOG_CATEGORY_CORE, "Saving keys to keychain...");
        NSError *error = nil;
        [KeychainManager saveAPIKey:persistVTKey
                      forIdentifier:kVirusTotalAPIKeyIdentifier
                              error:&error];
        [KeychainManager saveAPIKey:persistAbuseKey
                      forIdentifier:kAbuseIPDBAPIKeyIdentifier
                              error:&error];
        [KeychainManager saveAPIKey:persistGreyNoiseKey
                      forIdentifier:kGreyNoiseAPIKeyIdentifier
                              error:&error];

        SNB_LOG(SNBLogLevelInfo, SNB_LOG_CATEGORY_CORE, "✓ Keys saved");
        SNB_LOG(SNBLogLevelInfo, SNB_LOG_CATEGORY_CORE, "\nTo test persistence:");
        SNB_LOG(SNBLogLevelInfo, SNB_LOG_CATEGORY_CORE, "1. Run this program again to verify keys are still there");
        SNB_LOG(SNBLogLevelInfo, SNB_LOG_CATEGORY_CORE, "2. Use terminal commands to inspect keychain:");
        SNB_LOG(SNBLogLevelInfo, SNB_LOG_CATEGORY_CORE, "   security find-generic-password -s 'com.sniffnetbar.api-keys' -a 'VirusTotalAPIKey' -w");
        SNB_LOG(SNBLogLevelInfo, SNB_LOG_CATEGORY_CORE, "   security find-generic-password -s 'com.sniffnetbar.api-keys' -a 'AbuseIPDBAPIKey' -w");
        SNB_LOG(SNBLogLevelInfo, SNB_LOG_CATEGORY_CORE, "   security find-generic-password -s 'com.sniffnetbar.api-keys' -a 'GreyNoiseAPIKey' -w");
        SNB_LOG(SNBLogLevelInfo, SNB_LOG_CATEGORY_CORE, "\n3. To clean up:");
        SNB_LOG(SNBLogLevelInfo, SNB_LOG_CATEGORY_CORE, "   security delete-generic-password -s 'com.sniffnetbar.api-keys' -a 'VirusTotalAPIKey'");
        SNB_LOG(SNBLogLevelInfo, SNB_LOG_CATEGORY_CORE, "   security delete-generic-password -s 'com.sniffnetbar.api-keys' -a 'AbuseIPDBAPIKey'");
        SNB_LOG(SNBLogLevelInfo, SNB_LOG_CATEGORY_CORE, "   security delete-generic-password -s 'com.sniffnetbar.api-keys' -a 'GreyNoiseAPIKey'");

        return 0;
    }
}

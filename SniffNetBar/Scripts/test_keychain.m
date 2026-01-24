//
//  test_keychain.m
//  SniffNetBar
//
//  Test program for KeychainManager functionality
//

#import <Foundation/Foundation.h>
#import "KeychainManager.h"
#import "ConfigurationManager.h"
#import "Logger.h"

extern NSString * const kVirusTotalAPIKeyIdentifier;
extern NSString * const kAbuseIPDBAPIKeyIdentifier;
extern NSString * const kGreyNoiseAPIKeyIdentifier;

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        SNB_LOG(SNBLogLevelInfo, SNB_LOG_CATEGORY_CORE, "=== Testing KeychainManager ===\n");

        // Test 1: Save API keys
        SNB_LOG(SNBLogLevelInfo, SNB_LOG_CATEGORY_CORE, "Test 1: Saving API keys to keychain...");
        NSString *testVTKey = @"test_virustotal_key_12345";
        NSString *testAbuseKey = @"test_abuseipdb_key_67890";
        NSString *testGreyNoiseKey = @"test_greynoise_key_13579";

        NSError *error = nil;
        BOOL saveVTSuccess = [KeychainManager saveAPIKey:testVTKey
                                          forIdentifier:kVirusTotalAPIKeyIdentifier
                                                  error:&error];
        if (saveVTSuccess) {
            SNB_LOG(SNBLogLevelInfo, SNB_LOG_CATEGORY_CORE, "✓ VirusTotal API key saved successfully");
        } else {
            SNB_LOG(SNBLogLevelError, SNB_LOG_CATEGORY_CORE, "✗ Failed to save VirusTotal API key: %{public}@", error.localizedDescription);
            return 1;
        }

        error = nil;
        BOOL saveAbuseSuccess = [KeychainManager saveAPIKey:testAbuseKey
                                             forIdentifier:kAbuseIPDBAPIKeyIdentifier
                                                     error:&error];
        if (saveAbuseSuccess) {
            SNB_LOG(SNBLogLevelInfo, SNB_LOG_CATEGORY_CORE, "✓ AbuseIPDB API key saved successfully");
        } else {
            SNB_LOG(SNBLogLevelError, SNB_LOG_CATEGORY_CORE, "✗ Failed to save AbuseIPDB API key: %{public}@", error.localizedDescription);
            return 1;
        }

        error = nil;
        BOOL saveGreyNoiseSuccess = [KeychainManager saveAPIKey:testGreyNoiseKey
                                                  forIdentifier:kGreyNoiseAPIKeyIdentifier
                                                          error:&error];
        if (saveGreyNoiseSuccess) {
            SNB_LOG(SNBLogLevelInfo, SNB_LOG_CATEGORY_CORE, "✓ GreyNoise API key saved successfully");
        } else {
            SNB_LOG(SNBLogLevelError, SNB_LOG_CATEGORY_CORE, "✗ Failed to save GreyNoise API key: %{public}@", error.localizedDescription);
            return 1;
        }

        // Test 2: Retrieve API keys
        SNB_LOG(SNBLogLevelInfo, SNB_LOG_CATEGORY_CORE, "\nTest 2: Retrieving API keys from keychain...");
        error = nil;
        NSString *retrievedVTKey = [KeychainManager getAPIKeyForIdentifier:kVirusTotalAPIKeyIdentifier
                                                                     error:&error];
        if (retrievedVTKey && [retrievedVTKey isEqualToString:testVTKey]) {
            SNB_LOG(SNBLogLevelInfo, SNB_LOG_CATEGORY_CORE, "✓ VirusTotal API key retrieved successfully: %{public}@", retrievedVTKey);
        } else {
            SNB_LOG(SNBLogLevelError, SNB_LOG_CATEGORY_CORE, "✗ Failed to retrieve VirusTotal API key or mismatch. Got: %{public}@, Expected: %{public}@", retrievedVTKey, testVTKey);
            return 1;
        }

        error = nil;
        NSString *retrievedAbuseKey = [KeychainManager getAPIKeyForIdentifier:kAbuseIPDBAPIKeyIdentifier
                                                                        error:&error];
        if (retrievedAbuseKey && [retrievedAbuseKey isEqualToString:testAbuseKey]) {
            SNB_LOG(SNBLogLevelInfo, SNB_LOG_CATEGORY_CORE, "✓ AbuseIPDB API key retrieved successfully: %{public}@", retrievedAbuseKey);
        } else {
            SNB_LOG(SNBLogLevelError, SNB_LOG_CATEGORY_CORE, "✗ Failed to retrieve AbuseIPDB API key or mismatch. Got: %{public}@, Expected: %{public}@", retrievedAbuseKey, testAbuseKey);
            return 1;
        }

        error = nil;
        NSString *retrievedGreyNoiseKey = [KeychainManager getAPIKeyForIdentifier:kGreyNoiseAPIKeyIdentifier
                                                                            error:&error];
        if (retrievedGreyNoiseKey && [retrievedGreyNoiseKey isEqualToString:testGreyNoiseKey]) {
            SNB_LOG(SNBLogLevelInfo, SNB_LOG_CATEGORY_CORE, "✓ GreyNoise API key retrieved successfully: %{public}@", retrievedGreyNoiseKey);
        } else {
            SNB_LOG(SNBLogLevelError, SNB_LOG_CATEGORY_CORE, "✗ Failed to retrieve GreyNoise API key or mismatch. Got: %{public}@, Expected: %{public}@", retrievedGreyNoiseKey, testGreyNoiseKey);
            return 1;
        }

        // Test 3: Check existence
        SNB_LOG(SNBLogLevelInfo, SNB_LOG_CATEGORY_CORE, "\nTest 3: Checking key existence...");
        BOOL vtExists = [KeychainManager hasAPIKeyForIdentifier:kVirusTotalAPIKeyIdentifier];
        BOOL abuseExists = [KeychainManager hasAPIKeyForIdentifier:kAbuseIPDBAPIKeyIdentifier];
        BOOL greyNoiseExists = [KeychainManager hasAPIKeyForIdentifier:kGreyNoiseAPIKeyIdentifier];

        if (vtExists) {
            SNB_LOG(SNBLogLevelInfo, SNB_LOG_CATEGORY_CORE, "✓ VirusTotal API key exists in keychain");
        } else {
            SNB_LOG(SNBLogLevelError, SNB_LOG_CATEGORY_CORE, "✗ VirusTotal API key not found in keychain");
            return 1;
        }

        if (abuseExists) {
            SNB_LOG(SNBLogLevelInfo, SNB_LOG_CATEGORY_CORE, "✓ AbuseIPDB API key exists in keychain");
        } else {
            SNB_LOG(SNBLogLevelError, SNB_LOG_CATEGORY_CORE, "✗ AbuseIPDB API key not found in keychain");
            return 1;
        }

        if (greyNoiseExists) {
            SNB_LOG(SNBLogLevelInfo, SNB_LOG_CATEGORY_CORE, "✓ GreyNoise API key exists in keychain");
        } else {
            SNB_LOG(SNBLogLevelError, SNB_LOG_CATEGORY_CORE, "✗ GreyNoise API key not found in keychain");
            return 1;
        }

        // Test 4: Update API key
        SNB_LOG(SNBLogLevelInfo, SNB_LOG_CATEGORY_CORE, "\nTest 4: Updating API key...");
        NSString *updatedVTKey = @"updated_virustotal_key_99999";
        error = nil;
        BOOL updateSuccess = [KeychainManager saveAPIKey:updatedVTKey
                                           forIdentifier:kVirusTotalAPIKeyIdentifier
                                                   error:&error];
        if (updateSuccess) {
            SNB_LOG(SNBLogLevelInfo, SNB_LOG_CATEGORY_CORE, "✓ VirusTotal API key updated successfully");

            error = nil;
            NSString *verifyUpdated = [KeychainManager getAPIKeyForIdentifier:kVirusTotalAPIKeyIdentifier
                                                                        error:&error];
            if (verifyUpdated && [verifyUpdated isEqualToString:updatedVTKey]) {
                SNB_LOG(SNBLogLevelInfo, SNB_LOG_CATEGORY_CORE, "✓ Updated key verified: %{public}@", verifyUpdated);
            } else {
                SNB_LOG(SNBLogLevelError, SNB_LOG_CATEGORY_CORE, "✗ Updated key mismatch. Got: %{public}@, Expected: %{public}@", verifyUpdated, updatedVTKey);
                return 1;
            }
        } else {
            SNB_LOG(SNBLogLevelError, SNB_LOG_CATEGORY_CORE, "✗ Failed to update VirusTotal API key: %{public}@", error.localizedDescription);
            return 1;
        }

        // Test 5: ConfigurationManager integration
        SNB_LOG(SNBLogLevelInfo, SNB_LOG_CATEGORY_CORE, "\nTest 5: Testing ConfigurationManager integration...");
        ConfigurationManager *config = [ConfigurationManager sharedManager];

        NSString *configVTKey = config.virusTotalAPIKey;
        NSString *configAbuseKey = config.abuseIPDBAPIKey;
        NSString *configGreyNoiseKey = config.greyNoiseAPIKey;

        if ([configVTKey isEqualToString:updatedVTKey]) {
            SNB_LOG(SNBLogLevelInfo, SNB_LOG_CATEGORY_CORE, "✓ ConfigurationManager returns correct VirusTotal key: %{public}@", configVTKey);
        } else {
            SNB_LOG(SNBLogLevelError, SNB_LOG_CATEGORY_CORE, "✗ ConfigurationManager VirusTotal key mismatch. Got: %{public}@, Expected: %{public}@", configVTKey, updatedVTKey);
            return 1;
        }

        if ([configAbuseKey isEqualToString:testAbuseKey]) {
            SNB_LOG(SNBLogLevelInfo, SNB_LOG_CATEGORY_CORE, "✓ ConfigurationManager returns correct AbuseIPDB key: %{public}@", configAbuseKey);
        } else {
            SNB_LOG(SNBLogLevelError, SNB_LOG_CATEGORY_CORE, "✗ ConfigurationManager AbuseIPDB key mismatch. Got: %{public}@, Expected: %{public}@", configAbuseKey, testAbuseKey);
            return 1;
        }

        if ([configGreyNoiseKey isEqualToString:testGreyNoiseKey]) {
            SNB_LOG(SNBLogLevelInfo, SNB_LOG_CATEGORY_CORE, "✓ ConfigurationManager returns correct GreyNoise key: %{public}@", configGreyNoiseKey);
        } else {
            SNB_LOG(SNBLogLevelError, SNB_LOG_CATEGORY_CORE, "✗ ConfigurationManager GreyNoise key mismatch. Got: %{public}@, Expected: %{public}@", configGreyNoiseKey, testGreyNoiseKey);
            return 1;
        }

        // Test 6: Delete API keys
        SNB_LOG(SNBLogLevelInfo, SNB_LOG_CATEGORY_CORE, "\nTest 6: Deleting API keys from keychain...");
        error = nil;
        BOOL deleteVTSuccess = [KeychainManager deleteAPIKeyForIdentifier:kVirusTotalAPIKeyIdentifier
                                                                     error:&error];
        if (deleteVTSuccess) {
            SNB_LOG(SNBLogLevelInfo, SNB_LOG_CATEGORY_CORE, "✓ VirusTotal API key deleted successfully");

            BOOL stillExists = [KeychainManager hasAPIKeyForIdentifier:kVirusTotalAPIKeyIdentifier];
            if (!stillExists) {
                SNB_LOG(SNBLogLevelInfo, SNB_LOG_CATEGORY_CORE, "✓ Verified VirusTotal key no longer exists");
            } else {
                SNB_LOG(SNBLogLevelError, SNB_LOG_CATEGORY_CORE, "✗ VirusTotal key still exists after deletion");
                return 1;
            }
        } else {
            SNB_LOG(SNBLogLevelError, SNB_LOG_CATEGORY_CORE, "✗ Failed to delete VirusTotal API key: %{public}@", error.localizedDescription);
            return 1;
        }

        error = nil;
        BOOL deleteAbuseSuccess = [KeychainManager deleteAPIKeyForIdentifier:kAbuseIPDBAPIKeyIdentifier
                                                                        error:&error];
        if (deleteAbuseSuccess) {
            SNB_LOG(SNBLogLevelInfo, SNB_LOG_CATEGORY_CORE, "✓ AbuseIPDB API key deleted successfully");

            BOOL stillExists = [KeychainManager hasAPIKeyForIdentifier:kAbuseIPDBAPIKeyIdentifier];
            if (!stillExists) {
                SNB_LOG(SNBLogLevelInfo, SNB_LOG_CATEGORY_CORE, "✓ Verified AbuseIPDB key no longer exists");
            } else {
                SNB_LOG(SNBLogLevelError, SNB_LOG_CATEGORY_CORE, "✗ AbuseIPDB key still exists after deletion");
                return 1;
            }
        } else {
            SNB_LOG(SNBLogLevelError, SNB_LOG_CATEGORY_CORE, "✗ Failed to delete AbuseIPDB API key: %{public}@", error.localizedDescription);
            return 1;
        }

        error = nil;
        BOOL deleteGreyNoiseSuccess = [KeychainManager deleteAPIKeyForIdentifier:kGreyNoiseAPIKeyIdentifier
                                                                           error:&error];
        if (deleteGreyNoiseSuccess) {
            SNB_LOG(SNBLogLevelInfo, SNB_LOG_CATEGORY_CORE, "✓ GreyNoise API key deleted successfully");

            BOOL stillExists = [KeychainManager hasAPIKeyForIdentifier:kGreyNoiseAPIKeyIdentifier];
            if (!stillExists) {
                SNB_LOG(SNBLogLevelInfo, SNB_LOG_CATEGORY_CORE, "✓ Verified GreyNoise key no longer exists");
            } else {
                SNB_LOG(SNBLogLevelError, SNB_LOG_CATEGORY_CORE, "✗ GreyNoise key still exists after deletion");
                return 1;
            }
        } else {
            SNB_LOG(SNBLogLevelError, SNB_LOG_CATEGORY_CORE, "✗ Failed to delete GreyNoise API key: %{public}@", error.localizedDescription);
            return 1;
        }

        // Test 7: Verify ConfigurationManager returns empty after deletion
        SNB_LOG(SNBLogLevelInfo, SNB_LOG_CATEGORY_CORE, "\nTest 7: Verifying ConfigurationManager returns empty after deletion...");
        NSString *emptyVTKey = config.virusTotalAPIKey;
        NSString *emptyAbuseKey = config.abuseIPDBAPIKey;
        NSString *emptyGreyNoiseKey = config.greyNoiseAPIKey;

        if (emptyVTKey.length == 0) {
            SNB_LOG(SNBLogLevelInfo, SNB_LOG_CATEGORY_CORE, "✓ ConfigurationManager returns empty for VirusTotal key");
        } else {
            SNB_LOG(SNBLogLevelError, SNB_LOG_CATEGORY_CORE, "✗ ConfigurationManager still returns key after deletion: %{public}@", emptyVTKey);
            return 1;
        }

        if (emptyAbuseKey.length == 0) {
            SNB_LOG(SNBLogLevelInfo, SNB_LOG_CATEGORY_CORE, "✓ ConfigurationManager returns empty for AbuseIPDB key");
        } else {
            SNB_LOG(SNBLogLevelError, SNB_LOG_CATEGORY_CORE, "✗ ConfigurationManager still returns key after deletion: %{public}@", emptyAbuseKey);
            return 1;
        }

        if (emptyGreyNoiseKey.length == 0) {
            SNB_LOG(SNBLogLevelInfo, SNB_LOG_CATEGORY_CORE, "✓ ConfigurationManager returns empty for GreyNoise key");
        } else {
            SNB_LOG(SNBLogLevelError, SNB_LOG_CATEGORY_CORE, "✗ ConfigurationManager still returns key after deletion: %{public}@", emptyGreyNoiseKey);
            return 1;
        }

        SNB_LOG(SNBLogLevelInfo, SNB_LOG_CATEGORY_CORE, "\n=== All tests passed! ✓ ===");
        return 0;
    }
}

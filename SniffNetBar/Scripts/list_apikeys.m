//
//  list_apikeys.m
//  SniffNetBar
//
//  Command-line tool to list API keys in keychain
//

#import <Foundation/Foundation.h>
#import "KeychainManager.h"
#import "ConfigurationManager.h"

extern NSString * const kVirusTotalAPIKeyIdentifier;
extern NSString * const kAbuseIPDBAPIKeyIdentifier;
extern NSString * const kGreyNoiseAPIKeyIdentifier;
extern NSString * const kShodanAPIKeyIdentifier;
extern NSString * const kIpInfoAPITokenIdentifier;

NSString *maskAPIKey(NSString *apiKey) {
    if (!apiKey || apiKey.length == 0) {
        return @"(not set)";
    }
    if (apiKey.length <= 4) {
        return @"••••";
    }
    return [NSString stringWithFormat:@"••••%@",
            [apiKey substringFromIndex:apiKey.length - 4]];
}

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        [KeychainManager requestKeychainAccessWithError:nil];
        printf("=== SniffNetBar API Keys ===\n\n");

        NSArray<NSDictionary *> *providers = @[
            @{@"name": @"VirusTotal", @"identifier": kVirusTotalAPIKeyIdentifier},
            @{@"name": @"AbuseIPDB", @"identifier": kAbuseIPDBAPIKeyIdentifier},
            @{@"name": @"GreyNoise", @"identifier": kGreyNoiseAPIKeyIdentifier},
            @{@"name": @"Shodan", @"identifier": kShodanAPIKeyIdentifier},
            @{@"name": @"ipinfo", @"identifier": kIpInfoAPITokenIdentifier}
        ];

        for (NSDictionary *provider in providers) {
            NSString *name = provider[@"name"];
            NSString *identifier = provider[@"identifier"];

            NSError *error = nil;
            NSString *apiKey = [KeychainManager getAPIKeyForIdentifier:identifier
                                                                  error:&error];

            printf("%s:\n", [name UTF8String]);
            printf("  Identifier: %s\n", [identifier UTF8String]);

            if (apiKey.length > 0) {
                printf("  Status:     ✓ Configured\n");
                printf("  Key:        %s\n", [maskAPIKey(apiKey) UTF8String]);
            } else {
                printf("  Status:     ✗ Not configured\n");
                printf("  Key:        (not set)\n");
            }
            printf("\n");
        }

        printf("To set an API key:    ./build/set_apikey <provider> <key>\n");
        printf("To remove an API key: ./build/remove_apikey <provider>\n");

        return 0;
    }
}

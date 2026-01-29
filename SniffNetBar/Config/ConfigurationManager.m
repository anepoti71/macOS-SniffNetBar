//
//  ConfigurationManager.m
//  SniffNetBar
//
//  Centralized configuration management
//

#import "ConfigurationManager.h"
#import "KeychainManager.h"
#import "Logger.h"
#import "UserDefaultsKeys.h"

// Define keychain identifier constants
NSString * const kVirusTotalAPIKeyIdentifier = @"VirusTotalAPIKey";
NSString * const kAbuseIPDBAPIKeyIdentifier = @"AbuseIPDBAPIKey";
NSString * const kGreyNoiseAPIKeyIdentifier = @"GreyNoiseAPIKey";
NSString * const kShodanAPIKeyIdentifier = @"ShodanAPIKey";
NSString * const kIpInfoAPITokenIdentifier = @"IpInfoAPIToken";

@interface ConfigurationManager ()
@property (nonatomic, strong) NSDictionary *configuration;
@end

@implementation ConfigurationManager

static BOOL sConfigurationManagerInitializing = NO;

BOOL SNBConfigurationManagerIsInitializing(void) {
    return sConfigurationManagerInitializing;
}

+ (instancetype)sharedManager {
    static ConfigurationManager *sharedInstance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sharedInstance = [[self alloc] init];
    });
    return sharedInstance;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        [KeychainManager requestKeychainAccessWithError:nil];
        sConfigurationManagerInitializing = YES;
        [self loadConfiguration];
        sConfigurationManagerInitializing = NO;
    }
    return self;
}

- (void)loadConfiguration {
    NSString *path = [[NSBundle mainBundle] pathForResource:@"Configuration" ofType:@"plist"];
    if (!path) {
        SNBLogConfigError("Configuration.plist not found in bundle!");
        [self loadDefaultConfiguration];
        return;
    }

    NSDictionary *config = [NSDictionary dictionaryWithContentsOfFile:path];
    if (!config) {
        SNBLogConfigError("Failed to load Configuration.plist!");
        [self loadDefaultConfiguration];
        return;
    }

    self.configuration = config;
    SNBLogConfigInfo("Configuration loaded successfully from %{public}@", path);
    NSError *validationError = nil;
    if (![self validateConfiguration:&validationError]) {
        SNBLogConfigError("Configuration validation failed: %{public}@",
                          validationError.localizedDescription);
    }
}

- (void)loadDefaultConfiguration {
    // Fallback to hardcoded defaults if plist is missing
    self.configuration = @{
        @"DebugLogging": @YES,
        @"MenuUpdateInterval": @1.0,
        @"DeviceListRefreshInterval": @30.0,
        @"MaxTopHostsToShow": @5,
        @"MaxTopConnectionsToShow": @10,
        @"MaxTrustedIPsPerGroup": @10,
        @"MapMenuViewHeight": @320.0,
        @"MenuFixedWidth": @480.0,
        @"ReconnectDelay": @5.0,
        @"MaxReconnectAttempts": @3,
        @"PacketPollingInterval": @0.05,  // 50ms = 20 wakeups/sec (was 10ms = 100/sec)
        @"MaxLocationCacheSize": @500,
        @"LocationCacheExpirationTime": @7200.0,
        @"DefaultMapProvider": @"ipinfo.io",
        @"MaxConnectionLinesToShow": @10,
        @"ConnectionLineColor": @"#ff7a18",
        @"ConnectionLineWeight": @3,
        @"ConnectionLineOpacity": @0.9,
        @"GeoLocationSemaphoreLimit": @5,
        @"AnomalyWindowSeconds": @60.0,
        @"AnomalyRetrainInterval": @21600.0,
        @"ExplainabilityEnabled": @YES,
        @"ExplainabilityOllamaBaseURL": @"http://127.0.0.1:11434",
        @"ExplainabilityOllamaModel": @"llama3.1",
        @"ExplainabilityOllamaTimeout": @10.0,
        @"ExplainabilityMinScore": @0.90,
        @"PromotionOllamaBaseURL": @"http://127.0.0.1:11434",
        @"PromotionOllamaModel": @"qwen2.5:7b",
        @"PromotionOllamaTimeout": @30.0,
        @"ShodanEnabled": @NO,
        @"ShodanAPIURL": @"https://api.shodan.io",
        @"ShodanAPIKey": @"YOUR_API_KEY_HERE",
        @"ShodanTimeout": @10.0,
        @"ShodanMaxRequestsPerMin": @60,
        @"ShodanTTL": @86400.0
    };
    SNBLogConfigInfo("Using default configuration");
    NSError *validationError = nil;
    if (![self validateConfiguration:&validationError]) {
        SNBLogConfigError("Default configuration validation failed: %{public}@",
                          validationError.localizedDescription);
    }
}

- (void)reloadConfiguration {
    [self loadConfiguration];
}

- (BOOL)validateConfiguration:(NSError **)error {
    NSMutableArray<NSString *> *issues = [NSMutableArray array];

    if (self.menuUpdateInterval <= 0) {
        [issues addObject:@"MenuUpdateInterval must be greater than 0."];
    }
    if (self.deviceListRefreshInterval <= 0) {
        [issues addObject:@"DeviceListRefreshInterval must be greater than 0."];
    }
    if (self.menuFixedWidth <= 0 || self.mapMenuViewHeight <= 0) {
        [issues addObject:@"MenuFixedWidth and MapMenuViewHeight must be greater than 0."];
    }
    if (self.maxTopHostsToShow == 0 || self.maxTopConnectionsToShow == 0) {
        [issues addObject:@"MaxTopHostsToShow and MaxTopConnectionsToShow must be greater than 0."];
    }
    if (self.maxTrustedIPsPerGroup == 0) {
        [issues addObject:@"MaxTrustedIPsPerGroup must be greater than 0."];
    }
    if (self.maxReconnectAttempts == 0) {
        [issues addObject:@"MaxReconnectAttempts must be greater than 0."];
    }
    if (self.reconnectDelay < 0) {
        [issues addObject:@"ReconnectDelay must be 0 or greater."];
    }
    if (self.maxLocationCacheSize == 0 || self.locationCacheExpirationTime <= 0) {
        [issues addObject:@"Location cache size and expiration time must be greater than 0."];
    }
    if (self.threatIntelCacheSize == 0 || self.threatIntelCacheTTL <= 0) {
        [issues addObject:@"Threat intel cache size and TTL must be greater than 0."];
    }
    if (self.explainabilityEnabled) {
        if (self.explainabilityOllamaBaseURL.length == 0) {
            [issues addObject:@"ExplainabilityOllamaBaseURL must be set when explainability is enabled."];
        }
        if (self.explainabilityOllamaModel.length == 0) {
            [issues addObject:@"ExplainabilityOllamaModel must be set when explainability is enabled."];
        }
        if (self.explainabilityOllamaTimeout <= 0) {
            [issues addObject:@"ExplainabilityOllamaTimeout must be greater than 0."];
        }
        if (self.explainabilityMinScore < 0.0 || self.explainabilityMinScore > 1.0) {
            [issues addObject:@"ExplainabilityMinScore must be between 0.0 and 1.0."];
        }
    }
    if (self.defaultMapProvider.length == 0) {
        [issues addObject:@"DefaultMapProvider must be a non-empty string."];
    }

    if (self.virusTotalEnabled) {
        if (self.virusTotalAPIURL.length == 0) {
            [issues addObject:@"VirusTotalAPIURL must be set when VirusTotal is enabled."];
        }
        if (self.virusTotalAPIKey.length == 0) {
            [issues addObject:@"VirusTotalAPIKey must be set when VirusTotal is enabled."];
        }
        if (self.virusTotalMaxRequestsPerMin <= 0) {
            [issues addObject:@"VirusTotalMaxRequestsPerMin must be greater than 0."];
        }
        if (self.virusTotalTimeout <= 0) {
            [issues addObject:@"VirusTotalTimeout must be greater than 0."];
        }
    }

    if (self.abuseIPDBEnabled) {
        if (self.abuseIPDBAPIURL.length == 0) {
            [issues addObject:@"AbuseIPDBAPIURL must be set when AbuseIPDB is enabled."];
        }
        if (self.abuseIPDBAPIKey.length == 0) {
            [issues addObject:@"AbuseIPDBAPIKey must be set when AbuseIPDB is enabled."];
        }
        if (self.abuseIPDBMaxRequestsPerMin <= 0) {
            [issues addObject:@"AbuseIPDBMaxRequestsPerMin must be greater than 0."];
        }
        if (self.abuseIPDBTimeout <= 0) {
            [issues addObject:@"AbuseIPDBTimeout must be greater than 0."];
        }
    }

    if (self.greyNoiseEnabled) {
        if (self.greyNoiseAPIURL.length == 0) {
            [issues addObject:@"GreyNoiseAPIURL must be set when GreyNoise is enabled."];
        }
        if (self.greyNoiseAPIKey.length == 0) {
            [issues addObject:@"GreyNoiseAPIKey must be set when GreyNoise is enabled."];
        }
        if (self.greyNoiseMaxRequestsPerMin <= 0) {
            [issues addObject:@"GreyNoiseMaxRequestsPerMin must be greater than 0."];
        }
        if (self.greyNoiseTimeout <= 0) {
            [issues addObject:@"GreyNoiseTimeout must be greater than 0."];
        }
    }

    if (issues.count == 0) {
        return YES;
    }

    if (error) {
        NSString *description = [issues componentsJoinedByString:@" "];
        *error = [NSError errorWithDomain:@"ConfigurationManager"
                                     code:1001
                                 userInfo:@{NSLocalizedDescriptionKey: description}];
    }
    return NO;
}

#pragma mark - Logging Configuration

- (BOOL)debugLogging {
    return [self.configuration[@"DebugLogging"] boolValue];
}

#pragma mark - UI Update Configuration

- (NSTimeInterval)menuUpdateInterval {
    NSNumber *value = self.configuration[@"MenuUpdateInterval"];
    return value ? [value doubleValue] : 1.0;
}

- (NSTimeInterval)deviceListRefreshInterval {
    NSNumber *value = self.configuration[@"DeviceListRefreshInterval"];
    return value ? [value doubleValue] : 30.0;
}

- (NSUInteger)maxTopHostsToShow {
    NSNumber *value = self.configuration[@"MaxTopHostsToShow"];
    return value ? [value unsignedIntegerValue] : 5;
}

- (NSUInteger)maxTopConnectionsToShow {
    NSNumber *value = self.configuration[@"MaxTopConnectionsToShow"];
    return value ? [value unsignedIntegerValue] : 10;
}

- (NSUInteger)maxTrustedIPsPerGroup {
    NSNumber *value = self.configuration[@"MaxTrustedIPsPerGroup"];
    return value ? [value unsignedIntegerValue] : 10;
}

- (CGFloat)mapMenuViewHeight {
    NSNumber *value = self.configuration[@"MapMenuViewHeight"];
    return value ? [value doubleValue] : 320.0;
}

- (CGFloat)menuFixedWidth {
    NSNumber *value = self.configuration[@"MenuFixedWidth"];
    if (!value) {
        value = self.configuration[@"MenuMaxWidth"];
    }
    return value ? [value doubleValue] : 480.0;
}

#pragma mark - Reconnection Configuration

- (NSTimeInterval)reconnectDelay {
    NSNumber *value = self.configuration[@"ReconnectDelay"];
    return value ? [value doubleValue] : 5.0;
}

- (NSUInteger)maxReconnectAttempts {
    NSNumber *value = self.configuration[@"MaxReconnectAttempts"];
    return value ? [value unsignedIntegerValue] : 3;
}

#pragma mark - Packet Capture Configuration

- (NSTimeInterval)packetPollingInterval {
    NSNumber *value = self.configuration[@"PacketPollingInterval"];
    return value ? [value doubleValue] : 0.05;  // 50ms default
}

#pragma mark - Location Cache Configuration

- (NSUInteger)maxLocationCacheSize {
    NSNumber *value = self.configuration[@"MaxLocationCacheSize"];
    return value ? [value unsignedIntegerValue] : 500;
}

- (NSTimeInterval)locationCacheExpirationTime {
    NSNumber *value = self.configuration[@"LocationCacheExpirationTime"];
    return value ? [value doubleValue] : 7200.0;
}

#pragma mark - Map Configuration

- (NSString *)defaultMapProvider {
    NSString *value = self.configuration[@"DefaultMapProvider"];
    return value.length > 0 ? value : @"ipinfo.io";
}

- (NSUInteger)maxConnectionLinesToShow {
    NSNumber *value = self.configuration[@"MaxConnectionLinesToShow"];
    return value ? [value unsignedIntegerValue] : 10;
}

- (NSString *)connectionLineColor {
    NSString *value = self.configuration[@"ConnectionLineColor"];
    return value.length > 0 ? value : @"#ff7a18";
}

- (NSInteger)connectionLineWeight {
    NSNumber *value = self.configuration[@"ConnectionLineWeight"];
    return value ? [value integerValue] : 3;
}

- (CGFloat)connectionLineOpacity {
    NSNumber *value = self.configuration[@"ConnectionLineOpacity"];
    return value ? [value doubleValue] : 0.9;
}

- (NSUInteger)geoLocationSemaphoreLimit {
    NSNumber *value = self.configuration[@"GeoLocationSemaphoreLimit"];
    return value ? [value unsignedIntegerValue] : 5;
}

- (NSString *)ipInfoAPIToken {
    NSError *error = nil;
    NSString *keychainKey = [KeychainManager getAPIKeyForIdentifier:kIpInfoAPITokenIdentifier
                                                              error:&error];
    if (keychainKey.length > 0) {
        return keychainKey;
    }

    NSString *plistKey = self.configuration[@"IpInfoAPIToken"];
    if (plistKey.length > 0 && ![plistKey isEqualToString:@"YOUR_IPINFO_API_TOKEN_HERE"]) {
        [KeychainManager saveAPIKey:plistKey
                      forIdentifier:kIpInfoAPITokenIdentifier
                              error:nil];
        SNBLogConfigInfo("Migrated ipinfo token to keychain");
        return plistKey;
    }

    return @"";
}

#pragma mark - Threat Intelligence Configuration

- (NSUInteger)threatIntelCacheSize {
    NSNumber *value = self.configuration[@"ThreatIntelCacheSize"];
    return value ? [value unsignedIntegerValue] : 1000;
}

- (NSTimeInterval)threatIntelCacheTTL {
    NSNumber *value = self.configuration[@"ThreatIntelCacheTTL"];
    return value ? [value doubleValue] : 3600.0;
}

- (NSTimeInterval)threatIntelPersistenceTTLHours {
    NSNumber *value = self.configuration[@"ThreatIntelPersistenceTTLHours"];
    return value ? [value doubleValue] : 24.0;
}

#pragma mark - Anomaly Detection Configuration

- (NSTimeInterval)anomalyWindowSeconds {
    NSNumber *value = self.configuration[@"AnomalyWindowSeconds"];
    return value ? [value doubleValue] : 60.0;
}

- (NSTimeInterval)anomalyRetrainInterval {
    NSNumber *value = self.configuration[@"AnomalyRetrainInterval"];
    return value ? [value doubleValue] : 21600.0;
}

#pragma mark - About Configuration

- (NSString *)appVersion {
    NSString *value = self.configuration[@"AppVersion"];
    if (value.length > 0) {
        return value;
    }
    NSString *bundleVersion = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"];
    return bundleVersion.length > 0 ? bundleVersion : @"1.0.0";
}

#pragma mark - Explainability Configuration

- (BOOL)explainabilityEnabled {
    NSNumber *value = self.configuration[@"ExplainabilityEnabled"];
    return value ? [value boolValue] : YES;
}

- (NSString *)explainabilityOllamaBaseURL {
    NSString *value = self.configuration[@"ExplainabilityOllamaBaseURL"];
    return value.length > 0 ? value : @"http://127.0.0.1:11434";
}

- (NSString *)explainabilityOllamaModel {
    NSString *value = self.configuration[@"ExplainabilityOllamaModel"];
    return value.length > 0 ? value : @"llama3.1";
}

- (NSTimeInterval)explainabilityOllamaTimeout {
    NSNumber *value = self.configuration[@"ExplainabilityOllamaTimeout"];
    return value ? [value doubleValue] : 10.0;
}

- (double)explainabilityMinScore {
    NSNumber *value = self.configuration[@"ExplainabilityMinScore"];
    return value ? [value doubleValue] : 0.90;
}

#pragma mark - Promotion Agent Configuration

- (NSString *)promotionOllamaBaseURL {
    NSString *value = self.configuration[@"PromotionOllamaBaseURL"];
    return value.length > 0 ? value : @"http://127.0.0.1:11434";
}

- (NSString *)promotionOllamaModel {
    NSString *value = self.configuration[@"PromotionOllamaModel"];
    return value.length > 0 ? value : @"qwen2.5:7b";
}

- (NSTimeInterval)promotionOllamaTimeout {
    NSNumber *value = self.configuration[@"PromotionOllamaTimeout"];
    return value ? [value doubleValue] : 30.0;
}

#pragma mark - VirusTotal Provider Configuration

- (BOOL)virusTotalEnabled {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    if ([defaults objectForKey:SNBUserDefaultsKeyVirusTotalOptIn]) {
        return [defaults boolForKey:SNBUserDefaultsKeyVirusTotalOptIn];
    }
    NSNumber *value = self.configuration[@"VirusTotalEnabled"];
    return value ? [value boolValue] : NO;
}

- (NSString *)virusTotalAPIURL {
    NSString *value = self.configuration[@"VirusTotalAPIURL"];
    return value.length > 0 ? value : @"https://www.virustotal.com/api/v3";
}

- (NSString *)virusTotalAPIKey {
    // Try keychain first
    NSError *error = nil;
    NSString *keychainKey = [KeychainManager getAPIKeyForIdentifier:kVirusTotalAPIKeyIdentifier
                                                              error:&error];
    if (keychainKey.length > 0) {
        return keychainKey;
    }

    // Fall back to plist for backward compatibility (migration scenario)
    NSString *plistKey = self.configuration[@"VirusTotalAPIKey"];
    if (plistKey.length > 0 && ![plistKey isEqualToString:@"YOUR_API_KEY_HERE"]) {
        // Migrate to keychain
        [KeychainManager saveAPIKey:plistKey
                      forIdentifier:kVirusTotalAPIKeyIdentifier
                              error:nil];
        SNBLogConfigInfo("Migrated VirusTotal API key to keychain");
        return plistKey;
    }

    return @"";
}

- (NSTimeInterval)virusTotalTimeout {
    NSNumber *value = self.configuration[@"VirusTotalTimeout"];
    return value ? [value doubleValue] : 10.0;
}

- (NSInteger)virusTotalMaxRequestsPerMin {
    NSNumber *value = self.configuration[@"VirusTotalMaxRequestsPerMin"];
    return value ? [value integerValue] : 4;
}

- (NSTimeInterval)virusTotalTTL {
    NSNumber *value = self.configuration[@"VirusTotalTTL"];
    return value ? [value doubleValue] : 86400.0;
}

#pragma mark - AbuseIPDB Provider Configuration

- (BOOL)abuseIPDBEnabled {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    if ([defaults objectForKey:SNBUserDefaultsKeyAbuseIPDBOptIn]) {
        return [defaults boolForKey:SNBUserDefaultsKeyAbuseIPDBOptIn];
    }
    NSNumber *value = self.configuration[@"AbuseIPDBEnabled"];
    return value ? [value boolValue] : NO;
}

- (NSString *)abuseIPDBAPIURL {
    NSString *value = self.configuration[@"AbuseIPDBAPIURL"];
    return value.length > 0 ? value : @"https://api.abuseipdb.com/api/v2";
}

- (NSString *)abuseIPDBAPIKey {
    // Try keychain first
    NSError *error = nil;
    NSString *keychainKey = [KeychainManager getAPIKeyForIdentifier:kAbuseIPDBAPIKeyIdentifier
                                                              error:&error];
    if (keychainKey.length > 0) {
        return keychainKey;
    }

    // Fall back to plist for backward compatibility (migration scenario)
    NSString *plistKey = self.configuration[@"AbuseIPDBAPIKey"];
    if (plistKey.length > 0 && ![plistKey isEqualToString:@"YOUR_API_KEY_HERE"]) {
        // Migrate to keychain
        [KeychainManager saveAPIKey:plistKey
                      forIdentifier:kAbuseIPDBAPIKeyIdentifier
                              error:nil];
        SNBLogConfigInfo("Migrated AbuseIPDB API key to keychain");
        return plistKey;
    }

    return @"";
}

- (NSTimeInterval)abuseIPDBTimeout {
    NSNumber *value = self.configuration[@"AbuseIPDBTimeout"];
    return value ? [value doubleValue] : 10.0;
}

- (NSInteger)abuseIPDBMaxRequestsPerMin {
    NSNumber *value = self.configuration[@"AbuseIPDBMaxRequestsPerMin"];
    return value ? [value integerValue] : 60;
}

- (NSTimeInterval)abuseIPDBTTL {
    NSNumber *value = self.configuration[@"AbuseIPDBTTL"];
    return value ? [value doubleValue] : 86400.0;
}

- (NSInteger)abuseIPDBMaxAgeInDays {
    NSNumber *value = self.configuration[@"AbuseIPDBMaxAgeInDays"];
    return value ? [value integerValue] : 90;
}

#pragma mark - GreyNoise Provider Configuration

- (BOOL)greyNoiseEnabled {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    if ([defaults objectForKey:SNBUserDefaultsKeyGreyNoiseOptIn]) {
        return [defaults boolForKey:SNBUserDefaultsKeyGreyNoiseOptIn];
    }
    NSNumber *value = self.configuration[@"GreyNoiseEnabled"];
    return value ? [value boolValue] : NO;
}

- (NSString *)greyNoiseAPIURL {
    NSString *value = self.configuration[@"GreyNoiseAPIURL"];
    return value.length > 0 ? value : @"https://api.greynoise.io/v3";
}

- (NSString *)greyNoiseAPIKey {
    NSError *error = nil;
    NSString *keychainKey = [KeychainManager getAPIKeyForIdentifier:kGreyNoiseAPIKeyIdentifier
                                                              error:&error];
    if (keychainKey.length > 0) {
        return keychainKey;
    }

    NSString *plistKey = self.configuration[@"GreyNoiseAPIKey"];
    if (plistKey.length > 0 && ![plistKey isEqualToString:@"YOUR_API_KEY_HERE"]) {
        [KeychainManager saveAPIKey:plistKey
                      forIdentifier:kGreyNoiseAPIKeyIdentifier
                              error:nil];
        SNBLogConfigInfo("Migrated GreyNoise API key to keychain");
        return plistKey;
    }

    return @"";
}

- (NSTimeInterval)greyNoiseTimeout {
    NSNumber *value = self.configuration[@"GreyNoiseTimeout"];
    return value ? [value doubleValue] : 10.0;
}

- (NSInteger)greyNoiseMaxRequestsPerMin {
    NSNumber *value = self.configuration[@"GreyNoiseMaxRequestsPerMin"];
    return value ? [value integerValue] : 60;
}

- (NSTimeInterval)greyNoiseTTL {
    NSNumber *value = self.configuration[@"GreyNoiseTTL"];
    return value ? [value doubleValue] : 86400.0;
}

#pragma mark - Shodan Provider Configuration

- (BOOL)shodanEnabled {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    if ([defaults objectForKey:SNBUserDefaultsKeyShodanOptIn]) {
        return [defaults boolForKey:SNBUserDefaultsKeyShodanOptIn];
    }
    NSNumber *value = self.configuration[@"ShodanEnabled"];
    return value ? [value boolValue] : NO;
}

- (NSString *)shodanAPIURL {
    NSString *value = self.configuration[@"ShodanAPIURL"];
    return value.length > 0 ? value : @"https://api.shodan.io";
}

- (NSString *)shodanAPIKey {
    NSError *error = nil;
    NSString *keychainKey = [KeychainManager getAPIKeyForIdentifier:kShodanAPIKeyIdentifier
                                                              error:&error];
    if (keychainKey.length > 0) {
        NSString *trimmed = [keychainKey stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        if (trimmed.length > 0) {
            SNBLogConfigInfo("Loaded Shodan API key from keychain (length=%lu)",
                             (unsigned long)trimmed.length);
            return trimmed;
        }
    }

    NSString *plistKey = self.configuration[@"ShodanAPIKey"];
    if (plistKey.length > 0 && ![plistKey isEqualToString:@"YOUR_API_KEY_HERE"]) {
        NSString *trimmed = [plistKey stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        if (trimmed.length == 0) {
            return @"";
        }
        [KeychainManager saveAPIKey:trimmed
                      forIdentifier:kShodanAPIKeyIdentifier
                              error:nil];
        SNBLogConfigInfo("Migrated Shodan API key to keychain");
        return trimmed;
    }

    return @"";
}

- (NSTimeInterval)shodanTimeout {
    NSNumber *value = self.configuration[@"ShodanTimeout"];
    return value ? [value doubleValue] : 10.0;
}

- (NSInteger)shodanMaxRequestsPerMin {
    NSNumber *value = self.configuration[@"ShodanMaxRequestsPerMin"];
    return value ? [value integerValue] : 60;
}

- (NSTimeInterval)shodanTTL {
    NSNumber *value = self.configuration[@"ShodanTTL"];
    return value ? [value doubleValue] : 86400.0;
}

#pragma mark - API Key Management

- (void)setAPIKey:(nullable NSString *)apiKey forIdentifier:(NSString *)identifier {
    NSError *error = nil;
    if ([KeychainManager saveAPIKey:apiKey forIdentifier:identifier error:&error]) {
        SNBLogConfigInfo("API key saved to keychain: %{public}@", identifier);
    } else {
        SNBLogConfigError("Failed to save API key to keychain: %{public}@, error: %{public}@",
                          identifier, error.localizedDescription);
    }
}

@end

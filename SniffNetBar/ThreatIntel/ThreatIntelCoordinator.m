//
//  ThreatIntelCoordinator.m
//  SniffNetBar
//

#import "ThreatIntelCoordinator.h"
#import "ConfigurationManager.h"
#import "ThreatIntelFacade.h"
#import "ThreatIntelModels.h"
#import "UserDefaultsKeys.h"
#import "VirusTotalProvider.h"
#import "AbuseIPDBProvider.h"
#import "GreyNoiseProvider.h"
#import "ShodanProvider.h"
#import "IPAddressUtilities.h"
#import "TrustedIPStore.h"
#import "Logger.h"

@interface ThreatIntelCoordinator ()
@property (nonatomic, strong) ConfigurationManager *configuration;
@property (nonatomic, strong) NSMutableDictionary<NSString *, TIEnrichmentResponse *> *results;
@property (nonatomic, strong) NSMutableArray<NSString *> *resultOrder;
@property (nonatomic, strong) SNBTrustedIPStore *trustedStore;
@end

@implementation ThreatIntelCoordinator

static const NSUInteger kMaxThreatResults = 1000;

- (instancetype)initWithConfiguration:(ConfigurationManager *)configuration {
    self = [super init];
    if (self) {
        _configuration = configuration;
        _facade = [ThreatIntelFacade sharedInstance];
        _results = [NSMutableDictionary dictionary];
        _resultOrder = [NSMutableArray array];
        _trustedStore = [SNBTrustedIPStore sharedStore];
        [self loadEnabledState];
        [self configureProviders];
    }
    return self;
}

- (void)loadEnabledState {
    BOOL enabled = [[NSUserDefaults standardUserDefaults] boolForKey:SNBUserDefaultsKeyThreatIntelEnabled];
    self.facade.enabled = enabled;
    _enabled = enabled;
}

- (void)configureProviders {
    ConfigurationManager *config = self.configuration;

    BOOL virusTotalEnabled = config.virusTotalEnabled;
    NSString *virusTotalKey = virusTotalEnabled ? config.virusTotalAPIKey : @"";
    if (virusTotalEnabled && virusTotalKey.length > 0) {
        VirusTotalProvider *vtProvider = [[VirusTotalProvider alloc] initWithTTL:config.virusTotalTTL
                                                                      negativeTTL:3600.0];
        [vtProvider configureWithBaseURL:config.virusTotalAPIURL
                                  APIKey:virusTotalKey
                                 timeout:config.virusTotalTimeout
                       maxRequestsPerMin:config.virusTotalMaxRequestsPerMin
                              completion:^(NSError *error) {
            if (error) {
                SNBLogThreatIntelError("Failed to configure VirusTotal: %{public}@", error.localizedDescription);
            } else {
                SNBLogThreatIntelInfo("VirusTotal provider configured successfully");
            }
        }];
        [self.facade addProvider:vtProvider];
        SNBLogThreatIntelDebug("VirusTotal provider added");
        [self logProviderHealth:vtProvider];
    } else {
        SNBLogThreatIntelDebug("VirusTotal provider disabled (enabled: %{public}@, has key: %{public}@)",
                               virusTotalEnabled ? @"YES" : @"NO",
                               virusTotalKey.length > 0 ? @"YES" : @"NO");
    }

    BOOL abuseIPDBEnabled = config.abuseIPDBEnabled;
    NSString *abuseIPDBKey = abuseIPDBEnabled ? config.abuseIPDBAPIKey : @"";
    if (abuseIPDBEnabled && abuseIPDBKey.length > 0) {
        AbuseIPDBProvider *abuseProvider = [[AbuseIPDBProvider alloc] initWithTTL:config.abuseIPDBTTL
                                                                       negativeTTL:3600.0
                                                                     maxAgeInDays:config.abuseIPDBMaxAgeInDays];
        [abuseProvider configureWithBaseURL:config.abuseIPDBAPIURL
                                     APIKey:abuseIPDBKey
                                    timeout:config.abuseIPDBTimeout
                          maxRequestsPerMin:config.abuseIPDBMaxRequestsPerMin
                                 completion:^(NSError *error) {
            if (error) {
                SNBLogThreatIntelError("Failed to configure AbuseIPDB: %{public}@", error.localizedDescription);
            } else {
                SNBLogThreatIntelInfo("AbuseIPDB provider configured successfully");
            }
        }];
        [self.facade addProvider:abuseProvider];
        SNBLogThreatIntelDebug("AbuseIPDB provider added");
        [self logProviderHealth:abuseProvider];
    } else {
        SNBLogThreatIntelDebug("AbuseIPDB provider disabled (enabled: %{public}@, has key: %{public}@)",
                               abuseIPDBEnabled ? @"YES" : @"NO",
                               abuseIPDBKey.length > 0 ? @"YES" : @"NO");
    }

    BOOL greyNoiseEnabled = config.greyNoiseEnabled;
    NSString *greyNoiseKey = greyNoiseEnabled ? config.greyNoiseAPIKey : @"";
    if (greyNoiseEnabled && greyNoiseKey.length > 0) {
        GreyNoiseProvider *greyNoiseProvider = [[GreyNoiseProvider alloc] initWithTTL:config.greyNoiseTTL
                                                                           negativeTTL:3600.0];
        [greyNoiseProvider configureWithBaseURL:config.greyNoiseAPIURL
                                         APIKey:greyNoiseKey
                                        timeout:config.greyNoiseTimeout
                              maxRequestsPerMin:config.greyNoiseMaxRequestsPerMin
                                     completion:^(NSError *error) {
            if (error) {
                SNBLogThreatIntelError("Failed to configure GreyNoise: %{public}@", error.localizedDescription);
            } else {
                SNBLogThreatIntelInfo("GreyNoise provider configured successfully");
            }
        }];
        [self.facade addProvider:greyNoiseProvider];
        SNBLogThreatIntelDebug("GreyNoise provider added");
        [self logProviderHealth:greyNoiseProvider];
    } else {
        SNBLogThreatIntelDebug("GreyNoise provider disabled (enabled: %{public}@, has key: %{public}@)",
                               greyNoiseEnabled ? @"YES" : @"NO",
                               greyNoiseKey.length > 0 ? @"YES" : @"NO");
    }

    BOOL shodanEnabled = config.shodanEnabled;
    NSString *shodanKey = shodanEnabled ? config.shodanAPIKey : @"";
    if (shodanEnabled && shodanKey.length > 0) {
        ShodanProvider *shodanProvider = [[ShodanProvider alloc] initWithTTL:config.shodanTTL
                                                                  negativeTTL:3600.0];
        [shodanProvider configureWithBaseURL:config.shodanAPIURL
                                      APIKey:shodanKey
                                     timeout:config.shodanTimeout
                           maxRequestsPerMin:config.shodanMaxRequestsPerMin
                                  completion:^(NSError *error) {
            if (error) {
                SNBLogThreatIntelError("Failed to configure Shodan: %{public}@", error.localizedDescription);
            } else {
                SNBLogThreatIntelInfo("Shodan provider configured successfully");
            }
        }];
        [self.facade addProvider:shodanProvider];
        SNBLogThreatIntelDebug("Shodan provider added");
        [self logProviderHealth:shodanProvider];
    } else {
        SNBLogThreatIntelDebug("Shodan provider disabled (enabled: %{public}@, has key: %{public}@)",
                               shodanEnabled ? @"YES" : @"NO",
                               shodanKey.length > 0 ? @"YES" : @"NO");
    }

    SNBLogThreatIntelInfo("Threat Intelligence initialized (enabled: %{public}@)", self.isEnabled ? @"YES" : @"NO");
}

- (void)reloadProviders {
    [self.facade configureWithProviders:@[]];
    [self configureProviders];
}

- (void)logProviderHealth:(id<ThreatIntelProvider>)provider {
    [provider isHealthyWithCompletion:^(BOOL healthy) {
        SNBLogThreatIntelInfo("Provider %{public}@ health: %{public}@",
                              provider.name,
                              healthy ? @"OK" : @"NOT READY");
    }];
}

- (void)toggleEnabled {
    [self setEnabled:!self.isEnabled];
}

- (void)setEnabled:(BOOL)enabled {
    _enabled = enabled;
    self.facade.enabled = enabled;
    [[NSUserDefaults standardUserDefaults] setBool:enabled forKey:SNBUserDefaultsKeyThreatIntelEnabled];
    [[NSUserDefaults standardUserDefaults] synchronize];

    SNBLogThreatIntelInfo("Threat Intelligence %{public}@", enabled ? @"ENABLED" : @"DISABLED");

    if (!enabled) {
        [self.results removeAllObjects];
        [self.resultOrder removeAllObjects];
    }
}

- (NSDictionary<NSString *, TIEnrichmentResponse *> *)resultsSnapshot {
    return [self.results copy];
}

- (NSDictionary *)cacheStats {
    return [self.facade cacheStats];
}

- (NSString *)availabilityMessage {
    if (!self.isEnabled) {
        return nil;
    }
    return [self.facade availabilityMessage];
}

- (void)enrichIPIfNeeded:(NSString *)ipAddress completion:(dispatch_block_t)completion {
    if (!self.isEnabled) {
        return;
    }
    if (![IPAddressUtilities isPublicIPAddress:ipAddress]) {
        SNBLogThreatIntelDebug("Skipping threat intel for private/local IP: %{" SNB_IP_PRIVACY "}@", ipAddress);
        return;
    }
    if ([self.trustedStore isTrustedIP:ipAddress]) {
        if (self.results[ipAddress]) {
            [self.results removeObjectForKey:ipAddress];
            [self.resultOrder removeObject:ipAddress];
        }
        SNBLogThreatIntelInfo("Skipping threat intel for trusted IP: %{" SNB_IP_PRIVACY "}@", ipAddress);
        if (completion) {
            dispatch_async(dispatch_get_main_queue(), ^{
                completion();
            });
        }
        return;
    }
    if (self.results[ipAddress]) {
        return;
    }

    [self.facade enrichIP:ipAddress completion:^(TIEnrichmentResponse *response, NSError *error) {
        if (response && response.scoringResult) {
            self.results[ipAddress] = response;
            if (![self.resultOrder containsObject:ipAddress]) {
                [self.resultOrder addObject:ipAddress];
                if (self.resultOrder.count > kMaxThreatResults) {
                    NSString *oldest = self.resultOrder.firstObject;
                    if (oldest) {
                        [self.results removeObjectForKey:oldest];
                        [self.resultOrder removeObjectAtIndex:0];
                    }
                }
            }

            TIScoringResult *scoring = response.scoringResult;
            // Validate scoring result before logging
            if (scoring && scoring.indicator) {
                NSInteger score = scoring.finalScore;
                double confidence = scoring.confidence;
                NSString *verdict = [scoring verdictString];

                // Sanity check the values
                if (score < 0 || score > 10000) {
                    SNBLogThreatIntelError("Invalid threat intel score for %{" SNB_IP_PRIVACY "}@: %ld (corrupted data)",
                                          ipAddress, (long)score);
                } else {
                    SNBLogThreatIntelInfo("Threat Intel: %{" SNB_IP_PRIVACY "}@ -> %{public}@ (score: %ld, confidence: %.2f)",
                                          ipAddress, verdict ?: @"Unknown", (long)score, confidence);

                    // Trusted IPs are not enriched by default, so auto-untrust is not evaluated here.
                }
            } else {
                SNBLogThreatIntelWarn("Threat Intel: %{" SNB_IP_PRIVACY "}@ -> incomplete scoring result", ipAddress);
            }

            if (completion) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    completion();
                });
            }
        } else if (error) {
            NSString *provider = [self providerNameFromError:error];
            if (provider.length > 0) {
                SNBLogThreatIntelWarn("Threat Intel error for %{" SNB_IP_PRIVACY "}@ (%{public}@): %{public}@",
                                      ipAddress, provider, error.localizedDescription);
            } else {
                SNBLogThreatIntelWarn("Threat Intel error for %{" SNB_IP_PRIVACY "}@: %{public}@", ipAddress, error.localizedDescription);
            }
        }
    }];
}

- (NSString *)providerNameFromError:(NSError *)error {
    if (!error.domain || error.domain.length == 0) {
        return nil;
    }
    if ([error.domain isEqualToString:@"AbuseIPDBProvider"]) {
        return @"AbuseIPDB";
    }
    if ([error.domain isEqualToString:@"VirusTotalProvider"]) {
        return @"VirusTotal";
    }
    if ([error.domain isEqualToString:@"GreyNoiseProvider"]) {
        return @"GreyNoise";
    }
    if ([error.domain isEqualToString:@"ShodanProvider"]) {
        return @"Shodan";
    }
    NSArray<NSError *> *providerErrors = error.userInfo[@"providerErrors"];
    if ([providerErrors isKindOfClass:[NSArray class]] && providerErrors.count > 0) {
        NSMutableSet<NSString *> *names = [NSMutableSet set];
        for (NSError *providerError in providerErrors) {
            NSString *name = [self providerNameFromError:providerError];
            if (name.length > 0) {
                [names addObject:name];
            }
        }
        if (names.count == 1) {
            return names.anyObject;
        }
        if (names.count > 1) {
            NSArray<NSString *> *sorted = [[names allObjects] sortedArrayUsingSelector:@selector(compare:)];
            return [sorted componentsJoinedByString:@", "];
        }
    }
    return nil;
}

@end

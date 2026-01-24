//
//  ThreatIntelFacade.m
//  SniffNetBar
//

#import "ThreatIntelFacade.h"
#import "ThreatIntelCache.h"
#import "ThreatIntelStore.h"
#import "ConfigurationManager.h"
#import "IPAddressUtilities.h"
#import "Logger.h"
#import "AdaptiveScoring.h"
#import <math.h>

@interface ThreatIntelFacade ()
@property (nonatomic, strong) NSMutableArray<id<ThreatIntelProvider>> *providers;
@property (nonatomic, strong) ThreatIntelCache *cache;
@property (nonatomic, strong) ThreatIntelStore *store;
@property (nonatomic, strong) dispatch_queue_t enrichmentQueue;
@property (nonatomic, strong) NSMutableDictionary<NSString *, NSMutableArray *> *inFlightRequests;
@property (nonatomic, strong) NSMutableDictionary<NSString *, NSDate *> *providerDisabledUntil;
@property (nonatomic, strong) NSMutableDictionary<NSString *, NSString *> *providerDisableReasons;
@end

@implementation ThreatIntelFacade

static NSTimeInterval const kProviderErrorCooldown = 300.0;
static NSTimeInterval const kProviderRateLimitCooldown = 3600.0;
static NSTimeInterval const kProviderQuotaCooldown = 86400.0;  // 24 hours for quota exceeded
static NSTimeInterval const kProviderAuthCooldown = 3600.0;
static NSString *const kProviderRetryAfterKey = @"retry_after";

+ (instancetype)sharedInstance {
    static ThreatIntelFacade *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[self alloc] init];
    });
    return instance;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _providers = [NSMutableArray array];
        _cache = [[ThreatIntelCache alloc] initWithMaxSize:5000];
        ConfigurationManager *config = [ConfigurationManager sharedManager];
        NSTimeInterval ttlSeconds = MAX(0.0, config.threatIntelPersistenceTTLHours) * 3600.0;
        _store = [ThreatIntelStore sharedStoreWithTTLSeconds:ttlSeconds];
        _enrichmentQueue = dispatch_queue_create("com.sniffnetbar.threatintel.enrichment", DISPATCH_QUEUE_CONCURRENT);
        _inFlightRequests = [NSMutableDictionary dictionary];
        _providerDisabledUntil = [NSMutableDictionary dictionary];
        _providerDisableReasons = [NSMutableDictionary dictionary];
        _enabled = NO;
        [self loadProviderStatusesFromStore];
        [self.store clearExpiredProviderStatuses];
    }
    return self;
}

- (void)configureWithProviders:(NSArray<id<ThreatIntelProvider>> *)providers {
    [self.providers removeAllObjects];
    [self.providers addObjectsFromArray:providers];
    SNBLogThreatIntelDebug("Configured with %lu providers", (unsigned long)providers.count);
}

- (void)addProvider:(id<ThreatIntelProvider>)provider {
    [self.providers addObject:provider];
    SNBLogThreatIntelDebug("Added provider %{public}@", provider.name);
}

- (void)enrichIP:(NSString *)ipAddress completion:(TIEnrichmentCompletion)completion {
    TIIndicatorType type = TIIndicatorTypeIPv4;
    if (![self isValidIPAddress:ipAddress detectedType:&type]) {
        if (completion) {
            NSError *error = [NSError errorWithDomain:TIErrorDomain
                                                 code:TIErrorCodeUnsupportedIndicatorType
                                             userInfo:@{NSLocalizedDescriptionKey: @"Invalid IP address"}];
            completion(nil, error);
        }
        return;
    }
    TIIndicator *indicator = [[TIIndicator alloc] initWithType:type value:ipAddress];
    [self enrichIndicator:indicator completion:completion];
}

- (void)enrichIndicator:(TIIndicator *)indicator completion:(TIEnrichmentCompletion)completion {
    if (!self.enabled) {
        if (completion) {
            NSError *error = [NSError errorWithDomain:TIErrorDomain
                                                 code:TIErrorCodeProviderUnavailable
                                             userInfo:@{NSLocalizedDescriptionKey: @"Threat intelligence is disabled"}];
            completion(nil, error);
        }
        return;
    }

    // Check for in-flight requests (single-flight pattern)
    NSString *key = [self keyForIndicator:indicator];

    @synchronized(self.inFlightRequests) {
        NSMutableArray *callbacks = self.inFlightRequests[key];
        if (callbacks) {
            // Already in flight, add callback if provided
            if (completion) {
                [callbacks addObject:[completion copy]];
            }
            SNBLogThreatIntelDebug("Coalescing request for %{" SNB_IP_PRIVACY "}@", indicator.value);
            return;
        }

        // Start new request
        NSMutableArray *newCallbacks = [NSMutableArray array];
        if (completion) {
            [newCallbacks addObject:[completion copy]];
        }
        self.inFlightRequests[key] = newCallbacks;

        // Execute enrichment inside synchronized block to prevent race condition
        // where request could complete and remove key before other threads check
        dispatch_async(self.enrichmentQueue, ^{
            [self performEnrichmentForIndicator:indicator];
        });
    }
}

- (void)performEnrichmentForIndicator:(TIIndicator *)indicator {
    NSDate *startTime = [NSDate date];
    NSString *key = [self keyForIndicator:indicator];

    TIEnrichmentResponse *storedResponse = [self.store responseForIndicator:indicator];
    if (storedResponse) {
        for (TIResult *result in storedResponse.providerResults) {
            [self.cache setResult:result];
        }
    }

    // Get applicable providers
    NSArray<id<ThreatIntelProvider>> *applicableProviders = [self getApplicableProvidersForIndicator:indicator];

    if (applicableProviders.count == 0) {
        if (storedResponse) {
            [self completeEnrichmentForKey:key response:storedResponse error:nil];
        } else {
            [self completeEnrichmentForKey:key response:nil error:[self errorNoProviders]];
        }
        return;
    }

    // Create dispatch group for concurrent provider queries
    dispatch_group_t group = dispatch_group_create();
    NSMutableArray<TIResult *> *results = [NSMutableArray array];
    NSMutableArray<NSError *> *errors = [NSMutableArray array];
    NSMutableSet<NSString *> *existingProviders = [NSMutableSet set];
    __block NSInteger cacheHits = 0;
    __block BOOL timedOut = NO;
    NSDate *now = [NSDate date];
    __block NSInteger availableCount = 0;
    NSMutableArray<id<ThreatIntelProvider>> *providersToQuery = [NSMutableArray array];

    if (storedResponse) {
        for (TIResult *result in storedResponse.providerResults) {
            if (result.providerName.length > 0) {
                [existingProviders addObject:result.providerName];
            }
            [results addObject:result];
        }
    }

    for (id<ThreatIntelProvider> provider in applicableProviders) {
        if ([existingProviders containsObject:provider.name]) {
            continue;
        }
        // Check cache first
        TIResult *cachedResult = [self.cache getResultForProvider:provider.name indicator:indicator];

        if (cachedResult) {
            @synchronized(results) {
                [results addObject:cachedResult];
                cacheHits++;
            }
            continue;
        }

        BOOL isAvailable = [self isProviderAvailable:provider now:now];
        if (!isAvailable) {
            NSError *unavailable = [self errorProviderUnavailableForProvider:provider];
            @synchronized(results) {
                [errors addObject:unavailable];
            }
            @synchronized(self.providerDisableReasons) {
                NSString *reason = self.providerDisableReasons[provider.name];
                SNBLogThreatIntelWarn("Provider %{public}@ unavailable for %{" SNB_IP_PRIVACY "}@ (%{public}@)",
                                      provider.name,
                                      indicator.value,
                                      reason ?: @"cooldown");
            }
            continue;
        }

        availableCount += 1;
        [providersToQuery addObject:provider];
    }

    if (providersToQuery.count == 0) {
        if (results.count == 0) {
            [self completeEnrichmentForKey:key response:nil error:[self errorNoProviders]];
            return;
        }

        TIScoringResult *scoringResult = [self calculateScoringForResults:[results copy] indicator:indicator];

        TIEnrichmentResponse *response = [[TIEnrichmentResponse alloc] init];
        response.indicator = indicator;
        response.providerResults = [results copy];
        response.scoringResult = scoringResult;
        response.duration = [[NSDate date] timeIntervalSinceDate:startTime];
        response.cacheHits = cacheHits;

        SNBLogThreatIntelDebug("Enrichment completed for %{" SNB_IP_PRIVACY "}@ - %lu providers, %ld hits, score=%ld, verdict=%{public}@",
               indicator.value, (unsigned long)results.count, (long)cacheHits,
               (long)scoringResult.finalScore, [scoringResult verdictString]);

        if (response.scoringResult && response.providerResults.count > 0) {
            [self.store storeResponse:response];
        }

        [self completeEnrichmentForKey:key response:response error:nil];
        return;
    }

    if (storedResponse) {
        NSMutableArray<NSString *> *existingList = [NSMutableArray array];
        NSMutableArray<NSString *> *missingList = [NSMutableArray array];
        for (NSString *name in existingProviders) {
            [existingList addObject:name];
        }
        for (id<ThreatIntelProvider> provider in providersToQuery) {
            [missingList addObject:provider.name];
        }
        NSString *existingSummary = existingList.count > 0 ? [existingList componentsJoinedByString:@", "] : @"none";
        NSString *missingSummary = missingList.count > 0 ? [missingList componentsJoinedByString:@", "] : @"none";
        SNBLogThreatIntelInfo("Threat intel cache for %{" SNB_IP_PRIVACY "}@ -> existing [%{public}@], querying [%{public}@]",
                              indicator.value,
                              existingSummary,
                              missingSummary);
    } else {
        NSMutableArray<NSString *> *queryList = [NSMutableArray array];
        for (id<ThreatIntelProvider> provider in providersToQuery) {
            [queryList addObject:provider.name];
        }
        NSString *querySummary = queryList.count > 0 ? [queryList componentsJoinedByString:@", "] : @"none";
        SNBLogThreatIntelInfo("Threat intel query for %{" SNB_IP_PRIVACY "}@ -> providers [%{public}@]",
                              indicator.value,
                              querySummary);
    }

    for (id<ThreatIntelProvider> provider in providersToQuery) {
        dispatch_group_enter(group);

        // Query provider
        [provider enrichIndicator:indicator completion:^(TIResult *result, NSError *error) {
            if (result) {
                // Cache result even if this request times out to help future queries.
                [self.cache setResult:result];
                @synchronized(results) {
                    if (!timedOut) {
                        [results addObject:result];
                    }
                }
            } else if (error) {
                [self markProviderUnavailable:provider error:error];
                @synchronized(results) {
                    if (!timedOut) {
                        [errors addObject:error];
                    }
                }
            }
            dispatch_group_leave(group);
        }];
    }

    if (availableCount == 0 && results.count == 0) {
        [self completeEnrichmentForKey:key response:nil error:[self errorNoProviders]];
        return;
    }

    // Wait for all providers (with timeout)
    dispatch_time_t timeout = dispatch_time(DISPATCH_TIME_NOW, (int64_t)(10.0 * NSEC_PER_SEC));
    BOOL didTimeout = dispatch_group_wait(group, timeout) != 0;
    if (didTimeout) {
        @synchronized(results) {
            timedOut = YES;
        }
    }

    NSArray<TIResult *> *resultsSnapshot = nil;
    NSArray<NSError *> *errorsSnapshot = nil;
    @synchronized(results) {
        resultsSnapshot = [results copy];
        errorsSnapshot = [errors copy];
    }

    // Calculate scoring
    TIScoringResult *scoringResult = [self calculateScoringForResults:resultsSnapshot indicator:indicator];

    // Build response
    TIEnrichmentResponse *response = [[TIEnrichmentResponse alloc] init];
    response.indicator = indicator;
    response.providerResults = resultsSnapshot;
    response.scoringResult = scoringResult;
    response.duration = [[NSDate date] timeIntervalSinceDate:startTime];
    response.cacheHits = cacheHits;

    SNBLogThreatIntelDebug("Enrichment completed for %{" SNB_IP_PRIVACY "}@ - %lu providers, %ld hits, score=%ld, verdict=%{public}@",
           indicator.value, (unsigned long)results.count, (long)cacheHits,
           (long)scoringResult.finalScore, [scoringResult verdictString]);

    NSError *finalError = nil;
    if (didTimeout) {
        finalError = [self errorTimeoutWithProviderErrors:errorsSnapshot];
    } else if (resultsSnapshot.count == 0 && errorsSnapshot.count > 0) {
        finalError = [self errorProvidersFailedWithErrors:errorsSnapshot];
    }

    // Store to database (storeResponse handles async via dbQueue internally)
    if (response.scoringResult && response.providerResults.count > 0) {
        [self.store storeResponse:response];
    }

    [self completeEnrichmentForKey:key response:response error:finalError];
}

- (void)completeEnrichmentForKey:(NSString *)key
                        response:(TIEnrichmentResponse *)response
                           error:(NSError *)error {
    NSArray *callbacks = nil;

    @synchronized(self.inFlightRequests) {
        callbacks = [self.inFlightRequests[key] copy];
        [self.inFlightRequests removeObjectForKey:key];
    }

    dispatch_async(dispatch_get_main_queue(), ^{
        for (TIEnrichmentCompletion completion in callbacks) {
            completion(response, error);
        }
    });
}

- (NSArray<id<ThreatIntelProvider>> *)getApplicableProvidersForIndicator:(TIIndicator *)indicator {
    NSMutableArray *applicable = [NSMutableArray array];
    for (id<ThreatIntelProvider> provider in self.providers) {
        if ([provider supportsIndicatorType:indicator.type]) {
            [applicable addObject:provider];
        }
    }
    return applicable;
}

// MARK: - Provider Availability

- (BOOL)hasAvailableProviders {
    NSDate *now = [NSDate date];
    for (id<ThreatIntelProvider> provider in self.providers) {
        if ([provider supportsIndicatorType:TIIndicatorTypeIPv4] ||
            [provider supportsIndicatorType:TIIndicatorTypeIPv6]) {
            if ([self isProviderAvailable:provider now:now]) {
                return YES;
            }
        }
    }
    return NO;
}

- (NSString *)availabilityMessage {
    if (self.providers.count == 0) {
        return @"Threat Intel unavailable (no providers configured)";
    }

    if ([self hasAvailableProviders]) {
        return nil;
    }

    NSArray<NSString *> *reasons = [self providerDisableReasonSummaries];
    if (reasons.count == 0) {
        return @"Threat Intel unavailable (all providers disabled)";
    }
    if (reasons.count == 1) {
        return [NSString stringWithFormat:@"Threat Intel unavailable (%@)", reasons.firstObject];
    }
    return [NSString stringWithFormat:@"Threat Intel unavailable (%lu providers disabled)", (unsigned long)reasons.count];
}

- (BOOL)isProviderAvailable:(id<ThreatIntelProvider>)provider now:(NSDate *)now {
    @synchronized(self.providerDisabledUntil) {
        NSDate *disabledUntil = self.providerDisabledUntil[provider.name];
        if (!disabledUntil) {
            return YES;
        }
        if ([now compare:disabledUntil] != NSOrderedAscending) {
            // Provider cooldown has expired - re-enable it
            [self.providerDisabledUntil removeObjectForKey:provider.name];
            [self.providerDisableReasons removeObjectForKey:provider.name];
            [self.store clearProviderStatus:provider.name];
            SNBLogThreatIntelInfo("Provider %{public}@ re-enabled after cooldown", provider.name);
            return YES;
        }
        return NO;
    }
}

- (void)loadProviderStatusesFromStore {
    NSDictionary<NSString *, SNBProviderStatus *> *statuses = [self.store getAllProviderStatuses];
    NSDate *now = [NSDate date];
    NSInteger loadedCount = 0;

    for (NSString *providerName in statuses) {
        SNBProviderStatus *status = statuses[providerName];

        // Check if still disabled
        if (status.isDisabled && status.disabledUntil) {
            if ([now compare:status.disabledUntil] == NSOrderedAscending) {
                // Still disabled
                @synchronized(self.providerDisabledUntil) {
                    self.providerDisabledUntil[providerName] = status.disabledUntil;
                    self.providerDisableReasons[providerName] = status.disabledReason ?: @"Provider error";
                }
                loadedCount++;

                NSTimeInterval remaining = [status.disabledUntil timeIntervalSinceDate:now];
                SNBLogThreatIntelWarn("Loaded persistent provider status: %{public}@ disabled for %.0f more seconds - %{public}@",
                                     providerName, remaining, status.disabledReason ?: @"Unknown reason");
            } else {
                // Expired - clear from database
                [self.store clearProviderStatus:providerName];
                SNBLogThreatIntelInfo("Provider %{public}@ disabled status expired - re-enabled", providerName);
            }
        }
    }

    if (loadedCount > 0) {
        SNBLogThreatIntelInfo("Loaded %ld provider disabled states from persistent storage", (long)loadedCount);
    }
}

- (void)markProviderUnavailable:(id<ThreatIntelProvider>)provider error:(NSError *)error {
    if (!provider || !error) {
        return;
    }

    NSTimeInterval cooldown = kProviderErrorCooldown;
    NSString *reason = error.localizedDescription.length > 0 ? error.localizedDescription : @"Provider error";
    NSNumber *retryAfterValue = error.userInfo[kProviderRetryAfterKey];
    BOOL isQuotaExceeded = NO;

    // Differentiate between quota exceeded and rate limit
    if (error.code == TIErrorCodeQuotaExceeded) {
        // Quota exceeded - disable for 24 hours (until quota resets)
        cooldown = kProviderQuotaCooldown;
        reason = @"Daily quota exceeded";
        isQuotaExceeded = YES;
        SNBLogThreatIntelError("Provider %{public}@ QUOTA EXCEEDED - disabled until quota resets (24h)", provider.name);
    } else if (error.code == TIErrorCodeRateLimited || error.code == 429) {
        // Rate limited - temporary cooldown
        cooldown = retryAfterValue ? MAX(1.0, retryAfterValue.doubleValue) : kProviderRateLimitCooldown;
        reason = @"Rate limit reached (temporary)";
        SNBLogThreatIntelWarn("Provider %{public}@ rate limited - cooldown for %.0f seconds", provider.name, cooldown);
    } else if (error.code == TIErrorCodeAuthenticationFailed || error.code == 1003) {
        cooldown = kProviderAuthCooldown;
        reason = @"Authentication failed (check API key)";
        SNBLogThreatIntelError("Provider %{public}@ authentication failed - check API key", provider.name);
    } else if (retryAfterValue) {
        cooldown = MAX(1.0, retryAfterValue.doubleValue);
        SNBLogThreatIntelWarn("Provider %{public}@ error - retry after %.0f seconds: %{public}@",
                            provider.name, cooldown, error.localizedDescription);
    } else {
        SNBLogThreatIntelWarn("Provider %{public}@ error (cooldown %.0f seconds): %{public}@",
                            provider.name, cooldown, error.localizedDescription);
    }

    NSDate *disabledUntil = [NSDate dateWithTimeIntervalSinceNow:cooldown];
    @synchronized(self.providerDisabledUntil) {
        self.providerDisabledUntil[provider.name] = disabledUntil;
        self.providerDisableReasons[provider.name] = reason;
    }

    // Persist to database for persistence across app restarts
    SNBProviderStatus *status = [[SNBProviderStatus alloc] init];
    status.providerName = provider.name;
    status.isDisabled = YES;
    status.disabledUntil = disabledUntil;
    status.disabledReason = reason;
    status.errorCode = error.code;
    status.lastUpdated = [NSDate date];
    [self.store saveProviderStatus:status];

    if (isQuotaExceeded) {
        SNBLogThreatIntelError("Provider %{public}@ disabled until %{public}@ - reason: %{public}@",
                              provider.name, disabledUntil.description, reason);
    } else {
        SNBLogThreatIntelWarn("Provider %{public}@ disabled until %{public}@ - reason: %{public}@",
                              provider.name, disabledUntil.description, reason);
    }
}

- (NSArray<NSString *> *)providerDisableReasonSummaries {
    NSMutableArray<NSString *> *summaries = [NSMutableArray array];
    @synchronized(self.providerDisabledUntil) {
        for (NSString *providerName in self.providerDisabledUntil) {
            NSString *reason = self.providerDisableReasons[providerName] ?: @"Provider unavailable";
            [summaries addObject:[NSString stringWithFormat:@"%@: %@", providerName, reason]];
        }
    }
    return summaries;
}

// MARK: - Simple Scoring Engine

- (TIScoringResult *)calculateScoringForResults:(NSArray<TIResult *> *)results
                                      indicator:(TIIndicator *)indicator {
    TIScoringResult *scoring = [[TIScoringResult alloc] init];
    scoring.indicator = indicator;
    scoring.evaluatedAt = [NSDate date];

    NSMutableArray<TIScoreBreakdown *> *breakdown = [NSMutableArray array];
    NSInteger totalScore = 0;
    NSMutableArray<NSNumber *> *confidences = [NSMutableArray array];
    NSDictionary<NSString *, NSNumber *> *providerWeights =
        [[SNBAdaptiveScoring sharedScoring] providerWeights];
    NSSet<NSString *> *highRiskKeywords = [NSSet setWithArray:@[
        @"malware", @"trojan", @"phishing", @"scam", @"botnet", @"c2", @"command-and-control",
        @"vulnerability", @"exploit", @"scanner", @"spam", @"bruteforce", @"compromised", @"abuse"
    ]];

    // Simple scoring rules
    for (TIResult *result in results) {
        if (!result.verdict.hit) continue;

        NSInteger score = 0;
        NSString *ruleDesc = @"";
        double providerWeight = providerWeights[result.providerName].doubleValue;
        if (providerWeight <= 0.0) {
            providerWeight = 1.0;
        }

        // Score based on confidence
        if (result.verdict.confidence >= 75) {
            score = 40;
            ruleDesc = @"High confidence threat detected";
        } else if (result.verdict.confidence >= 50) {
            score = 25;
            ruleDesc = @"Medium confidence threat detected";
        } else if (result.verdict.confidence >= 25) {
            score = 10;
            ruleDesc = @"Low confidence threat detected";
        }

        // Category bonuses
        for (NSString *category in result.verdict.categories) {
            NSString *categoryLower = [category lowercaseString];
            BOOL matched = NO;
            for (NSString *keyword in highRiskKeywords) {
                if ([categoryLower containsString:keyword]) {
                    matched = YES;
                    break;
                }
            }
            if (matched) {
                score += 12;
            }
        }

        if (score > 0) {
            NSInteger weightedScore = (NSInteger)lround((double)score * providerWeight);
            if (weightedScore == 0) {
                weightedScore = 1;
            }
            TIScoreBreakdown *item = [[TIScoreBreakdown alloc] init];
            item.ruleName = [NSString stringWithFormat:@"%@_detection", result.providerName];
            item.ruleDescription = ruleDesc;
            item.provider = result.providerName;
            item.scoreContribution = weightedScore;
            item.confidence = result.verdict.confidence;
            item.evidence = @{
                @"categories": [result.verdict.categories componentsJoinedByString:@", "],
                @"confidence": [NSString stringWithFormat:@"%ld", (long)result.verdict.confidence],
                @"provider_weight": [NSString stringWithFormat:@"%.2f", providerWeight]
            };

            [breakdown addObject:item];
            totalScore += weightedScore;
            [confidences addObject:@(result.verdict.confidence / 100.0)];
        }
    }

    // Consensus bonus: if multiple providers agree
    NSInteger hitsCount = 0;
    for (TIResult *result in results) {
        if (result.verdict.hit) hitsCount++;
    }

    if (hitsCount >= 2) {
        NSInteger bonus = 5 * hitsCount;
        TIScoreBreakdown *item = [[TIScoreBreakdown alloc] init];
        item.ruleName = @"consensus_bonus";
        item.ruleDescription = [NSString stringWithFormat:@"%ld providers agree on threat", (long)hitsCount];
        item.provider = @"system";
        item.scoreContribution = bonus;
        item.confidence = 90;
        item.evidence = @{@"agreeing_providers": @(hitsCount).stringValue};
        [breakdown addObject:item];
        totalScore += bonus;
    }

    scoring.breakdown = breakdown;
    scoring.finalScore = totalScore;

    // Calculate confidence from ALL provider results, not just those with hits
    double avgConfidence = 0.0;
    if (results.count > 0) {
        double sum = 0.0;
        NSInteger validCount = 0;
        for (TIResult *result in results) {
            // Include all provider confidences, even if they didn't report a hit
            // This gives us an overall confidence in the assessment
            if (result.verdict) {
                sum += (result.verdict.confidence / 100.0);
                validCount++;
            }
        }
        if (validCount > 0) {
            avgConfidence = sum / validCount;
        }
    }
    scoring.confidence = avgConfidence;

    // Determine verdict
    if (totalScore >= 60) {
        scoring.verdict = TIThreatVerdictMalicious;
    } else if (totalScore >= 30) {
        scoring.verdict = TIThreatVerdictSuspicious;
    } else if (results.count > 0) {
        scoring.verdict = TIThreatVerdictClean;
    } else {
        scoring.verdict = TIThreatVerdictUnknown;
    }

    // Generate explanation
    scoring.explanation = [self generateExplanationForScoring:scoring];

    // Debug logging to track scoring calculation
    SNBLogThreatIntelDebug("Calculated scoring - score=%ld, confidence=%.2f, verdict=%{public}@, results=%lu",
                           (long)scoring.finalScore, scoring.confidence, [scoring verdictString], (unsigned long)results.count);

    return scoring;
}

- (NSString *)generateExplanationForScoring:(TIScoringResult *)scoring {
    if (scoring.breakdown.count == 0) {
        return @"No threat intelligence matches found.";
    }

    NSMutableString *explanation = [NSMutableString stringWithFormat:
                                   @"Score: %ld → %@\n\n",
                                   (long)scoring.finalScore,
                                   [scoring verdictString]];

    [explanation appendString:@"Contributing Factors:\n"];
    for (NSInteger i = 0; i < scoring.breakdown.count; i++) {
        TIScoreBreakdown *item = scoring.breakdown[i];
        [explanation appendFormat:@"%ld. [%@] %@ → +%ld pts\n",
         (long)(i + 1), item.provider, item.ruleDescription, (long)item.scoreContribution];
    }

    return explanation;
}

// MARK: - Batch Enrichment

static const NSUInteger kBatchSize = 5;  // Process 5 indicators at a time
static const NSTimeInterval kBatchDelaySeconds = 0.1;  // 100ms delay between batches

- (void)enrichIndicators:(NSArray<TIIndicator *> *)indicators
              completion:(void (^)(NSArray<TIEnrichmentResponse *> *))completion {
    if (!self.enabled) {
        if (completion) {
            completion(@[]);
        }
        return;
    }

    if (indicators.count == 0) {
        if (completion) {
            completion(@[]);
        }
        return;
    }

    // Performance: Process indicators in batches with delays to avoid API rate limit exhaustion
    // This prevents all indicators from being sent concurrently which would trigger rate limits
    dispatch_group_t group = dispatch_group_create();
    NSMutableArray<TIEnrichmentResponse *> *responses = [NSMutableArray arrayWithCapacity:indicators.count];

    // Pre-fill responses array with placeholders
    for (NSUInteger i = 0; i < indicators.count; i++) {
        [responses addObject:[NSNull null]];
    }

    // Process in batches of kBatchSize with kBatchDelaySeconds delay between batches
    NSUInteger totalBatches = (indicators.count + kBatchSize - 1) / kBatchSize;

    for (NSUInteger batch = 0; batch < totalBatches; batch++) {
        NSUInteger startIndex = batch * kBatchSize;
        NSUInteger endIndex = MIN(startIndex + kBatchSize, indicators.count);

        // Calculate delay for this batch (no delay for first batch)
        NSTimeInterval delay = batch * kBatchDelaySeconds;

        for (NSUInteger index = startIndex; index < endIndex; index++) {
            TIIndicator *indicator = indicators[index];
            dispatch_group_enter(group);

            // Dispatch with delay for rate limiting
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delay * NSEC_PER_SEC)),
                          self.enrichmentQueue, ^{
                [self enrichIndicator:indicator completion:^(TIEnrichmentResponse *response, NSError *error) {
                    if (response) {
                        @synchronized(responses) {
                            responses[index] = response;
                        }
                    }
                    dispatch_group_leave(group);
                }];
            });
        }
    }

    dispatch_group_notify(group, dispatch_get_main_queue(), ^{
        // Remove nulls
        NSMutableArray *validResponses = [NSMutableArray array];
        for (id obj in responses) {
            if (![obj isKindOfClass:[NSNull class]]) {
                [validResponses addObject:obj];
            }
        }
        if (completion) {
            completion(validResponses);
        }
    });
}

// MARK: - Cache Management

- (NSDictionary *)cacheStats {
    return [self.cache statsSnapshot];
}

- (void)clearCache {
    [self.cache clear];
}

// MARK: - Helpers

- (NSString *)keyForIndicator:(TIIndicator *)indicator {
    return [NSString stringWithFormat:@"%ld:%@", (long)indicator.type, indicator.value];
}

- (NSError *)errorNoProviders {
    return [NSError errorWithDomain:TIErrorDomain
                               code:TIErrorCodeProviderUnavailable
                           userInfo:@{NSLocalizedDescriptionKey: @"No providers available for indicator type"}];
}

- (NSError *)errorTimeoutWithProviderErrors:(NSArray<NSError *> *)errors {
    NSMutableDictionary *userInfo = [NSMutableDictionary dictionary];
    userInfo[NSLocalizedDescriptionKey] = @"Threat intelligence request timed out";
    userInfo[@"partialResults"] = @YES;
    if (errors.count > 0) {
        userInfo[@"providerErrors"] = errors;
    }
    return [NSError errorWithDomain:TIErrorDomain code:TIErrorCodeTimeout userInfo:userInfo];
}

- (NSError *)errorProvidersFailedWithErrors:(NSArray<NSError *> *)errors {
    NSMutableDictionary *userInfo = [NSMutableDictionary dictionary];
    userInfo[NSLocalizedDescriptionKey] = @"All threat intelligence providers failed";
    if (errors.count > 0) {
        userInfo[@"providerErrors"] = errors;
    }
    return [NSError errorWithDomain:TIErrorDomain code:TIErrorCodeNetworkError userInfo:userInfo];
}

- (NSError *)errorProviderUnavailableForProvider:(id<ThreatIntelProvider>)provider {
    NSString *message = [NSString stringWithFormat:@"%@ is temporarily unavailable", provider.name];
    return [NSError errorWithDomain:TIErrorDomain
                               code:TIErrorCodeProviderUnavailable
                           userInfo:@{NSLocalizedDescriptionKey: message}];
}

- (BOOL)isValidIPAddress:(NSString *)ip detectedType:(TIIndicatorType *)detectedType {
    if (!ip || ip.length == 0) {
        return NO;
    }

    // Use centralized validation
    if ([IPAddressUtilities isValidIPv4:ip]) {
        if (detectedType) {
            *detectedType = TIIndicatorTypeIPv4;
        }
        return YES;
    }

    if ([IPAddressUtilities isValidIPv6:ip]) {
        if (detectedType) {
            *detectedType = TIIndicatorTypeIPv6;
        }
        return YES;
    }

    return NO;
}

- (void)shutdown {
    for (id<ThreatIntelProvider> provider in self.providers) {
        if ([provider respondsToSelector:@selector(shutdown)]) {
            [provider shutdown];
        }
    }
    [self.providers removeAllObjects];
    [self.cache clear];
    [self.providerDisabledUntil removeAllObjects];
    [self.providerDisableReasons removeAllObjects];
}

@end

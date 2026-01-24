//
//  AbuseIPDBProvider.m
//  SniffNetBar
//
//  AbuseIPDB API v2 threat intelligence provider
//

#import "AbuseIPDBProvider.h"
#import "Logger.h"

static NSTimeInterval const kDefaultTTL = 86400.0;  // 24 hours
static NSTimeInterval const kDefaultNegativeTTL = 3600.0;  // 1 hour
static NSInteger const kDefaultMaxAgeInDays = 90;

@interface AbuseIPDBProvider ()
@property (nonatomic, strong) NSString *apiBaseURL;
@property (nonatomic, strong) NSString *apiKey;
@property (nonatomic, strong) NSURLSession *session;
@property (nonatomic, assign) NSTimeInterval timeout;
@property (nonatomic, assign) NSInteger maxRequestsPerMin;
@property (nonatomic, assign) NSTimeInterval ttl;
@property (nonatomic, assign) NSTimeInterval negTTL;
@property (nonatomic, assign) NSInteger maxAgeInDays;

// Rate limiting
@property (nonatomic, strong) dispatch_queue_t rateLimitQueue;
@property (nonatomic, strong) NSMutableArray<NSDate *> *requestTimestamps;
@end

@implementation AbuseIPDBProvider

- (instancetype)init {
    return [self initWithTTL:kDefaultTTL negativeTTL:kDefaultNegativeTTL maxAgeInDays:kDefaultMaxAgeInDays];
}

- (instancetype)initWithTTL:(NSTimeInterval)ttl
                negativeTTL:(NSTimeInterval)negativeTTL
              maxAgeInDays:(NSInteger)maxAgeInDays {
    self = [super init];
    if (self) {
        _ttl = ttl;
        _negTTL = negativeTTL;
        _maxAgeInDays = maxAgeInDays;
        _rateLimitQueue = dispatch_queue_create("com.sniffnetbar.abuseipdb.ratelimit", DISPATCH_QUEUE_SERIAL);
        _requestTimestamps = [NSMutableArray array];
        _timeout = 10.0;
        _maxRequestsPerMin = 60;
    }
    return self;
}

#pragma mark - ThreatIntelProvider Protocol

- (NSString *)name {
    return @"AbuseIPDB";
}

- (NSTimeInterval)defaultTTL {
    return self.ttl;
}

- (NSTimeInterval)negativeCacheTTL {
    return self.negTTL;
}

- (void)configureWithAPIKey:(NSString *)apiKey
                    timeout:(NSTimeInterval)timeout
          maxRequestsPerMin:(NSInteger)maxRequestsPerMin
                 completion:(void (^)(NSError *))completion {
    [self configureWithBaseURL:@"https://api.abuseipdb.com/api/v2"
                        APIKey:apiKey
                       timeout:timeout
             maxRequestsPerMin:maxRequestsPerMin
                    completion:completion];
}

- (void)configureWithBaseURL:(NSString *)baseURL
                      APIKey:(NSString *)apiKey
                     timeout:(NSTimeInterval)timeout
           maxRequestsPerMin:(NSInteger)maxRequestsPerMin
                  completion:(void (^)(NSError *))completion {
    if (!apiKey || apiKey.length == 0) {
        NSError *error = [NSError errorWithDomain:@"AbuseIPDBProvider"
                                             code:1001
                                         userInfo:@{NSLocalizedDescriptionKey: @"API key is required"}];
        if (completion) completion(error);
        return;
    }

    self.apiBaseURL = baseURL.length > 0 ? baseURL : @"https://api.abuseipdb.com/api/v2";
    self.apiKey = apiKey;
    self.timeout = timeout;
    self.maxRequestsPerMin = maxRequestsPerMin;

    NSURLSessionConfiguration *config = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    config.timeoutIntervalForRequest = timeout;
    config.timeoutIntervalForResource = timeout * 2;
    config.URLCache = nil;
    config.requestCachePolicy = NSURLRequestReloadIgnoringLocalCacheData;
    self.session = [NSURLSession sessionWithConfiguration:config];

    SNBLogThreatIntelInfo("Configured with API key (rate limit: %ld req/min, maxAge: %ld days, URL: %{public}@)",
                          (long)maxRequestsPerMin, (long)self.maxAgeInDays, self.apiBaseURL);

    if (completion) completion(nil);
}

- (void)isHealthyWithCompletion:(void (^)(BOOL))completion {
    BOOL healthy = (self.apiKey.length > 0 && self.session != nil);
    if (completion) completion(healthy);
}

- (BOOL)supportsIndicatorType:(TIIndicatorType)type {
    return (type == TIIndicatorTypeIPv4 || type == TIIndicatorTypeIPv6);
}

- (void)enrichIndicator:(TIIndicator *)indicator
             completion:(void (^)(TIResult *, NSError *))completion {
    if (!self.apiKey || self.apiKey.length == 0) {
        NSError *error = [NSError errorWithDomain:@"AbuseIPDBProvider"
                                             code:1001
                                         userInfo:@{NSLocalizedDescriptionKey: @"Provider not configured"}];
        if (completion) completion(nil, error);
        return;
    }

    if (![self supportsIndicatorType:indicator.type]) {
        NSError *error = [NSError errorWithDomain:@"AbuseIPDBProvider"
                                             code:1002
                                         userInfo:@{NSLocalizedDescriptionKey: @"Unsupported indicator type"}];
        if (completion) completion(nil, error);
        return;
    }

    // Apply rate limiting
    [self waitForRateLimitThenExecute:^{
        [self performEnrichment:indicator completion:completion];
    }];
}

- (void)shutdown {
    [self.session invalidateAndCancel];
    self.session = nil;
}

#pragma mark - Rate Limiting

- (void)waitForRateLimitThenExecute:(void (^)(void))block {
    dispatch_async(self.rateLimitQueue, ^{
        // Clean up old timestamps (older than 1 minute)
        NSDate *oneMinuteAgo = [NSDate dateWithTimeIntervalSinceNow:-60.0];
        [self.requestTimestamps filterUsingPredicate:[NSPredicate predicateWithBlock:^BOOL(NSDate *timestamp, NSDictionary *bindings) {
            return [timestamp compare:oneMinuteAgo] == NSOrderedDescending;
        }]];

        // Check if we're at rate limit
        if (self.requestTimestamps.count >= self.maxRequestsPerMin) {
            // Calculate how long to wait
            NSDate *oldestTimestamp = self.requestTimestamps.firstObject;
            NSTimeInterval waitTime = 60.0 - [[NSDate date] timeIntervalSinceDate:oldestTimestamp];

            if (waitTime > 0) {
                SNBLogThreatIntelDebug("Rate limit reached, waiting %.1f seconds", waitTime);
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(waitTime * NSEC_PER_SEC)),
                               self.rateLimitQueue, ^{
                    if (self.requestTimestamps.count > 0) {
                        [self.requestTimestamps removeObjectAtIndex:0];
                    }
                    [self.requestTimestamps addObject:[NSDate date]];
                    if (block) block();
                });
                return;
            }
        }

        // Record this request
        [self.requestTimestamps addObject:[NSDate date]];

        // Execute the block
        if (block) block();
    });
}

#pragma mark - API Request

- (void)performEnrichment:(TIIndicator *)indicator
               completion:(void (^)(TIResult *, NSError *))completion {
    // Build URL with query parameters
    NSURLComponents *components = [NSURLComponents componentsWithString:[NSString stringWithFormat:@"%@/check", self.apiBaseURL]];
    components.queryItems = @[
        [NSURLQueryItem queryItemWithName:@"ipAddress" value:indicator.value],
        [NSURLQueryItem queryItemWithName:@"maxAgeInDays" value:[NSString stringWithFormat:@"%ld", (long)self.maxAgeInDays]],
        [NSURLQueryItem queryItemWithName:@"verbose" value:@""]
    ];

    NSURL *url = components.URL;
    if (!url) {
        NSError *error = [NSError errorWithDomain:@"AbuseIPDBProvider"
                                             code:1005
                                         userInfo:@{NSLocalizedDescriptionKey: @"Invalid URL"}];
        if (completion) completion(nil, error);
        return;
    }

    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    [request setHTTPMethod:@"GET"];
    [request setValue:self.apiKey forHTTPHeaderField:@"Key"];
    [request setValue:@"application/json" forHTTPHeaderField:@"Accept"];

    SNBLogThreatIntelDebug("Querying IP: %{" SNB_IP_PRIVACY "}@", indicator.value);

    NSURLSessionDataTask *task = [self.session dataTaskWithRequest:request completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        if (error) {
            SNBLogThreatIntelWarn("Request failed: %{public}@", error.localizedDescription);
            if (completion) completion(nil, error);
            return;
        }

        NSHTTPURLResponse *httpResponse = (NSHTTPURLResponse *)response;

        // Handle HTTP errors
        if (httpResponse.statusCode == 401) {
            NSError *authError = [NSError errorWithDomain:@"AbuseIPDBProvider"
                                                     code:1003
                                                 userInfo:@{NSLocalizedDescriptionKey: @"Invalid API key"}];
            if (completion) completion(nil, authError);
            return;
        }

        if (httpResponse.statusCode == 422) {
            // Invalid IP address or parameter
            SNBLogThreatIntelDebug("Invalid IP or parameters: %{" SNB_IP_PRIVACY "}@", indicator.value);
            TIResult *result = [self createCleanResult:indicator];
            if (completion) completion(result, nil);
            return;
        }

        if (httpResponse.statusCode == 429) {
            SNBLogThreatIntelWarn("Rate limit (429) exceeded for AbuseIPDB IP: %{" SNB_IP_PRIVACY "}@", indicator.value);

            // Extract retry-after header if available
            NSString *retryAfterHeader = httpResponse.allHeaderFields[@"Retry-After"];
            NSTimeInterval retryDelay = retryAfterHeader ? [retryAfterHeader doubleValue] : 60.0;

            // Cap maximum retry delay at 120 seconds
            retryDelay = MIN(retryDelay, 120.0);

            NSError *rateError = [NSError errorWithDomain:@"AbuseIPDBProvider"
                                                     code:429
                                                 userInfo:@{
                                                     NSLocalizedDescriptionKey: @"Rate limit reached",
                                                     @"retry_after": @(retryDelay)
                                                 }];
            if (completion) completion(nil, rateError);
            return;
        }

        if (httpResponse.statusCode != 200) {
            NSError *httpError = [NSError errorWithDomain:@"AbuseIPDBProvider"
                                                     code:httpResponse.statusCode
                                                 userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"HTTP %ld", (long)httpResponse.statusCode]}];
            if (completion) completion(nil, httpError);
            return;
        }

        // Parse JSON response
        NSError *parseError = nil;
        NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:&parseError];

        if (parseError || !json) {
            SNBLogThreatIntelWarn("Failed to parse JSON: %{public}@", parseError.localizedDescription);
            if (completion) completion(nil, parseError);
            return;
        }

        // Parse and create result
        TIResult *result = [self parseAbuseIPDBResponse:json forIndicator:indicator];
        if (completion) completion(result, nil);
    }];

    [task resume];
}

#pragma mark - Response Parsing

- (TIResult *)parseAbuseIPDBResponse:(NSDictionary *)json forIndicator:(TIIndicator *)indicator {
    NSDictionary *data = json[@"data"];
    if (!data) {
        return [self createCleanResult:indicator];
    }

    // Parse key fields (handle NSNull safely)
    id abuseScoreObj = data[@"abuseConfidenceScore"];
    NSInteger abuseConfidenceScore = [abuseScoreObj respondsToSelector:@selector(integerValue)] ? [abuseScoreObj integerValue] : 0;

    id totalReportsObj = data[@"totalReports"];
    NSInteger totalReports = [totalReportsObj respondsToSelector:@selector(integerValue)] ? [totalReportsObj integerValue] : 0;

    id numDistinctUsersObj = data[@"numDistinctUsers"];
    NSInteger numDistinctUsers = [numDistinctUsersObj respondsToSelector:@selector(integerValue)] ? [numDistinctUsersObj integerValue] : 0;

    id isWhitelistedObj = data[@"isWhitelisted"];
    BOOL isWhitelisted = [isWhitelistedObj respondsToSelector:@selector(boolValue)] ? [isWhitelistedObj boolValue] : NO;

    // Safely extract strings (may be NSNull)
    id countryCodeObj = data[@"countryCode"];
    NSString *countryCode = [countryCodeObj isKindOfClass:[NSString class]] ? countryCodeObj : nil;

    id usageTypeObj = data[@"usageType"];
    NSString *usageType = [usageTypeObj isKindOfClass:[NSString class]] ? usageTypeObj : nil;

    id ispObj = data[@"isp"];
    NSString *isp = [ispObj isKindOfClass:[NSString class]] ? ispObj : nil;

    id domainObj = data[@"domain"];
    NSString *domain = [domainObj isKindOfClass:[NSString class]] ? domainObj : nil;

    id lastReportedAtObj = data[@"lastReportedAt"];
    NSString *lastReportedAt = [lastReportedAtObj isKindOfClass:[NSString class]] ? lastReportedAtObj : nil;

    SNBLogThreatIntelInfo("%{" SNB_IP_PRIVACY "}@ - Confidence: %ld%%, Reports: %ld, Users: %ld, Whitelisted: %{public}@",
                          indicator.value, (long)abuseConfidenceScore, (long)totalReports, (long)numDistinctUsers,
                          isWhitelisted ? @"YES" : @"NO");

    // Determine if malicious (abuse confidence > 50% or whitelisted but has reports)
    BOOL isMalicious = (abuseConfidenceScore > 50) || (!isWhitelisted && totalReports > 5);

    // Build categories
    NSMutableArray<NSString *> *categories = [NSMutableArray array];
    if (isWhitelisted) {
        [categories addObject:@"whitelisted"];
    }
    if (abuseConfidenceScore >= 75) {
        [categories addObject:@"high-confidence-abuse"];
    } else if (abuseConfidenceScore >= 50) {
        [categories addObject:@"moderate-abuse"];
    } else if (abuseConfidenceScore > 0) {
        [categories addObject:@"low-abuse"];
    }

    if (usageType) {
        [categories addObject:usageType];
    }

    // Parse reports for additional categories
    NSArray *reports = data[@"reports"];
    if (reports && [reports isKindOfClass:[NSArray class]]) {
        NSMutableSet<NSString *> *reportCategories = [NSMutableSet set];
        for (NSDictionary *report in reports) {
            NSArray *reportCats = report[@"categories"];
            if (reportCats && [reportCats isKindOfClass:[NSArray class]]) {
                for (NSNumber *categoryId in reportCats) {
                    NSString *catName = [self categoryNameForId:[categoryId integerValue]];
                    if (catName) {
                        [reportCategories addObject:catName];
                    }
                }
            }
        }

        // Add top 3 most common categories
        NSArray *sortedCategories = [[reportCategories allObjects] sortedArrayUsingSelector:@selector(compare:)];
        for (NSInteger i = 0; i < MIN(3, sortedCategories.count); i++) {
            [categories addObject:sortedCategories[i]];
        }
    }

    // Build metadata
    NSMutableDictionary *metadataDict = [NSMutableDictionary dictionary];
    metadataDict[@"abuse_confidence_score"] = @(abuseConfidenceScore);
    metadataDict[@"total_reports"] = @(totalReports);
    metadataDict[@"num_distinct_users"] = @(numDistinctUsers);
    metadataDict[@"is_whitelisted"] = @(isWhitelisted);

    if (countryCode) {
        metadataDict[@"country"] = countryCode;
    }
    if (isp) {
        metadataDict[@"isp"] = isp;
    }
    if (domain) {
        metadataDict[@"domain"] = domain;
    }
    if (usageType) {
        metadataDict[@"usage_type"] = usageType;
    }
    if (lastReportedAt) {
        metadataDict[@"last_reported_at"] = lastReportedAt;
    }

    // Create TIVerdict
    TIVerdict *verdict = [[TIVerdict alloc] init];
    verdict.hit = isMalicious;
    verdict.confidence = abuseConfidenceScore;  // Use abuse confidence directly
    verdict.categories = [categories copy];
    verdict.tags = @[];
    verdict.lastSeen = lastReportedAt ? [self parseISO8601Date:lastReportedAt] : nil;
    verdict.evidence = [metadataDict copy];

    // Create TIMetadata
    TIMetadata *metadata = [[TIMetadata alloc] init];
    metadata.sourceURL = [NSString stringWithFormat:@"https://www.abuseipdb.com/check/%@", indicator.value];
    metadata.fetchedAt = [NSDate date];
    metadata.ttlSeconds = isMalicious ? self.ttl : self.negTTL;
    metadata.expiresAt = [NSDate dateWithTimeIntervalSinceNow:metadata.ttlSeconds];
    metadata.rateLimitRemaining = -1;

    // Create TIResult
    TIResult *result = [[TIResult alloc] init];
    result.indicator = indicator;
    result.providerName = self.name;
    result.verdict = verdict;
    result.metadata = metadata;
    result.error = nil;

    return result;
}

- (TIResult *)createCleanResult:(TIIndicator *)indicator {
    // Create TIVerdict
    TIVerdict *verdict = [[TIVerdict alloc] init];
    verdict.hit = NO;
    verdict.confidence = 0;
    verdict.categories = @[];
    verdict.tags = @[];
    verdict.lastSeen = nil;
    verdict.evidence = @{};

    // Create TIMetadata
    TIMetadata *metadata = [[TIMetadata alloc] init];
    metadata.sourceURL = [NSString stringWithFormat:@"https://www.abuseipdb.com/check/%@", indicator.value];
    metadata.fetchedAt = [NSDate date];
    metadata.ttlSeconds = self.negTTL;
    metadata.expiresAt = [NSDate dateWithTimeIntervalSinceNow:self.negTTL];
    metadata.rateLimitRemaining = -1;

    // Create TIResult
    TIResult *result = [[TIResult alloc] init];
    result.indicator = indicator;
    result.providerName = self.name;
    result.verdict = verdict;
    result.metadata = metadata;
    result.error = nil;

    return result;
}

#pragma mark - Helpers

- (NSString *)categoryNameForId:(NSInteger)categoryId {
    // AbuseIPDB category mapping
    // https://www.abuseipdb.com/categories
    static NSDictionary *categoryMap = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        categoryMap = @{
            @3: @"Fraud Orders",
            @4: @"DDoS Attack",
            @5: @"FTP Brute-Force",
            @6: @"Ping of Death",
            @7: @"Phishing",
            @8: @"Fraud VoIP",
            @9: @"Open Proxy",
            @10: @"Web Spam",
            @11: @"Email Spam",
            @12: @"Blog Spam",
            @13: @"VPN IP",
            @14: @"Port Scan",
            @15: @"Hacking",
            @16: @"SQL Injection",
            @17: @"Spoofing",
            @18: @"Brute-Force",
            @19: @"Bad Web Bot",
            @20: @"Exploited Host",
            @21: @"Web App Attack",
            @22: @"SSH",
            @23: @"IoT Targeted"
        };
    });

    return categoryMap[@(categoryId)];
}

- (NSDate *)parseISO8601Date:(NSString *)dateString {
    if (!dateString || ![dateString isKindOfClass:[NSString class]] || dateString.length == 0) {
        return nil;
    }

    NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
    formatter.dateFormat = @"yyyy-MM-dd'T'HH:mm:ssZZZZZ";
    formatter.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
    formatter.timeZone = [NSTimeZone timeZoneForSecondsFromGMT:0];

    return [formatter dateFromString:dateString];
}

@end

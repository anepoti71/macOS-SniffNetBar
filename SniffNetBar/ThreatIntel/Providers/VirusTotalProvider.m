//
//  VirusTotalProvider.m
//  SniffNetBar
//
//  VirusTotal API v3 threat intelligence provider
//

#import "VirusTotalProvider.h"
#import "Logger.h"

static NSTimeInterval const kDefaultTTL = 86400.0;  // 24 hours
static NSTimeInterval const kDefaultNegativeTTL = 3600.0;  // 1 hour

@interface VirusTotalProvider ()
@property (nonatomic, strong) NSString *apiBaseURL;
@property (nonatomic, strong) NSString *apiKey;
@property (nonatomic, strong) NSURLSession *session;
@property (nonatomic, assign) NSTimeInterval timeout;
@property (nonatomic, assign) NSInteger maxRequestsPerMin;
@property (nonatomic, assign) NSTimeInterval ttl;
@property (nonatomic, assign) NSTimeInterval negTTL;

// Rate limiting
@property (nonatomic, strong) dispatch_queue_t rateLimitQueue;
@property (nonatomic, strong) NSMutableArray<NSDate *> *requestTimestamps;
@end

@implementation VirusTotalProvider

- (instancetype)init {
    return [self initWithTTL:kDefaultTTL negativeTTL:kDefaultNegativeTTL];
}

- (instancetype)initWithTTL:(NSTimeInterval)ttl negativeTTL:(NSTimeInterval)negativeTTL {
    self = [super init];
    if (self) {
        _ttl = ttl;
        _negTTL = negativeTTL;
        _rateLimitQueue = dispatch_queue_create("com.sniffnetbar.virustotal.ratelimit", DISPATCH_QUEUE_SERIAL);
        _requestTimestamps = [NSMutableArray array];
        _timeout = 10.0;
        _maxRequestsPerMin = 4;  // Free API tier limit
    }
    return self;
}

#pragma mark - ThreatIntelProvider Protocol

- (NSString *)name {
    return @"VirusTotal";
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
    [self configureWithBaseURL:@"https://www.virustotal.com/api/v3"
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
        NSError *error = [NSError errorWithDomain:@"VirusTotalProvider"
                                             code:1001
                                         userInfo:@{NSLocalizedDescriptionKey: @"API key is required"}];
        if (completion) completion(error);
        return;
    }

    self.apiBaseURL = baseURL.length > 0 ? baseURL : @"https://www.virustotal.com/api/v3";
    self.apiKey = apiKey;
    self.timeout = timeout;
    self.maxRequestsPerMin = maxRequestsPerMin;

    NSURLSessionConfiguration *config = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    config.timeoutIntervalForRequest = timeout;
    config.timeoutIntervalForResource = timeout * 2;
    config.URLCache = nil;
    config.requestCachePolicy = NSURLRequestReloadIgnoringLocalCacheData;
    self.session = [NSURLSession sessionWithConfiguration:config];

    SNBLogThreatIntelInfo("Configured with API key (rate limit: %ld req/min, URL: %{public}@)",
                          (long)maxRequestsPerMin, self.apiBaseURL);

    if (completion) completion(nil);
}

- (void)isHealthyWithCompletion:(void (^)(BOOL))completion {
    // Simple health check - verify API key is set and session exists
    BOOL healthy = (self.apiKey.length > 0 && self.session != nil);
    if (completion) completion(healthy);
}

- (BOOL)supportsIndicatorType:(TIIndicatorType)type {
    return (type == TIIndicatorTypeIPv4 || type == TIIndicatorTypeIPv6);
}

- (void)enrichIndicator:(TIIndicator *)indicator
             completion:(void (^)(TIResult *, NSError *))completion {
    if (!self.apiKey || self.apiKey.length == 0) {
        NSError *error = [NSError errorWithDomain:@"VirusTotalProvider"
                                             code:1001
                                         userInfo:@{NSLocalizedDescriptionKey: @"Provider not configured"}];
        if (completion) completion(nil, error);
        return;
    }

    if (![self supportsIndicatorType:indicator.type]) {
        NSError *error = [NSError errorWithDomain:@"VirusTotalProvider"
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

        [self.requestTimestamps addObject:[NSDate date]];
        if (block) block();
    });
}

#pragma mark - API Request

- (void)performEnrichment:(TIIndicator *)indicator
               completion:(void (^)(TIResult *, NSError *))completion {
    NSString *urlString = [NSString stringWithFormat:@"%@/ip_addresses/%@", self.apiBaseURL, indicator.value];
    NSURL *url = [NSURL URLWithString:urlString];

    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    [request setHTTPMethod:@"GET"];
    [request setValue:self.apiKey forHTTPHeaderField:@"x-apikey"];
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
            NSError *authError = [NSError errorWithDomain:@"VirusTotalProvider"
                                                     code:1003
                                                 userInfo:@{NSLocalizedDescriptionKey: @"Invalid API key"}];
            if (completion) completion(nil, authError);
            return;
        }

        if (httpResponse.statusCode == 404) {
            // IP not found in VT database - return clean result
            SNBLogThreatIntelDebug("IP not found in database: %{" SNB_IP_PRIVACY "}@", indicator.value);
            TIResult *result = [self createCleanResult:indicator];
            if (completion) completion(result, nil);
            return;
        }

        if (httpResponse.statusCode == 429) {
            SNBLogThreatIntelWarn("Rate limit (429) exceeded for VirusTotal IP: %{" SNB_IP_PRIVACY "}@", indicator.value);

            // Extract retry-after header if available
            NSString *retryAfterHeader = httpResponse.allHeaderFields[@"Retry-After"];
            NSTimeInterval retryDelay = retryAfterHeader ? [retryAfterHeader doubleValue] : 60.0;

            // Cap maximum retry delay at 120 seconds
            retryDelay = MIN(retryDelay, 120.0);

            NSError *rateError = [NSError errorWithDomain:@"VirusTotalProvider"
                                                     code:429
                                                 userInfo:@{
                                                     NSLocalizedDescriptionKey: @"Rate limit reached",
                                                     @"retry_after": @(retryDelay)
                                                 }];
            if (completion) completion(nil, rateError);
            return;
        }

        if (httpResponse.statusCode != 200) {
            NSError *httpError = [NSError errorWithDomain:@"VirusTotalProvider"
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
        TIResult *result = [self parseVirusTotalResponse:json forIndicator:indicator];
        if (completion) completion(result, nil);
    }];

    [task resume];
}

#pragma mark - Response Parsing

- (TIResult *)parseVirusTotalResponse:(NSDictionary *)json forIndicator:(TIIndicator *)indicator {
    NSDictionary *data = json[@"data"];
    if (!data) {
        return [self createCleanResult:indicator];
    }

    NSDictionary *attributes = data[@"attributes"];
    if (!attributes) {
        return [self createCleanResult:indicator];
    }

    // Parse analysis stats
    NSDictionary *stats = attributes[@"last_analysis_stats"];
    NSInteger harmless = [stats[@"harmless"] integerValue];
    NSInteger malicious = [stats[@"malicious"] integerValue];
    NSInteger suspicious = [stats[@"suspicious"] integerValue];
    NSInteger undetected = [stats[@"undetected"] integerValue];
    NSInteger timeout = [stats[@"timeout"] integerValue];

    NSInteger totalVotes = harmless + malicious + suspicious + undetected + timeout;

    SNBLogThreatIntelInfo("%{" SNB_IP_PRIVACY "}@ - Malicious: %ld, Suspicious: %ld, Harmless: %ld, Total: %ld",
                          indicator.value, (long)malicious, (long)suspicious, (long)harmless, (long)totalVotes);

    // Calculate confidence (0-100)
    NSInteger confidence = 0;
    if (totalVotes > 0) {
        // Weight malicious votes higher than suspicious
        NSInteger weightedBadVotes = (malicious * 2) + suspicious;
        confidence = (weightedBadVotes * 100) / (totalVotes * 2);
        confidence = MIN(100, confidence);  // Cap at 100
    }

    // Determine if it's malicious
    BOOL isMalicious = (malicious > 0 || suspicious > 2);

    // Extract categories
    NSMutableArray<NSString *> *categories = [NSMutableArray array];
    if (malicious > 0) {
        [categories addObject:@"malicious"];
    }
    if (suspicious > 0) {
        [categories addObject:@"suspicious"];
    }

    // Extract additional context from analysis results
    NSDictionary *analysisResults = attributes[@"last_analysis_results"];
    if (analysisResults) {
        NSMutableSet<NSString *> *detectedCategories = [NSMutableSet set];
        for (NSString *engineName in analysisResults) {
            NSDictionary *engineResult = analysisResults[engineName];
            NSString *category = engineResult[@"category"];
            NSString *result = engineResult[@"result"];

            if ([category isEqualToString:@"malicious"] && result) {
                [detectedCategories addObject:result];
            }
        }

        // Add top 3 most common detection names
        NSArray *sortedCategories = [[detectedCategories allObjects] sortedArrayUsingSelector:@selector(compare:)];
        for (NSInteger i = 0; i < MIN(3, sortedCategories.count); i++) {
            [categories addObject:sortedCategories[i]];
        }
    }

    // Build metadata
    NSMutableDictionary *metadataDict = [NSMutableDictionary dictionary];
    metadataDict[@"harmless"] = @(harmless);
    metadataDict[@"malicious"] = @(malicious);
    metadataDict[@"suspicious"] = @(suspicious);
    metadataDict[@"undetected"] = @(undetected);
    metadataDict[@"total_votes"] = @(totalVotes);

    if (attributes[@"as_owner"]) {
        metadataDict[@"as_owner"] = attributes[@"as_owner"];
    }
    if (attributes[@"country"]) {
        metadataDict[@"country"] = attributes[@"country"];
    }

    // Create TIVerdict
    TIVerdict *verdict = [[TIVerdict alloc] init];
    verdict.hit = isMalicious;
    verdict.confidence = confidence;
    verdict.categories = [categories copy];
    verdict.tags = @[];
    verdict.lastSeen = [NSDate date];
    verdict.evidence = [metadataDict copy];

    // Create TIMetadata
    TIMetadata *metadata = [[TIMetadata alloc] init];
    metadata.sourceURL = [NSString stringWithFormat:@"https://www.virustotal.com/gui/ip-address/%@", indicator.value];
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
    metadata.sourceURL = [NSString stringWithFormat:@"https://www.virustotal.com/gui/ip-address/%@", indicator.value];
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

@end

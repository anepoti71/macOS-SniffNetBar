//
//  ShodanProvider.m
//  SniffNetBar
//
//  Shodan API threat intelligence provider
//

#import "ShodanProvider.h"
#import "Logger.h"

static NSTimeInterval const kDefaultTTL = 86400.0;  // 24 hours
static NSTimeInterval const kDefaultNegativeTTL = 3600.0;  // 1 hour

@interface ShodanProvider ()
@property (nonatomic, copy) NSString *apiBaseURL;
@property (nonatomic, copy) NSString *apiKey;
@property (nonatomic, strong) NSURLSession *session;
@property (nonatomic, assign) NSTimeInterval timeout;
@property (nonatomic, assign) NSInteger maxRequestsPerMin;
@property (nonatomic, assign) NSTimeInterval ttl;
@property (nonatomic, assign) NSTimeInterval negTTL;

@property (nonatomic, strong) dispatch_queue_t rateLimitQueue;
@property (nonatomic, strong) NSMutableArray<NSDate *> *requestTimestamps;
@end

@implementation ShodanProvider

- (instancetype)init {
    return [self initWithTTL:kDefaultTTL negativeTTL:kDefaultNegativeTTL];
}

- (instancetype)initWithTTL:(NSTimeInterval)ttl negativeTTL:(NSTimeInterval)negativeTTL {
    self = [super init];
    if (self) {
        _ttl = ttl;
        _negTTL = negativeTTL;
        _timeout = 10.0;
        _maxRequestsPerMin = 60;
        _rateLimitQueue = dispatch_queue_create("com.sniffnetbar.shodan.ratelimit", DISPATCH_QUEUE_SERIAL);
        _requestTimestamps = [NSMutableArray array];
    }
    return self;
}

#pragma mark - ThreatIntelProvider Protocol

- (NSString *)name {
    return @"Shodan";
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
    [self configureWithBaseURL:@"https://api.shodan.io"
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
    if (apiKey.length == 0) {
        NSError *error = [NSError errorWithDomain:@"ShodanProvider"
                                             code:1001
                                         userInfo:@{NSLocalizedDescriptionKey: @"API key is required"}];
        if (completion) completion(error);
        return;
    }

    NSString *normalized = baseURL.length > 0 ? baseURL : @"https://api.shodan.io";
    if ([normalized hasSuffix:@"/"]) {
        normalized = [normalized substringToIndex:normalized.length - 1];
    }

    self.apiBaseURL = normalized;
    self.apiKey = apiKey;
    self.timeout = timeout;
    self.maxRequestsPerMin = maxRequestsPerMin;

    NSURLSessionConfiguration *config = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    config.timeoutIntervalForRequest = timeout;
    config.timeoutIntervalForResource = timeout * 2;
    config.URLCache = nil;
    config.requestCachePolicy = NSURLRequestReloadIgnoringLocalCacheData;
    self.session = [NSURLSession sessionWithConfiguration:config];

    SNBLogThreatIntelInfo("Configured with API key (length=%lu, rate limit: %ld req/min, URL: %{public}@)",
                          (unsigned long)self.apiKey.length,
                          (long)maxRequestsPerMin,
                          self.apiBaseURL);

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
        NSError *error = [NSError errorWithDomain:@"ShodanProvider"
                                             code:1001
                                         userInfo:@{NSLocalizedDescriptionKey: @"Provider not configured"}];
        if (completion) completion(nil, error);
        return;
    }

    if (![self supportsIndicatorType:indicator.type]) {
        NSError *error = [NSError errorWithDomain:@"ShodanProvider"
                                             code:1002
                                         userInfo:@{NSLocalizedDescriptionKey: @"Unsupported indicator type"}];
        if (completion) completion(nil, error);
        return;
    }

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
        NSDate *oneMinuteAgo = [NSDate dateWithTimeIntervalSinceNow:-60.0];
        [self.requestTimestamps filterUsingPredicate:[NSPredicate predicateWithBlock:^BOOL(NSDate *timestamp, NSDictionary *bindings) {
            return [timestamp compare:oneMinuteAgo] == NSOrderedDescending;
        }]];

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
    NSURL *baseURL = [NSURL URLWithString:self.apiBaseURL];
    NSURL *url = nil;
    if (baseURL) {
        NSURL *hostURL = [[baseURL URLByAppendingPathComponent:@"shodan"] URLByAppendingPathComponent:@"host"];
        hostURL = [hostURL URLByAppendingPathComponent:indicator.value];
        NSURLComponents *components = [NSURLComponents componentsWithURL:hostURL resolvingAgainstBaseURL:NO];
        components.queryItems = @[
            [NSURLQueryItem queryItemWithName:@"key" value:self.apiKey]
        ];
        url = components.URL;
    }
    if (!url) {
        NSError *error = [NSError errorWithDomain:@"ShodanProvider"
                                             code:1004
                                         userInfo:@{NSLocalizedDescriptionKey: @"Invalid URL"}];
        if (completion) completion(nil, error);
        return;
    }

    NSURLComponents *sanitizedComponents = [NSURLComponents componentsWithURL:url resolvingAgainstBaseURL:NO];
    sanitizedComponents.queryItems = @[
        [NSURLQueryItem queryItemWithName:@"key" value:@"***"]
    ];
    NSString *sanitizedURL = sanitizedComponents.URL.absoluteString ?: @"(invalid)";
    SNBLogThreatIntelDebug("Shodan request URL: %{public}@ (key length=%lu)",
                           sanitizedURL,
                           (unsigned long)self.apiKey.length);

    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    [request setHTTPMethod:@"GET"];
    [request setValue:@"application/json" forHTTPHeaderField:@"Accept"];

    SNBLogThreatIntelDebug("Querying IP: %{" SNB_IP_PRIVACY "}@", indicator.value);

    NSURLSessionDataTask *task = [self.session dataTaskWithRequest:request completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        if (error) {
            SNBLogThreatIntelWarn("Request failed: %{public}@", error.localizedDescription);
            if (completion) completion(nil, error);
            return;
        }

        NSHTTPURLResponse *httpResponse = (NSHTTPURLResponse *)response;
        NSInteger statusCode = httpResponse.statusCode;
        NSString *responseText = nil;
        if (data.length > 0) {
            responseText = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            if (!responseText) {
                responseText = [[NSString alloc] initWithData:data encoding:NSISOLatin1StringEncoding];
            }
        }
        NSString *trimmedResponse = nil;
        if (responseText.length > 0) {
            trimmedResponse = [responseText stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
            if (trimmedResponse.length > 300) {
                trimmedResponse = [[trimmedResponse substringToIndex:300] stringByAppendingString:@"..."];
            }
        }

        if (statusCode == 401 || statusCode == 403) {
            if (trimmedResponse.length > 0) {
                SNBLogThreatIntelWarn("Shodan auth response (status=%ld): %{public}@",
                                      (long)statusCode,
                                      trimmedResponse);
            }
            NSString *responseMessage = nil;
            if (data.length > 0) {
                NSDictionary *errorJSON = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
                if ([errorJSON isKindOfClass:[NSDictionary class]]) {
                    NSString *errorText = errorJSON[@"error"];
                    if ([errorText isKindOfClass:[NSString class]] && errorText.length > 0) {
                        responseMessage = errorText;
                    }
                }
            }
            NSString *message = responseMessage.length > 0
                ? [NSString stringWithFormat:@"Authentication failed (%@)", responseMessage]
                : @"Authentication failed (check API key)";
            NSError *authError = [NSError errorWithDomain:@"ShodanProvider"
                                                     code:1003
                                                 userInfo:@{NSLocalizedDescriptionKey: message}];
            if (completion) completion(nil, authError);
            return;
        }

        if (statusCode == 404) {
            TIResult *result = [self createCleanResult:indicator];
            if (completion) completion(result, nil);
            return;
        }

        if (statusCode == 429) {
            SNBLogThreatIntelWarn("Rate limit (429) exceeded for Shodan IP: %{" SNB_IP_PRIVACY "}@", indicator.value);
            if (trimmedResponse.length > 0) {
                SNBLogThreatIntelWarn("Shodan rate limit response: %{public}@", trimmedResponse);
            }

            NSString *retryAfterHeader = httpResponse.allHeaderFields[@"Retry-After"];
            NSTimeInterval retryDelay = retryAfterHeader ? [retryAfterHeader doubleValue] : 60.0;
            retryDelay = MIN(retryDelay, 120.0);

            NSError *rateError = [NSError errorWithDomain:@"ShodanProvider"
                                                     code:429
                                                 userInfo:@{
                                                     NSLocalizedDescriptionKey: @"Rate limit reached",
                                                     @"retry_after": @(retryDelay)
                                                 }];
            if (completion) completion(nil, rateError);
            return;
        }

        if (statusCode != 200) {
            if (trimmedResponse.length > 0) {
                SNBLogThreatIntelWarn("Shodan error response (status=%ld): %{public}@",
                                      (long)statusCode,
                                      trimmedResponse);
            }
            NSError *httpError = [NSError errorWithDomain:@"ShodanProvider"
                                                     code:statusCode
                                                 userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"HTTP %ld", (long)statusCode]}];
            if (completion) completion(nil, httpError);
            return;
        }

        NSError *parseError = nil;
        NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:&parseError];
        if (parseError || ![json isKindOfClass:[NSDictionary class]]) {
            SNBLogThreatIntelWarn("Failed to parse JSON: %{public}@", parseError.localizedDescription);
            NSError *error = [NSError errorWithDomain:@"ShodanProvider"
                                                 code:1005
                                             userInfo:@{NSLocalizedDescriptionKey: @"Failed to parse response"}];
            if (completion) completion(nil, error);
            return;
        }

        TIResult *result = [self buildResultFromJSON:json indicator:indicator response:httpResponse];
        if (completion) completion(result, nil);
    }];

    [task resume];
}

- (TIResult *)buildResultFromJSON:(NSDictionary *)json
                        indicator:(TIIndicator *)indicator
                         response:(NSHTTPURLResponse *)response {
    NSArray *tags = [json[@"tags"] isKindOfClass:[NSArray class]] ? json[@"tags"] : @[];
    NSArray *ports = [json[@"ports"] isKindOfClass:[NSArray class]] ? json[@"ports"] : @[];
    NSDictionary *vulns = [json[@"vulns"] isKindOfClass:[NSDictionary class]] ? json[@"vulns"] : nil;
    NSArray *vulnList = [json[@"vulns"] isKindOfClass:[NSArray class]] ? json[@"vulns"] : nil;

    NSUInteger vulnCount = vulns ? vulns.count : (vulnList ? vulnList.count : 0);
    BOOL hasVulns = vulnCount > 0;

    NSSet<NSString *> *suspiciousTags = [NSSet setWithArray:@[
        @"malware", @"botnet", @"c2", @"command-and-control",
        @"compromised", @"phishing", @"spam", @"scanner", @"vulnerable"
    ]];

    BOOL suspicious = NO;
    NSMutableArray<NSString *> *categories = [NSMutableArray array];
    NSMutableArray<NSString *> *normalizedTags = [NSMutableArray array];
    for (NSString *tag in tags) {
        if (![tag isKindOfClass:[NSString class]]) {
            continue;
        }
        NSString *lower = tag.lowercaseString;
        [normalizedTags addObject:tag];
        if ([suspiciousTags containsObject:lower]) {
            suspicious = YES;
            [categories addObject:tag];
        }
    }

    if (hasVulns) {
        [categories addObject:@"vulnerability"];
    }

    BOOL hit = hasVulns || suspicious;
    NSInteger confidence = 0;
    if (hasVulns) {
        confidence = 80;
    } else if (suspicious) {
        confidence = 60;
    }

    NSMutableDictionary *evidence = [NSMutableDictionary dictionary];
    evidence[@"port_count"] = @(ports.count);
    evidence[@"ports"] = ports;
    if (normalizedTags.count > 0) {
        evidence[@"tags"] = normalizedTags;
    }
    if (vulnCount > 0) {
        evidence[@"vuln_count"] = @(vulnCount);
    }
    NSString *org = [json[@"org"] isKindOfClass:[NSString class]] ? json[@"org"] : nil;
    if (org.length > 0) {
        evidence[@"org"] = org;
    }

    TIVerdict *verdict = [[TIVerdict alloc] init];
    verdict.hit = hit;
    verdict.confidence = confidence;
    verdict.categories = [categories copy];
    verdict.tags = [normalizedTags copy];
    verdict.lastSeen = nil;
    verdict.evidence = [evidence copy];

    TIMetadata *metadata = [[TIMetadata alloc] init];
    metadata.sourceURL = [NSString stringWithFormat:@"https://www.shodan.io/host/%@", indicator.value];
    metadata.fetchedAt = [NSDate date];
    metadata.ttlSeconds = hit ? self.ttl : self.negTTL;
    metadata.expiresAt = [NSDate dateWithTimeIntervalSinceNow:metadata.ttlSeconds];
    NSString *remainingHeader = response.allHeaderFields[@"X-RateLimit-Remaining"];
    metadata.rateLimitRemaining = remainingHeader ? [remainingHeader integerValue] : -1;

    TIResult *result = [[TIResult alloc] init];
    result.indicator = indicator;
    result.providerName = self.name;
    result.verdict = verdict;
    result.metadata = metadata;
    result.error = nil;

    return result;
}

- (TIResult *)createCleanResult:(TIIndicator *)indicator {
    TIVerdict *verdict = [[TIVerdict alloc] init];
    verdict.hit = NO;
    verdict.confidence = 0;
    verdict.categories = @[];
    verdict.tags = @[];
    verdict.lastSeen = nil;
    verdict.evidence = @{};

    TIMetadata *metadata = [[TIMetadata alloc] init];
    metadata.sourceURL = [NSString stringWithFormat:@"https://www.shodan.io/host/%@", indicator.value];
    metadata.fetchedAt = [NSDate date];
    metadata.ttlSeconds = self.negTTL;
    metadata.expiresAt = [NSDate dateWithTimeIntervalSinceNow:self.negTTL];
    metadata.rateLimitRemaining = -1;

    TIResult *result = [[TIResult alloc] init];
    result.indicator = indicator;
    result.providerName = self.name;
    result.verdict = verdict;
    result.metadata = metadata;
    result.error = nil;

    return result;
}

@end

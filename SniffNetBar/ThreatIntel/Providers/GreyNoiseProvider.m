//
//  GreyNoiseProvider.m
//  SniffNetBar
//
//  GreyNoise Community API threat intelligence provider
//

#import "GreyNoiseProvider.h"
#import "Logger.h"

static NSTimeInterval const kDefaultTTL = 86400.0;  // 24 hours
static NSTimeInterval const kDefaultNegativeTTL = 3600.0;  // 1 hour

@interface GreyNoiseProvider ()
@property (nonatomic, strong) NSString *apiBaseURL;
@property (nonatomic, strong) NSString *apiKey;
@property (nonatomic, strong) NSURLSession *session;
@property (nonatomic, assign) NSTimeInterval timeout;
@property (nonatomic, assign) NSInteger maxRequestsPerMin;
@property (nonatomic, assign) NSTimeInterval ttl;
@property (nonatomic, assign) NSTimeInterval negTTL;

@property (nonatomic, strong) dispatch_queue_t rateLimitQueue;
@property (nonatomic, strong) NSMutableArray<NSDate *> *requestTimestamps;
@end

@implementation GreyNoiseProvider

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
        _rateLimitQueue = dispatch_queue_create("com.sniffnetbar.greynoise.ratelimit", DISPATCH_QUEUE_SERIAL);
        _requestTimestamps = [NSMutableArray array];
    }
    return self;
}

#pragma mark - ThreatIntelProvider Protocol

- (NSString *)name {
    return @"GreyNoise";
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
    [self configureWithBaseURL:@"https://api.greynoise.io/v3"
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
        NSError *error = [NSError errorWithDomain:@"GreyNoiseProvider"
                                             code:1001
                                         userInfo:@{NSLocalizedDescriptionKey: @"API key is required"}];
        if (completion) completion(error);
        return;
    }

    NSString *normalized = baseURL.length > 0 ? baseURL : @"https://api.greynoise.io/v3";
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

    SNBLogThreatIntelInfo("Configured with API key (rate limit: %ld req/min, URL: %{public}@)",
                          (long)maxRequestsPerMin, self.apiBaseURL);

    if (completion) completion(nil);
}

- (void)isHealthyWithCompletion:(void (^)(BOOL))completion {
    BOOL healthy = (self.apiKey.length > 0 && self.session != nil);
    if (completion) completion(healthy);
}

- (BOOL)supportsIndicatorType:(TIIndicatorType)type {
    return (type == TIIndicatorTypeIPv4);
}

- (void)enrichIndicator:(TIIndicator *)indicator
             completion:(void (^)(TIResult *, NSError *))completion {
    if (!self.apiKey || self.apiKey.length == 0) {
        NSError *error = [NSError errorWithDomain:@"GreyNoiseProvider"
                                             code:1001
                                         userInfo:@{NSLocalizedDescriptionKey: @"Provider not configured"}];
        if (completion) completion(nil, error);
        return;
    }

    if (![self supportsIndicatorType:indicator.type]) {
        NSError *error = [NSError errorWithDomain:@"GreyNoiseProvider"
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
    NSString *urlString = [NSString stringWithFormat:@"%@/community/%@", self.apiBaseURL, indicator.value];
    NSURL *url = [NSURL URLWithString:urlString];

    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    [request setHTTPMethod:@"GET"];
    [request setValue:self.apiKey forHTTPHeaderField:@"key"];
    [request setValue:@"application/json" forHTTPHeaderField:@"Accept"];

    SNBLogThreatIntelDebug("Querying IP: %{" SNB_IP_PRIVACY "}@", indicator.value);

    NSURLSessionDataTask *task = [self.session dataTaskWithRequest:request completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        if (error) {
            SNBLogThreatIntelWarn("Request failed: %{public}@", error.localizedDescription);
            if (completion) completion(nil, error);
            return;
        }

        NSHTTPURLResponse *httpResponse = (NSHTTPURLResponse *)response;

        if (httpResponse.statusCode == 401) {
            NSError *authError = [NSError errorWithDomain:@"GreyNoiseProvider"
                                                     code:1003
                                                 userInfo:@{NSLocalizedDescriptionKey: @"Invalid API key"}];
            if (completion) completion(nil, authError);
            return;
        }

        if (httpResponse.statusCode == 404) {
            TIResult *result = [self createCleanResult:indicator];
            if (completion) completion(result, nil);
            return;
        }

        if (httpResponse.statusCode == 429) {
            SNBLogThreatIntelWarn("Rate limit (429) exceeded for GreyNoise IP: %{" SNB_IP_PRIVACY "}@", indicator.value);

            NSString *retryAfterHeader = httpResponse.allHeaderFields[@"Retry-After"];
            NSTimeInterval retryDelay = retryAfterHeader ? [retryAfterHeader doubleValue] : 60.0;
            retryDelay = MIN(retryDelay, 120.0);

            NSError *rateError = [NSError errorWithDomain:@"GreyNoiseProvider"
                                                     code:429
                                                 userInfo:@{
                                                     NSLocalizedDescriptionKey: @"Rate limit reached",
                                                     @"retry_after": @(retryDelay)
                                                 }];
            if (completion) completion(nil, rateError);
            return;
        }

        if (httpResponse.statusCode != 200) {
            NSError *httpError = [NSError errorWithDomain:@"GreyNoiseProvider"
                                                     code:httpResponse.statusCode
                                                 userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"HTTP %ld", (long)httpResponse.statusCode]}];
            if (completion) completion(nil, httpError);
            return;
        }

        NSError *parseError = nil;
        NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:&parseError];
        if (parseError || !json) {
            SNBLogThreatIntelWarn("Failed to parse JSON: %{public}@", parseError.localizedDescription);
            if (completion) completion(nil, parseError);
            return;
        }

        TIResult *result = [self parseGreyNoiseResponse:json forIndicator:indicator];
        if (completion) completion(result, nil);
    }];

    [task resume];
}

#pragma mark - Response Parsing

- (TIResult *)parseGreyNoiseResponse:(NSDictionary *)json forIndicator:(TIIndicator *)indicator {
    BOOL noise = NO;
    BOOL riot = NO;
    NSString *code = nil;
    NSString *message = nil;
    NSString *name = nil;
    NSString *link = nil;

    id noiseObj = json[@"noise"];
    if ([noiseObj respondsToSelector:@selector(boolValue)]) {
        noise = [noiseObj boolValue];
    }

    id riotObj = json[@"riot"];
    if ([riotObj respondsToSelector:@selector(boolValue)]) {
        riot = [riotObj boolValue];
    }

    id codeObj = json[@"code"];
    if ([codeObj isKindOfClass:[NSString class]]) {
        code = codeObj;
    }

    id messageObj = json[@"message"];
    if ([messageObj isKindOfClass:[NSString class]]) {
        message = messageObj;
    }

    id nameObj = json[@"name"];
    if ([nameObj isKindOfClass:[NSString class]]) {
        name = nameObj;
    }

    id linkObj = json[@"link"];
    if ([linkObj isKindOfClass:[NSString class]]) {
        link = linkObj;
    }

    NSMutableArray<NSString *> *categories = [NSMutableArray array];
    if (noise) {
        [categories addObject:@"benign-noise"];
    }
    if (riot) {
        [categories addObject:@"known-benign"];
    }
    if (name.length > 0) {
        [categories addObject:name];
    }

    NSMutableDictionary *metadataDict = [NSMutableDictionary dictionary];
    metadataDict[@"noise"] = @(noise);
    metadataDict[@"riot"] = @(riot);
    if (code) {
        metadataDict[@"code"] = code;
    }
    if (message) {
        metadataDict[@"message"] = message;
    }
    if (name) {
        metadataDict[@"name"] = name;
    }
    if (link) {
        metadataDict[@"link"] = link;
    }

    TIVerdict *verdict = [[TIVerdict alloc] init];
    verdict.hit = NO;
    verdict.confidence = 0;
    verdict.categories = [categories copy];
    verdict.tags = @[];
    verdict.lastSeen = nil;
    verdict.evidence = [metadataDict copy];

    BOOL cacheAsKnown = noise || riot;

    TIMetadata *metadata = [[TIMetadata alloc] init];
    metadata.sourceURL = link.length > 0 ? link : [NSString stringWithFormat:@"https://viz.greynoise.io/ip/%@", indicator.value];
    metadata.fetchedAt = [NSDate date];
    metadata.ttlSeconds = cacheAsKnown ? self.ttl : self.negTTL;
    metadata.expiresAt = [NSDate dateWithTimeIntervalSinceNow:metadata.ttlSeconds];
    metadata.rateLimitRemaining = -1;

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
    metadata.sourceURL = [NSString stringWithFormat:@"https://viz.greynoise.io/ip/%@", indicator.value];
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

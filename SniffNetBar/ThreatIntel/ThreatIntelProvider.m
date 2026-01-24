//
//  ThreatIntelProvider.m
//  SniffNetBar
//

#import "ThreatIntelProvider.h"
#import "ConfigurationManager.h"

// MARK: - Simple In-Memory Provider Implementation

@interface TISimpleProvider ()
@property (nonatomic, strong) NSMutableDictionary<NSString *, NSDictionary *> *maliciousSet;
@property (nonatomic, assign) NSTimeInterval timeout;
@end

@implementation TISimpleProvider

@synthesize name = _name;
@synthesize defaultTTL = _defaultTTL;
@synthesize negativeCacheTTL = _negativeCacheTTL;

- (instancetype)initWithName:(NSString *)name {
    self = [super init];
    if (self) {
        _name = [name copy];
        _defaultTTL = 21600; // 6 hours
        _negativeCacheTTL = 43200; // 12 hours
        _maliciousSet = [NSMutableDictionary dictionary];
        _timeout = 1.0;
    }
    return self;
}

- (void)configureWithAPIKey:(NSString *)apiKey
                    timeout:(NSTimeInterval)timeout
          maxRequestsPerMin:(NSInteger)maxRequestsPerMin
                 completion:(void (^)(NSError *))completion {
    _timeout = timeout;
    if (completion) {
        completion(nil); // Success
    }
}

- (void)isHealthyWithCompletion:(void (^)(BOOL))completion {
    if (completion) {
        completion(YES);
    }
}

- (void)enrichIndicator:(TIIndicator *)indicator
             completion:(void (^)(TIResult *, NSError *))completion {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        // Simulate async operation
        usleep((useconds_t)(self.timeout * 100000)); // Small delay

        TIResult *result = [[TIResult alloc] init];
        result.indicator = indicator;
        result.providerName = self.name;

        // Check if indicator is in malicious set
        NSDictionary *entry = self.maliciousSet[indicator.value];

        TIVerdict *verdict = [[TIVerdict alloc] init];
        if (entry) {
            verdict.hit = YES;
            verdict.confidence = [entry[@"confidence"] integerValue];
            verdict.categories = entry[@"categories"];
            verdict.tags = @[self.name];
            verdict.lastSeen = entry[@"lastSeen"];
        } else {
            verdict.hit = NO;
            verdict.confidence = 0;
            verdict.categories = @[];
            verdict.tags = @[];
        }
        result.verdict = verdict;

        // Metadata
        TIMetadata *metadata = [[TIMetadata alloc] init];
        metadata.fetchedAt = [NSDate date];
        NSTimeInterval ttl = verdict.hit ? self.defaultTTL : self.negativeCacheTTL;
        metadata.expiresAt = [NSDate dateWithTimeIntervalSinceNow:ttl];
        metadata.ttlSeconds = ttl;
        result.metadata = metadata;

        dispatch_async(dispatch_get_main_queue(), ^{
            if (completion) {
                completion(result, nil);
            }
        });
    });
}

- (BOOL)supportsIndicatorType:(TIIndicatorType)type {
    return type == TIIndicatorTypeIPv4 || type == TIIndicatorTypeIPv6;
}

- (void)addMaliciousIndicator:(NSString *)value
                          type:(TIIndicatorType)type
                    confidence:(NSInteger)confidence
                    categories:(NSArray<NSString *> *)categories {
    self.maliciousSet[value] = @{
        @"confidence": @(confidence),
        @"categories": categories ?: @[],
        @"lastSeen": [NSDate date]
    };
}

- (void)shutdown {
    [self.maliciousSet removeAllObjects];
}

@end

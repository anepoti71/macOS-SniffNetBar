//
//  MockThreatIntelProvider.m
//  SniffNetBar
//
//  Mock threat intelligence provider for testing
//

#import "MockThreatIntelProvider.h"

@interface MockThreatIntelProvider ()
@property (nonatomic, strong) NSMutableDictionary<NSString *, TIResult *> *mockResults;
@property (nonatomic, strong) NSMutableDictionary<NSString *, NSNumber *> *mockScores;
@end

@implementation MockThreatIntelProvider

- (instancetype)initWithName:(NSString *)name {
    self = [super init];
    if (self) {
        _name = [name copy];
        _defaultTTL = 3600;
        _negativeCacheTTL = 300;
        _shouldFail = NO;
        _errorToReturn = nil;
        _simulatedDelay = 0.0;
        _isHealthy = YES;
        _callCount = 0;
        _mockResults = [NSMutableDictionary dictionary];
        _mockScores = [NSMutableDictionary dictionary];
    }
    return self;
}

- (void)configureWithAPIKey:(NSString *)apiKey
                    timeout:(NSTimeInterval)timeout
          maxRequestsPerMin:(NSInteger)maxRequestsPerMin
                 completion:(void (^)(NSError * _Nullable))completion {
    if (completion) {
        completion(nil);
    }
}

- (void)isHealthyWithCompletion:(void (^)(BOOL))completion {
    if (completion) {
        completion(self.isHealthy);
    }
}

- (void)enrichIndicator:(TIIndicator *)indicator
             completion:(void (^)(TIResult * _Nullable, NSError * _Nullable))completion {
    self.callCount++;

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(self.simulatedDelay * NSEC_PER_SEC)),
                   dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        if (self.shouldFail) {
            if (completion) {
                NSError *error = self.errorToReturn ?: [NSError errorWithDomain:TIErrorDomain
                                                                            code:TIErrorCodeProviderUnavailable
                                                                        userInfo:@{NSLocalizedDescriptionKey: @"Mock provider failed"}];
                completion(nil, error);
            }
            return;
        }

        // Check for pre-configured result
        NSString *key = [NSString stringWithFormat:@"%ld:%@", (long)indicator.type, indicator.value];
        TIResult *result = self.mockResults[key];

        if (!result) {
            // Create result from mock score if available
            NSNumber *scoreObj = self.mockScores[indicator.value];
            NSInteger score = scoreObj ? [scoreObj integerValue] : 0;

            result = [[TIResult alloc] init];
            result.providerName = self.name;
            result.indicator = indicator;

            TIVerdict *verdict = [[TIVerdict alloc] init];
            verdict.hit = (score > 0);
            verdict.confidence = score;
            verdict.categories = (score > 50) ? @[@"malicious"] : @[];
            verdict.tags = @[];
            result.verdict = verdict;

            TIMetadata *metadata = [[TIMetadata alloc] init];
            metadata.expiresAt = [NSDate dateWithTimeIntervalSinceNow:self.defaultTTL];
            metadata.ttlSeconds = self.defaultTTL;
            result.metadata = metadata;
        }

        if (completion) {
            completion(result, nil);
        }
    });
}

- (BOOL)supportsIndicatorType:(TIIndicatorType)type {
    return (type == TIIndicatorTypeIPv4 || type == TIIndicatorTypeIPv6);
}

- (void)setMockResult:(TIResult *)result forIndicator:(TIIndicator *)indicator {
    NSString *key = [NSString stringWithFormat:@"%ld:%@", (long)indicator.type, indicator.value];
    if (result) {
        self.mockResults[key] = result;
    } else {
        [self.mockResults removeObjectForKey:key];
    }
}

- (void)setMockScore:(NSInteger)score forIndicatorValue:(NSString *)value {
    self.mockScores[value] = @(score);
}

@end

//
//  ThreatIntelModels.h
//  SniffNetBar
//
//  Core data models for threat intelligence integration
//

#import <Foundation/Foundation.h>
#import <Cocoa/Cocoa.h>

NS_ASSUME_NONNULL_BEGIN

// MARK: - Indicator Types

typedef NS_ENUM(NSInteger, TIIndicatorType) {
    TIIndicatorTypeIPv4,
    TIIndicatorTypeIPv6,
    TIIndicatorTypeDomain,
    TIIndicatorTypeURL,
    TIIndicatorTypeASN
};

// MARK: - Threat Verdict

typedef NS_ENUM(NSInteger, TIThreatVerdict) {
    TIThreatVerdictClean,
    TIThreatVerdictSuspicious,
    TIThreatVerdictMalicious,
    TIThreatVerdictUnknown
};

// MARK: - Indicator Model

@interface TIIndicator : NSObject <NSCopying>

@property (nonatomic, assign, readonly) TIIndicatorType type;
@property (nonatomic, copy, readonly) NSString *value;

- (instancetype)initWithType:(TIIndicatorType)type value:(NSString *)value;
+ (instancetype)indicatorWithIP:(NSString *)ip;
+ (instancetype)indicatorWithDomain:(NSString *)domain;

@end

// MARK: - Threat Intel Result

@interface TIVerdict : NSObject

@property (nonatomic, assign) BOOL hit;
@property (nonatomic, assign) NSInteger confidence; // 0-100
@property (nonatomic, copy) NSArray<NSString *> *categories;
@property (nonatomic, copy) NSArray<NSString *> *tags;
@property (nonatomic, strong, nullable) NSDate *lastSeen;
@property (nonatomic, strong, nullable) NSDictionary<NSString *, id> *evidence;

@end

@interface TIMetadata : NSObject

@property (nonatomic, copy, nullable) NSString *sourceURL;
@property (nonatomic, strong) NSDate *fetchedAt;
@property (nonatomic, strong) NSDate *expiresAt;
@property (nonatomic, assign) NSTimeInterval ttlSeconds;
@property (nonatomic, assign) NSInteger rateLimitRemaining;

@end

@interface TIResult : NSObject

@property (nonatomic, strong) TIIndicator *indicator;
@property (nonatomic, copy) NSString *providerName;
@property (nonatomic, strong) TIVerdict *verdict;
@property (nonatomic, strong) TIMetadata *metadata;
@property (nonatomic, strong, nullable) NSError *error;

@end

// MARK: - Scoring Result

@interface TIScoreBreakdown : NSObject

@property (nonatomic, copy) NSString *ruleName;
@property (nonatomic, copy) NSString *ruleDescription;
@property (nonatomic, copy) NSString *provider;
@property (nonatomic, assign) NSInteger scoreContribution;
@property (nonatomic, copy) NSDictionary<NSString *, NSString *> *evidence;
@property (nonatomic, assign) NSInteger confidence;

@end

@interface TIScoringResult : NSObject

@property (nonatomic, strong) TIIndicator *indicator;
@property (nonatomic, assign) NSInteger finalScore;
@property (nonatomic, assign) TIThreatVerdict verdict;
@property (nonatomic, copy) NSArray<TIScoreBreakdown *> *breakdown;
@property (nonatomic, assign) double confidence; // 0.0-1.0
@property (nonatomic, strong) NSDate *evaluatedAt;
@property (nonatomic, copy) NSString *explanation;

// Convenience
- (NSString *)verdictString;
- (NSColor *)verdictColor;

@end

// MARK: - Enrichment Response

@interface TIEnrichmentResponse : NSObject

@property (nonatomic, strong) TIIndicator *indicator;
@property (nonatomic, copy) NSArray<TIResult *> *providerResults;
@property (nonatomic, strong, nullable) TIScoringResult *scoringResult;
@property (nonatomic, assign) NSTimeInterval duration;
@property (nonatomic, assign) NSInteger cacheHits;

@end

// MARK: - Error Domain

extern NSString *const TIErrorDomain;

typedef NS_ENUM(NSInteger, TIErrorCode) {
    TIErrorCodeTimeout,
    TIErrorCodeQuotaExceeded,
    TIErrorCodeAuthenticationFailed,
    TIErrorCodeNetworkError,
    TIErrorCodeUnsupportedIndicatorType,
    TIErrorCodeProviderUnavailable,
    TIErrorCodeRateLimited
};

NS_ASSUME_NONNULL_END

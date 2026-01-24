//
//  TrustLearningModels.h
//  SniffNetBar
//

#import <Foundation/Foundation.h>
#import "TrustedIPStore.h"

NS_ASSUME_NONNULL_BEGIN

@interface SNBTrustFeatureVector : NSObject

@property (nonatomic, copy, nullable) NSString *ipAddress;
@property (nonatomic, copy, nullable) NSString *asn;
@property (nonatomic, copy, nullable) NSString *country;
@property (nonatomic, copy, nullable) NSString *organization;

@property (nonatomic, assign) NSInteger virusTotalScore;
@property (nonatomic, assign) NSInteger abuseIPDBScore;
@property (nonatomic, copy, nullable) NSString *greyNoiseClassification;
@property (nonatomic, assign) NSInteger shodanOpenPorts;

@property (nonatomic, assign) NSInteger destinationPort;
@property (nonatomic, copy, nullable) NSString *processName;
@property (nonatomic, assign) uint64_t bytesTransferred;
@property (nonatomic, assign) NSInteger connectionCount;
@property (nonatomic, assign) NSTimeInterval connectionDuration;

@property (nonatomic, assign) NSInteger previousTrustCount;
@property (nonatomic, assign) NSInteger previousUntrustCount;
@property (nonatomic, assign) NSTimeInterval daysSinceFirstSeen;

- (NSDictionary<NSString *, id> *)dictionaryRepresentation;
- (NSString *)jsonString;
+ (instancetype)vectorFromJSONString:(NSString *)json;

@end

@interface SNBTrustFeedback : NSObject

@property (nonatomic, copy) NSString *ipAddress;
@property (nonatomic, assign) BOOL trusted;
@property (nonatomic, assign) SNBTrustReason reason;
@property (nonatomic, strong) NSDate *timestamp;
@property (nonatomic, copy, nullable) NSString *sessionId;
@property (nonatomic, strong, nullable) SNBTrustFeatureVector *featureVector;

@end

@interface SNBTrustConfidence : NSObject

@property (nonatomic, assign) double confidence; // 0.0 - 1.0
@property (nonatomic, assign) NSInteger sampleCount;
@property (nonatomic, copy, nullable) NSString *primaryReason;
@property (nonatomic, assign) BOOL suggestTrust;

@end

@interface SNBTrustSuggestion : NSObject

@property (nonatomic, copy) NSString *ipAddress;
@property (nonatomic, assign) double confidence;
@property (nonatomic, assign) NSInteger sampleCount;
@property (nonatomic, copy, nullable) NSString *primaryReason;
@property (nonatomic, assign) SNBTrustReason suggestedReason;

@end

NS_ASSUME_NONNULL_END

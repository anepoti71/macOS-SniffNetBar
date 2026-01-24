//
//  AdaptiveScoring.h
//  SniffNetBar
//

#import <Foundation/Foundation.h>

@class SNBTrustFeedback;

NS_ASSUME_NONNULL_BEGIN

@interface SNBAdaptiveScoring : NSObject

@property (nonatomic, assign, readonly) double virusTotalWeight;
@property (nonatomic, assign, readonly) double abuseIPDBWeight;
@property (nonatomic, assign, readonly) double greyNoiseWeight;
@property (nonatomic, assign, readonly) double shodanWeight;

+ (instancetype)sharedScoring;

- (NSDictionary<NSString *, NSNumber *> *)providerWeights;
- (void)updateWeightsFromFeedback:(SNBTrustFeedback *)feedback;

@end

NS_ASSUME_NONNULL_END

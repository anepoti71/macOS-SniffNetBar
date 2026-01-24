//
//  TrustLearningEngine.h
//  SniffNetBar
//

#import <Foundation/Foundation.h>
#import "TrustedIPStore.h"

@class SNBTrustFeatureVector, SNBTrustFeedback, SNBTrustSuggestion;

NS_ASSUME_NONNULL_BEGIN

extern NSString *const SNBTrustSuggestionAvailableNotification;

@interface SNBTrustLearningEngine : NSObject

+ (instancetype)sharedEngine;

- (SNBTrustFeatureVector *)populateHistoricalFeaturesForIP:(NSString *)ipAddress
                                             featureVector:(SNBTrustFeatureVector *)featureVector;

- (void)recordFeedbackForIP:(NSString *)ipAddress
                    trusted:(BOOL)trusted
                     reason:(SNBTrustReason)reason
              featureVector:(nullable SNBTrustFeatureVector *)featureVector;

- (nullable SNBTrustSuggestion *)suggestTrustForIP:(NSString *)ipAddress
                                     featureVector:(nullable SNBTrustFeatureVector *)featureVector;

@end

NS_ASSUME_NONNULL_END

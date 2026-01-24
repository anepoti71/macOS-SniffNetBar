//
//  SNBScoringEngine.h
//  SniffNetBar
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@class SNBFlowEvent;
@class SNBRecommendation;
@class SNBAggregateSnapshot;

@class SNBScoringConfig;

@interface SNBScoringEngine : NSObject

- (instancetype)initWithConfig:(SNBScoringConfig *)config;

- (SNBRecommendation *)recommendationForEvent:(SNBFlowEvent *)event
                                     snapshot:(SNBAggregateSnapshot *)snapshot;

- (SNBRecommendation *)applyUserLabel:(NSString *)label
                       toRecommendation:(SNBRecommendation *)recommendation;

@end

NS_ASSUME_NONNULL_END

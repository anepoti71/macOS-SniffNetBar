//
//  SNBRecommendationStore.h
//  SniffNetBar
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@class SNBRecommendation;

@class SNBBehaviorDatabase;

@interface SNBRecommendationStore : NSObject

- (instancetype)initWithDatabase:(SNBBehaviorDatabase *)database;
- (NSArray<SNBRecommendation *> *)recommendationsSince:(NSDate *)since;
- (BOOL)upsertRecommendation:(SNBRecommendation *)recommendation;
- (BOOL)upsertRecommendations:(NSArray<SNBRecommendation *> *)recommendations;
- (BOOL)setUserLabel:(NSString *)label forClusterID:(NSString *)clusterID scope:(NSString *)scope;
- (NSString *)userLabelForClusterID:(NSString *)clusterID;
- (BOOL)updateRecommendationLabel:(NSString *)label forClusterID:(NSString *)clusterID;

@end

NS_ASSUME_NONNULL_END

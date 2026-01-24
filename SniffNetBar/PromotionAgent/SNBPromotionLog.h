//
//  SNBPromotionLog.h
//  SniffNetBar
//
//  SQLite audit trail for promotion decisions and user overrides.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@class SNBPromotionDecision;

typedef NS_ENUM(NSInteger, SNBPromotionAction);

@interface SNBPromotionLogEntry : NSObject
@property (nonatomic, assign) int64_t entryID;
@property (nonatomic, copy) NSString *clusterID;
@property (nonatomic, assign) SNBPromotionAction action;
@property (nonatomic, copy, nullable) NSString *reason;
@property (nonatomic, assign) NSInteger confidence;
@property (nonatomic, copy, nullable) NSArray<NSString *> *factors;
@property (nonatomic, copy, nullable) NSArray<NSString *> *blockers;
@property (nonatomic, assign) BOOL aiAssisted;
@property (nonatomic, copy, nullable) NSString *aiReasoning;
@property (nonatomic, strong) NSDate *evaluatedAt;
@property (nonatomic, strong, nullable) NSDate *appliedAt;
@end

@interface SNBPromotionLogStatistics : NSObject
@property (nonatomic, assign) NSUInteger totalDecisions;
@property (nonatomic, assign) NSUInteger autoPromoted;
@property (nonatomic, assign) NSUInteger autoBlocked;
@property (nonatomic, assign) NSUInteger suggested;
@property (nonatomic, assign) NSUInteger aiAssisted;
@property (nonatomic, assign) NSUInteger userOverrides;
@property (nonatomic, assign) double aiAccuracyRate;
@property (nonatomic, assign) double userOverrideRate;
@end

@interface SNBPromotionLog : NSObject

- (instancetype)initWithDatabasePath:(NSString *)path;

// Log decisions
- (BOOL)logDecision:(SNBPromotionDecision *)decision aiAssisted:(BOOL)aiAssisted;
- (BOOL)logDecision:(SNBPromotionDecision *)decision aiAssisted:(BOOL)aiAssisted aiReasoning:(nullable NSString *)aiReasoning;
- (BOOL)markDecisionApplied:(NSString *)clusterID;

// Log user overrides (for learning)
- (BOOL)logUserOverride:(NSString *)clusterID
            fromAction:(SNBPromotionAction)from
             toLabel:(NSString *)userLabel;

// Query audit trail
- (NSArray<SNBPromotionLogEntry *> *)decisionsForCluster:(NSString *)clusterID;
- (NSArray<SNBPromotionLogEntry *> *)recentDecisions:(NSUInteger)limit;
- (SNBPromotionLogStatistics *)statisticsSince:(NSDate *)since;

// Learning metrics
- (double)aiAccuracyRate;
- (double)userOverrideRate;

// Cleanup
- (BOOL)pruneOlderThan:(NSDate *)date;

@end

NS_ASSUME_NONNULL_END

//
//  SNBAggregateEngine.h
//  SniffNetBar
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@class SNBFlowEvent;

@interface SNBAggregateSnapshot : NSObject
@property (nonatomic, assign) uint64_t seenCount;
@property (nonatomic, copy) NSDictionary<NSString *, NSNumber *> *hourHistogram;
@property (nonatomic, copy) NSDictionary<NSString *, NSNumber *> *dowHistogram;
@property (nonatomic, assign) double bytesEwma;
@property (nonatomic, assign) double intervalEwma;
@property (nonatomic, assign) double intervalVarEwma;
@property (nonatomic, assign) double beaconScore;
@property (nonatomic, assign) uint64_t seen1h;
@property (nonatomic, assign) uint64_t seen24h;
@property (nonatomic, assign) uint64_t seen7d;
@property (nonatomic, copy) NSString *baselineASN;
@property (nonatomic, copy) NSString *baselineOrg;
@property (nonatomic, copy) NSString *baselineGeo;
@end

@class SNBBehaviorDatabase;

@interface SNBAggregateEngine : NSObject

- (instancetype)initWithDatabase:(SNBBehaviorDatabase *)database;

- (void)processEvents:(NSArray<SNBFlowEvent *> *)events;
- (uint64_t)seenCountForClusterID:(NSString *)clusterID;
- (SNBAggregateSnapshot *)snapshotForClusterID:(NSString *)clusterID;

@end

NS_ASSUME_NONNULL_END

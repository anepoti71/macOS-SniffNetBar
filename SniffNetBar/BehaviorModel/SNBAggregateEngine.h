//
//  SNBAggregateEngine.h
//  SniffNetBar
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@class SNBFlowEvent;

/// Configuration for the aggregate engine caching and batching behavior
@interface SNBAggregateEngineConfig : NSObject
@property (nonatomic, assign) NSUInteger maxCacheSize;          // Default: 10000
@property (nonatomic, assign) NSUInteger writeBatchSize;        // Default: 100
@property (nonatomic, assign) NSTimeInterval writeBatchInterval; // Default: 5.0 seconds
@property (nonatomic, assign) NSUInteger prewarmCount;          // Default: 1000 (top clusters to load)
+ (instancetype)defaultConfig;
@end

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
- (instancetype)initWithDatabase:(SNBBehaviorDatabase *)database
                          config:(nullable SNBAggregateEngineConfig *)config;

/// Process events and update aggregates (batched writes)
- (void)processEvents:(NSArray<SNBFlowEvent *> *)events;

/// Get the seen count for a cluster (from cache or DB)
- (uint64_t)seenCountForClusterID:(NSString *)clusterID;

/// Get a full snapshot for scoring (uses in-memory window counters)
- (SNBAggregateSnapshot *)snapshotForClusterID:(NSString *)clusterID;

/// Pre-warm cache with top N clusters by seen_count (call on startup)
- (void)prewarmCache;

/// Flush any pending writes to the database
- (void)flushPendingWrites;

/// Current cache statistics (for monitoring)
@property (nonatomic, readonly) NSUInteger cacheSize;
@property (nonatomic, readonly) NSUInteger pendingWriteCount;

@end

NS_ASSUME_NONNULL_END

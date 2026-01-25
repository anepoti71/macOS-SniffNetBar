//
//  SNBAggregateEngine.m
//  SniffNetBar
//
//  Optimized with LRU cache, in-memory rolling windows, and write-behind batching

#import "SNBAggregateEngine.h"
#import "SNBBehaviorDatabase.h"
#import "SNBEventSchema.h"
#import "SNBModelingUtilities.h"
#import <sqlite3.h>

#pragma mark - Configuration

@implementation SNBAggregateEngineConfig

+ (instancetype)defaultConfig {
    SNBAggregateEngineConfig *config = [[SNBAggregateEngineConfig alloc] init];
    config.maxCacheSize = 10000;
    config.writeBatchSize = 100;
    config.writeBatchInterval = 5.0;
    config.prewarmCount = 1000;
    return config;
}

@end

#pragma mark - Rolling Window Bucket

/// Represents a single time bucket for rolling window counters
@interface SNBWindowBucket : NSObject
@property (nonatomic, assign) double bucketStart;
@property (nonatomic, assign) uint64_t seenCount;
@property (nonatomic, assign) uint64_t bytesSum;
@end

@implementation SNBWindowBucket
@end

#pragma mark - Rolling Window Counter

/// In-memory circular buffer for rolling window counters
/// Maintains recent buckets without DB queries
@interface SNBRollingWindowCounter : NSObject
@property (nonatomic, strong) NSMutableArray<SNBWindowBucket *> *hourBuckets;   // 60 buckets (1 per minute for 1h)
@property (nonatomic, strong) NSMutableArray<SNBWindowBucket *> *dayBuckets;    // 24 buckets (1 per hour for 24h)
@property (nonatomic, strong) NSMutableArray<SNBWindowBucket *> *weekBuckets;   // 7 buckets (1 per day for 7d)
@property (nonatomic, assign) uint64_t totalSeen1h;
@property (nonatomic, assign) uint64_t totalSeen24h;
@property (nonatomic, assign) uint64_t totalSeen7d;
- (void)recordEventAtTimestamp:(double)timestamp bytes:(uint64_t)bytes;
- (void)pruneOldBuckets;
@end

@implementation SNBRollingWindowCounter

- (instancetype)init {
    self = [super init];
    if (self) {
        _hourBuckets = [NSMutableArray arrayWithCapacity:60];
        _dayBuckets = [NSMutableArray arrayWithCapacity:24];
        _weekBuckets = [NSMutableArray arrayWithCapacity:7];
        _totalSeen1h = 0;
        _totalSeen24h = 0;
        _totalSeen7d = 0;
    }
    return self;
}

- (void)recordEventAtTimestamp:(double)timestamp bytes:(uint64_t)bytes {
    // Minute bucket for 1h window
    double minuteBucket = floor(timestamp / 60.0) * 60.0;
    [self addToBuckets:self.hourBuckets bucketStart:minuteBucket bytes:bytes maxBuckets:60];

    // Hour bucket for 24h window
    double hourBucket = floor(timestamp / 3600.0) * 3600.0;
    [self addToBuckets:self.dayBuckets bucketStart:hourBucket bytes:bytes maxBuckets:24];

    // Day bucket for 7d window
    double dayBucket = floor(timestamp / 86400.0) * 86400.0;
    [self addToBuckets:self.weekBuckets bucketStart:dayBucket bytes:bytes maxBuckets:7];

    [self pruneOldBuckets];
}

- (void)addToBuckets:(NSMutableArray<SNBWindowBucket *> *)buckets
         bucketStart:(double)bucketStart
               bytes:(uint64_t)bytes
          maxBuckets:(NSUInteger)maxBuckets {
    // Find or create bucket
    SNBWindowBucket *bucket = nil;
    for (SNBWindowBucket *b in buckets) {
        if (b.bucketStart == bucketStart) {
            bucket = b;
            break;
        }
    }

    if (!bucket) {
        bucket = [[SNBWindowBucket alloc] init];
        bucket.bucketStart = bucketStart;
        bucket.seenCount = 0;
        bucket.bytesSum = 0;
        [buckets addObject:bucket];

        // Sort by bucketStart descending (newest first)
        [buckets sortUsingComparator:^NSComparisonResult(SNBWindowBucket *a, SNBWindowBucket *b) {
            if (a.bucketStart > b.bucketStart) return NSOrderedAscending;
            if (a.bucketStart < b.bucketStart) return NSOrderedDescending;
            return NSOrderedSame;
        }];

        // Trim old buckets
        while (buckets.count > maxBuckets) {
            [buckets removeLastObject];
        }
    }

    bucket.seenCount += 1;
    bucket.bytesSum += bytes;
}

- (void)pruneOldBuckets {
    double now = [[NSDate date] timeIntervalSince1970];
    double hourCutoff = now - 3600.0;
    double dayCutoff = now - 86400.0;
    double weekCutoff = now - 604800.0;

    // Prune and recalculate totals
    _totalSeen1h = [self pruneAndSum:self.hourBuckets cutoff:hourCutoff];
    _totalSeen24h = [self pruneAndSum:self.dayBuckets cutoff:dayCutoff];
    _totalSeen7d = [self pruneAndSum:self.weekBuckets cutoff:weekCutoff];
}

- (uint64_t)pruneAndSum:(NSMutableArray<SNBWindowBucket *> *)buckets cutoff:(double)cutoff {
    NSMutableIndexSet *toRemove = [NSMutableIndexSet indexSet];
    uint64_t total = 0;

    for (NSUInteger i = 0; i < buckets.count; i++) {
        SNBWindowBucket *bucket = buckets[i];
        if (bucket.bucketStart < cutoff) {
            [toRemove addIndex:i];
        } else {
            total += bucket.seenCount;
        }
    }

    [buckets removeObjectsAtIndexes:toRemove];
    return total;
}

@end

#pragma mark - LRU Cache Node

/// Doubly-linked list node for LRU eviction
@interface SNBLRUNode : NSObject
@property (nonatomic, copy) NSString *key;
@property (nonatomic, strong) id value;
@property (nonatomic, weak) SNBLRUNode *prev;
@property (nonatomic, strong) SNBLRUNode *next;
@end

@implementation SNBLRUNode
@end

#pragma mark - Aggregate State

@interface SNBAggregateState : NSObject
@property (nonatomic, assign) uint64_t seenCount;
@property (nonatomic, strong) NSMutableDictionary<NSString *, NSNumber *> *hourHistogram;
@property (nonatomic, strong) NSMutableDictionary<NSString *, NSNumber *> *dowHistogram;
@property (nonatomic, assign) double bytesEwma;
@property (nonatomic, assign) double intervalEwma;
@property (nonatomic, assign) double intervalVarEwma;
@property (nonatomic, assign) double beaconScore;
@property (nonatomic, assign) double lastSeen;
@property (nonatomic, copy) NSString *baselineASN;
@property (nonatomic, copy) NSString *baselineOrg;
@property (nonatomic, copy) NSString *baselineGeo;
@property (nonatomic, assign) BOOL isDirty; // Needs DB write
@property (nonatomic, strong) SNBRollingWindowCounter *windowCounter;
@end

@implementation SNBAggregateState

- (instancetype)init {
    self = [super init];
    if (self) {
        _windowCounter = [[SNBRollingWindowCounter alloc] init];
        _isDirty = NO;
    }
    return self;
}

@end

#pragma mark - Aggregate Snapshot

@implementation SNBAggregateSnapshot
@end

#pragma mark - Aggregate Engine

@interface SNBAggregateEngine ()
@property (nonatomic, strong) SNBBehaviorDatabase *database;
@property (nonatomic, strong) SNBAggregateEngineConfig *config;

// LRU Cache
@property (nonatomic, strong) NSMutableDictionary<NSString *, SNBLRUNode *> *cacheMap;
@property (nonatomic, strong) SNBLRUNode *cacheHead; // Most recently used
@property (nonatomic, strong) SNBLRUNode *cacheTail; // Least recently used

// Write batching
@property (nonatomic, strong) NSMutableSet<NSString *> *dirtyClusterIDs;
@property (nonatomic, strong) dispatch_source_t flushTimer;
@property (nonatomic, assign) NSUInteger eventsSinceLastFlush;

// Prepared statements
@property (nonatomic, assign) sqlite3_stmt *windowUpsertStmt;
@property (nonatomic, assign) sqlite3_stmt *aggregateUpsertStmt;
@end

static void *SNBAggregateQueueKey = &SNBAggregateQueueKey;

@implementation SNBAggregateEngine

- (instancetype)initWithDatabase:(SNBBehaviorDatabase *)database {
    return [self initWithDatabase:database config:nil];
}

- (instancetype)initWithDatabase:(SNBBehaviorDatabase *)database
                          config:(SNBAggregateEngineConfig *)config {
    self = [super init];
    if (self) {
        _database = database;
        _config = config ?: [SNBAggregateEngineConfig defaultConfig];
        dispatch_queue_set_specific(_database.queue, SNBAggregateQueueKey, SNBAggregateQueueKey, NULL);

        // Initialize LRU cache
        _cacheMap = [NSMutableDictionary dictionaryWithCapacity:_config.maxCacheSize];
        _cacheHead = nil;
        _cacheTail = nil;

        // Initialize write batching
        _dirtyClusterIDs = [NSMutableSet set];
        _eventsSinceLastFlush = 0;

        [self ensureSchema];
        [self prepareStatements];
        [self startFlushTimer];
    }
    return self;
}

- (void)dealloc {
    [self stopFlushTimer];
    [self flushPendingWrites];

    if (_windowUpsertStmt) {
        sqlite3_finalize(_windowUpsertStmt);
    }
    if (_aggregateUpsertStmt) {
        sqlite3_finalize(_aggregateUpsertStmt);
    }
}

#pragma mark - Public Properties

- (NSUInteger)cacheSize {
    return self.cacheMap.count;
}

- (NSUInteger)pendingWriteCount {
    return self.dirtyClusterIDs.count;
}

#pragma mark - LRU Cache Operations

- (void)moveNodeToHead:(SNBLRUNode *)node {
    if (node == self.cacheHead) {
        return; // Already at head
    }

    // Remove from current position
    if (node.prev) {
        node.prev.next = node.next;
    }
    if (node.next) {
        node.next.prev = node.prev;
    }
    if (node == self.cacheTail) {
        self.cacheTail = node.prev;
    }

    // Insert at head
    node.prev = nil;
    node.next = self.cacheHead;
    if (self.cacheHead) {
        self.cacheHead.prev = node;
    }
    self.cacheHead = node;

    if (!self.cacheTail) {
        self.cacheTail = node;
    }
}

- (void)addNodeToHead:(SNBLRUNode *)node {
    node.prev = nil;
    node.next = self.cacheHead;
    if (self.cacheHead) {
        self.cacheHead.prev = node;
    }
    self.cacheHead = node;

    if (!self.cacheTail) {
        self.cacheTail = node;
    }
}

- (SNBLRUNode *)removeTailNode {
    SNBLRUNode *tail = self.cacheTail;
    if (!tail) {
        return nil;
    }

    if (tail.prev) {
        tail.prev.next = nil;
        self.cacheTail = tail.prev;
    } else {
        self.cacheHead = nil;
        self.cacheTail = nil;
    }

    return tail;
}

- (void)evictIfNeeded {
    while (self.cacheMap.count >= self.config.maxCacheSize) {
        SNBLRUNode *lruNode = [self removeTailNode];
        if (lruNode) {
            // Flush dirty state before eviction
            SNBAggregateState *state = (SNBAggregateState *)lruNode.value;
            if (state.isDirty) {
                [self writeStateToDB:state forClusterID:lruNode.key];
            }
            [self.cacheMap removeObjectForKey:lruNode.key];
            [self.dirtyClusterIDs removeObject:lruNode.key];
        }
    }
}

- (SNBAggregateState *)getCachedStateForClusterID:(NSString *)clusterID {
    SNBLRUNode *node = self.cacheMap[clusterID];
    if (node) {
        [self moveNodeToHead:node];
        return (SNBAggregateState *)node.value;
    }
    return nil;
}

- (void)setCachedState:(SNBAggregateState *)state forClusterID:(NSString *)clusterID {
    SNBLRUNode *existingNode = self.cacheMap[clusterID];
    if (existingNode) {
        existingNode.value = state;
        [self moveNodeToHead:existingNode];
    } else {
        [self evictIfNeeded];
        SNBLRUNode *newNode = [[SNBLRUNode alloc] init];
        newNode.key = clusterID;
        newNode.value = state;
        [self addNodeToHead:newNode];
        self.cacheMap[clusterID] = newNode;
    }
}

#pragma mark - Write Batching

- (void)startFlushTimer {
    dispatch_queue_t queue = self.database.queue;
    self.flushTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, queue);

    uint64_t interval = (uint64_t)(self.config.writeBatchInterval * NSEC_PER_SEC);
    dispatch_source_set_timer(self.flushTimer, dispatch_time(DISPATCH_TIME_NOW, interval), interval, interval / 10);

    __weak typeof(self) weakSelf = self;
    dispatch_source_set_event_handler(self.flushTimer, ^{
        [weakSelf flushPendingWritesInternal];
    });

    dispatch_resume(self.flushTimer);
}

- (void)stopFlushTimer {
    if (self.flushTimer) {
        dispatch_source_cancel(self.flushTimer);
        self.flushTimer = nil;
    }
}

- (void)flushPendingWrites {
    dispatch_sync(self.database.queue, ^{
        [self flushPendingWritesInternal];
    });
}

- (void)flushPendingWritesInternal {
    if (self.dirtyClusterIDs.count == 0) {
        return;
    }

    sqlite3 *db = self.database.db;
    if (!db) {
        return;
    }

    sqlite3_exec(db, "BEGIN IMMEDIATE;", NULL, NULL, NULL);

    NSSet<NSString *> *clusterIDsToFlush = [self.dirtyClusterIDs copy];
    for (NSString *clusterID in clusterIDsToFlush) {
        SNBLRUNode *node = self.cacheMap[clusterID];
        if (node) {
            SNBAggregateState *state = (SNBAggregateState *)node.value;
            if (state.isDirty) {
                [self writeStateToDB:state forClusterID:clusterID];
                state.isDirty = NO;
            }
        }
    }

    [self.dirtyClusterIDs removeAllObjects];
    self.eventsSinceLastFlush = 0;

    sqlite3_exec(db, "COMMIT;", NULL, NULL, NULL);
}

- (void)markClusterDirty:(NSString *)clusterID {
    SNBLRUNode *node = self.cacheMap[clusterID];
    if (node) {
        SNBAggregateState *state = (SNBAggregateState *)node.value;
        state.isDirty = YES;
    }
    [self.dirtyClusterIDs addObject:clusterID];
    self.eventsSinceLastFlush++;

    // Flush if batch size reached
    if (self.eventsSinceLastFlush >= self.config.writeBatchSize) {
        [self flushPendingWritesInternal];
    }
}

- (void)writeStateToDB:(SNBAggregateState *)state forClusterID:(NSString *)clusterID {
    sqlite3_stmt *stmt = self.aggregateUpsertStmt;
    if (!stmt) {
        return;
    }

    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    sqlite3_bind_text(stmt, 1, clusterID.UTF8String, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)state.seenCount);
    sqlite3_bind_double(stmt, 3, state.lastSeen);
    sqlite3_bind_double(stmt, 4, state.bytesEwma);
    sqlite3_bind_double(stmt, 5, 1.0); // freq_ewma placeholder
    sqlite3_bind_text(stmt, 6, [self jsonStringForHistogram:state.hourHistogram].UTF8String, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, [self jsonStringForHistogram:state.dowHistogram].UTF8String, -1, SQLITE_TRANSIENT);
    sqlite3_bind_double(stmt, 8, state.intervalEwma);
    sqlite3_bind_double(stmt, 9, state.intervalVarEwma);
    sqlite3_bind_double(stmt, 10, state.beaconScore);
    sqlite3_bind_text(stmt, 11, state.baselineASN.UTF8String ?: "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 12, state.baselineOrg.UTF8String ?: "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 13, state.baselineGeo.UTF8String ?: "", -1, SQLITE_TRANSIENT);

    sqlite3_step(stmt);
}

#pragma mark - Cache Pre-warming

- (void)prewarmCache {
    dispatch_sync(self.database.queue, ^{
        sqlite3 *db = self.database.db;
        if (!db) {
            return;
        }

        NSString *sql = [NSString stringWithFormat:
            @"SELECT cluster_id, seen_count, last_seen, bytes_ewma, "
            @"hour_hist, dow_hist, interval_ewma, interval_var_ewma, beacon_score, "
            @"baseline_asn, baseline_org, baseline_geo "
            @"FROM aggregates ORDER BY seen_count DESC LIMIT %lu;",
            (unsigned long)self.config.prewarmCount];

        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(db, sql.UTF8String, -1, &stmt, NULL) != SQLITE_OK) {
            return;
        }

        NSUInteger loaded = 0;
        while (sqlite3_step(stmt) == SQLITE_ROW && loaded < self.config.prewarmCount) {
            const unsigned char *clusterIDRaw = sqlite3_column_text(stmt, 0);
            if (!clusterIDRaw) continue;

            NSString *clusterID = [NSString stringWithUTF8String:(const char *)clusterIDRaw];

            SNBAggregateState *state = [[SNBAggregateState alloc] init];
            state.seenCount = (uint64_t)sqlite3_column_int64(stmt, 1);
            state.lastSeen = sqlite3_column_double(stmt, 2);
            state.bytesEwma = sqlite3_column_double(stmt, 3);

            const unsigned char *hourHistRaw = sqlite3_column_text(stmt, 4);
            const unsigned char *dowHistRaw = sqlite3_column_text(stmt, 5);
            state.hourHistogram = [self histogramFromJSON:hourHistRaw];
            state.dowHistogram = [self histogramFromJSON:dowHistRaw];

            state.intervalEwma = sqlite3_column_double(stmt, 6);
            state.intervalVarEwma = sqlite3_column_double(stmt, 7);
            state.beaconScore = sqlite3_column_double(stmt, 8);

            const unsigned char *asn = sqlite3_column_text(stmt, 9);
            const unsigned char *org = sqlite3_column_text(stmt, 10);
            const unsigned char *geo = sqlite3_column_text(stmt, 11);
            state.baselineASN = asn ? [NSString stringWithUTF8String:(const char *)asn] : @"";
            state.baselineOrg = org ? [NSString stringWithUTF8String:(const char *)org] : @"";
            state.baselineGeo = geo ? [NSString stringWithUTF8String:(const char *)geo] : @"";

            state.isDirty = NO;

            [self setCachedState:state forClusterID:clusterID];
            loaded++;
        }

        sqlite3_finalize(stmt);
        NSLog(@"AggregateEngine: Pre-warmed cache with %lu clusters", (unsigned long)loaded);
    });
}

- (NSMutableDictionary<NSString *, NSNumber *> *)histogramFromJSON:(const unsigned char *)jsonRaw {
    if (!jsonRaw) {
        return [NSMutableDictionary dictionary];
    }
    NSString *jsonString = [NSString stringWithUTF8String:(const char *)jsonRaw];
    if (jsonString.length == 0 || [jsonString isEqualToString:@"{}"]) {
        return [NSMutableDictionary dictionary];
    }
    NSData *data = [jsonString dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *dict = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    return dict ? [dict mutableCopy] : [NSMutableDictionary dictionary];
}

#pragma mark - Event Processing

- (void)processEvents:(NSArray<SNBFlowEvent *> *)events {
    if (events.count == 0) {
        return;
    }

    dispatch_sync(self.database.queue, ^{
        for (SNBFlowEvent *event in events) {
            NSString *clusterID = SNBClusterIDForEvent(event);
            SNBAggregateState *state = [self aggregateStateForClusterID:clusterID];

            uint64_t bytes = event.bytesIn + event.bytesOut;
            double timestamp = event.end.timeIntervalSince1970;

            // Update state
            state.seenCount += 1;
            [self updateHistogramsForState:state timestamp:event.end];
            [self updateIntervalStatsForState:state timestamp:timestamp];

            // Update in-memory rolling windows (no DB query!)
            [state.windowCounter recordEventAtTimestamp:timestamp bytes:bytes];

            // Update EWMA
            state.bytesEwma = state.seenCount == 1 ? bytes : (0.3 * bytes) + (0.7 * state.bytesEwma);
            state.beaconScore = [self computeBeaconScoreForState:state];
            state.lastSeen = timestamp;

            // Update baselines
            if (event.asn.length > 0) {
                state.baselineASN = event.asn;
            }
            if (event.org.length > 0) {
                state.baselineOrg = event.org;
            }
            if (event.country.length > 0 || event.region.length > 0) {
                NSString *geo = [NSString stringWithFormat:@"%@-%@", event.country ?: @"", event.region ?: @""];
                if (geo.length > 1) {
                    state.baselineGeo = geo;
                }
            }

            // Mark for batched write
            [self markClusterDirty:clusterID];
        }
    });
}

- (uint64_t)seenCountForClusterID:(NSString *)clusterID {
    SNBAggregateState *state = [self getCachedStateForClusterID:clusterID];
    return state ? state.seenCount : 0;
}

- (SNBAggregateSnapshot *)snapshotForClusterID:(NSString *)clusterID {
    __block SNBAggregateSnapshot *snapshot = [[SNBAggregateSnapshot alloc] init];

    dispatch_sync(self.database.queue, ^{
        SNBAggregateState *state = [self aggregateStateForClusterID:clusterID];

        snapshot.seenCount = state.seenCount;
        snapshot.hourHistogram = [state.hourHistogram copy];
        snapshot.dowHistogram = [state.dowHistogram copy];
        snapshot.bytesEwma = state.bytesEwma;
        snapshot.intervalEwma = state.intervalEwma;
        snapshot.intervalVarEwma = state.intervalVarEwma;
        snapshot.beaconScore = state.beaconScore;
        snapshot.baselineASN = state.baselineASN ?: @"";
        snapshot.baselineOrg = state.baselineOrg ?: @"";
        snapshot.baselineGeo = state.baselineGeo ?: @"";

        // Get rolling window counts from in-memory counters (no DB query!)
        [state.windowCounter pruneOldBuckets];
        snapshot.seen1h = state.windowCounter.totalSeen1h;
        snapshot.seen24h = state.windowCounter.totalSeen24h;
        snapshot.seen7d = state.windowCounter.totalSeen7d;
    });

    return snapshot;
}

#pragma mark - State Management

- (SNBAggregateState *)aggregateStateForClusterID:(NSString *)clusterID {
    // Check cache first
    SNBAggregateState *state = [self getCachedStateForClusterID:clusterID];
    if (state) {
        return state;
    }

    // Load from DB
    state = [self loadStateFromDB:clusterID];
    if (!state) {
        // Create new state
        state = [[SNBAggregateState alloc] init];
        state.seenCount = 0;
        state.hourHistogram = [NSMutableDictionary dictionary];
        state.dowHistogram = [NSMutableDictionary dictionary];
        state.bytesEwma = 0.0;
        state.intervalEwma = 0.0;
        state.intervalVarEwma = 0.0;
        state.beaconScore = 0.0;
        state.lastSeen = 0.0;
        state.baselineASN = @"";
        state.baselineOrg = @"";
        state.baselineGeo = @"";
        state.isDirty = NO;
    }

    // Add to cache
    [self setCachedState:state forClusterID:clusterID];
    return state;
}

- (SNBAggregateState *)loadStateFromDB:(NSString *)clusterID {
    sqlite3 *db = self.database.db;
    if (!db || clusterID.length == 0) {
        return nil;
    }

    const char *sql =
        "SELECT seen_count, last_seen, bytes_ewma, hour_hist, dow_hist, "
        "interval_ewma, interval_var_ewma, beacon_score, "
        "baseline_asn, baseline_org, baseline_geo "
        "FROM aggregates WHERE cluster_id = ?;";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return nil;
    }

    sqlite3_bind_text(stmt, 1, clusterID.UTF8String, -1, SQLITE_TRANSIENT);

    SNBAggregateState *state = nil;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        state = [[SNBAggregateState alloc] init];
        state.seenCount = (uint64_t)sqlite3_column_int64(stmt, 0);
        state.lastSeen = sqlite3_column_double(stmt, 1);
        state.bytesEwma = sqlite3_column_double(stmt, 2);

        const unsigned char *hourHistRaw = sqlite3_column_text(stmt, 3);
        const unsigned char *dowHistRaw = sqlite3_column_text(stmt, 4);
        state.hourHistogram = [self histogramFromJSON:hourHistRaw];
        state.dowHistogram = [self histogramFromJSON:dowHistRaw];

        state.intervalEwma = sqlite3_column_double(stmt, 5);
        state.intervalVarEwma = sqlite3_column_double(stmt, 6);
        state.beaconScore = sqlite3_column_double(stmt, 7);

        const unsigned char *asn = sqlite3_column_text(stmt, 8);
        const unsigned char *org = sqlite3_column_text(stmt, 9);
        const unsigned char *geo = sqlite3_column_text(stmt, 10);
        state.baselineASN = asn ? [NSString stringWithUTF8String:(const char *)asn] : @"";
        state.baselineOrg = org ? [NSString stringWithUTF8String:(const char *)org] : @"";
        state.baselineGeo = geo ? [NSString stringWithUTF8String:(const char *)geo] : @"";

        state.isDirty = NO;
    }

    sqlite3_finalize(stmt);
    return state;
}

#pragma mark - Histogram Updates

- (void)updateHistogramsForState:(SNBAggregateState *)state timestamp:(NSDate *)timestamp {
    NSDateComponents *components = [[NSCalendar currentCalendar]
                                    components:(NSCalendarUnitHour | NSCalendarUnitWeekday)
                                    fromDate:timestamp];
    NSString *hourKey = [NSString stringWithFormat:@"%ld", (long)components.hour];
    NSString *dowKey = [NSString stringWithFormat:@"%ld", (long)components.weekday];
    NSNumber *hourCount = state.hourHistogram[hourKey] ?: @0;
    NSNumber *dowCount = state.dowHistogram[dowKey] ?: @0;
    state.hourHistogram[hourKey] = @(hourCount.unsignedLongLongValue + 1);
    state.dowHistogram[dowKey] = @(dowCount.unsignedLongLongValue + 1);
}

- (void)updateIntervalStatsForState:(SNBAggregateState *)state timestamp:(double)timestamp {
    if (state.lastSeen > 0) {
        double interval = timestamp - state.lastSeen;
        if (interval > 0) {
            double diff = interval - state.intervalEwma;
            state.intervalEwma = state.intervalEwma == 0.0 ? interval : (0.3 * interval) + (0.7 * state.intervalEwma);
            state.intervalVarEwma = state.intervalVarEwma == 0.0 ? diff * diff : (0.3 * diff * diff) + (0.7 * state.intervalVarEwma);
        }
    }
}

- (double)computeBeaconScoreForState:(SNBAggregateState *)state {
    if (state.seenCount < 5 || state.intervalEwma <= 0.0) {
        return 0.0;
    }
    double denom = (state.intervalEwma * state.intervalEwma) + 1.0;
    double ratio = state.intervalVarEwma / denom;
    double score = 1.0 - MIN(1.0, ratio * 10.0);
    return MAX(0.0, score);
}

#pragma mark - Schema and Statements

- (void)ensureSchema {
    sqlite3 *db = self.database.db;
    if (!db) {
        return;
    }
    const char *sql =
        "CREATE TABLE IF NOT EXISTS aggregates ("
        "cluster_id TEXT PRIMARY KEY, "
        "seen_count INTEGER, "
        "last_seen REAL, "
        "bytes_ewma REAL, "
        "freq_ewma REAL, "
        "hour_hist TEXT, "
        "dow_hist TEXT, "
        "interval_ewma REAL, "
        "interval_var_ewma REAL, "
        "beacon_score REAL, "
        "baseline_asn TEXT, "
        "baseline_org TEXT, "
        "baseline_geo TEXT"
        ");";
    sqlite3_exec(db, sql, NULL, NULL, NULL);

    // Add columns if missing (migration)
    sqlite3_exec(db, "ALTER TABLE aggregates ADD COLUMN baseline_asn TEXT;", NULL, NULL, NULL);
    sqlite3_exec(db, "ALTER TABLE aggregates ADD COLUMN baseline_org TEXT;", NULL, NULL, NULL);
    sqlite3_exec(db, "ALTER TABLE aggregates ADD COLUMN baseline_geo TEXT;", NULL, NULL, NULL);

    // Index for prewarm query
    sqlite3_exec(db, "CREATE INDEX IF NOT EXISTS idx_aggregates_seen_count ON aggregates(seen_count DESC);", NULL, NULL, NULL);
}

- (void)prepareStatements {
    sqlite3 *db = self.database.db;
    if (!db) {
        return;
    }

    const char *upsertSql =
        "INSERT INTO aggregates (cluster_id, seen_count, last_seen, bytes_ewma, freq_ewma, "
        "hour_hist, dow_hist, interval_ewma, interval_var_ewma, beacon_score, "
        "baseline_asn, baseline_org, baseline_geo) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(cluster_id) DO UPDATE SET "
        "seen_count = excluded.seen_count, "
        "last_seen = excluded.last_seen, "
        "bytes_ewma = excluded.bytes_ewma, "
        "freq_ewma = excluded.freq_ewma, "
        "hour_hist = excluded.hour_hist, "
        "dow_hist = excluded.dow_hist, "
        "interval_ewma = excluded.interval_ewma, "
        "interval_var_ewma = excluded.interval_var_ewma, "
        "beacon_score = excluded.beacon_score, "
        "baseline_asn = excluded.baseline_asn, "
        "baseline_org = excluded.baseline_org, "
        "baseline_geo = excluded.baseline_geo;";

    sqlite3_prepare_v2(db, upsertSql, -1, &_aggregateUpsertStmt, NULL);
}

- (NSString *)jsonStringForHistogram:(NSDictionary<NSString *, NSNumber *> *)hist {
    if (!hist || hist.count == 0) {
        return @"{}";
    }
    NSData *data = [NSJSONSerialization dataWithJSONObject:hist options:0 error:nil];
    if (!data) {
        return @"{}";
    }
    NSString *string = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    return string.length > 0 ? string : @"{}";
}

@end

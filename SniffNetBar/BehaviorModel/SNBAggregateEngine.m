//
//  SNBAggregateEngine.m
//  SniffNetBar
//

#import "SNBAggregateEngine.h"
#import "SNBBehaviorDatabase.h"
#import "SNBEventSchema.h"
#import "SNBModelingUtilities.h"
#import "Logger.h"
#import <sqlite3.h>

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
@end

@implementation SNBAggregateState
@end

@implementation SNBAggregateSnapshot
@end

@interface SNBAggregateEngine ()
@property (nonatomic, strong) SNBBehaviorDatabase *database;
@property (nonatomic, strong) NSMutableDictionary<NSString *, SNBAggregateState *> *cache;
@property (nonatomic, assign) sqlite3_stmt *windowUpsertStmt;
@end

static void *SNBAggregateQueueKey = &SNBAggregateQueueKey;

@implementation SNBAggregateEngine

- (instancetype)initWithDatabase:(SNBBehaviorDatabase *)database {
    self = [super init];
    if (self) {
        _database = database;
        dispatch_queue_set_specific(_database.queue, SNBAggregateQueueKey, SNBAggregateQueueKey, NULL);
        _cache = [NSMutableDictionary dictionary];
        [self ensureSchema];
        [self prepareStatements];
    }
    return self;
}

- (void)processEvents:(NSArray<SNBFlowEvent *> *)events {
    if (events.count == 0) {
        return;
    }
    dispatch_sync(self.database.queue, ^{
        sqlite3 *db = self.database.db;
        if (!db) {
            return;
        }
        sqlite3_exec(db, "BEGIN IMMEDIATE;", NULL, NULL, NULL);

        const char *sql =
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

        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
            sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
            return;
        }

        for (SNBFlowEvent *event in events) {
            NSString *clusterID = SNBClusterIDForEvent(event);
            SNBAggregateState *state = [self aggregateStateForClusterID:clusterID];

            uint64_t bytes = event.bytesIn + event.bytesOut;
            double lastSeen = event.end.timeIntervalSince1970;

            state.seenCount += 1;
            [self updateHistogramsForState:state timestamp:event.end];
            [self updateIntervalStatsForState:state timestamp:lastSeen];
            [self updateRollingWindowsForCluster:clusterID timestamp:event.end bytes:bytes];

            state.bytesEwma = state.seenCount == 1 ? bytes : (0.3 * bytes) + (0.7 * state.bytesEwma);
            state.beaconScore = [self computeBeaconScoreForState:state];
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

            sqlite3_reset(stmt);
            sqlite3_bind_text(stmt, 1, clusterID.UTF8String, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(stmt, 2, (sqlite3_int64)state.seenCount);
            sqlite3_bind_double(stmt, 3, lastSeen);
            sqlite3_bind_double(stmt, 4, state.bytesEwma);
            sqlite3_bind_double(stmt, 5, 1.0);
            sqlite3_bind_text(stmt, 6, [self jsonStringForHistogram:state.hourHistogram].UTF8String, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 7, [self jsonStringForHistogram:state.dowHistogram].UTF8String, -1, SQLITE_TRANSIENT);
            sqlite3_bind_double(stmt, 8, state.intervalEwma);
            sqlite3_bind_double(stmt, 9, state.intervalVarEwma);
            sqlite3_bind_double(stmt, 10, state.beaconScore);
            sqlite3_bind_text(stmt, 11, state.baselineASN.UTF8String, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 12, state.baselineOrg.UTF8String, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 13, state.baselineGeo.UTF8String, -1, SQLITE_TRANSIENT);
            sqlite3_step(stmt);
        }

        sqlite3_finalize(stmt);
        sqlite3_exec(db, "COMMIT;", NULL, NULL, NULL);
    });
}

- (uint64_t)seenCountForClusterID:(NSString *)clusterID {
    SNBAggregateState *state = self.cache[clusterID];
    return state ? state.seenCount : 0;
}

- (SNBAggregateSnapshot *)snapshotForClusterID:(NSString *)clusterID {
    SNBAggregateState *state = [self aggregateStateForClusterID:clusterID];
    SNBAggregateSnapshot *snapshot = [[SNBAggregateSnapshot alloc] init];
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

    if (dispatch_get_specific(SNBAggregateQueueKey)) {
        snapshot.seen1h = [self seenCountForClusterID:clusterID windowSeconds:3600];
        snapshot.seen24h = [self seenCountForClusterID:clusterID windowSeconds:86400];
        snapshot.seen7d = [self seenCountForClusterID:clusterID windowSeconds:604800];
    } else {
        dispatch_sync(self.database.queue, ^{
            snapshot.seen1h = [self seenCountForClusterID:clusterID windowSeconds:3600];
            snapshot.seen24h = [self seenCountForClusterID:clusterID windowSeconds:86400];
            snapshot.seen7d = [self seenCountForClusterID:clusterID windowSeconds:604800];
        });
    }

    return snapshot;
}

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
    sqlite3_exec(db, "ALTER TABLE aggregates ADD COLUMN baseline_asn TEXT;", NULL, NULL, NULL);
    sqlite3_exec(db, "ALTER TABLE aggregates ADD COLUMN baseline_org TEXT;", NULL, NULL, NULL);
    sqlite3_exec(db, "ALTER TABLE aggregates ADD COLUMN baseline_geo TEXT;", NULL, NULL, NULL);

    const char *windowSql =
        "CREATE TABLE IF NOT EXISTS aggregates_windows ("
        "cluster_id TEXT, "
        "window_type TEXT, "
        "bucket_start REAL, "
        "seen_count INTEGER, "
        "bytes_sum INTEGER, "
        "PRIMARY KEY(cluster_id, window_type, bucket_start)"
        ");";
    sqlite3_exec(db, windowSql, NULL, NULL, NULL);
}

- (SNBAggregateState *)aggregateStateForClusterID:(NSString *)clusterID {
    SNBAggregateState *state = self.cache[clusterID];
    if (state) {
        return state;
    }
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
    [self loadBaselineForState:state clusterID:clusterID];
    self.cache[clusterID] = state;
    return state;
}

- (void)loadBaselineForState:(SNBAggregateState *)state clusterID:(NSString *)clusterID {
    if (!state || clusterID.length == 0) {
        return;
    }
    sqlite3 *db = self.database.db;
    if (!db) {
        return;
    }
    void (^loadBlock)(void) = ^{
        const char *sql =
            "SELECT baseline_asn, baseline_org, baseline_geo "
            "FROM aggregates WHERE cluster_id = ?;";
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
            return;
        }
        sqlite3_bind_text(stmt, 1, clusterID.UTF8String, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const unsigned char *asn = sqlite3_column_text(stmt, 0);
            const unsigned char *org = sqlite3_column_text(stmt, 1);
            const unsigned char *geo = sqlite3_column_text(stmt, 2);
            state.baselineASN = asn ? [NSString stringWithUTF8String:(const char *)asn] : @"";
            state.baselineOrg = org ? [NSString stringWithUTF8String:(const char *)org] : @"";
            state.baselineGeo = geo ? [NSString stringWithUTF8String:(const char *)geo] : @"";
        }
        sqlite3_finalize(stmt);
    };

    if (dispatch_get_specific(SNBAggregateQueueKey)) {
        loadBlock();
    } else {
        dispatch_sync(self.database.queue, loadBlock);
    }
}

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
    state.lastSeen = timestamp;
}

- (void)updateRollingWindowsForCluster:(NSString *)clusterID
                             timestamp:(NSDate *)timestamp
                                 bytes:(uint64_t)bytes {
    double ts = timestamp.timeIntervalSince1970;
    double hourBucket = floor(ts / 3600.0) * 3600.0;
    double dayBucket = floor(ts / 86400.0) * 86400.0;
    double weekBucket = floor(ts / 604800.0) * 604800.0;

    [self upsertWindowForCluster:clusterID windowType:@"1h" bucketStart:hourBucket bytes:bytes];
    [self upsertWindowForCluster:clusterID windowType:@"24h" bucketStart:dayBucket bytes:bytes];
    [self upsertWindowForCluster:clusterID windowType:@"7d" bucketStart:weekBucket bytes:bytes];
}

- (void)upsertWindowForCluster:(NSString *)clusterID
                    windowType:(NSString *)windowType
                   bucketStart:(double)bucketStart
                         bytes:(uint64_t)bytes {
    sqlite3_stmt *stmt = self.windowUpsertStmt;
    if (!stmt) {
        return;
    }
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);
    sqlite3_bind_text(stmt, 1, clusterID.UTF8String, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, windowType.UTF8String, -1, SQLITE_TRANSIENT);
    sqlite3_bind_double(stmt, 3, bucketStart);
    sqlite3_bind_int64(stmt, 4, (sqlite3_int64)bytes);
    sqlite3_step(stmt);
}

- (uint64_t)seenCountForClusterID:(NSString *)clusterID windowSeconds:(NSTimeInterval)windowSeconds {
    sqlite3 *db = self.database.db;
    if (!db) {
        return 0;
    }
    double now = [[NSDate date] timeIntervalSince1970];
    double cutoff = now - windowSeconds;
    const char *sql =
        "SELECT IFNULL(SUM(seen_count), 0) FROM aggregates_windows "
        "WHERE cluster_id = ? AND bucket_start >= ?;";
    sqlite3_stmt *stmt = NULL;
    uint64_t count = 0;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, clusterID.UTF8String, -1, SQLITE_TRANSIENT);
        sqlite3_bind_double(stmt, 2, cutoff);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            count = (uint64_t)sqlite3_column_int64(stmt, 0);
        }
    }
    sqlite3_finalize(stmt);
    return count;
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

- (void)prepareStatements {
    sqlite3 *db = self.database.db;
    if (!db) {
        return;
    }
    const char *sql =
        "INSERT INTO aggregates_windows (cluster_id, window_type, bucket_start, seen_count, bytes_sum) "
        "VALUES (?, ?, ?, 1, ?) "
        "ON CONFLICT(cluster_id, window_type, bucket_start) DO UPDATE SET "
        "seen_count = seen_count + 1, "
        "bytes_sum = bytes_sum + excluded.bytes_sum;";
    sqlite3_prepare_v2(db, sql, -1, &_windowUpsertStmt, NULL);
}

- (NSString *)jsonStringForHistogram:(NSDictionary<NSString *, NSNumber *> *)hist {
    if (!hist) {
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

//
//  AnomalyStore.m
//  SniffNetBar
//
//  SQLite persistence for anomaly detection data
//

#import "AnomalyStore.h"
#import "Logger.h"
#import "SNBTimerCoordinator.h"
#import <sqlite3.h>

// Batching configuration constants
static const NSUInteger kMaxBatchSize = 100;           // Flush after 100 records
static const NSTimeInterval kBatchFlushInterval = 5.0; // Flush every 5 seconds

@interface SNBAnomalyWindowBatch : NSObject
@property (nonatomic, copy) NSString *ipAddress;
@property (nonatomic, assign) NSTimeInterval windowStart;
@property (nonatomic, assign) NSInteger dstPort;
@property (nonatomic, assign) NSInteger proto;
@property (nonatomic, assign) double totalBytes;
@property (nonatomic, assign) double totalPackets;
@property (nonatomic, assign) double uniqueSrcPorts;
@property (nonatomic, assign) double flowCount;
@property (nonatomic, assign) double avgPktSize;
@property (nonatomic, assign) double bytesPerFlow;
@property (nonatomic, assign) double pktsPerFlow;
@property (nonatomic, assign) double burstiness;
@property (nonatomic, assign) BOOL isNewDst;
@property (nonatomic, assign) BOOL isRareDst;
@property (nonatomic, assign) double score;
@end

@implementation SNBAnomalyWindowBatch
@end

@interface SNBAnomalyStore ()
@property (nonatomic, assign) sqlite3 *db;
@property (nonatomic, strong) NSMutableArray<SNBAnomalyWindowBatch *> *pendingWindows;
@property (nonatomic, strong) dispatch_queue_t batchQueue;
@property (nonatomic, strong) dispatch_queue_t dbQueue;
@property (nonatomic, copy) SNBTimerID flushTimerID;
@end

@implementation SNBAnomalyWindowRecord
@end

@implementation SNBAnomalyStore

+ (instancetype)sharedStore {
    static SNBAnomalyStore *sharedStore = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sharedStore = [[SNBAnomalyStore alloc] init];
    });
    return sharedStore;
}

#pragma mark - Transaction Helpers

- (BOOL)beginWriteTransactionWithSavepoint:(NSString * _Nullable * _Nullable)savepointName {
    if (!self.db) {
        return NO;
    }

    if (sqlite3_get_autocommit(self.db) == 0) {
        NSString *name = [NSString stringWithFormat:@"snb_%u", arc4random()];
        NSString *sql = [NSString stringWithFormat:@"SAVEPOINT %@;", name];
        int status = sqlite3_exec(self.db, sql.UTF8String, NULL, NULL, NULL);
        if (status == SQLITE_OK) {
            if (savepointName) {
                *savepointName = name;
            }
            return YES;
        }
        SNBLogError("AnomalyStore: Failed to create savepoint: %s (code %d)", sqlite3_errmsg(self.db), status);
        return NO;
    }

    int status = sqlite3_exec(self.db, "BEGIN IMMEDIATE;", NULL, NULL, NULL);
    if (status != SQLITE_OK) {
        SNBLogError("AnomalyStore: Failed to begin transaction: %s (code %d)", sqlite3_errmsg(self.db), status);
        return NO;
    }
    if (savepointName) {
        *savepointName = nil;
    }
    return YES;
}

- (void)endWriteTransactionWithSavepoint:(NSString * _Nullable)savepointName success:(BOOL)success {
    if (!self.db) {
        return;
    }

    if (savepointName.length > 0) {
        if (success) {
            NSString *sql = [NSString stringWithFormat:@"RELEASE SAVEPOINT %@;", savepointName];
            sqlite3_exec(self.db, sql.UTF8String, NULL, NULL, NULL);
        } else {
            NSString *rollback = [NSString stringWithFormat:@"ROLLBACK TO SAVEPOINT %@;", savepointName];
            sqlite3_exec(self.db, rollback.UTF8String, NULL, NULL, NULL);
            NSString *release = [NSString stringWithFormat:@"RELEASE SAVEPOINT %@;", savepointName];
            sqlite3_exec(self.db, release.UTF8String, NULL, NULL, NULL);
        }
        return;
    }

    sqlite3_exec(self.db, success ? "COMMIT;" : "ROLLBACK;", NULL, NULL, NULL);
}

+ (NSString *)applicationSupportDirectory {
    NSArray<NSString *> *paths = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory,
                                                                     NSUserDomainMask,
                                                                     YES);
    NSString *baseDir = paths.firstObject ?: NSTemporaryDirectory();
    NSString *appDir = [baseDir stringByAppendingPathComponent:@"SniffNetBar"];
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:appDir]) {
        [fm createDirectoryAtPath:appDir withIntermediateDirectories:YES attributes:nil error:nil];
    }
    return appDir;
}

+ (NSString *)applicationSupportDirectoryPath {
    return [self applicationSupportDirectory];
}

+ (NSString *)defaultDatabasePath {
    return [[self applicationSupportDirectory] stringByAppendingPathComponent:@"anomaly.sqlite"];
}

+ (NSString *)defaultModelPath {
    return [[self applicationSupportDirectory] stringByAppendingPathComponent:@"anomaly_model.joblib"];
}

+ (NSString *)defaultCoreMLModelPath {
    NSString *supportPath = [[self applicationSupportDirectory] stringByAppendingPathComponent:@"anomaly_model.mlmodelc"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:supportPath]) {
        return supportPath;
    }
    NSString *bundled = [[NSBundle mainBundle] pathForResource:@"anomaly_model" ofType:@"mlmodelc"];
    if (bundled.length > 0) {
        return bundled;
    }
    return supportPath;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _pendingWindows = [NSMutableArray array];
        _batchQueue = dispatch_queue_create("com.sniffnetbar.anomalystore.batch", DISPATCH_QUEUE_SERIAL);
        _dbQueue = dispatch_queue_create("com.sniffnetbar.anomalystore.db", DISPATCH_QUEUE_SERIAL);

        [self openDatabase];
        [self ensureSchema];

        // Set up periodic flush timer via centralized coordinator (better battery efficiency)
        __weak typeof(self) weakSelf = self;
        SNBTimerCoordinator *coordinator = [SNBTimerCoordinator sharedCoordinator];
        _flushTimerID = [coordinator scheduleRepeatingTimerWithInterval:kBatchFlushInterval
                                                                  queue:dispatch_get_main_queue()
                                                                handler:^{
            [weakSelf flush];
        }];
    }
    return self;
}

- (void)dealloc {
    SNBTimerCoordinator *coordinator = [SNBTimerCoordinator sharedCoordinator];
    [coordinator cancelTimer:_flushTimerID];
    _flushTimerID = nil;

    // Flush any pending writes before closing
    [self flush];

    if (self.db) {
        sqlite3_close(self.db);
        self.db = NULL;
    }
}

- (void)openDatabase {
    static BOOL s_loggedDatabaseOpen = NO;
    NSString *path = [SNBAnomalyStore defaultDatabasePath];

    // Ensure the parent directory exists
    NSString *directory = [path stringByDeletingLastPathComponent];
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:directory]) {
        NSError *error = nil;
        if (![fm createDirectoryAtPath:directory withIntermediateDirectories:YES attributes:nil error:&error]) {
            SNBLogError("AnomalyStore: Failed to create database directory at %{public}@ (%{public}@)",
                        directory, error.localizedDescription);
            return;
        }
    }

    // Use sqlite3_open_v2 with explicit flags to create the database
    int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE;
    int result = sqlite3_open_v2([path fileSystemRepresentation], &_db, flags, NULL);

    if (result != SQLITE_OK) {
        SNBLogError("AnomalyStore: Failed to open/create database at %{public}@: %s (error code: %d)",
                    path, sqlite3_errmsg(self.db), result);
        if (self.db) {
            sqlite3_close(self.db);
            self.db = NULL;
        }
    } else {
        sqlite3_exec(self.db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);
        sqlite3_exec(self.db, "PRAGMA synchronous=NORMAL;", NULL, NULL, NULL);
        sqlite3_busy_timeout(self.db, 2000);
        if (!s_loggedDatabaseOpen) {
            SNBLogInfo("AnomalyStore: Opened database at %{public}@", path);
            s_loggedDatabaseOpen = YES;
        }
    }
}

- (void)ensureSchema {
    if (!self.db) {
        return;
    }

    const char *createWindows =
        "CREATE TABLE IF NOT EXISTS anomaly_windows ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "window_start INTEGER NOT NULL, "
        "dst_ip TEXT NOT NULL, "
        "dst_port INTEGER NOT NULL, "
        "proto INTEGER NOT NULL, "
        "total_bytes REAL NOT NULL, "
        "total_packets REAL NOT NULL, "
        "unique_src_ports REAL NOT NULL, "
        "flow_count REAL NOT NULL, "
        "avg_pkt_size REAL NOT NULL, "
        "bytes_per_flow REAL NOT NULL, "
        "pkts_per_flow REAL NOT NULL, "
        "burstiness REAL NOT NULL, "
        "is_new_dst INTEGER NOT NULL, "
        "is_rare_dst INTEGER NOT NULL, "
        "score REAL NOT NULL, "
        "created_at INTEGER NOT NULL"
        ");";

    const char *createIpStats =
        "CREATE TABLE IF NOT EXISTS anomaly_ip_stats ("
        "dst_ip TEXT PRIMARY KEY, "
        "seen_count INTEGER NOT NULL, "
        "last_seen INTEGER NOT NULL, "
        "avg_score REAL NOT NULL"
        ");";

    // Performance: Create indexes for common query patterns
    const char *createIndexTime =
        "CREATE INDEX IF NOT EXISTS idx_anomaly_windows_time "
        "ON anomaly_windows(window_start);";

    const char *createIndexIP =
        "CREATE INDEX IF NOT EXISTS idx_anomaly_windows_ip "
        "ON anomaly_windows(dst_ip);";

    const char *createIndexComposite =
        "CREATE INDEX IF NOT EXISTS idx_anomaly_windows_ip_time "
        "ON anomaly_windows(dst_ip, window_start DESC);";

    const char *createIndexScore =
        "CREATE INDEX IF NOT EXISTS idx_anomaly_windows_score "
        "ON anomaly_windows(score DESC) WHERE score >= 0.5;";

    const char *createExplanations =
        "CREATE TABLE IF NOT EXISTS anomaly_explanations ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "window_start INTEGER NOT NULL, "
        "dst_ip TEXT NOT NULL, "
        "risk_band TEXT NOT NULL, "
        "summary TEXT NOT NULL, "
        "evidence_tags TEXT NOT NULL, "
        "prompt_version TEXT NOT NULL, "
        "created_at INTEGER NOT NULL, "
        "UNIQUE(window_start, dst_ip)"
        ");";

    sqlite3_exec(self.db, createWindows, NULL, NULL, NULL);
    sqlite3_exec(self.db, createIpStats, NULL, NULL, NULL);
    sqlite3_exec(self.db, createIndexTime, NULL, NULL, NULL);
    sqlite3_exec(self.db, createIndexIP, NULL, NULL, NULL);
    sqlite3_exec(self.db, createIndexComposite, NULL, NULL, NULL);
    sqlite3_exec(self.db, createIndexScore, NULL, NULL, NULL);
    sqlite3_exec(self.db, createExplanations, NULL, NULL, NULL);
}

- (NSInteger)seenCountForIP:(NSString *)ipAddress {
    if (!self.db) {
        return 0;
    }
    __block NSInteger seenCount = 0;
    dispatch_sync(self.dbQueue, ^{
        sqlite3_stmt *stmt = NULL;
        const char *sql = "SELECT seen_count FROM anomaly_ip_stats WHERE dst_ip = ?;";
        if (sqlite3_prepare_v2(self.db, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, ipAddress.UTF8String, -1, SQLITE_TRANSIENT);
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                seenCount = sqlite3_column_int(stmt, 0);
            }
        }
        sqlite3_finalize(stmt);
    });
    return seenCount;
}

- (void)recordWindowForIP:(NSString *)ipAddress
              windowStart:(NSTimeInterval)windowStart
                  dstPort:(NSInteger)dstPort
                    proto:(NSInteger)proto
               totalBytes:(double)totalBytes
             totalPackets:(double)totalPackets
          uniqueSrcPorts:(double)uniqueSrcPorts
                flowCount:(double)flowCount
             avgPktSize:(double)avgPktSize
          bytesPerFlow:(double)bytesPerFlow
            pktsPerFlow:(double)pktsPerFlow
              burstiness:(double)burstiness
                 isNewDst:(BOOL)isNewDst
                isRareDst:(BOOL)isRareDst
                   score:(double)score {
    if (!self.db) {
        return;
    }

    // Performance optimization: Batch writes instead of writing immediately
    // This reduces disk I/O from thousands of writes/sec to ~20 writes/sec
    dispatch_async(self.batchQueue, ^{
        SNBAnomalyWindowBatch *batch = [[SNBAnomalyWindowBatch alloc] init];
        batch.ipAddress = ipAddress;
        batch.windowStart = windowStart;
        batch.dstPort = dstPort;
        batch.proto = proto;
        batch.totalBytes = totalBytes;
        batch.totalPackets = totalPackets;
        batch.uniqueSrcPorts = uniqueSrcPorts;
        batch.flowCount = flowCount;
        batch.avgPktSize = avgPktSize;
        batch.bytesPerFlow = bytesPerFlow;
        batch.pktsPerFlow = pktsPerFlow;
        batch.burstiness = burstiness;
        batch.isNewDst = isNewDst;
        batch.isRareDst = isRareDst;
        batch.score = score;

        [self.pendingWindows addObject:batch];

        // Auto-flush when batch size is reached
        if (self.pendingWindows.count >= kMaxBatchSize) {
            [self flushBatchedWindows];
        }
    });
}

// Internal method to flush buffered window records (called on batchQueue)
- (void)flushBatchedWindows {
    if (self.pendingWindows.count == 0) {
        return;
    }

    NSArray<SNBAnomalyWindowBatch *> *toFlush = [self.pendingWindows copy];
    [self.pendingWindows removeAllObjects];

    dispatch_sync(self.dbQueue, ^{
        NSString *savepointName = nil;
        if (![self beginWriteTransactionWithSavepoint:&savepointName]) {
            return;
        }
        BOOL success = YES;

        const char *insertWindow =
            "INSERT INTO anomaly_windows ("
            "window_start, dst_ip, dst_port, proto, total_bytes, total_packets, "
            "unique_src_ports, flow_count, avg_pkt_size, bytes_per_flow, pkts_per_flow, "
            "burstiness, is_new_dst, is_rare_dst, score, created_at"
            ") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);";

        const char *upsertIp =
            "INSERT INTO anomaly_ip_stats (dst_ip, seen_count, last_seen, avg_score) "
            "VALUES (?, 1, ?, ?) "
            "ON CONFLICT(dst_ip) DO UPDATE SET "
            "seen_count = seen_count + 1, "
            "last_seen = excluded.last_seen, "
            "avg_score = (avg_score * (seen_count) + excluded.avg_score) / (seen_count + 1);";

        NSTimeInterval now = [[NSDate date] timeIntervalSince1970];

        for (SNBAnomalyWindowBatch *batch in toFlush) {
            sqlite3_stmt *stmt = NULL;

            // Insert window record
            if (sqlite3_prepare_v2(self.db, insertWindow, -1, &stmt, NULL) == SQLITE_OK) {
                sqlite3_bind_int64(stmt, 1, (sqlite3_int64)batch.windowStart);
                sqlite3_bind_text(stmt, 2, batch.ipAddress.UTF8String, -1, SQLITE_TRANSIENT);
                sqlite3_bind_int(stmt, 3, (int)batch.dstPort);
                sqlite3_bind_int(stmt, 4, (int)batch.proto);
                sqlite3_bind_double(stmt, 5, batch.totalBytes);
                sqlite3_bind_double(stmt, 6, batch.totalPackets);
                sqlite3_bind_double(stmt, 7, batch.uniqueSrcPorts);
                sqlite3_bind_double(stmt, 8, batch.flowCount);
                sqlite3_bind_double(stmt, 9, batch.avgPktSize);
                sqlite3_bind_double(stmt, 10, batch.bytesPerFlow);
                sqlite3_bind_double(stmt, 11, batch.pktsPerFlow);
                sqlite3_bind_double(stmt, 12, batch.burstiness);
                sqlite3_bind_int(stmt, 13, batch.isNewDst ? 1 : 0);
                sqlite3_bind_int(stmt, 14, batch.isRareDst ? 1 : 0);
                sqlite3_bind_double(stmt, 15, batch.score);
                sqlite3_bind_int64(stmt, 16, (sqlite3_int64)now);
                if (sqlite3_step(stmt) != SQLITE_DONE) {
                    success = NO;
                }
            } else {
                success = NO;
            }
            sqlite3_finalize(stmt);

            // Update IP stats
            if (sqlite3_prepare_v2(self.db, upsertIp, -1, &stmt, NULL) == SQLITE_OK) {
                sqlite3_bind_text(stmt, 1, batch.ipAddress.UTF8String, -1, SQLITE_TRANSIENT);
                sqlite3_bind_int64(stmt, 2, (sqlite3_int64)now);
                sqlite3_bind_double(stmt, 3, batch.score);
                if (sqlite3_step(stmt) != SQLITE_DONE) {
                    success = NO;
                }
            } else {
                success = NO;
            }
            sqlite3_finalize(stmt);
        }

        [self endWriteTransactionWithSavepoint:savepointName success:success];
    });
}

// Public flush method - can be called from any thread
- (void)flush {
    dispatch_async(self.batchQueue, ^{
        [self flushBatchedWindows];
    });
}

- (NSArray<SNBAnomalyWindowRecord *> *)windowsNeedingExplanationWithMinimumScore:(double)minimumScore
                                                                          limit:(NSInteger)limit {
    if (!self.db) {
        return @[];
    }
    __block NSMutableArray<SNBAnomalyWindowRecord *> *results = [NSMutableArray array];
    dispatch_sync(self.dbQueue, ^{
        sqlite3_stmt *stmt = NULL;
        const char *sql =
            "SELECT w.window_start, w.dst_ip, w.dst_port, w.proto, "
            "w.is_new_dst, w.is_rare_dst, w.score, IFNULL(s.seen_count, 0) "
            "FROM anomaly_windows w "
            "LEFT JOIN anomaly_explanations e "
            "ON e.window_start = w.window_start AND e.dst_ip = w.dst_ip "
            "LEFT JOIN anomaly_ip_stats s "
            "ON s.dst_ip = w.dst_ip "
            "WHERE e.id IS NULL AND w.score >= ? "
            "ORDER BY w.window_start DESC "
            "LIMIT ?;";

        if (sqlite3_prepare_v2(self.db, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_double(stmt, 1, minimumScore);
            sqlite3_bind_int(stmt, 2, (int)limit);
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                SNBAnomalyWindowRecord *record = [[SNBAnomalyWindowRecord alloc] init];
                record.windowStart = sqlite3_column_int64(stmt, 0);
                const unsigned char *ip = sqlite3_column_text(stmt, 1);
                record.dstIP = ip ? [NSString stringWithUTF8String:(const char *)ip] : @"";
                record.dstPort = sqlite3_column_int(stmt, 2);
                record.proto = sqlite3_column_int(stmt, 3);
                record.isNew = sqlite3_column_int(stmt, 4) != 0;
                record.isRare = sqlite3_column_int(stmt, 5) != 0;
                record.score = sqlite3_column_double(stmt, 6);
                record.seenCount = sqlite3_column_int(stmt, 7);
                [results addObject:record];
            }
        }
        sqlite3_finalize(stmt);
    });
    return results;
}

- (void)storeExplanationForIP:(NSString *)ipAddress
                  windowStart:(NSTimeInterval)windowStart
                     riskBand:(NSString *)riskBand
                      summary:(NSString *)summary
                 evidenceTags:(NSArray<NSString *> *)evidenceTags
                 promptVersion:(NSString *)promptVersion {
    if (!self.db) {
        return;
    }
    dispatch_sync(self.dbQueue, ^{
        NSString *tagsJSON = @"[]";
        NSError *error = nil;
        NSData *tagsData = [NSJSONSerialization dataWithJSONObject:evidenceTags ?: @[] options:0 error:&error];
        if (tagsData) {
            NSString *encoded = [[NSString alloc] initWithData:tagsData encoding:NSUTF8StringEncoding];
            if (encoded.length > 0) {
                tagsJSON = encoded;
            }
        }

        NSString *savepointName = nil;
        if (![self beginWriteTransactionWithSavepoint:&savepointName]) {
            return;
        }
        BOOL success = YES;

        sqlite3_stmt *stmt = NULL;
        const char *sql =
            "INSERT OR REPLACE INTO anomaly_explanations ("
            "window_start, dst_ip, risk_band, summary, evidence_tags, prompt_version, created_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?);";

        if (sqlite3_prepare_v2(self.db, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_int64(stmt, 1, (sqlite3_int64)windowStart);
            sqlite3_bind_text(stmt, 2, ipAddress.UTF8String, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 3, riskBand.UTF8String, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 4, summary.UTF8String, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 5, tagsJSON.UTF8String, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 6, promptVersion.UTF8String, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(stmt, 7, (sqlite3_int64)[[NSDate date] timeIntervalSince1970]);
            if (sqlite3_step(stmt) != SQLITE_DONE) {
                success = NO;
            }
        } else {
            success = NO;
        }
        sqlite3_finalize(stmt);
        [self endWriteTransactionWithSavepoint:savepointName success:success];
    });
}

@end

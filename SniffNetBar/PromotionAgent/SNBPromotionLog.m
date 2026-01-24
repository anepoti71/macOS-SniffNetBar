//
//  SNBPromotionLog.m
//  SniffNetBar
//

#import "SNBPromotionLog.h"
#import "SNBPromotionDecision.h"
#import "Logger.h"
#import <sqlite3.h>

@implementation SNBPromotionLogEntry
@end

@implementation SNBPromotionLogStatistics
@end

@interface SNBPromotionLog ()
@property (nonatomic, copy) NSString *databasePath;
@property (nonatomic, assign) sqlite3 *database;
@property (nonatomic, strong) dispatch_queue_t dbQueue;
@end

@implementation SNBPromotionLog

- (instancetype)initWithDatabasePath:(NSString *)path {
    self = [super init];
    if (self) {
        _databasePath = [path copy];
        _dbQueue = dispatch_queue_create("com.sniffnetbar.promotionlog", DISPATCH_QUEUE_SERIAL);
        [self openDatabase];
        [self createTables];
    }
    return self;
}

- (void)dealloc {
    if (_database) {
        sqlite3_close(_database);
        _database = NULL;
    }
}

#pragma mark - Database Setup

- (BOOL)openDatabase {
    NSString *dir = [self.databasePath stringByDeletingLastPathComponent];
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:dir]) {
        NSError *error = nil;
        [fm createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:&error];
        if (error) {
            SNBLogAgentWarn("Failed to create promotion log directory: %{public}@", error.localizedDescription);
            return NO;
        }
    }

    int result = sqlite3_open(self.databasePath.UTF8String, &_database);
    if (result != SQLITE_OK) {
        SNBLogAgentWarn("Failed to open promotion log database: %d", result);
        return NO;
    }

    sqlite3_exec(_database, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);
    sqlite3_exec(_database, "PRAGMA synchronous=NORMAL;", NULL, NULL, NULL);

    return YES;
}

- (BOOL)createTables {
    const char *createPromotionLog =
        "CREATE TABLE IF NOT EXISTS promotion_log ("
        "    id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "    cluster_id TEXT NOT NULL,"
        "    action INTEGER NOT NULL,"
        "    reason TEXT,"
        "    confidence INTEGER,"
        "    factors_json TEXT,"
        "    blockers_json TEXT,"
        "    ai_assisted INTEGER DEFAULT 0,"
        "    ai_reasoning TEXT,"
        "    evaluated_at REAL NOT NULL,"
        "    applied_at REAL"
        ");";

    const char *createUserOverrides =
        "CREATE TABLE IF NOT EXISTS user_overrides ("
        "    id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "    cluster_id TEXT NOT NULL,"
        "    original_action INTEGER,"
        "    user_label TEXT NOT NULL,"
        "    override_at REAL NOT NULL"
        ");";

    const char *createIndexCluster = "CREATE INDEX IF NOT EXISTS idx_cluster ON promotion_log(cluster_id);";
    const char *createIndexEvaluated = "CREATE INDEX IF NOT EXISTS idx_evaluated ON promotion_log(evaluated_at);";
    const char *createIndexOverrideCluster = "CREATE INDEX IF NOT EXISTS idx_override_cluster ON user_overrides(cluster_id);";

    char *errorMsg = NULL;
    int result = sqlite3_exec(_database, createPromotionLog, NULL, NULL, &errorMsg);
    if (result != SQLITE_OK) {
        SNBLogAgentWarn("Failed to create promotion_log table: %s", errorMsg);
        sqlite3_free(errorMsg);
        return NO;
    }

    result = sqlite3_exec(_database, createUserOverrides, NULL, NULL, &errorMsg);
    if (result != SQLITE_OK) {
        SNBLogAgentWarn("Failed to create user_overrides table: %s", errorMsg);
        sqlite3_free(errorMsg);
        return NO;
    }

    sqlite3_exec(_database, createIndexCluster, NULL, NULL, NULL);
    sqlite3_exec(_database, createIndexEvaluated, NULL, NULL, NULL);
    sqlite3_exec(_database, createIndexOverrideCluster, NULL, NULL, NULL);

    return YES;
}

#pragma mark - Logging

- (BOOL)logDecision:(SNBPromotionDecision *)decision aiAssisted:(BOOL)aiAssisted {
    return [self logDecision:decision aiAssisted:aiAssisted aiReasoning:nil];
}

- (BOOL)logDecision:(SNBPromotionDecision *)decision aiAssisted:(BOOL)aiAssisted aiReasoning:(NSString *)aiReasoning {
    __block BOOL success = NO;

    dispatch_sync(self.dbQueue, ^{
        const char *sql =
            "INSERT INTO promotion_log (cluster_id, action, reason, confidence, factors_json, blockers_json, ai_assisted, ai_reasoning, evaluated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);";

        sqlite3_stmt *stmt = NULL;
        int result = sqlite3_prepare_v2(self.database, sql, -1, &stmt, NULL);
        if (result != SQLITE_OK) {
            SNBLogAgentWarn("Failed to prepare log insert: %d", result);
            return;
        }

        sqlite3_bind_text(stmt, 1, decision.clusterID.UTF8String, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 2, (int)decision.action);
        sqlite3_bind_text(stmt, 3, decision.reason.UTF8String, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 4, (int)decision.confidence);

        NSString *factorsJson = [self jsonStringFromArray:decision.factors];
        sqlite3_bind_text(stmt, 5, factorsJson.UTF8String, -1, SQLITE_TRANSIENT);

        NSString *blockersJson = [self jsonStringFromArray:decision.blockers];
        sqlite3_bind_text(stmt, 6, blockersJson.UTF8String, -1, SQLITE_TRANSIENT);

        sqlite3_bind_int(stmt, 7, aiAssisted ? 1 : 0);
        sqlite3_bind_text(stmt, 8, aiReasoning.UTF8String, -1, SQLITE_TRANSIENT);

        double timestamp = decision.evaluatedAt ? [decision.evaluatedAt timeIntervalSinceReferenceDate] : [[NSDate date] timeIntervalSinceReferenceDate];
        sqlite3_bind_double(stmt, 9, timestamp);

        result = sqlite3_step(stmt);
        success = (result == SQLITE_DONE);
        if (!success) {
            SNBLogAgentWarn("Failed to insert log entry: %d", result);
        }

        sqlite3_finalize(stmt);
    });

    return success;
}

- (BOOL)markDecisionApplied:(NSString *)clusterID {
    __block BOOL success = NO;

    dispatch_sync(self.dbQueue, ^{
        const char *sql =
            "UPDATE promotion_log SET applied_at = ? "
            "WHERE cluster_id = ? AND applied_at IS NULL "
            "ORDER BY evaluated_at DESC LIMIT 1;";

        sqlite3_stmt *stmt = NULL;
        int result = sqlite3_prepare_v2(self.database, sql, -1, &stmt, NULL);
        if (result != SQLITE_OK) {
            return;
        }

        double now = [[NSDate date] timeIntervalSinceReferenceDate];
        sqlite3_bind_double(stmt, 1, now);
        sqlite3_bind_text(stmt, 2, clusterID.UTF8String, -1, SQLITE_TRANSIENT);

        result = sqlite3_step(stmt);
        success = (result == SQLITE_DONE);
        sqlite3_finalize(stmt);
    });

    return success;
}

- (BOOL)logUserOverride:(NSString *)clusterID
            fromAction:(SNBPromotionAction)from
             toLabel:(NSString *)userLabel {
    __block BOOL success = NO;

    dispatch_sync(self.dbQueue, ^{
        const char *sql =
            "INSERT INTO user_overrides (cluster_id, original_action, user_label, override_at) "
            "VALUES (?, ?, ?, ?);";

        sqlite3_stmt *stmt = NULL;
        int result = sqlite3_prepare_v2(self.database, sql, -1, &stmt, NULL);
        if (result != SQLITE_OK) {
            return;
        }

        sqlite3_bind_text(stmt, 1, clusterID.UTF8String, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 2, (int)from);
        sqlite3_bind_text(stmt, 3, userLabel.UTF8String, -1, SQLITE_TRANSIENT);
        sqlite3_bind_double(stmt, 4, [[NSDate date] timeIntervalSinceReferenceDate]);

        result = sqlite3_step(stmt);
        success = (result == SQLITE_DONE);
        sqlite3_finalize(stmt);
    });

    return success;
}

#pragma mark - Queries

- (NSArray<SNBPromotionLogEntry *> *)decisionsForCluster:(NSString *)clusterID {
    __block NSMutableArray<SNBPromotionLogEntry *> *entries = [NSMutableArray array];

    dispatch_sync(self.dbQueue, ^{
        const char *sql =
            "SELECT id, cluster_id, action, reason, confidence, factors_json, blockers_json, "
            "ai_assisted, ai_reasoning, evaluated_at, applied_at "
            "FROM promotion_log WHERE cluster_id = ? ORDER BY evaluated_at DESC;";

        sqlite3_stmt *stmt = NULL;
        int result = sqlite3_prepare_v2(self.database, sql, -1, &stmt, NULL);
        if (result != SQLITE_OK) {
            return;
        }

        sqlite3_bind_text(stmt, 1, clusterID.UTF8String, -1, SQLITE_TRANSIENT);

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            SNBPromotionLogEntry *entry = [self entryFromStatement:stmt];
            if (entry) {
                [entries addObject:entry];
            }
        }

        sqlite3_finalize(stmt);
    });

    return entries;
}

- (NSArray<SNBPromotionLogEntry *> *)recentDecisions:(NSUInteger)limit {
    __block NSMutableArray<SNBPromotionLogEntry *> *entries = [NSMutableArray array];

    dispatch_sync(self.dbQueue, ^{
        const char *sql =
            "SELECT id, cluster_id, action, reason, confidence, factors_json, blockers_json, "
            "ai_assisted, ai_reasoning, evaluated_at, applied_at "
            "FROM promotion_log ORDER BY evaluated_at DESC LIMIT ?;";

        sqlite3_stmt *stmt = NULL;
        int result = sqlite3_prepare_v2(self.database, sql, -1, &stmt, NULL);
        if (result != SQLITE_OK) {
            return;
        }

        sqlite3_bind_int(stmt, 1, (int)limit);

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            SNBPromotionLogEntry *entry = [self entryFromStatement:stmt];
            if (entry) {
                [entries addObject:entry];
            }
        }

        sqlite3_finalize(stmt);
    });

    return entries;
}

- (SNBPromotionLogStatistics *)statisticsSince:(NSDate *)since {
    __block SNBPromotionLogStatistics *stats = [[SNBPromotionLogStatistics alloc] init];

    dispatch_sync(self.dbQueue, ^{
        double sinceTimestamp = [since timeIntervalSinceReferenceDate];

        // Count total decisions
        const char *countSql = "SELECT COUNT(*) FROM promotion_log WHERE evaluated_at >= ?;";
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(self.database, countSql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_double(stmt, 1, sinceTimestamp);
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                stats.totalDecisions = (NSUInteger)sqlite3_column_int64(stmt, 0);
            }
            sqlite3_finalize(stmt);
        }

        // Count by action
        const char *actionSql = "SELECT action, COUNT(*) FROM promotion_log WHERE evaluated_at >= ? GROUP BY action;";
        if (sqlite3_prepare_v2(self.database, actionSql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_double(stmt, 1, sinceTimestamp);
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                SNBPromotionAction action = (SNBPromotionAction)sqlite3_column_int(stmt, 0);
                NSUInteger count = (NSUInteger)sqlite3_column_int64(stmt, 1);
                switch (action) {
                    case SNBPromotionActionAutoPromote:
                        stats.autoPromoted = count;
                        break;
                    case SNBPromotionActionAutoBlock:
                        stats.autoBlocked = count;
                        break;
                    case SNBPromotionActionSuggest:
                        stats.suggested = count;
                        break;
                    default:
                        break;
                }
            }
            sqlite3_finalize(stmt);
        }

        // Count AI-assisted
        const char *aiSql = "SELECT COUNT(*) FROM promotion_log WHERE evaluated_at >= ? AND ai_assisted = 1;";
        if (sqlite3_prepare_v2(self.database, aiSql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_double(stmt, 1, sinceTimestamp);
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                stats.aiAssisted = (NSUInteger)sqlite3_column_int64(stmt, 0);
            }
            sqlite3_finalize(stmt);
        }

        // Count user overrides
        const char *overrideSql = "SELECT COUNT(*) FROM user_overrides WHERE override_at >= ?;";
        if (sqlite3_prepare_v2(self.database, overrideSql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_double(stmt, 1, sinceTimestamp);
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                stats.userOverrides = (NSUInteger)sqlite3_column_int64(stmt, 0);
            }
            sqlite3_finalize(stmt);
        }

        // Calculate rates
        if (stats.aiAssisted > 0) {
            // AI accuracy = AI decisions that were NOT overridden / total AI decisions
            NSUInteger aiOverridden = 0;
            const char *aiOverrideSql =
                "SELECT COUNT(DISTINCT pl.cluster_id) FROM promotion_log pl "
                "INNER JOIN user_overrides uo ON pl.cluster_id = uo.cluster_id "
                "WHERE pl.evaluated_at >= ? AND pl.ai_assisted = 1 AND uo.override_at > pl.evaluated_at;";
            if (sqlite3_prepare_v2(self.database, aiOverrideSql, -1, &stmt, NULL) == SQLITE_OK) {
                sqlite3_bind_double(stmt, 1, sinceTimestamp);
                if (sqlite3_step(stmt) == SQLITE_ROW) {
                    aiOverridden = (NSUInteger)sqlite3_column_int64(stmt, 0);
                }
                sqlite3_finalize(stmt);
            }
            stats.aiAccuracyRate = 1.0 - ((double)aiOverridden / (double)stats.aiAssisted);
        }

        if (stats.totalDecisions > 0) {
            stats.userOverrideRate = (double)stats.userOverrides / (double)stats.totalDecisions;
        }
    });

    return stats;
}

- (double)aiAccuracyRate {
    NSDate *since = [NSDate dateWithTimeIntervalSinceNow:-30 * 86400]; // Last 30 days
    SNBPromotionLogStatistics *stats = [self statisticsSince:since];
    return stats.aiAccuracyRate;
}

- (double)userOverrideRate {
    NSDate *since = [NSDate dateWithTimeIntervalSinceNow:-30 * 86400];
    SNBPromotionLogStatistics *stats = [self statisticsSince:since];
    return stats.userOverrideRate;
}

- (BOOL)pruneOlderThan:(NSDate *)date {
    __block BOOL success = NO;

    dispatch_sync(self.dbQueue, ^{
        double timestamp = [date timeIntervalSinceReferenceDate];

        const char *pruneLogs = "DELETE FROM promotion_log WHERE evaluated_at < ?;";
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(self.database, pruneLogs, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_double(stmt, 1, timestamp);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }

        const char *pruneOverrides = "DELETE FROM user_overrides WHERE override_at < ?;";
        if (sqlite3_prepare_v2(self.database, pruneOverrides, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_double(stmt, 1, timestamp);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
            success = YES;
        }
    });

    return success;
}

#pragma mark - Helpers

- (SNBPromotionLogEntry *)entryFromStatement:(sqlite3_stmt *)stmt {
    SNBPromotionLogEntry *entry = [[SNBPromotionLogEntry alloc] init];

    entry.entryID = sqlite3_column_int64(stmt, 0);

    const char *clusterID = (const char *)sqlite3_column_text(stmt, 1);
    entry.clusterID = clusterID ? [NSString stringWithUTF8String:clusterID] : @"";

    entry.action = (SNBPromotionAction)sqlite3_column_int(stmt, 2);

    const char *reason = (const char *)sqlite3_column_text(stmt, 3);
    entry.reason = reason ? [NSString stringWithUTF8String:reason] : nil;

    entry.confidence = sqlite3_column_int(stmt, 4);

    const char *factorsJson = (const char *)sqlite3_column_text(stmt, 5);
    entry.factors = [self arrayFromJsonString:factorsJson ? [NSString stringWithUTF8String:factorsJson] : nil];

    const char *blockersJson = (const char *)sqlite3_column_text(stmt, 6);
    entry.blockers = [self arrayFromJsonString:blockersJson ? [NSString stringWithUTF8String:blockersJson] : nil];

    entry.aiAssisted = (sqlite3_column_int(stmt, 7) != 0);

    const char *aiReasoning = (const char *)sqlite3_column_text(stmt, 8);
    entry.aiReasoning = aiReasoning ? [NSString stringWithUTF8String:aiReasoning] : nil;

    double evaluatedAt = sqlite3_column_double(stmt, 9);
    entry.evaluatedAt = [NSDate dateWithTimeIntervalSinceReferenceDate:evaluatedAt];

    if (sqlite3_column_type(stmt, 10) != SQLITE_NULL) {
        double appliedAt = sqlite3_column_double(stmt, 10);
        entry.appliedAt = [NSDate dateWithTimeIntervalSinceReferenceDate:appliedAt];
    }

    return entry;
}

- (NSString *)jsonStringFromArray:(NSArray *)array {
    if (!array || array.count == 0) {
        return @"[]";
    }
    NSError *error = nil;
    NSData *data = [NSJSONSerialization dataWithJSONObject:array options:0 error:&error];
    if (error) {
        return @"[]";
    }
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}

- (NSArray<NSString *> *)arrayFromJsonString:(NSString *)json {
    if (!json || json.length == 0) {
        return @[];
    }
    NSError *error = nil;
    NSData *data = [json dataUsingEncoding:NSUTF8StringEncoding];
    NSArray *array = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
    if (error || ![array isKindOfClass:[NSArray class]]) {
        return @[];
    }
    return array;
}

@end

//
//  SNBRecommendationStore.m
//  SniffNetBar
//

#import "SNBRecommendationStore.h"
#import "SNBBehaviorDatabase.h"
#import "SNBEventSchema.h"
#import "Logger.h"
#import <sqlite3.h>

@interface SNBRecommendationStore ()
@property (nonatomic, strong) SNBBehaviorDatabase *database;
@end

@implementation SNBRecommendationStore

- (instancetype)initWithDatabase:(SNBBehaviorDatabase *)database {
    self = [super init];
    if (self) {
        _database = database;
        [self ensureSchema];
    }
    return self;
}

- (NSArray<SNBRecommendation *> *)recommendationsSince:(NSDate *)since {
    __block NSMutableArray<SNBRecommendation *> *results = [NSMutableArray array];
    dispatch_sync(self.database.queue, ^{
        sqlite3 *db = self.database.db;
        if (!db) {
            return;
        }
        const char *sql =
            "SELECT cluster_id, label, confidence, summary, evidence_json, actions_json, generated_at, "
            "extended_context, asn_anomaly, ip_only, base_confidence, score "
            "FROM recommendations WHERE generated_at > ? ORDER BY generated_at DESC;";
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
            return;
        }
        sqlite3_bind_double(stmt, 1, since.timeIntervalSince1970);
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            SNBRecommendation *rec = [[SNBRecommendation alloc] init];
            rec.clusterID = [self stringColumn:stmt index:0];
            rec.label = [self stringColumn:stmt index:1];
            rec.confidence = sqlite3_column_int(stmt, 2);
            rec.summary = [self stringColumn:stmt index:3];
            rec.evidence = [self jsonArrayColumn:stmt index:4];
            rec.actions = [self jsonArrayColumn:stmt index:5];
            rec.generatedAt = [NSDate dateWithTimeIntervalSince1970:sqlite3_column_double(stmt, 6)];
            rec.extendedContext = [self stringColumn:stmt index:7];
            rec.asnAnomaly = sqlite3_column_int(stmt, 8) != 0;
            rec.ipOnly = sqlite3_column_int(stmt, 9) != 0;
            rec.baseConfidence = sqlite3_column_int(stmt, 10);
            rec.score = sqlite3_column_int(stmt, 11);
            [results addObject:rec];
        }
        sqlite3_finalize(stmt);
    });
    return results;
}

- (BOOL)upsertRecommendation:(SNBRecommendation *)recommendation {
    if (!recommendation) {
        return NO;
    }
    __block BOOL success = YES;
    dispatch_sync(self.database.queue, ^{
        sqlite3 *db = self.database.db;
        if (!db) {
            success = NO;
            return;
        }
        const char *sql =
            "INSERT INTO recommendations (cluster_id, label, confidence, summary, evidence_json, actions_json, "
            "generated_at, extended_context, asn_anomaly, ip_only, base_confidence, score) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(cluster_id) DO UPDATE SET "
            "label = excluded.label, "
            "confidence = excluded.confidence, "
            "summary = excluded.summary, "
            "evidence_json = excluded.evidence_json, "
            "actions_json = excluded.actions_json, "
            "generated_at = excluded.generated_at, "
            "extended_context = excluded.extended_context, "
            "asn_anomaly = excluded.asn_anomaly, "
            "ip_only = excluded.ip_only, "
            "base_confidence = excluded.base_confidence, "
            "score = excluded.score;";
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
            success = NO;
            return;
        }
        NSString *evidenceJSON = [self jsonStringFromObject:recommendation.evidence];
        NSString *actionsJSON = [self jsonStringFromObject:recommendation.actions];
        sqlite3_bind_text(stmt, 1, recommendation.clusterID.UTF8String, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, recommendation.label.UTF8String, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 3, (int)recommendation.confidence);
        sqlite3_bind_text(stmt, 4, recommendation.summary.UTF8String, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 5, evidenceJSON.UTF8String, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 6, actionsJSON.UTF8String, -1, SQLITE_TRANSIENT);
        sqlite3_bind_double(stmt, 7, recommendation.generatedAt.timeIntervalSince1970);
        NSString *extendedContext = recommendation.extendedContext ?: @"{}";
        sqlite3_bind_text(stmt, 8, extendedContext.UTF8String, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 9, recommendation.asnAnomaly ? 1 : 0);
        sqlite3_bind_int(stmt, 10, recommendation.ipOnly ? 1 : 0);
        sqlite3_bind_int(stmt, 11, (int)recommendation.baseConfidence);
        sqlite3_bind_int(stmt, 12, (int)recommendation.score);
        if (sqlite3_step(stmt) != SQLITE_DONE) {
            success = NO;
        }
        sqlite3_finalize(stmt);
    });
    return success;
}

- (void)ensureSchema {
    sqlite3 *db = self.database.db;
    if (!db) {
        return;
    }
    const char *sql =
        "CREATE TABLE IF NOT EXISTS recommendations ("
        "cluster_id TEXT PRIMARY KEY, "
        "label TEXT, "
        "confidence INTEGER, "
        "summary TEXT, "
        "evidence_json TEXT, "
        "actions_json TEXT, "
        "generated_at REAL, "
        "extended_context TEXT, "
        "asn_anomaly INTEGER, "
        "ip_only INTEGER, "
        "base_confidence INTEGER, "
        "score INTEGER"
        ");";
    sqlite3_exec(db, sql, NULL, NULL, NULL);
    sqlite3_exec(db, "ALTER TABLE recommendations ADD COLUMN extended_context TEXT;", NULL, NULL, NULL);
    sqlite3_exec(db, "ALTER TABLE recommendations ADD COLUMN asn_anomaly INTEGER;", NULL, NULL, NULL);
    sqlite3_exec(db, "ALTER TABLE recommendations ADD COLUMN ip_only INTEGER;", NULL, NULL, NULL);
    sqlite3_exec(db, "ALTER TABLE recommendations ADD COLUMN base_confidence INTEGER;", NULL, NULL, NULL);
    sqlite3_exec(db, "ALTER TABLE recommendations ADD COLUMN score INTEGER;", NULL, NULL, NULL);

    const char *labelsSql =
        "CREATE TABLE IF NOT EXISTS cluster_labels ("
        "cluster_id TEXT, "
        "label TEXT, "
        "scope TEXT, "
        "updated_at REAL, "
        "PRIMARY KEY(cluster_id, scope)"
        ");";
    sqlite3_exec(db, labelsSql, NULL, NULL, NULL);
}

- (NSString *)stringColumn:(sqlite3_stmt *)stmt index:(int)index {
    const unsigned char *text = sqlite3_column_text(stmt, index);
    return text ? [NSString stringWithUTF8String:(const char *)text] : @"";
}

- (NSArray *)jsonArrayColumn:(sqlite3_stmt *)stmt index:(int)index {
    const unsigned char *text = sqlite3_column_text(stmt, index);
    if (!text) {
        return @[];
    }
    NSData *data = [NSData dataWithBytes:text length:strlen((const char *)text)];
    id obj = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    return [obj isKindOfClass:[NSArray class]] ? obj : @[];
}

- (NSString *)jsonStringFromObject:(id)obj {
    if (!obj) {
        return @"[]";
    }
    NSData *data = [NSJSONSerialization dataWithJSONObject:obj options:0 error:nil];
    if (!data) {
        return @"[]";
    }
    NSString *string = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    return string.length > 0 ? string : @"[]";
}

- (BOOL)setUserLabel:(NSString *)label forClusterID:(NSString *)clusterID scope:(NSString *)scope {
    if (clusterID.length == 0 || label.length == 0 || scope.length == 0) {
        return NO;
    }
    __block BOOL success = YES;
    dispatch_sync(self.database.queue, ^{
        sqlite3 *db = self.database.db;
        if (!db) {
            success = NO;
            return;
        }
        const char *sql =
            "INSERT INTO cluster_labels (cluster_id, label, scope, updated_at) "
            "VALUES (?, ?, ?, ?) "
            "ON CONFLICT(cluster_id, scope) DO UPDATE SET "
            "label = excluded.label, "
            "updated_at = excluded.updated_at;";
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
            success = NO;
            return;
        }
        sqlite3_bind_text(stmt, 1, clusterID.UTF8String, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, label.UTF8String, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, scope.UTF8String, -1, SQLITE_TRANSIENT);
        sqlite3_bind_double(stmt, 4, [[NSDate date] timeIntervalSince1970]);
        if (sqlite3_step(stmt) != SQLITE_DONE) {
            success = NO;
        }
        sqlite3_finalize(stmt);
    });
    return success;
}

- (NSString *)userLabelForClusterID:(NSString *)clusterID {
    if (clusterID.length == 0) {
        return @"";
    }
    __block NSString *label = @"";
    dispatch_sync(self.database.queue, ^{
        sqlite3 *db = self.database.db;
        if (!db) {
            return;
        }
        const char *sql =
            "SELECT label FROM cluster_labels "
            "WHERE cluster_id = ? ORDER BY updated_at DESC LIMIT 1;";
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
            return;
        }
        sqlite3_bind_text(stmt, 1, clusterID.UTF8String, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            label = [self stringColumn:stmt index:0];
        }
        sqlite3_finalize(stmt);
    });
    return label;
}

- (BOOL)updateRecommendationLabel:(NSString *)label forClusterID:(NSString *)clusterID {
    if (clusterID.length == 0 || label.length == 0) {
        return NO;
    }
    __block BOOL success = YES;
    dispatch_sync(self.database.queue, ^{
        sqlite3 *db = self.database.db;
        if (!db) {
            success = NO;
            return;
        }
        const char *sql =
            "UPDATE recommendations SET label = ?, confidence = ?, summary = ?, generated_at = ? "
            "WHERE cluster_id = ?;";
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
            success = NO;
            return;
        }
        sqlite3_bind_text(stmt, 1, label.UTF8String, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 2, 95);
        sqlite3_bind_text(stmt, 3, "User label applied", -1, SQLITE_TRANSIENT);
        sqlite3_bind_double(stmt, 4, [[NSDate date] timeIntervalSince1970]);
        sqlite3_bind_text(stmt, 5, clusterID.UTF8String, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) != SQLITE_DONE) {
            success = NO;
        }
        sqlite3_finalize(stmt);
    });
    return success;
}

- (BOOL)upsertRecommendations:(NSArray<SNBRecommendation *> *)recommendations {
    if (recommendations.count == 0) {
        return YES;
    }
    __block BOOL success = YES;
    dispatch_sync(self.database.queue, ^{
        sqlite3 *db = self.database.db;
        if (!db) {
            success = NO;
            return;
        }
        sqlite3_exec(db, "BEGIN IMMEDIATE;", NULL, NULL, NULL);
        const char *sql =
            "INSERT INTO recommendations (cluster_id, label, confidence, summary, evidence_json, actions_json, "
            "generated_at, extended_context, asn_anomaly, ip_only, base_confidence, score) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(cluster_id) DO UPDATE SET "
            "label = excluded.label, "
            "confidence = excluded.confidence, "
            "summary = excluded.summary, "
            "evidence_json = excluded.evidence_json, "
            "actions_json = excluded.actions_json, "
            "generated_at = excluded.generated_at, "
            "extended_context = excluded.extended_context, "
            "asn_anomaly = excluded.asn_anomaly, "
            "ip_only = excluded.ip_only, "
            "base_confidence = excluded.base_confidence, "
            "score = excluded.score;";
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
            sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
            success = NO;
            return;
        }
        for (SNBRecommendation *recommendation in recommendations) {
            NSString *evidenceJSON = [self jsonStringFromObject:recommendation.evidence];
            NSString *actionsJSON = [self jsonStringFromObject:recommendation.actions];
            sqlite3_reset(stmt);
            sqlite3_bind_text(stmt, 1, recommendation.clusterID.UTF8String, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 2, recommendation.label.UTF8String, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(stmt, 3, (int)recommendation.confidence);
            sqlite3_bind_text(stmt, 4, recommendation.summary.UTF8String, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 5, evidenceJSON.UTF8String, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 6, actionsJSON.UTF8String, -1, SQLITE_TRANSIENT);
            sqlite3_bind_double(stmt, 7, recommendation.generatedAt.timeIntervalSince1970);
            NSString *extendedContext = recommendation.extendedContext ?: @"{}";
            sqlite3_bind_text(stmt, 8, extendedContext.UTF8String, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(stmt, 9, recommendation.asnAnomaly ? 1 : 0);
            sqlite3_bind_int(stmt, 10, recommendation.ipOnly ? 1 : 0);
            sqlite3_bind_int(stmt, 11, (int)recommendation.baseConfidence);
            sqlite3_bind_int(stmt, 12, (int)recommendation.score);
            if (sqlite3_step(stmt) != SQLITE_DONE) {
                success = NO;
                break;
            }
        }
        sqlite3_finalize(stmt);
        sqlite3_exec(db, success ? "COMMIT;" : "ROLLBACK;", NULL, NULL, NULL);
    });
    return success;
}

@end

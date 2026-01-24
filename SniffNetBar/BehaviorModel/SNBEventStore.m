//
//  SNBEventStore.m
//  SniffNetBar
//

#import "SNBEventStore.h"
#import "SNBBehaviorDatabase.h"
#import "SNBEventSchema.h"
#import "SNBModelingUtilities.h"
#import "Logger.h"
#import <sqlite3.h>

@interface SNBEventStore ()
@property (nonatomic, strong) SNBBehaviorDatabase *database;
@end

@implementation SNBEventStore

- (instancetype)initWithDatabase:(SNBBehaviorDatabase *)database {
    self = [super init];
    if (self) {
        _database = database;
        [self ensureSchema];
    }
    return self;
}

- (BOOL)appendEvents:(NSArray<SNBFlowEvent *> *)events {
    if (events.count == 0) {
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
            "INSERT INTO events ("
            "cluster_id, start_ts, end_ts, direction, proto, src_ip, dst_ip, src_port, dst_port, "
            "bytes_in, bytes_out, packets, duration, dns_query, sni, http_host, "
            "process_name, bundle_id, signing_status, code_hash, outcome, asn, org, country, region, "
            "hosting, vpn, relay, vt_score, abuse_score, greynoise_class"
            ") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);";

        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
            sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
            success = NO;
            return;
        }

        for (SNBFlowEvent *event in events) {
            sqlite3_reset(stmt);
            NSString *clusterID = SNBClusterIDForEvent(event);
            sqlite3_bind_text(stmt, 1, clusterID.UTF8String, -1, SQLITE_TRANSIENT);
            sqlite3_bind_double(stmt, 2, event.start.timeIntervalSince1970);
            sqlite3_bind_double(stmt, 3, event.end.timeIntervalSince1970);
            sqlite3_bind_text(stmt, 4, event.direction.UTF8String, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 5, event.protocolName.UTF8String, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 6, event.srcIP.UTF8String, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 7, event.dstIP.UTF8String, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(stmt, 8, (int)event.srcPort);
            sqlite3_bind_int(stmt, 9, (int)event.dstPort);
            sqlite3_bind_int64(stmt, 10, (sqlite3_int64)event.bytesIn);
            sqlite3_bind_int64(stmt, 11, (sqlite3_int64)event.bytesOut);
            sqlite3_bind_int64(stmt, 12, (sqlite3_int64)event.packets);
            sqlite3_bind_double(stmt, 13, event.duration);
            sqlite3_bind_text(stmt, 14, event.dnsQuery.UTF8String, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 15, event.sni.UTF8String, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 16, event.httpHost.UTF8String, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 17, event.processName.UTF8String, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 18, event.bundleID.UTF8String, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 19, event.signingStatus.UTF8String, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 20, event.codeHash.UTF8String, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 21, event.outcome.UTF8String, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 22, event.asn.UTF8String, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 23, event.org.UTF8String, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 24, event.country.UTF8String, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 25, event.region.UTF8String, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(stmt, 26, event.hosting ? 1 : 0);
            sqlite3_bind_int(stmt, 27, event.vpn ? 1 : 0);
            sqlite3_bind_int(stmt, 28, event.relay ? 1 : 0);
            sqlite3_bind_double(stmt, 29, event.vtScore ? event.vtScore.doubleValue : 0.0);
            sqlite3_bind_double(stmt, 30, event.abuseScore ? event.abuseScore.doubleValue : 0.0);
            sqlite3_bind_text(stmt, 31, event.greyNoiseClass.UTF8String, -1, SQLITE_TRANSIENT);
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

- (void)ensureSchema {
    sqlite3 *db = self.database.db;
    if (!db) {
        return;
    }
    const char *sql =
        "CREATE TABLE IF NOT EXISTS events ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "cluster_id TEXT, "
        "start_ts REAL, "
        "end_ts REAL, "
        "direction TEXT, "
        "proto TEXT, "
        "src_ip TEXT, "
        "dst_ip TEXT, "
        "src_port INTEGER, "
        "dst_port INTEGER, "
        "bytes_in INTEGER, "
        "bytes_out INTEGER, "
        "packets INTEGER, "
        "duration REAL, "
        "dns_query TEXT, "
        "sni TEXT, "
        "http_host TEXT, "
        "process_name TEXT, "
        "bundle_id TEXT, "
        "signing_status TEXT, "
        "code_hash TEXT, "
        "outcome TEXT, "
        "asn TEXT, "
        "org TEXT, "
        "country TEXT, "
        "region TEXT, "
        "hosting INTEGER, "
        "vpn INTEGER, "
        "relay INTEGER, "
        "vt_score REAL, "
        "abuse_score REAL, "
        "greynoise_class TEXT"
        ");";
    sqlite3_exec(db, sql, NULL, NULL, NULL);

    sqlite3_exec(db, "ALTER TABLE events ADD COLUMN cluster_id TEXT;", NULL, NULL, NULL);
    sqlite3_exec(db, "ALTER TABLE events ADD COLUMN asn TEXT;", NULL, NULL, NULL);
    sqlite3_exec(db, "ALTER TABLE events ADD COLUMN org TEXT;", NULL, NULL, NULL);
    sqlite3_exec(db, "ALTER TABLE events ADD COLUMN country TEXT;", NULL, NULL, NULL);
    sqlite3_exec(db, "ALTER TABLE events ADD COLUMN region TEXT;", NULL, NULL, NULL);
    sqlite3_exec(db, "ALTER TABLE events ADD COLUMN hosting INTEGER;", NULL, NULL, NULL);
    sqlite3_exec(db, "ALTER TABLE events ADD COLUMN vpn INTEGER;", NULL, NULL, NULL);
    sqlite3_exec(db, "ALTER TABLE events ADD COLUMN relay INTEGER;", NULL, NULL, NULL);
    sqlite3_exec(db, "ALTER TABLE events ADD COLUMN vt_score REAL;", NULL, NULL, NULL);
    sqlite3_exec(db, "ALTER TABLE events ADD COLUMN abuse_score REAL;", NULL, NULL, NULL);
    sqlite3_exec(db, "ALTER TABLE events ADD COLUMN greynoise_class TEXT;", NULL, NULL, NULL);
    sqlite3_exec(db, "CREATE INDEX IF NOT EXISTS idx_events_cluster_end ON events(cluster_id, end_ts);", NULL, NULL, NULL);
}

- (SNBFlowEvent *)latestEventForClusterID:(NSString *)clusterID
                               firstSeen:(NSDate * _Nullable * _Nullable)firstSeen {
    if (clusterID.length == 0) {
        return nil;
    }
    __block SNBFlowEvent *event = nil;
    __block NSDate *first = nil;
    dispatch_sync(self.database.queue, ^{
        sqlite3 *db = self.database.db;
        if (!db) {
            return;
        }

        const char *firstSql = "SELECT MIN(start_ts) FROM events WHERE cluster_id = ?;";
        sqlite3_stmt *firstStmt = NULL;
        if (sqlite3_prepare_v2(db, firstSql, -1, &firstStmt, NULL) == SQLITE_OK) {
            sqlite3_bind_text(firstStmt, 1, clusterID.UTF8String, -1, SQLITE_TRANSIENT);
            if (sqlite3_step(firstStmt) == SQLITE_ROW) {
                double ts = sqlite3_column_double(firstStmt, 0);
                if (ts > 0) {
                    first = [NSDate dateWithTimeIntervalSince1970:ts];
                }
            }
        }
        sqlite3_finalize(firstStmt);

        const char *sql =
            "SELECT start_ts, end_ts, direction, proto, src_ip, dst_ip, src_port, dst_port, "
            "bytes_in, bytes_out, packets, duration, dns_query, sni, http_host, process_name, "
            "bundle_id, signing_status, code_hash, outcome, asn, org, country, region, "
            "hosting, vpn, relay, vt_score, abuse_score, greynoise_class "
            "FROM events WHERE cluster_id = ? ORDER BY end_ts DESC LIMIT 1;";
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
            sqlite3_finalize(stmt);
            return;
        }
        sqlite3_bind_text(stmt, 1, clusterID.UTF8String, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            event = [[SNBFlowEvent alloc] init];
            event.start = [NSDate dateWithTimeIntervalSince1970:sqlite3_column_double(stmt, 0)];
            event.end = [NSDate dateWithTimeIntervalSince1970:sqlite3_column_double(stmt, 1)];
            event.direction = [self stringColumn:stmt index:2];
            event.protocolName = [self stringColumn:stmt index:3];
            event.srcIP = [self stringColumn:stmt index:4];
            event.dstIP = [self stringColumn:stmt index:5];
            event.srcPort = sqlite3_column_int(stmt, 6);
            event.dstPort = sqlite3_column_int(stmt, 7);
            event.bytesIn = (uint64_t)sqlite3_column_int64(stmt, 8);
            event.bytesOut = (uint64_t)sqlite3_column_int64(stmt, 9);
            event.packets = (uint64_t)sqlite3_column_int64(stmt, 10);
            event.duration = sqlite3_column_double(stmt, 11);
            event.dnsQuery = [self stringColumn:stmt index:12];
            event.sni = [self stringColumn:stmt index:13];
            event.httpHost = [self stringColumn:stmt index:14];
            event.processName = [self stringColumn:stmt index:15];
            event.bundleID = [self stringColumn:stmt index:16];
            event.signingStatus = [self stringColumn:stmt index:17];
            event.codeHash = [self stringColumn:stmt index:18];
            event.outcome = [self stringColumn:stmt index:19];
            event.asn = [self stringColumn:stmt index:20];
            event.org = [self stringColumn:stmt index:21];
            event.country = [self stringColumn:stmt index:22];
            event.region = [self stringColumn:stmt index:23];
            event.hosting = sqlite3_column_int(stmt, 24) != 0;
            event.vpn = sqlite3_column_int(stmt, 25) != 0;
            event.relay = sqlite3_column_int(stmt, 26) != 0;
            event.vtScore = @(sqlite3_column_double(stmt, 27));
            event.abuseScore = @(sqlite3_column_double(stmt, 28));
            event.greyNoiseClass = [self stringColumn:stmt index:29];
        }
        sqlite3_finalize(stmt);
    });
    if (firstSeen) {
        *firstSeen = first;
    }
    return event;
}

- (NSString *)stringColumn:(sqlite3_stmt *)stmt index:(int)index {
    const unsigned char *text = sqlite3_column_text(stmt, index);
    return text ? [NSString stringWithUTF8String:(const char *)text] : @"";
}

@end

//
//  behavior_model_cli.m
//  SniffNetBar
//

#import <Foundation/Foundation.h>
#import <sqlite3.h>

static NSString *DefaultDBPath(void) {
    NSArray<NSString *> *paths = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory,
                                                                     NSUserDomainMask,
                                                                     YES);
    NSString *baseDir = paths.firstObject ?: NSTemporaryDirectory();
    return [[baseDir stringByAppendingPathComponent:@"SniffNetBar"]
            stringByAppendingPathComponent:@"behavioral.sqlite"];
}

static void PrintUsage(void) {
    fprintf(stderr, "Usage: behavior_model_cli [--db PATH] [--since SECONDS] [--limit N]\n");
}

static NSString *JSONStringFromColumn(sqlite3_stmt *stmt, int index) {
    const unsigned char *text = sqlite3_column_text(stmt, index);
    if (!text) {
        return @"[]";
    }
    return [NSString stringWithUTF8String:(const char *)text];
}

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        NSString *dbPath = DefaultDBPath();
        NSTimeInterval sinceSeconds = 3600.0;
        int limit = 10;

        for (int i = 1; i < argc; i++) {
            if (strcmp(argv[i], "--db") == 0 && i + 1 < argc) {
                dbPath = [NSString stringWithUTF8String:argv[++i]];
            } else if (strcmp(argv[i], "--since") == 0 && i + 1 < argc) {
                sinceSeconds = atof(argv[++i]);
            } else if (strcmp(argv[i], "--limit") == 0 && i + 1 < argc) {
                limit = atoi(argv[++i]);
            } else if (strcmp(argv[i], "--help") == 0) {
                PrintUsage();
                return 0;
            } else {
                PrintUsage();
                return 1;
            }
        }

        sqlite3 *db = NULL;
        if (sqlite3_open_v2(dbPath.fileSystemRepresentation, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
            fprintf(stderr, "Failed to open db at %s\n", dbPath.fileSystemRepresentation);
            if (db) {
                sqlite3_close(db);
            }
            return 1;
        }

        sqlite3_stmt *countStmt = NULL;
        if (sqlite3_prepare_v2(db, "SELECT count(*) FROM recommendations;", -1, &countStmt, NULL) == SQLITE_OK) {
            if (sqlite3_step(countStmt) == SQLITE_ROW) {
                fprintf(stdout, "recommendations: %d\n", sqlite3_column_int(countStmt, 0));
            }
        }
        sqlite3_finalize(countStmt);

        const char *sql =
            "SELECT cluster_id, label, confidence, summary, evidence_json, actions_json, generated_at "
            "FROM recommendations WHERE generated_at > ? ORDER BY generated_at DESC LIMIT ?;";

        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
            fprintf(stderr, "Failed to prepare query\n");
            sqlite3_close(db);
            return 1;
        }

        NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
        sqlite3_bind_double(stmt, 1, now - sinceSeconds);
        sqlite3_bind_int(stmt, 2, limit);

        fprintf(stdout, "recent recommendations (last %.0fs, limit %d):\n", sinceSeconds, limit);
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            NSString *cluster = [NSString stringWithUTF8String:(const char *)sqlite3_column_text(stmt, 0)];
            NSString *label = [NSString stringWithUTF8String:(const char *)sqlite3_column_text(stmt, 1)];
            int confidence = sqlite3_column_int(stmt, 2);
            NSString *summary = [NSString stringWithUTF8String:(const char *)sqlite3_column_text(stmt, 3)];
            NSString *evidence = JSONStringFromColumn(stmt, 4);
            NSString *actions = JSONStringFromColumn(stmt, 5);
            double generatedAt = sqlite3_column_double(stmt, 6);

            fprintf(stdout, "- %s | %s (%d)\n", cluster.UTF8String, label.UTF8String, confidence);
            fprintf(stdout, "  summary: %s\n", summary.UTF8String);
            fprintf(stdout, "  evidence: %s\n", evidence.UTF8String);
            fprintf(stdout, "  actions: %s\n", actions.UTF8String);
            fprintf(stdout, "  generated_at: %.0f\n", generatedAt);
        }

        sqlite3_finalize(stmt);
        sqlite3_close(db);
    }
    return 0;
}

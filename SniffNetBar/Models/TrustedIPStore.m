//
//  TrustedIPStore.m
//  SniffNetBar
//
//  Persistence for user-trusted IPs with learning context
//

#import "TrustedIPStore.h"
#import "Logger.h"
#import <sqlite3.h>
#import <arpa/inet.h>

NSString *const SNBTrustedIPStoreDidChangeNotification = @"SNBTrustedIPStoreDidChangeNotification";

#pragma mark - SNBTrustContext Implementation

@implementation SNBTrustContext

+ (NSString *)displayStringForReason:(SNBTrustReason)reason {
    switch (reason) {
        case SNBTrustReasonKnownService:
            return @"Known service (CDN, cloud)";
        case SNBTrustReasonOwnInfrastructure:
            return @"My infrastructure";
        case SNBTrustReasonFalsePositive:
            return @"False positive";
        case SNBTrustReasonTestingDev:
            return @"Testing/development";
        case SNBTrustReasonOther:
            return @"Other";
        case SNBTrustReasonAgent:
            return @"Agent decision";
        case SNBTrustReasonUnspecified:
        default:
            return @"Unspecified";
    }
}

+ (NSArray<NSNumber *> *)allReasons {
    return @[
        @(SNBTrustReasonKnownService),
        @(SNBTrustReasonOwnInfrastructure),
        @(SNBTrustReasonFalsePositive),
        @(SNBTrustReasonTestingDev),
        @(SNBTrustReasonOther)
    ];
}

- (id)copyWithZone:(NSZone *)zone {
    SNBTrustContext *copy = [[SNBTrustContext allocWithZone:zone] init];
    copy.ipAddress = self.ipAddress;
    copy.reason = self.reason;
    copy.customReasonNote = self.customReasonNote;
    copy.threatScoreAtDecision = self.threatScoreAtDecision;
    copy.verdictAtDecision = self.verdictAtDecision;
    copy.processName = self.processName;
    copy.processPID = self.processPID;
    copy.destinationPort = self.destinationPort;
    copy.hostname = self.hostname;
    copy.trustedAt = self.trustedAt;
    copy.untrustedAt = self.untrustedAt;
    copy.autoUntrusted = self.autoUntrusted;
    return copy;
}

@end

#pragma mark - SNBTrustHistoryEntry Implementation

@implementation SNBTrustHistoryEntry
@end

#pragma mark - SNBTrustedIPStore Implementation

@interface SNBTrustedIPStore ()
@property (nonatomic, strong) dispatch_queue_t ioQueue;
@property (nonatomic, assign) sqlite3 *database;
@end

@implementation SNBTrustedIPStore

+ (instancetype)sharedStore {
    static SNBTrustedIPStore *shared = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        shared = [[SNBTrustedIPStore alloc] init];
    });
    return shared;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _ioQueue = dispatch_queue_create("com.sniffnetbar.trustedipstore", DISPATCH_QUEUE_SERIAL);
        _autoUntrustThreshold = 85;  // Default threshold for auto-untrust
        dispatch_sync(_ioQueue, ^{
            [self openDatabaseAtPath:[self defaultDatabasePath]];
        });
    }
    return self;
}

- (void)dealloc {
    dispatch_sync(self.ioQueue, ^{
        if (self.database) {
            sqlite3_close(self.database);
            self.database = NULL;
        }
    });
}

- (NSString *)defaultDatabasePath {
    NSArray<NSString *> *paths = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, YES);
    NSString *base = paths.firstObject ?: NSTemporaryDirectory();
    NSString *dir = [base stringByAppendingPathComponent:@"SniffNetBar"];
    NSError *error = nil;
    [[NSFileManager defaultManager] createDirectoryAtPath:dir
                              withIntermediateDirectories:YES
                                               attributes:nil
                                                    error:&error];
    if (error) {
        SNBLogUIDebug("TrustedIPStore: failed to create App Support dir: %s",
                      error.localizedDescription.UTF8String);
    }
    return [dir stringByAppendingPathComponent:@"trusted_ips.sqlite"];
}

- (void)openDatabaseAtPath:(NSString *)path {
    sqlite3 *db = NULL;
    int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX;
    if (sqlite3_open_v2(path.UTF8String, &db, flags, NULL) != SQLITE_OK) {
        SNBLogUIDebug("TrustedIPStore: failed to open database: %s", sqlite3_errmsg(db));
        if (db) {
            sqlite3_close(db);
        }
        return;
    }

    // Main trusted_ips table with context fields
    const char *sql =
        "CREATE TABLE IF NOT EXISTS trusted_ips ("
        "ip TEXT PRIMARY KEY,"
        "trusted INTEGER NOT NULL,"
        "reason INTEGER DEFAULT 0,"
        "custom_reason_note TEXT,"
        "threat_score_at_decision INTEGER DEFAULT 0,"
        "verdict_at_decision TEXT,"
        "process_name TEXT,"
        "process_pid INTEGER DEFAULT 0,"
        "destination_port INTEGER DEFAULT 0,"
        "hostname TEXT,"
        "auto_untrusted INTEGER DEFAULT 0,"
        "created_at REAL,"
        "updated_at REAL,"
        "removed_at REAL"
        ");";

    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        SNBLogUIDebug("TrustedIPStore: failed to create trusted_ips table: %s", err ?: "unknown");
        sqlite3_free(err);
    }

    // Trust history table for audit trail
    const char *historySql =
        "CREATE TABLE IF NOT EXISTS trust_history ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "ip TEXT NOT NULL,"
        "trusted INTEGER NOT NULL,"
        "reason INTEGER DEFAULT 0,"
        "custom_reason_note TEXT,"
        "threat_score_at_decision INTEGER DEFAULT 0,"
        "verdict_at_decision TEXT,"
        "auto_action INTEGER DEFAULT 0,"
        "timestamp REAL NOT NULL"
        ");";

    err = NULL;
    if (sqlite3_exec(db, historySql, NULL, NULL, &err) != SQLITE_OK) {
        SNBLogUIDebug("TrustedIPStore: failed to create trust_history table: %s", err ?: "unknown");
        sqlite3_free(err);
    }

    // Create index for history lookups
    const char *indexSql = "CREATE INDEX IF NOT EXISTS idx_trust_history_ip ON trust_history(ip);";
    sqlite3_exec(db, indexSql, NULL, NULL, NULL);

    // Migrate existing table if needed (add new columns)
    [self migrateSchemaIfNeeded:db];

    _database = db;
}

- (void)migrateSchemaIfNeeded:(sqlite3 *)db {
    // Check if new columns exist, add if missing
    const char *columns[] = {
        "reason", "custom_reason_note", "threat_score_at_decision", "verdict_at_decision",
        "process_name", "process_pid", "destination_port", "hostname", "auto_untrusted"
    };
    const char *columnTypes[] = {
        "INTEGER DEFAULT 0", "TEXT", "INTEGER DEFAULT 0", "TEXT",
        "TEXT", "INTEGER DEFAULT 0", "INTEGER DEFAULT 0", "TEXT", "INTEGER DEFAULT 0"
    };

    for (int i = 0; i < sizeof(columns) / sizeof(columns[0]); i++) {
        NSString *checkSql = [NSString stringWithFormat:@"SELECT %s FROM trusted_ips LIMIT 1", columns[i]];
        if (sqlite3_exec(db, checkSql.UTF8String, NULL, NULL, NULL) != SQLITE_OK) {
            NSString *alterSql = [NSString stringWithFormat:@"ALTER TABLE trusted_ips ADD COLUMN %s %s",
                                  columns[i], columnTypes[i]];
            sqlite3_exec(db, alterSql.UTF8String, NULL, NULL, NULL);
            SNBLogUIDebug("TrustedIPStore: migrated schema, added column %s", columns[i]);
        }
    }
}

- (nullable NSString *)normalizedIPAddress:(NSString *)ipAddress {
    if (ipAddress.length == 0) {
        return nil;
    }
    struct in_addr addr4;
    if (inet_pton(AF_INET, ipAddress.UTF8String, &addr4) == 1) {
        char buffer[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &addr4, buffer, sizeof(buffer))) {
            return [NSString stringWithUTF8String:buffer];
        }
        return nil;
    }
    struct in6_addr addr6;
    if (inet_pton(AF_INET6, ipAddress.UTF8String, &addr6) == 1) {
        char buffer[INET6_ADDRSTRLEN];
        if (inet_ntop(AF_INET6, &addr6, buffer, sizeof(buffer))) {
            return [[NSString stringWithUTF8String:buffer] lowercaseString];
        }
        return nil;
    }
    return nil;
}

#pragma mark - Basic Trust Operations

- (BOOL)isTrustedIP:(NSString *)ipAddress {
    NSString *normalized = [self normalizedIPAddress:ipAddress];
    if (!normalized || !self.database) {
        return NO;
    }
    __block BOOL trusted = NO;
    dispatch_sync(self.ioQueue, ^{
        sqlite3_stmt *stmt = NULL;
        const char *sql = "SELECT trusted FROM trusted_ips WHERE ip = ?1 AND trusted = 1 LIMIT 1;";
        if (sqlite3_prepare_v2(self.database, sql, -1, &stmt, NULL) != SQLITE_OK) {
            return;
        }
        sqlite3_bind_text(stmt, 1, normalized.UTF8String, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            trusted = sqlite3_column_int(stmt, 0) != 0;
        }
        sqlite3_finalize(stmt);
    });
    return trusted;
}

- (nullable SNBTrustContext *)trustContextForIP:(NSString *)ipAddress {
    NSString *normalized = [self normalizedIPAddress:ipAddress];
    if (!normalized || !self.database) {
        return nil;
    }

    __block SNBTrustContext *context = nil;
    dispatch_sync(self.ioQueue, ^{
        sqlite3_stmt *stmt = NULL;
        const char *sql =
            "SELECT ip, trusted, reason, custom_reason_note, threat_score_at_decision, "
            "verdict_at_decision, process_name, process_pid, destination_port, hostname, "
            "auto_untrusted, created_at, removed_at "
            "FROM trusted_ips WHERE ip = ?1 LIMIT 1;";

        if (sqlite3_prepare_v2(self.database, sql, -1, &stmt, NULL) != SQLITE_OK) {
            return;
        }
        sqlite3_bind_text(stmt, 1, normalized.UTF8String, -1, SQLITE_TRANSIENT);

        if (sqlite3_step(stmt) == SQLITE_ROW) {
            context = [[SNBTrustContext alloc] init];
            const unsigned char *ip = sqlite3_column_text(stmt, 0);
            context.ipAddress = ip ? [NSString stringWithUTF8String:(const char *)ip] : nil;
            // Note: trusted column at index 1, but we're returning context regardless
            context.reason = sqlite3_column_int(stmt, 2);
            const unsigned char *note = sqlite3_column_text(stmt, 3);
            context.customReasonNote = note ? [NSString stringWithUTF8String:(const char *)note] : nil;
            context.threatScoreAtDecision = sqlite3_column_int(stmt, 4);
            const unsigned char *verdict = sqlite3_column_text(stmt, 5);
            context.verdictAtDecision = verdict ? [NSString stringWithUTF8String:(const char *)verdict] : nil;
            const unsigned char *procName = sqlite3_column_text(stmt, 6);
            context.processName = procName ? [NSString stringWithUTF8String:(const char *)procName] : nil;
            context.processPID = (pid_t)sqlite3_column_int(stmt, 7);
            context.destinationPort = sqlite3_column_int(stmt, 8);
            const unsigned char *hostname = sqlite3_column_text(stmt, 9);
            context.hostname = hostname ? [NSString stringWithUTF8String:(const char *)hostname] : nil;
            context.autoUntrusted = sqlite3_column_int(stmt, 10) != 0;

            double createdAt = sqlite3_column_double(stmt, 11);
            if (createdAt > 0) {
                context.trustedAt = [NSDate dateWithTimeIntervalSince1970:createdAt];
            }
            double removedAt = sqlite3_column_double(stmt, 12);
            if (removedAt > 0) {
                context.untrustedAt = [NSDate dateWithTimeIntervalSince1970:removedAt];
            }
        }
        sqlite3_finalize(stmt);
    });
    return context;
}

- (void)setTrusted:(BOOL)trusted forIP:(NSString *)ipAddress {
    [self setTrusted:trusted forIP:ipAddress withContext:nil];
}

- (void)setTrusted:(BOOL)trusted
             forIP:(NSString *)ipAddress
       withContext:(nullable SNBTrustContext *)context {
    NSString *normalized = [self normalizedIPAddress:ipAddress];
    if (!normalized || !self.database) {
        return;
    }

    SNBTrustContext *safeContext = context ?: [[SNBTrustContext alloc] init];
    if (safeContext.ipAddress.length == 0) {
        safeContext.ipAddress = ipAddress;
    }

    dispatch_async(self.ioQueue, ^{
        sqlite3_stmt *stmt = NULL;
        const char *sql =
            "INSERT OR REPLACE INTO trusted_ips "
            "(ip, trusted, reason, custom_reason_note, threat_score_at_decision, verdict_at_decision, "
            "process_name, process_pid, destination_port, hostname, auto_untrusted, "
            "created_at, updated_at, removed_at) "
            "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, "
            "COALESCE((SELECT created_at FROM trusted_ips WHERE ip = ?1), ?12), ?13, ?14);";

        if (sqlite3_prepare_v2(self.database, sql, -1, &stmt, NULL) != SQLITE_OK) {
            return;
        }

        NSTimeInterval now = [[NSDate date] timeIntervalSince1970];

        sqlite3_bind_text(stmt, 1, normalized.UTF8String, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 2, trusted ? 1 : 0);
        sqlite3_bind_int(stmt, 3, (int)(safeContext.reason));

        if (safeContext.customReasonNote.length > 0) {
            sqlite3_bind_text(stmt, 4, safeContext.customReasonNote.UTF8String, -1, SQLITE_TRANSIENT);
        } else {
            sqlite3_bind_null(stmt, 4);
        }

        sqlite3_bind_int(stmt, 5, (int)safeContext.threatScoreAtDecision);

        if (safeContext.verdictAtDecision.length > 0) {
            sqlite3_bind_text(stmt, 6, safeContext.verdictAtDecision.UTF8String, -1, SQLITE_TRANSIENT);
        } else {
            sqlite3_bind_null(stmt, 6);
        }

        if (safeContext.processName.length > 0) {
            sqlite3_bind_text(stmt, 7, safeContext.processName.UTF8String, -1, SQLITE_TRANSIENT);
        } else {
            sqlite3_bind_null(stmt, 7);
        }

        sqlite3_bind_int(stmt, 8, (int)safeContext.processPID);
        sqlite3_bind_int(stmt, 9, (int)safeContext.destinationPort);

        if (safeContext.hostname.length > 0) {
            sqlite3_bind_text(stmt, 10, safeContext.hostname.UTF8String, -1, SQLITE_TRANSIENT);
        } else {
            sqlite3_bind_null(stmt, 10);
        }

        sqlite3_bind_int(stmt, 11, safeContext.autoUntrusted ? 1 : 0);
        sqlite3_bind_double(stmt, 12, now);  // created_at (if new)
        sqlite3_bind_double(stmt, 13, now);  // updated_at

        if (trusted) {
            sqlite3_bind_null(stmt, 14);  // removed_at
        } else {
            sqlite3_bind_double(stmt, 14, now);  // removed_at
        }

        sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        // Record in history
        [self recordHistoryForIP:normalized
                         trusted:trusted
                          reason:safeContext.reason
                customReasonNote:safeContext.customReasonNote
          threatScoreAtDecision:safeContext.threatScoreAtDecision
              verdictAtDecision:safeContext.verdictAtDecision
                     autoAction:safeContext.autoUntrusted];

        SNBLogUIDebug("TrustedIPStore: %s trust for IP %s (reason: %d, score: %ld)",
                      trusted ? "set" : "removed",
                      normalized.UTF8String,
                      (int)safeContext.reason,
                      (long)safeContext.threatScoreAtDecision);

        dispatch_async(dispatch_get_main_queue(), ^{
            [[NSNotificationCenter defaultCenter] postNotificationName:SNBTrustedIPStoreDidChangeNotification
                                                                object:normalized];
        });
    });
}

- (void)removeTrustedIP:(NSString *)ipAddress {
    [self setTrusted:NO forIP:ipAddress];
}

#pragma mark - Auto-Untrust

- (BOOL)autoUntrustIPIfNeeded:(NSString *)ipAddress
               withThreatScore:(NSInteger)threatScore
                       verdict:(NSString *)verdict {
    if (threatScore < self.autoUntrustThreshold) {
        return NO;
    }

    if (![self isTrustedIP:ipAddress]) {
        return NO;
    }

    SNBTrustContext *context = [[SNBTrustContext alloc] init];
    context.ipAddress = ipAddress;
    context.reason = SNBTrustReasonUnspecified;
    context.threatScoreAtDecision = threatScore;
    context.verdictAtDecision = verdict;
    context.autoUntrusted = YES;

    [self setTrusted:NO forIP:ipAddress withContext:context];

    SNBLogUIDebug("TrustedIPStore: AUTO-UNTRUSTED IP %s due to high threat score %ld (threshold: %ld)",
                  ipAddress.UTF8String, (long)threatScore, (long)self.autoUntrustThreshold);

    return YES;
}

#pragma mark - History

- (void)recordHistoryForIP:(NSString *)ip
                   trusted:(BOOL)trusted
                    reason:(SNBTrustReason)reason
          customReasonNote:(NSString *)note
    threatScoreAtDecision:(NSInteger)score
        verdictAtDecision:(NSString *)verdict
               autoAction:(BOOL)autoAction {
    if (!self.database || ip.length == 0) {
        return;
    }

    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "INSERT INTO trust_history "
        "(ip, trusted, reason, custom_reason_note, threat_score_at_decision, verdict_at_decision, auto_action, timestamp) "
        "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8);";

    if (sqlite3_prepare_v2(self.database, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return;
    }

    NSTimeInterval now = [[NSDate date] timeIntervalSince1970];

    sqlite3_bind_text(stmt, 1, ip.UTF8String, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, trusted ? 1 : 0);
    sqlite3_bind_int(stmt, 3, (int)reason);

    if (note.length > 0) {
        sqlite3_bind_text(stmt, 4, note.UTF8String, -1, SQLITE_TRANSIENT);
    } else {
        sqlite3_bind_null(stmt, 4);
    }

    sqlite3_bind_int(stmt, 5, (int)score);

    if (verdict.length > 0) {
        sqlite3_bind_text(stmt, 6, verdict.UTF8String, -1, SQLITE_TRANSIENT);
    } else {
        sqlite3_bind_null(stmt, 6);
    }

    sqlite3_bind_int(stmt, 7, autoAction ? 1 : 0);
    sqlite3_bind_double(stmt, 8, now);

    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

- (NSArray<SNBTrustHistoryEntry *> *)trustHistoryForIP:(NSString *)ipAddress {
    NSString *normalized = [self normalizedIPAddress:ipAddress];
    if (!normalized || !self.database) {
        return @[];
    }

    __block NSMutableArray<SNBTrustHistoryEntry *> *entries = [NSMutableArray array];

    dispatch_sync(self.ioQueue, ^{
        sqlite3_stmt *stmt = NULL;
        const char *sql =
            "SELECT ip, trusted, reason, custom_reason_note, threat_score_at_decision, "
            "verdict_at_decision, auto_action, timestamp "
            "FROM trust_history WHERE ip = ?1 ORDER BY timestamp DESC LIMIT 50;";

        if (sqlite3_prepare_v2(self.database, sql, -1, &stmt, NULL) != SQLITE_OK) {
            return;
        }
        sqlite3_bind_text(stmt, 1, normalized.UTF8String, -1, SQLITE_TRANSIENT);

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            SNBTrustHistoryEntry *entry = [[SNBTrustHistoryEntry alloc] init];
            const unsigned char *ip = sqlite3_column_text(stmt, 0);
            entry.ipAddress = ip ? [NSString stringWithUTF8String:(const char *)ip] : @"";
            entry.trusted = sqlite3_column_int(stmt, 1) != 0;
            entry.reason = sqlite3_column_int(stmt, 2);
            const unsigned char *note = sqlite3_column_text(stmt, 3);
            entry.customReasonNote = note ? [NSString stringWithUTF8String:(const char *)note] : nil;
            entry.threatScoreAtDecision = sqlite3_column_int(stmt, 4);
            const unsigned char *verdict = sqlite3_column_text(stmt, 5);
            entry.verdictAtDecision = verdict ? [NSString stringWithUTF8String:(const char *)verdict] : nil;
            entry.autoAction = sqlite3_column_int(stmt, 6) != 0;
            double timestamp = sqlite3_column_double(stmt, 7);
            entry.timestamp = [NSDate dateWithTimeIntervalSince1970:timestamp];
            [entries addObject:entry];
        }
        sqlite3_finalize(stmt);
    });

    return entries;
}

- (NSArray<SNBTrustContext *> *)allTrustedIPContexts {
    if (!self.database) {
        return @[];
    }

    __block NSMutableArray<SNBTrustContext *> *contexts = [NSMutableArray array];

    dispatch_sync(self.ioQueue, ^{
        sqlite3_stmt *stmt = NULL;
        const char *sql =
            "SELECT ip, reason, custom_reason_note, threat_score_at_decision, verdict_at_decision, "
            "process_name, process_pid, destination_port, hostname, auto_untrusted, created_at "
            "FROM trusted_ips WHERE trusted = 1 ORDER BY created_at DESC;";

        if (sqlite3_prepare_v2(self.database, sql, -1, &stmt, NULL) != SQLITE_OK) {
            return;
        }

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            SNBTrustContext *context = [[SNBTrustContext alloc] init];
            const unsigned char *ip = sqlite3_column_text(stmt, 0);
            context.ipAddress = ip ? [NSString stringWithUTF8String:(const char *)ip] : nil;
            context.reason = sqlite3_column_int(stmt, 1);
            const unsigned char *note = sqlite3_column_text(stmt, 2);
            context.customReasonNote = note ? [NSString stringWithUTF8String:(const char *)note] : nil;
            context.threatScoreAtDecision = sqlite3_column_int(stmt, 3);
            const unsigned char *verdict = sqlite3_column_text(stmt, 4);
            context.verdictAtDecision = verdict ? [NSString stringWithUTF8String:(const char *)verdict] : nil;
            const unsigned char *procName = sqlite3_column_text(stmt, 5);
            context.processName = procName ? [NSString stringWithUTF8String:(const char *)procName] : nil;
            context.processPID = (pid_t)sqlite3_column_int(stmt, 6);
            context.destinationPort = sqlite3_column_int(stmt, 7);
            const unsigned char *hostname = sqlite3_column_text(stmt, 8);
            context.hostname = hostname ? [NSString stringWithUTF8String:(const char *)hostname] : nil;
            context.autoUntrusted = sqlite3_column_int(stmt, 9) != 0;
            double createdAt = sqlite3_column_double(stmt, 10);
            if (createdAt > 0) {
                context.trustedAt = [NSDate dateWithTimeIntervalSince1970:createdAt];
            }
            [contexts addObject:context];
        }
        sqlite3_finalize(stmt);
    });

    return contexts;
}

@end

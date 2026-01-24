//
//  ProcessIdentityStore.m
//  SniffNetBar
//

#import "ProcessIdentityStore.h"
#import "ProcessIdentityModels.h"
#import "Logger.h"
#import <sqlite3.h>

static NSString * const kProcessIdentityDBFilename = @"process_identity.sqlite";

@interface SNBProcessIdentityStore ()
@property (nonatomic, assign) sqlite3 *db;
@property (nonatomic, strong) dispatch_queue_t queue;
@property (nonatomic, assign) sqlite3_stmt *selectByCDHashStmt;
@property (nonatomic, assign) sqlite3_stmt *selectByTeamSigningStmt;
@property (nonatomic, assign) sqlite3_stmt *selectBySHAStmt;
@property (nonatomic, assign) sqlite3_stmt *upsertCDHashStmt;
@property (nonatomic, assign) sqlite3_stmt *upsertTeamSigningStmt;
@property (nonatomic, assign) sqlite3_stmt *upsertSHAStmt;
@property (nonatomic, assign) sqlite3_stmt *insertObservationStmt;
@end

@implementation SNBProcessIdentityStore

+ (instancetype)sharedStore {
    static SNBProcessIdentityStore *shared = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        shared = [[SNBProcessIdentityStore alloc] init];
    });
    return shared;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _queue = dispatch_queue_create("com.sniffnetbar.process_identity.store", DISPATCH_QUEUE_SERIAL);
        [self openDatabase];
        [self ensureSchema];
        [self prepareStatements];
    }
    return self;
}

- (void)dealloc {
    if (_selectByCDHashStmt) {
        sqlite3_finalize(_selectByCDHashStmt);
    }
    if (_selectByTeamSigningStmt) {
        sqlite3_finalize(_selectByTeamSigningStmt);
    }
    if (_selectBySHAStmt) {
        sqlite3_finalize(_selectBySHAStmt);
    }
    if (_upsertCDHashStmt) {
        sqlite3_finalize(_upsertCDHashStmt);
    }
    if (_upsertTeamSigningStmt) {
        sqlite3_finalize(_upsertTeamSigningStmt);
    }
    if (_upsertSHAStmt) {
        sqlite3_finalize(_upsertSHAStmt);
    }
    if (_insertObservationStmt) {
        sqlite3_finalize(_insertObservationStmt);
    }
    if (_db) {
        sqlite3_close(_db);
    }
}

- (nullable SNBProcessIdentityRecord *)resolveIdentityWithCDHash:(nullable NSString *)cdhash
                                                          teamID:(nullable NSString *)teamID
                                                       signingID:(nullable NSString *)signingID
                                                          sha256:(nullable NSString *)sha256 {
    __block SNBProcessIdentityRecord *record = nil;
    dispatch_sync(self.queue, ^{
        if (!self.db) {
            return;
        }
        if (cdhash.length > 0) {
            record = [self recordByCDHash:cdhash];
            if (record) {
                return;
            }
        }
        if (teamID.length > 0 && signingID.length > 0) {
            record = [self recordByTeamID:teamID signingID:signingID];
            if (record) {
                return;
            }
        }
        if (sha256.length > 0) {
            record = [self recordBySHA256:sha256];
        }
    });
    return record;
}

- (nullable SNBProcessIdentityRecord *)upsertIdentity:(SNBProcessIdentityRecord *)record {
    if (!record) {
        return nil;
    }
    __block SNBProcessIdentityRecord *updated = nil;
    dispatch_sync(self.queue, ^{
        if (!self.db) {
            return;
        }
        sqlite3_stmt *stmt = NULL;
        if (record.teamID.length > 0 && record.signingID.length > 0) {
            stmt = self.upsertTeamSigningStmt;
        } else if (record.cdhash.length > 0) {
            stmt = self.upsertCDHashStmt;
        } else if (record.sha256.length > 0) {
            stmt = self.upsertSHAStmt;
        } else {
            return;
        }

        sqlite3_reset(stmt);
        [self bindIdentityRecord:record toStatement:stmt];
        int result = sqlite3_step(stmt);
        if (result != SQLITE_DONE) {
            SNBLogWarn("ProcessIdentity upsert failed: %s", sqlite3_errmsg(self.db));
            return;
        }

        updated = [self resolveIdentityWithCDHash:record.cdhash
                                          teamID:record.teamID
                                       signingID:record.signingID
                                          sha256:record.sha256];
    });
    return updated;
}

- (void)recordObservationForIdentityID:(NSInteger)identityID
                                   pid:(pid_t)pid
                                  ppid:(pid_t)ppid
                                   uid:(uid_t)uid
                                  path:(nullable NSString *)path
                              riskScore:(NSInteger)riskScore
                                verdict:(nullable NSString *)verdict
                          telemetryJSON:(nullable NSString *)telemetryJSON {
    if (identityID <= 0) {
        return;
    }
    dispatch_async(self.queue, ^{
        if (!self.db || !self.insertObservationStmt) {
            return;
        }
        sqlite3_reset(self.insertObservationStmt);
        sqlite3_bind_int(self.insertObservationStmt, 1, (int)identityID);
        sqlite3_bind_int(self.insertObservationStmt, 2, (int)pid);
        sqlite3_bind_int(self.insertObservationStmt, 3, (int)ppid);
        sqlite3_bind_int(self.insertObservationStmt, 4, (int)uid);
        if (path.length > 0) {
            sqlite3_bind_text(self.insertObservationStmt, 5, path.UTF8String, -1, SQLITE_TRANSIENT);
        } else {
            sqlite3_bind_null(self.insertObservationStmt, 5);
        }
        sqlite3_bind_int64(self.insertObservationStmt, 6, (sqlite3_int64)[NSDate date].timeIntervalSince1970);
        sqlite3_bind_int(self.insertObservationStmt, 7, (int)riskScore);
        if (verdict.length > 0) {
            sqlite3_bind_text(self.insertObservationStmt, 8, verdict.UTF8String, -1, SQLITE_TRANSIENT);
        } else {
            sqlite3_bind_null(self.insertObservationStmt, 8);
        }
        if (telemetryJSON.length > 0) {
            sqlite3_bind_text(self.insertObservationStmt, 9, telemetryJSON.UTF8String, -1, SQLITE_TRANSIENT);
        } else {
            sqlite3_bind_null(self.insertObservationStmt, 9);
        }
        if (sqlite3_step(self.insertObservationStmt) != SQLITE_DONE) {
            SNBLogWarn("ProcessIdentity observation insert failed: %s", sqlite3_errmsg(self.db));
        }
    });
}

#pragma mark - Database Setup

- (void)openDatabase {
    NSString *path = [[self.class applicationSupportDirectory] stringByAppendingPathComponent:kProcessIdentityDBFilename];
    int flags = SQLITE_OPEN_CREATE | SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX;
    int result = sqlite3_open_v2([path fileSystemRepresentation], &_db, flags, NULL);
    if (result != SQLITE_OK) {
        SNBLogWarn("Failed to open process identity database at %{public}@ (%s)", path, sqlite3_errmsg(self.db));
        if (self.db) {
            sqlite3_close(self.db);
        }
        self.db = NULL;
        return;
    }
    sqlite3_exec(self.db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);
    sqlite3_exec(self.db, "PRAGMA synchronous=NORMAL;", NULL, NULL, NULL);
    sqlite3_busy_timeout(self.db, 2000);
}

- (void)ensureSchema {
    if (!self.db) {
        return;
    }
    const char *createIdentity =
        "CREATE TABLE IF NOT EXISTS process_identity ("
        "id INTEGER PRIMARY KEY,"
        "cdhash TEXT,"
        "team_id TEXT,"
        "bundle_id TEXT,"
        "signing_id TEXT,"
        "signature_valid INTEGER,"
        "signature_kind TEXT,"
        "entitlements_hash TEXT,"
        "sha256 TEXT,"
        "path_hint TEXT,"
        "first_seen INTEGER NOT NULL,"
        "last_seen INTEGER NOT NULL,"
        "seen_count INTEGER NOT NULL DEFAULT 1,"
        "risk_score INTEGER,"
        "verdict TEXT,"
        "confidence REAL,"
        "notes TEXT"
        ");";
    sqlite3_exec(self.db, createIdentity, NULL, NULL, NULL);
    sqlite3_exec(self.db,
                 "CREATE UNIQUE INDEX IF NOT EXISTS idx_identity_cdhash "
                 "ON process_identity(cdhash) "
                 "WHERE cdhash IS NOT NULL AND cdhash != '';",
                 NULL, NULL, NULL);
    sqlite3_exec(self.db,
                 "CREATE UNIQUE INDEX IF NOT EXISTS idx_identity_team_signing "
                 "ON process_identity(team_id, signing_id) "
                 "WHERE team_id IS NOT NULL AND team_id != '' AND signing_id IS NOT NULL AND signing_id != '';",
                 NULL, NULL, NULL);
    sqlite3_exec(self.db,
                 "CREATE UNIQUE INDEX IF NOT EXISTS idx_identity_sha256 "
                 "ON process_identity(sha256) "
                 "WHERE sha256 IS NOT NULL AND sha256 != '';",
                 NULL, NULL, NULL);

    const char *createObservation =
        "CREATE TABLE IF NOT EXISTS process_observation ("
        "id INTEGER PRIMARY KEY,"
        "identity_id INTEGER NOT NULL REFERENCES process_identity(id),"
        "pid INTEGER,"
        "ppid INTEGER,"
        "uid INTEGER,"
        "path TEXT,"
        "observed_at INTEGER NOT NULL,"
        "risk_score INTEGER,"
        "verdict TEXT,"
        "telemetry_json TEXT"
        ");";
    sqlite3_exec(self.db, createObservation, NULL, NULL, NULL);
}

- (void)prepareStatements {
    if (!self.db) {
        return;
    }
    const char *selectColumns =
        "SELECT id, cdhash, team_id, bundle_id, signing_id, signature_valid, signature_kind,"
        " entitlements_hash, sha256, path_hint, first_seen, last_seen, seen_count, risk_score, verdict, confidence, notes"
        " FROM process_identity ";

    NSString *selectByCDHashSQL = [NSString stringWithFormat:@"%s WHERE cdhash = ? LIMIT 1;", selectColumns];
    sqlite3_prepare_v2(self.db, selectByCDHashSQL.UTF8String, -1, &_selectByCDHashStmt, NULL);

    NSString *selectByTeamSigningSQL = [NSString stringWithFormat:@"%s WHERE team_id = ? AND signing_id = ? "
                                         "ORDER BY confidence DESC, last_seen DESC LIMIT 1;", selectColumns];
    sqlite3_prepare_v2(self.db, selectByTeamSigningSQL.UTF8String, -1, &_selectByTeamSigningStmt, NULL);

    NSString *selectBySHASQL = [NSString stringWithFormat:@"%s WHERE sha256 = ? LIMIT 1;", selectColumns];
    sqlite3_prepare_v2(self.db, selectBySHASQL.UTF8String, -1, &_selectBySHAStmt, NULL);

    const char *upsertCDHashSQL =
        "INSERT INTO process_identity "
        "(cdhash, team_id, bundle_id, signing_id, signature_valid, signature_kind, entitlements_hash, sha256, path_hint, "
        "first_seen, last_seen, seen_count, risk_score, verdict, confidence, notes) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?) "
        "ON CONFLICT(cdhash) DO UPDATE SET "
        "team_id=excluded.team_id, bundle_id=excluded.bundle_id, signing_id=excluded.signing_id, "
        "signature_valid=excluded.signature_valid, signature_kind=excluded.signature_kind, "
        "entitlements_hash=COALESCE(excluded.entitlements_hash, process_identity.entitlements_hash), "
        "sha256=COALESCE(excluded.sha256, process_identity.sha256), "
        "path_hint=COALESCE(excluded.path_hint, process_identity.path_hint), "
        "last_seen=excluded.last_seen, seen_count=process_identity.seen_count + 1, "
        "risk_score=excluded.risk_score, verdict=excluded.verdict, confidence=excluded.confidence, "
        "notes=COALESCE(excluded.notes, process_identity.notes);";
    sqlite3_prepare_v2(self.db, upsertCDHashSQL, -1, &_upsertCDHashStmt, NULL);

    const char *upsertTeamSigningSQL =
        "INSERT INTO process_identity "
        "(cdhash, team_id, bundle_id, signing_id, signature_valid, signature_kind, entitlements_hash, sha256, path_hint, "
        "first_seen, last_seen, seen_count, risk_score, verdict, confidence, notes) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?) "
        "ON CONFLICT(team_id, signing_id) DO UPDATE SET "
        "cdhash=COALESCE(excluded.cdhash, process_identity.cdhash), "
        "bundle_id=excluded.bundle_id, signature_valid=excluded.signature_valid, signature_kind=excluded.signature_kind, "
        "entitlements_hash=COALESCE(excluded.entitlements_hash, process_identity.entitlements_hash), "
        "sha256=COALESCE(excluded.sha256, process_identity.sha256), "
        "path_hint=COALESCE(excluded.path_hint, process_identity.path_hint), "
        "last_seen=excluded.last_seen, seen_count=process_identity.seen_count + 1, "
        "risk_score=excluded.risk_score, verdict=excluded.verdict, confidence=excluded.confidence, "
        "notes=COALESCE(excluded.notes, process_identity.notes);";
    sqlite3_prepare_v2(self.db, upsertTeamSigningSQL, -1, &_upsertTeamSigningStmt, NULL);

    const char *upsertSHASQL =
        "INSERT INTO process_identity "
        "(sha256, signature_valid, signature_kind, path_hint, first_seen, last_seen, seen_count, risk_score, verdict, confidence, notes) "
        "VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?) "
        "ON CONFLICT(sha256) DO UPDATE SET "
        "signature_valid=excluded.signature_valid, signature_kind=excluded.signature_kind, "
        "path_hint=COALESCE(excluded.path_hint, process_identity.path_hint), "
        "last_seen=excluded.last_seen, seen_count=process_identity.seen_count + 1, "
        "risk_score=excluded.risk_score, verdict=excluded.verdict, confidence=excluded.confidence, "
        "notes=COALESCE(excluded.notes, process_identity.notes);";
    sqlite3_prepare_v2(self.db, upsertSHASQL, -1, &_upsertSHAStmt, NULL);

    const char *insertObservationSQL =
        "INSERT INTO process_observation "
        "(identity_id, pid, ppid, uid, path, observed_at, risk_score, verdict, telemetry_json) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);";
    sqlite3_prepare_v2(self.db, insertObservationSQL, -1, &_insertObservationStmt, NULL);
}

#pragma mark - Query Helpers

- (nullable SNBProcessIdentityRecord *)recordByCDHash:(NSString *)cdhash {
    sqlite3_reset(self.selectByCDHashStmt);
    sqlite3_bind_text(self.selectByCDHashStmt, 1, cdhash.UTF8String, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(self.selectByCDHashStmt) == SQLITE_ROW) {
        return [self recordFromStatement:self.selectByCDHashStmt];
    }
    return nil;
}

- (nullable SNBProcessIdentityRecord *)recordByTeamID:(NSString *)teamID signingID:(NSString *)signingID {
    sqlite3_reset(self.selectByTeamSigningStmt);
    sqlite3_bind_text(self.selectByTeamSigningStmt, 1, teamID.UTF8String, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(self.selectByTeamSigningStmt, 2, signingID.UTF8String, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(self.selectByTeamSigningStmt) == SQLITE_ROW) {
        return [self recordFromStatement:self.selectByTeamSigningStmt];
    }
    return nil;
}

- (nullable SNBProcessIdentityRecord *)recordBySHA256:(NSString *)sha256 {
    sqlite3_reset(self.selectBySHAStmt);
    sqlite3_bind_text(self.selectBySHAStmt, 1, sha256.UTF8String, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(self.selectBySHAStmt) == SQLITE_ROW) {
        return [self recordFromStatement:self.selectBySHAStmt];
    }
    return nil;
}

- (SNBProcessIdentityRecord *)recordFromStatement:(sqlite3_stmt *)stmt {
    SNBProcessIdentityRecord *record = [[SNBProcessIdentityRecord alloc] init];
    record.identityID = sqlite3_column_int(stmt, 0);
    record.cdhash = [self stringColumn:stmt index:1];
    record.teamID = [self stringColumn:stmt index:2];
    record.bundleID = [self stringColumn:stmt index:3];
    record.signingID = [self stringColumn:stmt index:4];
    record.signatureValid = sqlite3_column_int(stmt, 5) != 0;
    record.signatureKind = [self stringColumn:stmt index:6];
    record.entitlementsHash = [self stringColumn:stmt index:7];
    record.sha256 = [self stringColumn:stmt index:8];
    record.pathHint = [self stringColumn:stmt index:9];
    record.firstSeen = sqlite3_column_int64(stmt, 10);
    record.lastSeen = sqlite3_column_int64(stmt, 11);
    record.seenCount = sqlite3_column_int(stmt, 12);
    record.riskScore = sqlite3_column_int(stmt, 13);
    record.verdict = [self stringColumn:stmt index:14];
    record.confidence = sqlite3_column_double(stmt, 15);
    record.notes = [self stringColumn:stmt index:16];
    return record;
}

#pragma mark - Bind Helpers

- (void)bindIdentityRecord:(SNBProcessIdentityRecord *)record toStatement:(sqlite3_stmt *)stmt {
    int index = 1;
    [self bindText:record.cdhash toStatement:stmt index:index++];
    [self bindText:record.teamID toStatement:stmt index:index++];
    [self bindText:record.bundleID toStatement:stmt index:index++];
    [self bindText:record.signingID toStatement:stmt index:index++];
    sqlite3_bind_int(stmt, index++, record.signatureValid ? 1 : 0);
    [self bindText:record.signatureKind toStatement:stmt index:index++];
    [self bindText:record.entitlementsHash toStatement:stmt index:index++];
    [self bindText:record.sha256 toStatement:stmt index:index++];
    [self bindText:record.pathHint toStatement:stmt index:index++];
    sqlite3_bind_int64(stmt, index++, (sqlite3_int64)record.firstSeen);
    sqlite3_bind_int64(stmt, index++, (sqlite3_int64)record.lastSeen);
    sqlite3_bind_int(stmt, index++, (int)record.riskScore);
    [self bindText:record.verdict toStatement:stmt index:index++];
    sqlite3_bind_double(stmt, index++, record.confidence);
    [self bindText:record.notes toStatement:stmt index:index++];
}

- (void)bindText:(nullable NSString *)text toStatement:(sqlite3_stmt *)stmt index:(int)index {
    if (text.length > 0) {
        sqlite3_bind_text(stmt, index, text.UTF8String, -1, SQLITE_TRANSIENT);
    } else {
        sqlite3_bind_null(stmt, index);
    }
}

- (nullable NSString *)stringColumn:(sqlite3_stmt *)stmt index:(int)index {
    if (sqlite3_column_type(stmt, index) == SQLITE_NULL) {
        return nil;
    }
    const unsigned char *text = sqlite3_column_text(stmt, index);
    if (!text) {
        return nil;
    }
    return [NSString stringWithUTF8String:(const char *)text];
}

#pragma mark - Paths

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

@end

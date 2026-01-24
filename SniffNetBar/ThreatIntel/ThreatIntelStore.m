//
//  ThreatIntelStore.m
//  SniffNetBar
//
//  SQLite persistence for threat intelligence results
//

#import "ThreatIntelStore.h"
#import "Logger.h"
#import "SNBTimerCoordinator.h"
#import <sqlite3.h>

// Purge interval for automatic cleanup of expired entries
static const NSTimeInterval kPurgeInterval = 300.0;  // 5 minutes

@implementation SNBProviderStatus
@end

@interface ThreatIntelStore ()
@property (nonatomic, assign) sqlite3 *db;
@property (nonatomic, assign) NSTimeInterval ttlSeconds;
@property (nonatomic, strong) dispatch_queue_t dbQueue;
// Prepared statements for performance (avoid repeated prepare/finalize)
@property (nonatomic, assign) sqlite3_stmt *selectStmt;
@property (nonatomic, assign) sqlite3_stmt *insertStmt;
@property (nonatomic, assign) sqlite3_stmt *deleteStmt;
@property (nonatomic, assign) sqlite3_stmt *purgeStmt;
// Automatic purge timer
@property (nonatomic, copy) SNBTimerID purgeTimerID;
@end

@implementation ThreatIntelStore

+ (instancetype)sharedStore {
    static ThreatIntelStore *sharedStore = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sharedStore = [[ThreatIntelStore alloc] initWithTTLSeconds:0];
    });
    return sharedStore;
}

+ (instancetype)sharedStoreWithTTLSeconds:(NSTimeInterval)ttlSeconds {
    ThreatIntelStore *store = [self sharedStore];
    store.ttlSeconds = ttlSeconds;
    return store;
}

- (instancetype)initWithTTLSeconds:(NSTimeInterval)ttlSeconds {
    self = [super init];
    if (self) {
        _ttlSeconds = ttlSeconds;
        _dbQueue = dispatch_queue_create("com.sniffnetbar.threatintel.store", DISPATCH_QUEUE_SERIAL);
        [self openDatabase];
        [self ensureSchema];
        [self prepareCachedStatements];
        [self startPurgeTimer];
    }
    return self;
}

- (void)dealloc {
    // Cancel purge timer
    if (_purgeTimerID) {
        [[SNBTimerCoordinator sharedCoordinator] cancelTimer:_purgeTimerID];
        _purgeTimerID = nil;
    }

    // Finalize prepared statements
    if (_selectStmt) {
        sqlite3_finalize(_selectStmt);
        _selectStmt = NULL;
    }
    if (_insertStmt) {
        sqlite3_finalize(_insertStmt);
        _insertStmt = NULL;
    }
    if (_deleteStmt) {
        sqlite3_finalize(_deleteStmt);
        _deleteStmt = NULL;
    }
    if (_purgeStmt) {
        sqlite3_finalize(_purgeStmt);
        _purgeStmt = NULL;
    }

    if (self.db) {
        sqlite3_close(self.db);
        self.db = NULL;
    }
}

- (TIEnrichmentResponse *)responseForIndicator:(TIIndicator *)indicator {
    if (!indicator || !self.db) {
        SNBLogThreatIntelDebug("responseForIndicator called with invalid parameters (indicator=%p, db=%p)",
                              indicator, self.db);
        return nil;
    }

    SNBLogThreatIntelDebug("Checking database cache for %{" SNB_IP_PRIVACY "}@", indicator.value);

    __block TIEnrichmentResponse *response = nil;
    dispatch_sync(self.dbQueue, ^{
        // Use cached prepared statement for better performance
        if (!self.selectStmt) {
            SNBLogThreatIntelError("SELECT statement not prepared");
            return;
        }

        // Reset and bind parameters
        sqlite3_reset(self.selectStmt);
        sqlite3_bind_int(self.selectStmt, 1, (int)indicator.type);
        sqlite3_bind_text(self.selectStmt, 2, indicator.value.UTF8String, -1, SQLITE_TRANSIENT);

        int stepResult = sqlite3_step(self.selectStmt);
        if (stepResult == SQLITE_ROW) {
            const unsigned char *jsonText = sqlite3_column_text(self.selectStmt, 0);
            sqlite3_int64 expiresAt = sqlite3_column_int64(self.selectStmt, 1);
            NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
            NSTimeInterval remainingSeconds = (NSTimeInterval)expiresAt - now;

            if (expiresAt > 0 && now > (NSTimeInterval)expiresAt) {
                SNBLogThreatIntelInfo("⊗ Cache EXPIRED for %{" SNB_IP_PRIVACY "}@ (expired %.0f seconds ago) - deleting",
                                     indicator.value, -remainingSeconds);
                [self deleteIndicatorLocked:indicator];
                return;
            }

            if (jsonText) {
                NSString *jsonString = [NSString stringWithUTF8String:(const char *)jsonText];
                size_t jsonSize = strlen((const char *)jsonText);
                response = [self responseFromJSONString:jsonString];
                if (response) {
                    SNBLogThreatIntelInfo("✓ Cache HIT for %{" SNB_IP_PRIVACY "}@ from DATABASE (expires in %.0f hours, json_size: %lu bytes)",
                                         indicator.value, remainingSeconds / 3600.0, (unsigned long)jsonSize);
                } else {
                    SNBLogThreatIntelError("Failed to deserialize cached result for %{" SNB_IP_PRIVACY "}@",
                                          indicator.value);
                }
            }
        } else if (stepResult == SQLITE_DONE) {
            SNBLogThreatIntelInfo("⊗ Cache MISS for %{" SNB_IP_PRIVACY "}@ - not in database",
                                 indicator.value);
        } else {
            SNBLogThreatIntelError("SELECT failed for %{" SNB_IP_PRIVACY "}@: %s (code: %d)",
                                  indicator.value, sqlite3_errmsg(self.db), stepResult);
        }
    });

    return response;
}

- (void)storeResponse:(TIEnrichmentResponse *)response {
    if (!response || !response.indicator || !self.db) {
        SNBLogThreatIntelWarn("storeResponse called with invalid parameters (response=%p, indicator=%p, db=%p)",
                             response, response ? response.indicator : NULL, self.db);
        return;
    }

    NSString *jsonString = [self jsonStringFromResponse:response];
    if (jsonString.length == 0) {
        SNBLogThreatIntelWarn("Failed to serialize response for %{" SNB_IP_PRIVACY "}@",
                             response.indicator.value);
        return;
    }

    NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
    NSTimeInterval expiresAt = now + self.ttlSeconds;

    NSString *ipAddress = response.indicator.value;
    TIIndicatorType indicatorType = response.indicator.type;

    SNBLogThreatIntelInfo("Storing threat intel result to database: %{" SNB_IP_PRIVACY "}@ (TTL: %.0f hours)",
                         ipAddress, self.ttlSeconds / 3600.0);

    dispatch_async(self.dbQueue, ^{
        // Use cached prepared statement for better performance
        if (!self.insertStmt) {
            SNBLogThreatIntelError("INSERT statement not prepared");
            return;
        }

        SNBLogThreatIntelDebug("Executing INSERT for %{" SNB_IP_PRIVACY "}@ [type=%d, now=%lld, expires=%lld, ttl_hours=%.1f]",
                              ipAddress, (int)indicatorType,
                              (sqlite3_int64)now, (sqlite3_int64)expiresAt,
                              self.ttlSeconds / 3600.0);

        // Reset and bind parameters
        sqlite3_reset(self.insertStmt);
        sqlite3_bind_text(self.insertStmt, 1, ipAddress.UTF8String, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(self.insertStmt, 2, (int)indicatorType);
        sqlite3_bind_int64(self.insertStmt, 3, (sqlite3_int64)now);
        sqlite3_bind_int64(self.insertStmt, 4, (sqlite3_int64)expiresAt);
        sqlite3_bind_text(self.insertStmt, 5, jsonString.UTF8String, -1, SQLITE_TRANSIENT);

        int result = sqlite3_step(self.insertStmt);
        int lastInsertRowId = (int)sqlite3_last_insert_rowid(self.db);

        if (result == SQLITE_DONE) {
            SNBLogThreatIntelInfo("✓ Successfully stored %{" SNB_IP_PRIVACY "}@ to database (rowid: %d, json_size: %lu bytes)",
                                  ipAddress, lastInsertRowId, (unsigned long)jsonString.length);
        } else if (result == SQLITE_BUSY || result == SQLITE_LOCKED) {
            SNBLogThreatIntelError("INSERT failed - database locked for %{" SNB_IP_PRIVACY "}@: %s (code: %d)",
                                  ipAddress, sqlite3_errmsg(self.db), result);
        } else {
            SNBLogThreatIntelError("INSERT failed for %{" SNB_IP_PRIVACY "}@: %s (code: %d)",
                                  ipAddress, sqlite3_errmsg(self.db), result);
        }
    });
}

- (void)purgeExpired {
    if (!self.db) {
        return;
    }

    NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
    dispatch_async(self.dbQueue, ^{
        // Use cached prepared statement for better performance
        if (!self.purgeStmt) {
            SNBLogThreatIntelDebug("Purge statement not prepared, skipping");
            return;
        }

        sqlite3_reset(self.purgeStmt);
        sqlite3_bind_int64(self.purgeStmt, 1, (sqlite3_int64)now);
        int result = sqlite3_step(self.purgeStmt);

        if (result == SQLITE_DONE) {
            int deletedCount = sqlite3_changes(self.db);
            if (deletedCount > 0) {
                SNBLogThreatIntelInfo("Purged %d expired entries from threat intel cache", deletedCount);
            }
        }
    });
}

#pragma mark - Database Setup

- (void)openDatabase {
    NSString *path = [[self class] defaultDatabasePath];

    SNBLogThreatIntelInfo("Opening threat intel database at: %{public}@", path);

    NSString *directory = [path stringByDeletingLastPathComponent];
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:directory]) {
        [fm createDirectoryAtPath:directory withIntermediateDirectories:YES attributes:nil error:nil];
        SNBLogThreatIntelDebug("Created database directory: %{public}@", directory);
    }

    int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX;
    int result = sqlite3_open_v2([path fileSystemRepresentation], &_db, flags, NULL);
    if (result != SQLITE_OK) {
        SNBLogThreatIntelError("Failed to open threat intel db at %{public}@: %s",
                              path, sqlite3_errmsg(self.db));
        if (self.db) {
            sqlite3_close(self.db);
            self.db = NULL;
        }
        return;
    }

    SNBLogThreatIntelInfo("Database opened successfully");

    // Enable WAL mode for better concurrent access
    sqlite3_exec(self.db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);

    // Verify WAL mode was set
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(self.db, "PRAGMA journal_mode;", -1, &stmt, NULL) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const unsigned char *mode = sqlite3_column_text(stmt, 0);
            SNBLogThreatIntelInfo("Journal mode: %s", mode ? (const char *)mode : "unknown");
        }
        sqlite3_finalize(stmt);
    }

    sqlite3_exec(self.db, "PRAGMA synchronous=NORMAL;", NULL, NULL, NULL);
    SNBLogThreatIntelDebug("Set synchronous=NORMAL");

    // Increase busy timeout to handle concurrent writes (30 seconds)
    sqlite3_busy_timeout(self.db, 30000);
    SNBLogThreatIntelDebug("Set busy timeout to 30000ms");

    // Enable memory-mapped I/O for better performance
    sqlite3_exec(self.db, "PRAGMA mmap_size=268435456;", NULL, NULL, NULL);  // 256MB
    SNBLogThreatIntelDebug("Set mmap_size to 256MB");

    // Increase cache size for better performance
    sqlite3_exec(self.db, "PRAGMA cache_size=-8000;", NULL, NULL, NULL);  // 8MB cache
    SNBLogThreatIntelDebug("Set cache_size to 8MB");
}

- (void)ensureSchema {
    if (!self.db) {
        return;
    }

    const char *createTable =
        "CREATE TABLE IF NOT EXISTS threat_intel_cache ("
        "ip TEXT NOT NULL, "
        "indicator_type INTEGER NOT NULL, "
        "evaluated_at INTEGER NOT NULL, "
        "expires_at INTEGER NOT NULL, "
        "response_json TEXT NOT NULL, "
        "PRIMARY KEY (ip, indicator_type)"
        ");";
    sqlite3_exec(self.db, createTable, NULL, NULL, NULL);
    sqlite3_exec(self.db, "CREATE INDEX IF NOT EXISTS idx_threat_intel_expires ON threat_intel_cache (expires_at);",
                 NULL, NULL, NULL);

    const char *createProviderStatusTable =
        "CREATE TABLE IF NOT EXISTS provider_status ("
        "provider_name TEXT PRIMARY KEY, "
        "is_disabled INTEGER NOT NULL DEFAULT 0, "
        "disabled_until INTEGER, "
        "disabled_reason TEXT, "
        "error_code INTEGER, "
        "last_updated INTEGER NOT NULL"
        ");";
    sqlite3_exec(self.db, createProviderStatusTable, NULL, NULL, NULL);
    sqlite3_exec(self.db, "CREATE INDEX IF NOT EXISTS idx_provider_disabled_until ON provider_status (disabled_until);",
                 NULL, NULL, NULL);
}

- (void)prepareCachedStatements {
    if (!self.db) {
        return;
    }

    // SELECT statement for lookups
    const char *selectSQL = "SELECT response_json, expires_at FROM threat_intel_cache "
                            "WHERE indicator_type = ? AND ip = ? LIMIT 1;";
    if (sqlite3_prepare_v2(self.db, selectSQL, -1, &_selectStmt, NULL) != SQLITE_OK) {
        SNBLogThreatIntelError("Failed to prepare SELECT statement: %s", sqlite3_errmsg(self.db));
    }

    // INSERT/REPLACE statement for storing results
    const char *insertSQL = "INSERT OR REPLACE INTO threat_intel_cache "
                            "(ip, indicator_type, evaluated_at, expires_at, response_json) "
                            "VALUES (?, ?, ?, ?, ?);";
    if (sqlite3_prepare_v2(self.db, insertSQL, -1, &_insertStmt, NULL) != SQLITE_OK) {
        SNBLogThreatIntelError("Failed to prepare INSERT statement: %s", sqlite3_errmsg(self.db));
    }

    // DELETE statement for removing specific entries
    const char *deleteSQL = "DELETE FROM threat_intel_cache WHERE indicator_type = ? AND ip = ?;";
    if (sqlite3_prepare_v2(self.db, deleteSQL, -1, &_deleteStmt, NULL) != SQLITE_OK) {
        SNBLogThreatIntelError("Failed to prepare DELETE statement: %s", sqlite3_errmsg(self.db));
    }

    // PURGE statement for removing expired entries
    const char *purgeSQL = "DELETE FROM threat_intel_cache WHERE expires_at <= ?;";
    if (sqlite3_prepare_v2(self.db, purgeSQL, -1, &_purgeStmt, NULL) != SQLITE_OK) {
        SNBLogThreatIntelError("Failed to prepare PURGE statement: %s", sqlite3_errmsg(self.db));
    }

    SNBLogThreatIntelDebug("Prepared %d cached SQL statements", 4);
}

- (void)startPurgeTimer {
    __weak typeof(self) weakSelf = self;
    SNBTimerCoordinator *coordinator = [SNBTimerCoordinator sharedCoordinator];
    self.purgeTimerID = [coordinator scheduleRepeatingTimerWithInterval:kPurgeInterval
                                                                  queue:nil  // Uses main queue
                                                                handler:^{
        [weakSelf purgeExpired];
    }];
    SNBLogThreatIntelDebug("Started automatic purge timer (interval: %.0f seconds)", kPurgeInterval);
}

+ (NSString *)defaultDatabasePath {
    NSArray<NSString *> *paths = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory,
                                                                     NSUserDomainMask,
                                                                     YES);
    NSString *baseDir = paths.firstObject ?: NSTemporaryDirectory();
    NSString *appDir = [baseDir stringByAppendingPathComponent:@"SniffNetBar"];
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:appDir]) {
        [fm createDirectoryAtPath:appDir withIntermediateDirectories:YES attributes:nil error:nil];
    }
    return [appDir stringByAppendingPathComponent:@"threat_intel.sqlite"];
}

- (void)deleteIndicatorLocked:(TIIndicator *)indicator {
    // Use cached prepared statement for better performance
    if (!self.deleteStmt) {
        return;
    }
    sqlite3_reset(self.deleteStmt);
    sqlite3_bind_int(self.deleteStmt, 1, (int)indicator.type);
    sqlite3_bind_text(self.deleteStmt, 2, indicator.value.UTF8String, -1, SQLITE_TRANSIENT);
    sqlite3_step(self.deleteStmt);
}

#pragma mark - Serialization

- (NSString *)jsonStringFromResponse:(TIEnrichmentResponse *)response {
    NSDictionary *dict = [self dictionaryFromResponse:response];
    if (!dict) {
        return nil;
    }

    // Debug logging before serialization
    if (response.scoringResult) {
        SNBLogThreatIntelDebug("Serializing scoring - score=%ld, confidence=%.2f, verdict=%ld",
                              (long)response.scoringResult.finalScore,
                              response.scoringResult.confidence,
                              (long)response.scoringResult.verdict);
    }

    NSError *error = nil;
    NSData *data = [NSJSONSerialization dataWithJSONObject:dict options:0 error:&error];
    if (!data || error) {
        SNBLogThreatIntelWarn("ThreatIntelStore JSON encode failed: %{public}@", error.localizedDescription);
        return nil;
    }
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}

- (NSDictionary *)dictionaryFromResponse:(TIEnrichmentResponse *)response {
    NSMutableArray *providerResults = [NSMutableArray array];
    for (TIResult *result in response.providerResults) {
        NSDictionary *resultDict = @{
            @"provider_name": result.providerName ?: @"",
            @"verdict": [self dictionaryFromVerdict:result.verdict],
            @"metadata": [self dictionaryFromMetadata:result.metadata]
        };
        [providerResults addObject:resultDict];
    }

    NSMutableDictionary *dict = [NSMutableDictionary dictionary];
    dict[@"indicator"] = @{
        @"type": @(response.indicator.type),
        @"value": response.indicator.value ?: @""
    };
    dict[@"provider_results"] = providerResults;
    if (response.scoringResult) {
        dict[@"scoring_result"] = [self dictionaryFromScoring:response.scoringResult];
    }
    dict[@"duration"] = @(response.duration);
    dict[@"cache_hits"] = @(response.cacheHits);
    return dict;
}

- (NSDictionary *)dictionaryFromVerdict:(TIVerdict *)verdict {
    NSMutableDictionary *dict = [NSMutableDictionary dictionary];
    dict[@"hit"] = @(verdict.hit);
    dict[@"confidence"] = @(verdict.confidence);
    dict[@"categories"] = verdict.categories ?: @[];
    dict[@"tags"] = verdict.tags ?: @[];
    dict[@"last_seen"] = verdict.lastSeen ? @([verdict.lastSeen timeIntervalSince1970]) : [NSNull null];
    dict[@"evidence"] = verdict.evidence ?: @{};
    return dict;
}

- (NSDictionary *)dictionaryFromMetadata:(TIMetadata *)metadata {
    NSMutableDictionary *dict = [NSMutableDictionary dictionary];
    dict[@"source_url"] = metadata.sourceURL ?: @"";
    dict[@"fetched_at"] = @([metadata.fetchedAt timeIntervalSince1970]);
    dict[@"expires_at"] = @([metadata.expiresAt timeIntervalSince1970]);
    dict[@"ttl_seconds"] = @(metadata.ttlSeconds);
    dict[@"rate_limit_remaining"] = @(metadata.rateLimitRemaining);
    return dict;
}

- (NSDictionary *)dictionaryFromScoring:(TIScoringResult *)scoring {
    NSMutableArray *breakdown = [NSMutableArray array];
    for (TIScoreBreakdown *item in scoring.breakdown) {
        NSDictionary *itemDict = @{
            @"rule_name": item.ruleName ?: @"",
            @"rule_description": item.ruleDescription ?: @"",
            @"provider": item.provider ?: @"",
            @"score": @(item.scoreContribution),
            @"evidence": item.evidence ?: @{},
            @"confidence": @(item.confidence)
        };
        [breakdown addObject:itemDict];
    }

    return @{
        @"final_score": @(scoring.finalScore),
        @"verdict": @(scoring.verdict),
        @"breakdown": breakdown,
        @"confidence": @(scoring.confidence),
        @"evaluated_at": @([scoring.evaluatedAt timeIntervalSince1970]),
        @"explanation": scoring.explanation ?: @""
    };
}

- (TIEnrichmentResponse *)responseFromJSONString:(NSString *)jsonString {
    if (jsonString.length == 0) {
        return nil;
    }
    NSData *data = [jsonString dataUsingEncoding:NSUTF8StringEncoding];
    if (!data) {
        return nil;
    }
    NSError *error = nil;
    NSDictionary *dict = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
    if (![dict isKindOfClass:[NSDictionary class]] || error) {
        SNBLogThreatIntelWarn("ThreatIntelStore JSON decode failed: %{public}@", error.localizedDescription);
        return nil;
    }
    return [self responseFromDictionary:dict];
}

- (TIEnrichmentResponse *)responseFromDictionary:(NSDictionary *)dict {
    NSDictionary *indicatorDict = dict[@"indicator"];
    NSNumber *typeNumber = indicatorDict[@"type"];
    NSString *value = indicatorDict[@"value"];
    if (![typeNumber isKindOfClass:[NSNumber class]] || ![value isKindOfClass:[NSString class]]) {
        return nil;
    }

    TIIndicator *indicator = [[TIIndicator alloc] initWithType:(TIIndicatorType)typeNumber.integerValue value:value];
    TIEnrichmentResponse *response = [[TIEnrichmentResponse alloc] init];
    response.indicator = indicator;

    NSArray *resultsArray = dict[@"provider_results"];
    NSMutableArray<TIResult *> *results = [NSMutableArray array];
    if ([resultsArray isKindOfClass:[NSArray class]]) {
        for (NSDictionary *resultDict in resultsArray) {
            TIResult *result = [self resultFromDictionary:resultDict indicator:indicator];
            if (result) {
                [results addObject:result];
            }
        }
    }
    response.providerResults = results;

    NSDictionary *scoringDict = dict[@"scoring_result"];
    if ([scoringDict isKindOfClass:[NSDictionary class]]) {
        response.scoringResult = [self scoringFromDictionary:scoringDict indicator:indicator];
    }
    NSNumber *duration = dict[@"duration"];
    NSNumber *cacheHits = dict[@"cache_hits"];
    response.duration = [duration isKindOfClass:[NSNumber class]] ? duration.doubleValue : 0.0;
    response.cacheHits = [cacheHits isKindOfClass:[NSNumber class]] ? cacheHits.integerValue : 0;
    return response;
}

- (TIResult *)resultFromDictionary:(NSDictionary *)dict indicator:(TIIndicator *)indicator {
    NSString *providerName = dict[@"provider_name"];
    NSDictionary *verdictDict = dict[@"verdict"];
    NSDictionary *metadataDict = dict[@"metadata"];
    if (![providerName isKindOfClass:[NSString class]] ||
        ![verdictDict isKindOfClass:[NSDictionary class]] ||
        ![metadataDict isKindOfClass:[NSDictionary class]]) {
        return nil;
    }

    TIVerdict *verdict = [self verdictFromDictionary:verdictDict];
    TIMetadata *metadata = [self metadataFromDictionary:metadataDict];
    if (!verdict || !metadata) {
        return nil;
    }

    TIResult *result = [[TIResult alloc] init];
    result.indicator = indicator;
    result.providerName = providerName;
    result.verdict = verdict;
    result.metadata = metadata;
    result.error = nil;
    return result;
}

- (TIVerdict *)verdictFromDictionary:(NSDictionary *)dict {
    TIVerdict *verdict = [[TIVerdict alloc] init];
    NSNumber *hit = dict[@"hit"];
    NSNumber *confidence = dict[@"confidence"];
    NSArray *categories = dict[@"categories"];
    NSArray *tags = dict[@"tags"];
    id lastSeen = dict[@"last_seen"];
    NSDictionary *evidence = dict[@"evidence"];

    verdict.hit = [hit isKindOfClass:[NSNumber class]] ? hit.boolValue : NO;
    verdict.confidence = [confidence isKindOfClass:[NSNumber class]] ? confidence.integerValue : 0;
    verdict.categories = [categories isKindOfClass:[NSArray class]] ? categories : @[];
    verdict.tags = [tags isKindOfClass:[NSArray class]] ? tags : @[];
    verdict.evidence = [evidence isKindOfClass:[NSDictionary class]] ? evidence : @{};
    if ([lastSeen isKindOfClass:[NSNumber class]]) {
        verdict.lastSeen = [NSDate dateWithTimeIntervalSince1970:[lastSeen doubleValue]];
    }
    return verdict;
}

- (TIMetadata *)metadataFromDictionary:(NSDictionary *)dict {
    TIMetadata *metadata = [[TIMetadata alloc] init];
    NSString *sourceURL = dict[@"source_url"];
    NSNumber *fetchedAt = dict[@"fetched_at"];
    NSNumber *expiresAt = dict[@"expires_at"];
    NSNumber *ttlSeconds = dict[@"ttl_seconds"];
    NSNumber *rateLimit = dict[@"rate_limit_remaining"];

    if ([sourceURL isKindOfClass:[NSString class]]) {
        metadata.sourceURL = sourceURL;
    }
    if ([fetchedAt isKindOfClass:[NSNumber class]]) {
        metadata.fetchedAt = [NSDate dateWithTimeIntervalSince1970:fetchedAt.doubleValue];
    }
    if ([expiresAt isKindOfClass:[NSNumber class]]) {
        metadata.expiresAt = [NSDate dateWithTimeIntervalSince1970:expiresAt.doubleValue];
    }
    metadata.ttlSeconds = [ttlSeconds isKindOfClass:[NSNumber class]] ? ttlSeconds.doubleValue : metadata.ttlSeconds;
    metadata.rateLimitRemaining = [rateLimit isKindOfClass:[NSNumber class]] ? rateLimit.integerValue : -1;
    return metadata;
}

- (TIScoringResult *)scoringFromDictionary:(NSDictionary *)dict indicator:(TIIndicator *)indicator {
    TIScoringResult *scoring = [[TIScoringResult alloc] init];
    scoring.indicator = indicator;
    NSNumber *finalScore = dict[@"final_score"];
    NSNumber *verdict = dict[@"verdict"];
    NSNumber *confidence = dict[@"confidence"];
    NSNumber *evaluatedAt = dict[@"evaluated_at"];
    NSString *explanation = dict[@"explanation"];

    // Validate and bounds-check finalScore (expected range: 0-10000)
    if ([finalScore isKindOfClass:[NSNumber class]]) {
        NSInteger scoreValue = finalScore.integerValue;
        if (scoreValue < 0 || scoreValue > 10000) {
            SNBLogThreatIntelError("Invalid finalScore during deserialization: %ld (corrupted data, resetting to 0)", (long)scoreValue);
            scoreValue = 0;
        }
        scoring.finalScore = scoreValue;
    } else {
        scoring.finalScore = 0;
    }

    // Validate verdict enum (0-3)
    if ([verdict isKindOfClass:[NSNumber class]]) {
        NSInteger verdictValue = verdict.integerValue;
        if (verdictValue < 0 || verdictValue > 3) {
            SNBLogThreatIntelError("Invalid verdict during deserialization: %ld (corrupted data, setting to Unknown)", (long)verdictValue);
            verdictValue = 3; // TIThreatVerdictUnknown
        }
        scoring.verdict = (TIThreatVerdict)verdictValue;
    } else {
        scoring.verdict = TIThreatVerdictUnknown;
    }

    // Validate confidence (expected range: 0.0-1.0)
    if ([confidence isKindOfClass:[NSNumber class]]) {
        double confidenceValue = confidence.doubleValue;
        if (confidenceValue < 0.0 || confidenceValue > 1.0) {
            SNBLogThreatIntelError("Invalid confidence during deserialization: %.2f (corrupted data, resetting to 0.0)", confidenceValue);
            confidenceValue = 0.0;
        }
        scoring.confidence = confidenceValue;
    } else {
        scoring.confidence = 0.0;
    }

    scoring.evaluatedAt = [evaluatedAt isKindOfClass:[NSNumber class]]
        ? [NSDate dateWithTimeIntervalSince1970:evaluatedAt.doubleValue]
        : [NSDate date];
    scoring.explanation = [explanation isKindOfClass:[NSString class]] ? explanation : @"";

    NSArray *breakdownArray = dict[@"breakdown"];
    NSMutableArray<TIScoreBreakdown *> *breakdown = [NSMutableArray array];
    if ([breakdownArray isKindOfClass:[NSArray class]]) {
        for (NSDictionary *itemDict in breakdownArray) {
            TIScoreBreakdown *item = [self breakdownFromDictionary:itemDict];
            if (item) {
                [breakdown addObject:item];
            }
        }
    }
    scoring.breakdown = breakdown;

    // Debug logging after deserialization
    SNBLogThreatIntelDebug("Deserialized scoring - score=%ld, confidence=%.2f, verdict=%ld, breakdown=%lu",
                          (long)scoring.finalScore, scoring.confidence,
                          (long)scoring.verdict, (unsigned long)breakdown.count);

    return scoring;
}

- (TIScoreBreakdown *)breakdownFromDictionary:(NSDictionary *)dict {
    if (![dict isKindOfClass:[NSDictionary class]]) {
        return nil;
    }
    TIScoreBreakdown *item = [[TIScoreBreakdown alloc] init];
    NSString *ruleName = dict[@"rule_name"];
    NSString *ruleDescription = dict[@"rule_description"];
    NSString *provider = dict[@"provider"];
    NSNumber *score = dict[@"score"];
    NSDictionary *evidence = dict[@"evidence"];
    NSNumber *confidence = dict[@"confidence"];

    item.ruleName = [ruleName isKindOfClass:[NSString class]] ? ruleName : @"";
    item.ruleDescription = [ruleDescription isKindOfClass:[NSString class]] ? ruleDescription : @"";
    item.provider = [provider isKindOfClass:[NSString class]] ? provider : @"";

    // Validate scoreContribution (expected range: 0-100)
    if ([score isKindOfClass:[NSNumber class]]) {
        NSInteger scoreValue = score.integerValue;
        if (scoreValue < 0 || scoreValue > 1000) {
            SNBLogThreatIntelError("Invalid scoreContribution in breakdown: %ld (corrupted data, resetting to 0)", (long)scoreValue);
            scoreValue = 0;
        }
        item.scoreContribution = scoreValue;
    } else {
        item.scoreContribution = 0;
    }

    item.evidence = [evidence isKindOfClass:[NSDictionary class]] ? evidence : @{};

    // Validate confidence (expected range: 0-100 for breakdown items)
    if ([confidence isKindOfClass:[NSNumber class]]) {
        NSInteger confidenceValue = confidence.integerValue;
        if (confidenceValue < 0 || confidenceValue > 100) {
            SNBLogThreatIntelError("Invalid confidence in breakdown: %ld (corrupted data, resetting to 0)", (long)confidenceValue);
            confidenceValue = 0;
        }
        item.confidence = confidenceValue;
    } else {
        item.confidence = 0;
    }

    return item;
}

#pragma mark - Provider Status Management

- (void)saveProviderStatus:(SNBProviderStatus *)status {
    if (!status || !status.providerName || !self.db) {
        return;
    }

    NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
    NSTimeInterval disabledUntilTimestamp = status.disabledUntil ? [status.disabledUntil timeIntervalSince1970] : 0;

    dispatch_async(self.dbQueue, ^{
        const char *sql =
            "INSERT OR REPLACE INTO provider_status "
            "(provider_name, is_disabled, disabled_until, disabled_reason, error_code, last_updated) "
            "VALUES (?, ?, ?, ?, ?, ?);";
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(self.db, sql, -1, &stmt, NULL) != SQLITE_OK) {
            SNBLogThreatIntelWarn("ThreatIntelStore provider status insert prepare failed: %s", sqlite3_errmsg(self.db));
            return;
        }

        sqlite3_bind_text(stmt, 1, status.providerName.UTF8String, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 2, status.isDisabled ? 1 : 0);
        if (disabledUntilTimestamp > 0) {
            sqlite3_bind_int64(stmt, 3, (sqlite3_int64)disabledUntilTimestamp);
        } else {
            sqlite3_bind_null(stmt, 3);
        }
        if (status.disabledReason.length > 0) {
            sqlite3_bind_text(stmt, 4, status.disabledReason.UTF8String, -1, SQLITE_TRANSIENT);
        } else {
            sqlite3_bind_null(stmt, 4);
        }
        sqlite3_bind_int(stmt, 5, (int)status.errorCode);
        sqlite3_bind_int64(stmt, 6, (sqlite3_int64)now);

        if (sqlite3_step(stmt) != SQLITE_DONE) {
            SNBLogThreatIntelWarn("ThreatIntelStore provider status insert failed: %s", sqlite3_errmsg(self.db));
        } else {
            SNBLogThreatIntelDebug("Saved provider status: %{public}@ disabled=%d until=%{public}@ reason=%{public}@",
                                  status.providerName, status.isDisabled,
                                  status.disabledUntil ? status.disabledUntil.description : @"N/A",
                                  status.disabledReason ?: @"N/A");
        }
        sqlite3_finalize(stmt);
    });
}

- (SNBProviderStatus *)getProviderStatus:(NSString *)providerName {
    if (!providerName || !self.db) {
        return nil;
    }

    __block SNBProviderStatus *status = nil;
    dispatch_sync(self.dbQueue, ^{
        const char *sql = "SELECT is_disabled, disabled_until, disabled_reason, error_code, last_updated "
                          "FROM provider_status WHERE provider_name = ? LIMIT 1;";
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(self.db, sql, -1, &stmt, NULL) != SQLITE_OK) {
            SNBLogThreatIntelWarn("ThreatIntelStore provider status query prepare failed: %s", sqlite3_errmsg(self.db));
            return;
        }

        sqlite3_bind_text(stmt, 1, providerName.UTF8String, -1, SQLITE_TRANSIENT);

        if (sqlite3_step(stmt) == SQLITE_ROW) {
            status = [[SNBProviderStatus alloc] init];
            status.providerName = providerName;
            status.isDisabled = sqlite3_column_int(stmt, 0) != 0;

            if (sqlite3_column_type(stmt, 1) != SQLITE_NULL) {
                sqlite3_int64 disabledUntilTimestamp = sqlite3_column_int64(stmt, 1);
                status.disabledUntil = [NSDate dateWithTimeIntervalSince1970:(NSTimeInterval)disabledUntilTimestamp];
            }

            if (sqlite3_column_type(stmt, 2) != SQLITE_NULL) {
                const unsigned char *reason = sqlite3_column_text(stmt, 2);
                status.disabledReason = [NSString stringWithUTF8String:(const char *)reason];
            }

            status.errorCode = sqlite3_column_int(stmt, 3);

            sqlite3_int64 lastUpdated = sqlite3_column_int64(stmt, 4);
            status.lastUpdated = [NSDate dateWithTimeIntervalSince1970:(NSTimeInterval)lastUpdated];
        }

        sqlite3_finalize(stmt);
    });

    return status;
}

- (NSDictionary<NSString *, SNBProviderStatus *> *)getAllProviderStatuses {
    if (!self.db) {
        return @{};
    }

    NSMutableDictionary<NSString *, SNBProviderStatus *> *statuses = [NSMutableDictionary dictionary];

    dispatch_sync(self.dbQueue, ^{
        const char *sql = "SELECT provider_name, is_disabled, disabled_until, disabled_reason, error_code, last_updated "
                          "FROM provider_status;";
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(self.db, sql, -1, &stmt, NULL) != SQLITE_OK) {
            SNBLogThreatIntelWarn("ThreatIntelStore get all provider statuses prepare failed: %s", sqlite3_errmsg(self.db));
            return;
        }

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const unsigned char *name = sqlite3_column_text(stmt, 0);
            if (!name) continue;

            SNBProviderStatus *status = [[SNBProviderStatus alloc] init];
            status.providerName = [NSString stringWithUTF8String:(const char *)name];
            status.isDisabled = sqlite3_column_int(stmt, 1) != 0;

            if (sqlite3_column_type(stmt, 2) != SQLITE_NULL) {
                sqlite3_int64 disabledUntilTimestamp = sqlite3_column_int64(stmt, 2);
                status.disabledUntil = [NSDate dateWithTimeIntervalSince1970:(NSTimeInterval)disabledUntilTimestamp];
            }

            if (sqlite3_column_type(stmt, 3) != SQLITE_NULL) {
                const unsigned char *reason = sqlite3_column_text(stmt, 3);
                status.disabledReason = [NSString stringWithUTF8String:(const char *)reason];
            }

            status.errorCode = sqlite3_column_int(stmt, 4);

            sqlite3_int64 lastUpdated = sqlite3_column_int64(stmt, 5);
            status.lastUpdated = [NSDate dateWithTimeIntervalSince1970:(NSTimeInterval)lastUpdated];

            statuses[status.providerName] = status;
        }

        sqlite3_finalize(stmt);
    });

    SNBLogThreatIntelDebug("Loaded %lu provider statuses from database", (unsigned long)statuses.count);
    return statuses;
}

- (void)clearProviderStatus:(NSString *)providerName {
    if (!providerName || !self.db) {
        return;
    }

    dispatch_async(self.dbQueue, ^{
        const char *sql = "DELETE FROM provider_status WHERE provider_name = ?;";
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(self.db, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, providerName.UTF8String, -1, SQLITE_TRANSIENT);
            sqlite3_step(stmt);
            SNBLogThreatIntelDebug("Cleared provider status for %{public}@", providerName);
        }
        sqlite3_finalize(stmt);
    });
}

- (void)clearExpiredProviderStatuses {
    if (!self.db) {
        return;
    }

    NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
    dispatch_async(self.dbQueue, ^{
        const char *sql = "DELETE FROM provider_status WHERE disabled_until IS NOT NULL AND disabled_until <= ?;";
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(self.db, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_int64(stmt, 1, (sqlite3_int64)now);
            if (sqlite3_step(stmt) == SQLITE_DONE) {
                int deleted = sqlite3_changes(self.db);
                if (deleted > 0) {
                    SNBLogThreatIntelDebug("Cleared %d expired provider statuses", deleted);
                }
            }
        }
        sqlite3_finalize(stmt);
    });
}

@end

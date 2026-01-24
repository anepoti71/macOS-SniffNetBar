//
//  TrustLearningEngine.m
//  SniffNetBar
//

#import "TrustLearningEngine.h"
#import "TrustLearningModels.h"
#import "AdaptiveScoring.h"
#import "Config/UserDefaultsKeys.h"
#import "Logger.h"
#import <sqlite3.h>

NSString *const SNBTrustSuggestionAvailableNotification = @"SNBTrustSuggestionAvailableNotification";

static const NSInteger SNBTrustSuggestionMinSamples = 3;

@interface SNBTrustLearningEngine ()
@property (nonatomic, strong) dispatch_queue_t ioQueue;
@property (nonatomic, assign) sqlite3 *database;
@property (nonatomic, copy) NSString *sessionId;
@property (nonatomic, strong) NSMutableSet<NSString *> *notifiedIPs;
@end

@implementation SNBTrustLearningEngine

+ (instancetype)sharedEngine {
    static SNBTrustLearningEngine *shared = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        shared = [[SNBTrustLearningEngine alloc] init];
    });
    return shared;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _ioQueue = dispatch_queue_create("com.sniffnetbar.trustlearning", DISPATCH_QUEUE_SERIAL);
        _sessionId = [NSUUID UUID].UUIDString;
        _notifiedIPs = [NSMutableSet set];
        dispatch_sync(_ioQueue, ^{
            [self openDatabaseAtPath:[self databasePath]];
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

- (NSString *)databasePath {
    NSArray<NSString *> *paths = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory,
                                                                      NSUserDomainMask,
                                                                      YES);
    NSString *base = paths.firstObject ?: NSTemporaryDirectory();
    NSString *dir = [base stringByAppendingPathComponent:@"SniffNetBar"];
    NSError *error = nil;
    [[NSFileManager defaultManager] createDirectoryAtPath:dir
                              withIntermediateDirectories:YES
                                               attributes:nil
                                                    error:&error];
    if (error) {
        SNBLogUIDebug("TrustLearningEngine: failed to create App Support dir: %s",
                      error.localizedDescription.UTF8String);
    }
    return [dir stringByAppendingPathComponent:@"trusted_ips.sqlite"];
}

- (void)openDatabaseAtPath:(NSString *)path {
    sqlite3 *db = NULL;
    int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX;
    if (sqlite3_open_v2(path.UTF8String, &db, flags, NULL) != SQLITE_OK) {
        SNBLogUIDebug("TrustLearningEngine: failed to open database: %s", sqlite3_errmsg(db));
        if (db) {
            sqlite3_close(db);
        }
        return;
    }

    const char *feedbackSql =
        "CREATE TABLE IF NOT EXISTS trust_feedback ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "ip TEXT NOT NULL,"
        "feature_vector_json TEXT NOT NULL,"
        "user_decision INTEGER NOT NULL,"
        "reason INTEGER,"
        "timestamp REAL NOT NULL,"
        "session_id TEXT"
        ");";

    char *err = NULL;
    if (sqlite3_exec(db, feedbackSql, NULL, NULL, &err) != SQLITE_OK) {
        SNBLogUIDebug("TrustLearningEngine: failed to create trust_feedback table: %s", err ?: "unknown");
        sqlite3_free(err);
    }

    const char *patternsSql =
        "CREATE TABLE IF NOT EXISTS learned_patterns ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "pattern_type TEXT,"
        "pattern_value TEXT,"
        "trust_probability REAL,"
        "sample_count INTEGER,"
        "last_updated REAL,"
        "UNIQUE(pattern_type, pattern_value)"
        ");";

    err = NULL;
    if (sqlite3_exec(db, patternsSql, NULL, NULL, &err) != SQLITE_OK) {
        SNBLogUIDebug("TrustLearningEngine: failed to create learned_patterns table: %s", err ?: "unknown");
        sqlite3_free(err);
    }

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
        SNBLogUIDebug("TrustLearningEngine: failed to create trust_history table: %s", err ?: "unknown");
        sqlite3_free(err);
    }

    const char *feedbackIndexSql = "CREATE INDEX IF NOT EXISTS idx_trust_feedback_ip ON trust_feedback(ip);";
    sqlite3_exec(db, feedbackIndexSql, NULL, NULL, NULL);

    _database = db;
}

- (SNBTrustFeatureVector *)populateHistoricalFeaturesForIP:(NSString *)ipAddress
                                             featureVector:(SNBTrustFeatureVector *)featureVector {
    if (!self.database || ipAddress.length == 0) {
        return featureVector;
    }

    dispatch_sync(self.ioQueue, ^{
        sqlite3_stmt *stmt = NULL;
        const char *countSql =
            "SELECT "
            "SUM(CASE WHEN trusted = 1 THEN 1 ELSE 0 END), "
            "SUM(CASE WHEN trusted = 0 THEN 1 ELSE 0 END) "
            "FROM trust_history WHERE ip = ?1;";
        if (sqlite3_prepare_v2(self.database, countSql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, ipAddress.UTF8String, -1, SQLITE_TRANSIENT);
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                featureVector.previousTrustCount = sqlite3_column_int(stmt, 0);
                featureVector.previousUntrustCount = sqlite3_column_int(stmt, 1);
            }
            sqlite3_finalize(stmt);
        }

        const char *firstSeenSql = "SELECT MIN(timestamp) FROM trust_history WHERE ip = ?1;";
        stmt = NULL;
        if (sqlite3_prepare_v2(self.database, firstSeenSql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, ipAddress.UTF8String, -1, SQLITE_TRANSIENT);
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                double firstSeen = sqlite3_column_double(stmt, 0);
                if (firstSeen > 0) {
                    NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
                    featureVector.daysSinceFirstSeen = (now - firstSeen) / (60.0 * 60.0 * 24.0);
                }
            }
            sqlite3_finalize(stmt);
        }
    });

    return featureVector;
}

- (NSArray<NSDictionary<NSString *, NSString *> *> *)patternsForFeatureVector:(SNBTrustFeatureVector *)vector {
    NSMutableArray<NSDictionary<NSString *, NSString *> *> *patterns = [NSMutableArray array];
    if (vector.asn.length > 0) {
        [patterns addObject:@{@"type": @"asn", @"value": vector.asn}];
    }
    if (vector.organization.length > 0) {
        [patterns addObject:@{@"type": @"org", @"value": vector.organization}];
    }
    if (vector.destinationPort > 0 && vector.processName.length > 0) {
        NSString *value = [NSString stringWithFormat:@"%ld|%@",
                           (long)vector.destinationPort, vector.processName];
        [patterns addObject:@{@"type": @"port_process", @"value": value}];
    }
    return patterns;
}

- (void)updatePatternsForVector:(SNBTrustFeatureVector *)vector trusted:(BOOL)trusted {
    NSArray<NSDictionary<NSString *, NSString *> *> *patterns = [self patternsForFeatureVector:vector];
    if (patterns.count == 0 || !self.database) {
        return;
    }

    NSTimeInterval now = [[NSDate date] timeIntervalSince1970];

    for (NSDictionary<NSString *, NSString *> *pattern in patterns) {
        NSString *type = pattern[@"type"];
        NSString *value = pattern[@"value"];
        if (type.length == 0 || value.length == 0) {
            continue;
        }

        sqlite3_stmt *stmt = NULL;
        const char *selectSql =
            "SELECT trust_probability, sample_count FROM learned_patterns "
            "WHERE pattern_type = ?1 AND pattern_value = ?2 LIMIT 1;";
        double oldProb = 0.0;
        NSInteger oldCount = 0;
        BOOL found = NO;
        if (sqlite3_prepare_v2(self.database, selectSql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, type.UTF8String, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 2, value.UTF8String, -1, SQLITE_TRANSIENT);
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                oldProb = sqlite3_column_double(stmt, 0);
                oldCount = sqlite3_column_int(stmt, 1);
                found = YES;
            }
            sqlite3_finalize(stmt);
        }

        double newProb = 0.0;
        NSInteger newCount = oldCount + 1;
        if (newCount > 0) {
            newProb = ((oldProb * oldCount) + (trusted ? 1.0 : 0.0)) / (double)newCount;
        }

        if (found) {
            const char *updateSql =
                "UPDATE learned_patterns SET trust_probability = ?1, sample_count = ?2, last_updated = ?3 "
                "WHERE pattern_type = ?4 AND pattern_value = ?5;";
            stmt = NULL;
            if (sqlite3_prepare_v2(self.database, updateSql, -1, &stmt, NULL) == SQLITE_OK) {
                sqlite3_bind_double(stmt, 1, newProb);
                sqlite3_bind_int(stmt, 2, (int)newCount);
                sqlite3_bind_double(stmt, 3, now);
                sqlite3_bind_text(stmt, 4, type.UTF8String, -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(stmt, 5, value.UTF8String, -1, SQLITE_TRANSIENT);
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
        } else {
            const char *insertSql =
                "INSERT INTO learned_patterns (pattern_type, pattern_value, trust_probability, sample_count, last_updated) "
                "VALUES (?1, ?2, ?3, ?4, ?5);";
            stmt = NULL;
            if (sqlite3_prepare_v2(self.database, insertSql, -1, &stmt, NULL) == SQLITE_OK) {
                sqlite3_bind_text(stmt, 1, type.UTF8String, -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(stmt, 2, value.UTF8String, -1, SQLITE_TRANSIENT);
                sqlite3_bind_double(stmt, 3, newProb);
                sqlite3_bind_int(stmt, 4, (int)newCount);
                sqlite3_bind_double(stmt, 5, now);
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
        }
    }
}

- (void)recordFeedbackForIP:(NSString *)ipAddress
                    trusted:(BOOL)trusted
                     reason:(SNBTrustReason)reason
              featureVector:(SNBTrustFeatureVector *)featureVector {
    if (ipAddress.length == 0 || !self.database) {
        return;
    }

    SNBTrustFeatureVector *vector = featureVector ?: [[SNBTrustFeatureVector alloc] init];
    if (vector.ipAddress.length == 0) {
        vector.ipAddress = ipAddress;
    }
    [self populateHistoricalFeaturesForIP:ipAddress featureVector:vector];

    SNBTrustFeedback *feedback = [[SNBTrustFeedback alloc] init];
    feedback.ipAddress = ipAddress;
    feedback.trusted = trusted;
    feedback.reason = reason;
    feedback.timestamp = [NSDate date];
    feedback.sessionId = self.sessionId;
    feedback.featureVector = vector;

    NSString *json = [vector jsonString];
    NSTimeInterval now = [feedback.timestamp timeIntervalSince1970];

    dispatch_async(self.ioQueue, ^{
        sqlite3_stmt *stmt = NULL;
        const char *sql =
            "INSERT INTO trust_feedback "
            "(ip, feature_vector_json, user_decision, reason, timestamp, session_id) "
            "VALUES (?1, ?2, ?3, ?4, ?5, ?6);";
        if (sqlite3_prepare_v2(self.database, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, ipAddress.UTF8String, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 2, json.UTF8String, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(stmt, 3, trusted ? 1 : 0);
            sqlite3_bind_int(stmt, 4, (int)reason);
            sqlite3_bind_double(stmt, 5, now);
            if (feedback.sessionId.length > 0) {
                sqlite3_bind_text(stmt, 6, feedback.sessionId.UTF8String, -1, SQLITE_TRANSIENT);
            } else {
                sqlite3_bind_null(stmt, 6);
            }
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }

        [self updatePatternsForVector:vector trusted:trusted];
    });

    [[SNBAdaptiveScoring sharedScoring] updateWeightsFromFeedback:feedback];
}

- (nullable SNBTrustSuggestion *)suggestTrustForIP:(NSString *)ipAddress
                                     featureVector:(SNBTrustFeatureVector *)featureVector {
    if (ipAddress.length == 0 || !self.database) {
        return nil;
    }

    SNBTrustFeatureVector *vector = featureVector ?: [[SNBTrustFeatureVector alloc] init];
    if (vector.ipAddress.length == 0) {
        vector.ipAddress = ipAddress;
    }

    NSArray<NSDictionary<NSString *, NSString *> *> *patterns = [self patternsForFeatureVector:vector];
    if (patterns.count == 0) {
        return nil;
    }

    __block double weightedSum = 0.0;
    __block NSInteger totalSamples = 0;
    __block NSDictionary<NSString *, NSString *> *strongestPattern = nil;

    dispatch_sync(self.ioQueue, ^{
        for (NSDictionary<NSString *, NSString *> *pattern in patterns) {
            NSString *type = pattern[@"type"];
            NSString *value = pattern[@"value"];
            sqlite3_stmt *stmt = NULL;
            const char *sql =
                "SELECT trust_probability, sample_count FROM learned_patterns "
                "WHERE pattern_type = ?1 AND pattern_value = ?2 LIMIT 1;";
            if (sqlite3_prepare_v2(self.database, sql, -1, &stmt, NULL) == SQLITE_OK) {
                sqlite3_bind_text(stmt, 1, type.UTF8String, -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(stmt, 2, value.UTF8String, -1, SQLITE_TRANSIENT);
                if (sqlite3_step(stmt) == SQLITE_ROW) {
                    double prob = sqlite3_column_double(stmt, 0);
                    NSInteger count = sqlite3_column_int(stmt, 1);
                    if (count > 0) {
                        weightedSum += prob * count;
                        totalSamples += count;
                        if (!strongestPattern || count > [strongestPattern[@"count"] integerValue]) {
                            strongestPattern = @{
                                @"type": type,
                                @"value": value,
                                @"count": @(count)
                            };
                        }
                    }
                }
                sqlite3_finalize(stmt);
            }
        }
    });

    if (totalSamples == 0) {
        return nil;
    }

    double confidence = weightedSum / (double)totalSamples;
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    double threshold = [defaults doubleForKey:SNBUserDefaultsKeySuggestionConfidenceThreshold];
    if (threshold <= 0.0) {
        threshold = 0.7;
    }
    BOOL enabled = [defaults objectForKey:SNBUserDefaultsKeyEnableProactiveSuggestions]
        ? [defaults boolForKey:SNBUserDefaultsKeyEnableProactiveSuggestions] : YES;

    if (!enabled || confidence < threshold || totalSamples < SNBTrustSuggestionMinSamples) {
        return nil;
    }

    SNBTrustSuggestion *suggestion = [[SNBTrustSuggestion alloc] init];
    suggestion.ipAddress = ipAddress;
    suggestion.confidence = confidence;
    suggestion.sampleCount = totalSamples;

    NSString *patternType = strongestPattern[@"type"];
    if ([patternType isEqualToString:@"org"] || [patternType isEqualToString:@"asn"]) {
        suggestion.suggestedReason = SNBTrustReasonKnownService;
    } else if ([patternType isEqualToString:@"port_process"]) {
        suggestion.suggestedReason = SNBTrustReasonOwnInfrastructure;
    } else {
        suggestion.suggestedReason = SNBTrustReasonUnspecified;
    }

    suggestion.primaryReason = [SNBTrustContext displayStringForReason:suggestion.suggestedReason];
    [self maybeNotifySuggestion:suggestion];

    return suggestion;
}

- (void)maybeNotifySuggestion:(SNBTrustSuggestion *)suggestion {
    if (!suggestion || suggestion.ipAddress.length == 0) {
        return;
    }
    if ([self.notifiedIPs containsObject:suggestion.ipAddress]) {
        return;
    }
    [self.notifiedIPs addObject:suggestion.ipAddress];
    dispatch_async(dispatch_get_main_queue(), ^{
        [[NSNotificationCenter defaultCenter] postNotificationName:SNBTrustSuggestionAvailableNotification
                                                            object:nil
                                                          userInfo:@{
                                                            @"ip": suggestion.ipAddress,
                                                            @"suggestion": suggestion
                                                          }];
    });
}

@end

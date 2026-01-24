//
//  SNBLocationStore.m
//  SniffNetBar
//

#import "SNBLocationStore.h"
#import <sqlite3.h>
#import "Logger.h"

@interface SNBLocationStore ()
@property (nonatomic, assign) NSTimeInterval expirationInterval;
@property (nonatomic, strong) dispatch_queue_t ioQueue;
@property (nonatomic, assign) sqlite3 *database;
@end

@implementation SNBLocationStore

+ (instancetype)sharedStoreWithPath:(NSString *)path
                 expirationInterval:(NSTimeInterval)expiration {
    static SNBLocationStore *sharedStore = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sharedStore = [[SNBLocationStore alloc] initWithPath:path
                                        expirationInterval:expiration];
    });
    return sharedStore;
}

- (instancetype)initWithPath:(NSString *)path expirationInterval:(NSTimeInterval)expiration {
    self = [super init];
    if (self) {
        _expirationInterval = expiration;
        _ioQueue = dispatch_queue_create("com.sniffnetbar.locationstore", DISPATCH_QUEUE_SERIAL);
        dispatch_sync(_ioQueue, ^{
            [self openDatabaseAtPath:path];
        });
    }
    return self;
}

- (void)dealloc {
    [self close];
}

- (void)openDatabaseAtPath:(NSString *)path {
    sqlite3 *db = NULL;
    int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX;
    if (sqlite3_open_v2(path.UTF8String, &db, flags, NULL) != SQLITE_OK) {
        SNBLogUIDebug("Failed to open location store: %s", sqlite3_errmsg(db));
        if (db) {
            sqlite3_close(db);
        }
        return;
    }
    const char *sql =
        "CREATE TABLE IF NOT EXISTS locations ("
        "ip TEXT PRIMARY KEY,"
        "lat REAL,"
        "lon REAL,"
        "name TEXT,"
        "isp TEXT,"
        "timestamp REAL"
        ");";
    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        SNBLogUIDebug("Could not create location table: %s", err ?: "unknown");
        sqlite3_free(err);
    }
    _database = db;
}

- (void)close {
    dispatch_sync(_ioQueue, ^{
        if (self.database) {
            sqlite3_close(self.database);
            self.database = NULL;
        }
    });
}

- (nullable NSDictionary<NSString *, id> *)locationForIP:(NSString *)ip {
    if (ip.length == 0 || !self.database) {
        return nil;
    }
    __block NSDictionary<NSString *, id> *result = nil;
    dispatch_sync(self.ioQueue, ^{
        sqlite3_stmt *stmt = NULL;
        const char *sql = "SELECT lat, lon, name, isp, timestamp FROM locations WHERE ip = ?1;";
        if (sqlite3_prepare_v2(self.database, sql, -1, &stmt, NULL) != SQLITE_OK) {
            return;
        }
        sqlite3_bind_text(stmt, 1, ip.UTF8String, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            NSTimeInterval timestamp = sqlite3_column_double(stmt, 4);
            if (self.expirationInterval > 0 && ([[NSDate date] timeIntervalSince1970] - timestamp) > self.expirationInterval) {
                [self deleteLocationForIP:ip];
            } else {
                double lat = sqlite3_column_double(stmt, 0);
                double lon = sqlite3_column_double(stmt, 1);
                const unsigned char *nameValue = sqlite3_column_text(stmt, 2);
                const unsigned char *ispValue = sqlite3_column_text(stmt, 3);
                NSMutableDictionary *payload = [NSMutableDictionary dictionary];
                payload[@"lat"] = @(lat);
                payload[@"lon"] = @(lon);
                if (nameValue) {
                    payload[@"name"] = [NSString stringWithUTF8String:(const char *)nameValue];
                }
                if (ispValue) {
                    payload[@"isp"] = [NSString stringWithUTF8String:(const char *)ispValue];
                }
                result = [payload copy];
            }
        }
        sqlite3_finalize(stmt);
    });
    return result;
}

- (void)storeLocation:(NSDictionary<NSString *, id> *)location forIP:(NSString *)ip {
    if (ip.length == 0 || !location || !self.database) {
        return;
    }
    dispatch_async(self.ioQueue, ^{
        sqlite3_stmt *stmt = NULL;
        const char *sql = "INSERT OR REPLACE INTO locations (ip, lat, lon, name, isp, timestamp) VALUES (?1, ?2, ?3, ?4, ?5, ?6);";
        if (sqlite3_prepare_v2(self.database, sql, -1, &stmt, NULL) != SQLITE_OK) {
            return;
        }
        sqlite3_bind_text(stmt, 1, ip.UTF8String, -1, SQLITE_TRANSIENT);
        sqlite3_bind_double(stmt, 2, [location[@"lat"] doubleValue]);
        sqlite3_bind_double(stmt, 3, [location[@"lon"] doubleValue]);
        NSString *name = location[@"name"];
        NSString *isp = location[@"isp"];
        NSString *nameText = name ?: @"";
        sqlite3_bind_text(stmt, 4, nameText.UTF8String, -1, SQLITE_TRANSIENT);
        NSString *ispText = isp ?: @"";
        sqlite3_bind_text(stmt, 5, ispText.UTF8String, -1, SQLITE_TRANSIENT);
        sqlite3_bind_double(stmt, 6, [[NSDate date] timeIntervalSince1970]);
        if (sqlite3_step(stmt) != SQLITE_DONE) {
            SNBLogUIDebug("Failed to persist location for %s: %s", ip.UTF8String, sqlite3_errmsg(self.database));
        }
        sqlite3_finalize(stmt);
    });
}

- (void)deleteLocationForIP:(NSString *)ip {
    if (!ip.length || !self.database) {
        return;
    }
    sqlite3_stmt *stmt = NULL;
    const char *sql = "DELETE FROM locations WHERE ip = ?1;";
    if (sqlite3_prepare_v2(self.database, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return;
    }
    sqlite3_bind_text(stmt, 1, ip.UTF8String, -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

- (void)cleanupExpiredEntries {
    if (self.expirationInterval <= 0 || !self.database) {
        return;
    }
    dispatch_async(self.ioQueue, ^{
        sqlite3_stmt *stmt = NULL;
        const char *sql = "DELETE FROM locations WHERE timestamp < ?1;";
        if (sqlite3_prepare_v2(self.database, sql, -1, &stmt, NULL) != SQLITE_OK) {
            return;
        }
        double cutoff = [[NSDate date] timeIntervalSince1970] - self.expirationInterval;
        sqlite3_bind_double(stmt, 1, cutoff);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    });
}

@end

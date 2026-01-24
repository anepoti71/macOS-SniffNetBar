//
//  SNBBehaviorDatabase.m
//  SniffNetBar
//

#import "SNBBehaviorDatabase.h"
#import "Logger.h"

@interface SNBBehaviorDatabase ()
@property (nonatomic, assign) sqlite3 *db;
@property (nonatomic, strong) dispatch_queue_t queue;
@end

@implementation SNBBehaviorDatabase

- (instancetype)initWithPath:(NSString *)path {
    self = [super init];
    if (self) {
        _queue = dispatch_queue_create("com.sniffnetbar.behavior.db", DISPATCH_QUEUE_SERIAL);
        [self openDatabaseAtPath:path];
    }
    return self;
}

- (void)openDatabaseAtPath:(NSString *)path {
    NSString *directory = [path stringByDeletingLastPathComponent];
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:directory]) {
        [fm createDirectoryAtPath:directory withIntermediateDirectories:YES attributes:nil error:nil];
    }
    if (sqlite3_open_v2(path.fileSystemRepresentation, &_db,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL) != SQLITE_OK) {
        SNBLogBehaviorError("BehaviorDatabase: Failed to open database at %{public}@", path);
        if (self.db) {
            sqlite3_close(self.db);
            self.db = NULL;
        }
        return;
    }
    sqlite3_exec(self.db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);
    sqlite3_exec(self.db, "PRAGMA synchronous=NORMAL;", NULL, NULL, NULL);
}

@end

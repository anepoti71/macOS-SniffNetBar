//
//  SNBBehaviorDatabase.h
//  SniffNetBar
//

#import <Foundation/Foundation.h>
#import <sqlite3.h>

NS_ASSUME_NONNULL_BEGIN

@interface SNBBehaviorDatabase : NSObject

@property (nonatomic, readonly) sqlite3 *db;
@property (nonatomic, readonly) dispatch_queue_t queue;

- (instancetype)initWithPath:(NSString *)path;

@end

NS_ASSUME_NONNULL_END

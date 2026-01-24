//
//  SNBEventStore.h
//  SniffNetBar
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@class SNBFlowEvent;

@class SNBBehaviorDatabase;

@interface SNBEventStore : NSObject

- (instancetype)initWithDatabase:(SNBBehaviorDatabase *)database;
- (BOOL)appendEvents:(NSArray<SNBFlowEvent *> *)events;
- (SNBFlowEvent * _Nullable)latestEventForClusterID:(NSString *)clusterID
                                          firstSeen:(NSDate * _Nullable * _Nullable)firstSeen;

@end

NS_ASSUME_NONNULL_END

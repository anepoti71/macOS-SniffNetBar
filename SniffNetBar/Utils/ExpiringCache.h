//
//  ExpiringCache.h
//  SniffNetBar
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface SNBExpiringCache<KeyType, ObjectType> : NSObject

- (instancetype)initWithMaxSize:(NSUInteger)maxSize
             expirationInterval:(NSTimeInterval)expirationInterval;
- (nullable ObjectType)objectForKey:(KeyType)key;
- (void)setObject:(ObjectType)object forKey:(KeyType)key;
- (void)removeObjectForKey:(KeyType)key;
- (void)removeAllObjects;
- (NSUInteger)cleanupAndReturnExpiredCount;

@end

NS_ASSUME_NONNULL_END

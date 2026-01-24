//
//  SNBLocationStore.h
//  SniffNetBar
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface SNBLocationStore : NSObject

+ (instancetype)sharedStoreWithPath:(NSString *)path
                 expirationInterval:(NSTimeInterval)expiration;

- (instancetype)initWithPath:(NSString *)path expirationInterval:(NSTimeInterval)expiration;
- (nullable NSDictionary<NSString *, id> *)locationForIP:(NSString *)ip;
- (void)storeLocation:(NSDictionary<NSString *, id> *)location forIP:(NSString *)ip;
- (void)cleanupExpiredEntries;

- (void)close;

@end

NS_ASSUME_NONNULL_END

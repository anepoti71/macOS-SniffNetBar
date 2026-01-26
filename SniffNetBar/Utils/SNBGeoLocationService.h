//
//  SNBGeoLocationService.h
//  SniffNetBar
//

#import <Foundation/Foundation.h>
#import <CoreLocation/CoreLocation.h>

@class SNBExpiringCache;
@class SNBLocationStore;

NS_ASSUME_NONNULL_BEGIN

@interface SNBGeoLocationService : NSObject

@property (nonatomic, copy) NSString *providerName;
@property (atomic, assign, readonly) NSUInteger locationVersion;
@property (nonatomic, copy, readonly) NSString *publicIPAddress;
@property (nonatomic, strong, readonly, nullable) NSValue *publicIPCoordinate;

- (instancetype)initWithProviderName:(NSString *)providerName;
- (NSDictionary<NSString *, NSDictionary *> *)cachedLocationsForIPs:(NSArray<NSString *> *)ips;
- (nullable NSDictionary *)locationForIP:(NSString *)ip;
- (void)resolveTargetIPs:(NSSet<NSString *> *)targetIPs
              completion:(void (^)(NSString *ip, CLLocationCoordinate2D coord, BOOL success))completion;
- (void)updatePublicIPIfNeededWithCompletion:(void (^)(BOOL updated))completion;
- (void)performCacheCleanup;

@end

NS_ASSUME_NONNULL_END

//
//  GreyNoiseProvider.h
//  SniffNetBar
//
//  GreyNoise Community API threat intelligence provider
//

#import <Foundation/Foundation.h>
#import "ThreatIntelProvider.h"

NS_ASSUME_NONNULL_BEGIN

/**
 * GreyNoise Community API provider for IPv4 reputation/context checks
 * Community API provides noise/riot classification for public IPs.
 */
@interface GreyNoiseProvider : NSObject <ThreatIntelProvider>

- (instancetype)initWithTTL:(NSTimeInterval)ttl
                negativeTTL:(NSTimeInterval)negativeTTL;

- (void)configureWithBaseURL:(NSString *)baseURL
                      APIKey:(NSString *)apiKey
                     timeout:(NSTimeInterval)timeout
           maxRequestsPerMin:(NSInteger)maxRequestsPerMin
                  completion:(void (^)(NSError * _Nullable error))completion;

@end

NS_ASSUME_NONNULL_END

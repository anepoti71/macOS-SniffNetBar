//
//  ShodanProvider.h
//  SniffNetBar
//

#import "ThreatIntelProvider.h"

NS_ASSUME_NONNULL_BEGIN

@interface ShodanProvider : NSObject <ThreatIntelProvider>

- (instancetype)initWithTTL:(NSTimeInterval)ttl negativeTTL:(NSTimeInterval)negativeTTL;

- (void)configureWithBaseURL:(NSString *)baseURL
                      APIKey:(NSString *)apiKey
                     timeout:(NSTimeInterval)timeout
           maxRequestsPerMin:(NSInteger)maxRequestsPerMin
                  completion:(void (^ _Nullable)(NSError * _Nullable error))completion;

@end

NS_ASSUME_NONNULL_END

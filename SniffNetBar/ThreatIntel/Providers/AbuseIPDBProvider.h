//
//  AbuseIPDBProvider.h
//  SniffNetBar
//
//  AbuseIPDB API v2 threat intelligence provider
//

#import <Foundation/Foundation.h>
#import "ThreatIntelProvider.h"

NS_ASSUME_NONNULL_BEGIN

/**
 * AbuseIPDB API v2 provider for IP address abuse reporting and checking
 *
 * Supports IPv4 and IPv6 address lookups via AbuseIPDB's public API.
 * Provides abuse confidence scores (0-100) and reporting history.
 *
 * API Documentation: https://docs.abuseipdb.com/#check-endpoint
 */
@interface AbuseIPDBProvider : NSObject <ThreatIntelProvider>

@property (nonatomic, copy, readonly) NSString *name;
@property (nonatomic, assign, readonly) NSTimeInterval defaultTTL;
@property (nonatomic, assign, readonly) NSTimeInterval negativeCacheTTL;

/**
 * Initialize with custom TTL values and maxAgeInDays
 * @param ttl Time-to-live for positive results (default: 24 hours)
 * @param negativeTTL Time-to-live for negative results (default: 1 hour)
 * @param maxAgeInDays Look back this many days for abuse reports (default: 90)
 */
- (instancetype)initWithTTL:(NSTimeInterval)ttl
                negativeTTL:(NSTimeInterval)negativeTTL
              maxAgeInDays:(NSInteger)maxAgeInDays;

/**
 * Configure provider with custom API base URL
 * @param baseURL The base URL for the AbuseIPDB API
 * @param apiKey The AbuseIPDB API key
 * @param timeout Request timeout in seconds
 * @param maxRequestsPerMin Rate limit (requests per minute)
 * @param completion Completion handler called when configuration is complete
 */
- (void)configureWithBaseURL:(NSString *)baseURL
                      APIKey:(NSString *)apiKey
                     timeout:(NSTimeInterval)timeout
           maxRequestsPerMin:(NSInteger)maxRequestsPerMin
                  completion:(void (^ _Nullable)(NSError * _Nullable error))completion;

@end

NS_ASSUME_NONNULL_END

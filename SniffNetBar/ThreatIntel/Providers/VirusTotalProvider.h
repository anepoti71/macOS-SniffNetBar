//
//  VirusTotalProvider.h
//  SniffNetBar
//
//  VirusTotal API v3 threat intelligence provider
//

#import <Foundation/Foundation.h>
#import "ThreatIntelProvider.h"

NS_ASSUME_NONNULL_BEGIN

/**
 * VirusTotal API v3 provider for IP address reputation checks
 *
 * Supports IPv4 and IPv6 address lookups via VirusTotal's public API.
 * Implements rate limiting and caching as per the ThreatIntelProvider protocol.
 *
 * API Documentation: https://developers.virustotal.com/reference/ip-info
 */
@interface VirusTotalProvider : NSObject <ThreatIntelProvider>

@property (nonatomic, copy, readonly) NSString *name;
@property (nonatomic, assign, readonly) NSTimeInterval defaultTTL;
@property (nonatomic, assign, readonly) NSTimeInterval negativeCacheTTL;

/**
 * Initialize with custom TTL values
 * @param ttl Time-to-live for positive results (default: 24 hours)
 * @param negativeTTL Time-to-live for negative results (default: 1 hour)
 */
- (instancetype)initWithTTL:(NSTimeInterval)ttl negativeTTL:(NSTimeInterval)negativeTTL;

/**
 * Configure provider with custom API base URL
 * @param baseURL The base URL for the VirusTotal API
 * @param apiKey The VirusTotal API key
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

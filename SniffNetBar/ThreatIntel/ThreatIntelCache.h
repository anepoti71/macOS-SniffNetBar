//
//  ThreatIntelCache.h
//  SniffNetBar
//
//  Simple TTL-based cache for threat intel results
//

#import <Foundation/Foundation.h>
#import "ThreatIntelModels.h"

NS_ASSUME_NONNULL_BEGIN

@interface ThreatIntelCache : NSObject

- (instancetype)initWithMaxSize:(NSInteger)maxSize;

/// Get cached result
- (TIResult * _Nullable)getResultForProvider:(NSString *)provider
                                   indicator:(TIIndicator *)indicator;

/// Store result with TTL
- (void)setResult:(TIResult *)result;

/// Check if result is stale (near expiry)
- (BOOL)isStaleForProvider:(NSString *)provider
                 indicator:(TIIndicator *)indicator
            refreshWindow:(NSTimeInterval)refreshWindow;

/// Invalidate cache
- (void)invalidateProvider:(NSString * _Nullable)provider
                 indicator:(TIIndicator * _Nullable)indicator;

/// Clear all
- (void)clear;

/// Stats
- (NSInteger)size;
- (double)hitRate;
- (NSDictionary *)statsSnapshot;

@end

NS_ASSUME_NONNULL_END

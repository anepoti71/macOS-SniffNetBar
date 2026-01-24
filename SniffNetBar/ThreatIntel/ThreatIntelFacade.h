//
//  ThreatIntelFacade.h
//  SniffNetBar
//
//  Main facade for threat intelligence enrichment
//

#import <Foundation/Foundation.h>
#import "ThreatIntelModels.h"
#import "ThreatIntelProvider.h"

NS_ASSUME_NONNULL_BEGIN

typedef void (^TIEnrichmentCompletion)(TIEnrichmentResponse * _Nullable response, NSError * _Nullable error);

@interface ThreatIntelFacade : NSObject

/// Singleton instance
+ (instancetype)sharedInstance;

/// Enable/disable threat intel
@property (nonatomic, assign, getter=isEnabled) BOOL enabled;

/// Configure with providers
- (void)configureWithProviders:(NSArray<id<ThreatIntelProvider>> *)providers;

/// Add a provider
- (void)addProvider:(id<ThreatIntelProvider>)provider;

/// Enrich a single indicator
- (void)enrichIndicator:(TIIndicator *)indicator
             completion:(TIEnrichmentCompletion)completion;

/// Enrich IP address (convenience)
- (void)enrichIP:(NSString *)ipAddress
      completion:(TIEnrichmentCompletion)completion;

/// Enrich multiple indicators (batch)
- (void)enrichIndicators:(NSArray<TIIndicator *> *)indicators
              completion:(void (^)(NSArray<TIEnrichmentResponse *> *responses))completion;

/// Get cache stats
- (NSDictionary *)cacheStats;

/// Check if any providers are available
- (BOOL)hasAvailableProviders;

/// Availability message when providers are unavailable
- (NSString * _Nullable)availabilityMessage;

/// Clear cache
- (void)clearCache;

/// Shutdown
- (void)shutdown;

@end

NS_ASSUME_NONNULL_END

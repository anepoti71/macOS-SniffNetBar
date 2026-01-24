//
//  ThreatIntelStore.h
//  SniffNetBar
//
//  SQLite persistence for threat intelligence results
//

#import <Foundation/Foundation.h>
#import "ThreatIntelModels.h"

NS_ASSUME_NONNULL_BEGIN

@interface SNBProviderStatus : NSObject
@property (nonatomic, copy) NSString *providerName;
@property (nonatomic, assign) BOOL isDisabled;
@property (nonatomic, strong, nullable) NSDate *disabledUntil;
@property (nonatomic, copy, nullable) NSString *disabledReason;
@property (nonatomic, assign) NSInteger errorCode;
@property (nonatomic, strong, nullable) NSDate *lastUpdated;
@end

@interface ThreatIntelStore : NSObject

+ (instancetype)sharedStore;
+ (instancetype)sharedStoreWithTTLSeconds:(NSTimeInterval)ttlSeconds;

- (instancetype)initWithTTLSeconds:(NSTimeInterval)ttlSeconds;

/// Fetch a persisted response if not expired.
- (TIEnrichmentResponse * _Nullable)responseForIndicator:(TIIndicator *)indicator;

/// Persist a response with TTL starting from now.
- (void)storeResponse:(TIEnrichmentResponse *)response;

/// Remove expired entries.
- (void)purgeExpired;

/// Provider status management
- (void)saveProviderStatus:(SNBProviderStatus *)status;
- (SNBProviderStatus * _Nullable)getProviderStatus:(NSString *)providerName;
- (NSDictionary<NSString *, SNBProviderStatus *> *)getAllProviderStatuses;
- (void)clearProviderStatus:(NSString *)providerName;
- (void)clearExpiredProviderStatuses;

@end

NS_ASSUME_NONNULL_END

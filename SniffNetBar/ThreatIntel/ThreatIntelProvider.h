//
//  ThreatIntelProvider.h
//  SniffNetBar
//
//  Provider interface for threat intelligence sources
//

#import <Foundation/Foundation.h>
#import "ThreatIntelModels.h"

NS_ASSUME_NONNULL_BEGIN

// MARK: - Provider Protocol

@protocol ThreatIntelProvider <NSObject>

@required

/// Provider metadata
@property (nonatomic, copy, readonly) NSString *name;
@property (nonatomic, assign, readonly) NSTimeInterval defaultTTL;
@property (nonatomic, assign, readonly) NSTimeInterval negativeCacheTTL;

/// Configure the provider
- (void)configureWithAPIKey:(NSString * _Nullable)apiKey
                    timeout:(NSTimeInterval)timeout
          maxRequestsPerMin:(NSInteger)maxRequestsPerMin
                 completion:(void (^)(NSError * _Nullable error))completion;

/// Check if provider is healthy
- (void)isHealthyWithCompletion:(void (^)(BOOL healthy))completion;

/// Main enrichment method
- (void)enrichIndicator:(TIIndicator *)indicator
             completion:(void (^)(TIResult * _Nullable result, NSError * _Nullable error))completion;

/// Check if indicator type is supported
- (BOOL)supportsIndicatorType:(TIIndicatorType)type;

@optional

/// Shutdown/cleanup
- (void)shutdown;

@end

// MARK: - Simple In-Memory Provider (for testing/feeds)

@interface TISimpleProvider : NSObject <ThreatIntelProvider>

@property (nonatomic, copy, readonly) NSString *name;
@property (nonatomic, assign, readonly) NSTimeInterval defaultTTL;
@property (nonatomic, assign, readonly) NSTimeInterval negativeCacheTTL;

- (instancetype)initWithName:(NSString *)name;

/// Add known malicious indicators (for feed-based providers)
- (void)addMaliciousIndicator:(NSString *)value
                          type:(TIIndicatorType)type
                    confidence:(NSInteger)confidence
                    categories:(NSArray<NSString *> *)categories;

@end

NS_ASSUME_NONNULL_END

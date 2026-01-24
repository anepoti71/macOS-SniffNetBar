//
//  MockThreatIntelProvider.h
//  SniffNetBar
//
//  Mock threat intelligence provider for testing
//

#import <Foundation/Foundation.h>
#import "ThreatIntelProvider.h"

NS_ASSUME_NONNULL_BEGIN

@interface MockThreatIntelProvider : NSObject <ThreatIntelProvider>

@property (nonatomic, copy, readonly) NSString *name;
@property (nonatomic, assign, readonly) NSTimeInterval defaultTTL;
@property (nonatomic, assign, readonly) NSTimeInterval negativeCacheTTL;

// Test control properties
@property (nonatomic, assign) BOOL shouldFail;
@property (nonatomic, strong, nullable) NSError *errorToReturn;
@property (nonatomic, assign) NSTimeInterval simulatedDelay;
@property (nonatomic, assign) BOOL isHealthy;
@property (nonatomic, assign) NSInteger callCount;

// Configure mock responses
- (instancetype)initWithName:(NSString *)name;
- (void)setMockResult:(TIResult * _Nullable)result forIndicator:(TIIndicator *)indicator;
- (void)setMockScore:(NSInteger)score forIndicatorValue:(NSString *)value;

@end

NS_ASSUME_NONNULL_END

//
//  ThreatIntelCoordinator.h
//  SniffNetBar
//

#import <Foundation/Foundation.h>

@class ConfigurationManager;
@class ThreatIntelFacade;
@class TIEnrichmentResponse;

@interface ThreatIntelCoordinator : NSObject

@property (nonatomic, strong, readonly) ThreatIntelFacade *facade;
@property (nonatomic, assign, readonly, getter=isEnabled) BOOL enabled;

- (instancetype)initWithConfiguration:(ConfigurationManager *)configuration;
- (void)toggleEnabled;
- (void)setEnabled:(BOOL)enabled;
- (void)reloadProviders;
- (NSDictionary<NSString *, TIEnrichmentResponse *> *)resultsSnapshot;
- (NSDictionary *)cacheStats;
- (NSString * _Nullable)availabilityMessage;
- (void)enrichIPIfNeeded:(NSString *)ipAddress completion:(dispatch_block_t)completion;

@end

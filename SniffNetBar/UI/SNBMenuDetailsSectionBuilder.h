//
//  SNBMenuDetailsSectionBuilder.h
//  SniffNetBar
//

#import <Cocoa/Cocoa.h>

@class MenuBuilder;
@class TrafficStats;
@class TIEnrichmentResponse;
@class SNBNetworkAsset;
@class SNBMenuTopHostsSectionBuilder;

NS_ASSUME_NONNULL_BEGIN

@interface SNBMenuDetailsSectionBuilder : NSObject

- (instancetype)initWithTopHostsBuilder:(SNBMenuTopHostsSectionBuilder *)topHostsBuilder;

- (NSMenuItem *)buildDetailsMenuItemWithStats:(TrafficStats *)stats
                          threatIntelEnabled:(BOOL)threatIntelEnabled
                     threatIntelStatusMessage:(nullable NSString *)threatIntelStatusMessage
                           threatIntelResults:(NSDictionary<NSString *, TIEnrichmentResponse *> *)threatIntelResults
                                    cacheStats:(NSDictionary * _Nullable)cacheStats
                          assetMonitorEnabled:(BOOL)assetMonitorEnabled
                               networkAssets:(NSArray<SNBNetworkAsset *> *)networkAssets
                             recentNewAssets:(NSArray<SNBNetworkAsset *> *)recentNewAssets
                                  menuBuilder:(MenuBuilder *)menuBuilder;

- (void)refreshDetailStatsWithStats:(TrafficStats *)stats
                        menuBuilder:(MenuBuilder *)menuBuilder;

- (void)reset;

@end

NS_ASSUME_NONNULL_END

//
//  MenuBuilder.h
//  SniffNetBar
//

#import <Cocoa/Cocoa.h>
#import "MapMenuView.h"

@class ConfigurationManager;
@class NetworkDevice;
@class TrafficStats;
@class TIEnrichmentResponse;
@class SNBNetworkAsset;
@class SNBPromotionDecision;

@protocol MenuBuilderDelegate <NSObject>
- (void)menuBuilderNeedsVisualizationRefresh:(id)sender;
@end

@interface MenuBuilder : NSObject <MapMenuViewDelegate>

// Selected connection from map (for highlighting)
@property (nonatomic, copy) NSString *selectedSourceIP;
@property (nonatomic, copy) NSString *selectedDestinationIP;

@property (nonatomic, weak) id<MenuBuilderDelegate> delegate;

@property (nonatomic, assign) BOOL showTopHosts;
@property (nonatomic, assign) BOOL showTopConnections;
@property (nonatomic, assign) BOOL showMap;
@property (nonatomic, assign) BOOL showProcessActivity;
@property (nonatomic, assign) BOOL dailyStatsEnabled;
@property (nonatomic, assign) BOOL statsReportAvailable;
@property (nonatomic, assign) BOOL debugEnabled;
@property (nonatomic, strong) NSDate *captureStartDate;
@property (nonatomic, copy, readonly) NSString *mapProviderName;
@property (nonatomic, assign, readonly) BOOL menuIsOpen;
@property (nonatomic, assign) BOOL helperOperational;
@property (nonatomic, assign) BOOL modelingXpcOperational;
@property (nonatomic, assign) BOOL promotionAgentEnabled;
@property (nonatomic, assign) BOOL promotionAgentOperational;
@property (nonatomic, assign) BOOL promotionAgentAIAvailable;
@property (nonatomic, strong, nullable) SNBPromotionDecision *promotionAgentLastDecision;
@property (nonatomic, copy) NSArray<SNBPromotionDecision *> *promotionAgentSuggestions;

// Expandable sections state
@property (nonatomic, assign) BOOL showCleanConnections;
@property (nonatomic, assign) BOOL showTrustedIPs;
@property (nonatomic, assign) BOOL showAllAssets;
@property (nonatomic, assign) BOOL showProviderDetails;
@property (nonatomic, assign) BOOL showLowSeverityThreats;
@property (nonatomic, assign) BOOL showHistoricalThreats;

// Main section collapse/expand state
@property (nonatomic, assign) BOOL sectionThreatsExpanded;
@property (nonatomic, assign) BOOL sectionNetworkActivityExpanded;
@property (nonatomic, assign) BOOL sectionNetworkDevicesExpanded;
@property (nonatomic, assign) BOOL sectionTopHostsExpanded;
@property (nonatomic, assign) BOOL sectionTopConnectionsExpanded;
@property (nonatomic, assign) BOOL sectionNetworkAssetsExpanded;
@property (nonatomic, assign) BOOL sectionProcessActivityExpanded;

- (instancetype)initWithMenu:(NSMenu *)menu
                  statusItem:(NSStatusItem *)statusItem
               configuration:(ConfigurationManager *)configuration;
- (void)updateStatusWithStats:(TrafficStats *)stats selectedDevice:(NetworkDevice *)selectedDevice;
- (void)updateMenuWithStats:(TrafficStats *)stats
                    devices:(NSArray<NetworkDevice *> *)devices
             selectedDevice:(NetworkDevice *)selectedDevice
         threatIntelEnabled:(BOOL)threatIntelEnabled
     threatIntelStatusMessage:(NSString * _Nullable)threatIntelStatusMessage
        threatIntelResults:(NSDictionary<NSString *, TIEnrichmentResponse *> *)threatIntelResults
                 cacheStats:(NSDictionary *)cacheStats
          openAtLoginEnabled:(BOOL)openAtLoginEnabled
        assetMonitorEnabled:(BOOL)assetMonitorEnabled
             networkAssets:(NSArray<SNBNetworkAsset *> *)networkAssets
           recentNewAssets:(NSArray<SNBNetworkAsset *> *)recentNewAssets
                     target:(id)target;
- (void)refreshVisualizationWithStats:(TrafficStats *)stats
                  threatIntelEnabled:(BOOL)threatIntelEnabled
              threatIntelStatusMessage:(NSString * _Nullable)threatIntelStatusMessage
                 threatIntelResults:(NSDictionary<NSString *, TIEnrichmentResponse *> *)threatIntelResults
                          cacheStats:(NSDictionary *)cacheStats
                assetMonitorEnabled:(BOOL)assetMonitorEnabled
                     networkAssets:(NSArray<SNBNetworkAsset *> *)networkAssets
                   recentNewAssets:(NSArray<SNBNetworkAsset *> *)recentNewAssets;
- (void)menuWillOpenWithStats:(TrafficStats *)stats;
- (void)menuDidClose;
- (void)selectMapProviderWithName:(NSString *)providerName stats:(TrafficStats *)stats;

// Expandable section toggles
- (void)toggleShowCleanConnections;
- (void)toggleShowAllAssets;
- (void)toggleShowProviderDetails;
- (void)toggleShowLowSeverityThreats;
- (void)toggleShowHistoricalThreats;

// Main section toggles
- (void)toggleSectionThreats;
- (void)toggleSectionNetworkActivity;
- (void)toggleSectionNetworkDevices;
- (void)toggleSectionTopHosts;
- (void)toggleSectionTopConnections;
- (void)toggleSectionNetworkAssets;
- (void)toggleSectionProcessActivity;

@end

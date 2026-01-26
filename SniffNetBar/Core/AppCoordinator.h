//
//  AppCoordinator.h
//  SniffNetBar
//
//  Main coordinator for orchestrating application subsystems
//

#import <Cocoa/Cocoa.h>

@class ConfigurationManager;
@class DeviceManager;
@class MenuBuilder;
@class PacketCaptureManager;
@class ThreatIntelCoordinator;
@class TrafficStatistics;
@class NetworkDevice;
@class SNBStatusBarManager;

@interface AppCoordinator : NSObject

@property (nonatomic, strong, readonly) TrafficStatistics *statistics;
@property (nonatomic, strong, readonly) DeviceManager *deviceManager;
@property (nonatomic, strong, readonly) MenuBuilder *menuBuilder;
@property (nonatomic, strong, readonly) ThreatIntelCoordinator *threatIntelCoordinator;
@property (nonatomic, strong, readonly) ConfigurationManager *configuration;

- (instancetype)initWithStatusBarManager:(SNBStatusBarManager *)statusBarManager
                              statusMenu:(NSMenu *)statusMenu;
- (void)start;
- (void)stop;
- (void)updateMenu;
- (void)updateMenuIfNeeded;

// User actions
- (void)selectDevice:(NetworkDevice *)device;
- (void)toggleShowTopHosts:(NSMenuItem *)sender;
- (void)toggleShowTopConnections:(NSMenuItem *)sender;
- (void)toggleShowMap:(NSMenuItem *)sender;
- (void)toggleShowProcessActivity:(NSMenuItem *)sender;
- (void)toggleDebugMode:(NSMenuItem *)sender;
- (void)toggleThreatIntelProvider:(NSMenuItem *)sender;
- (void)selectMapProvider:(NSMenuItem *)sender;
- (void)toggleThreatIntel:(NSMenuItem *)sender;
- (void)togglePromotionAgent:(NSMenuItem *)sender;
- (void)toggleDailyStatistics:(NSMenuItem *)sender;
- (void)toggleOpenAtLogin:(NSMenuItem *)sender;
- (void)openStatisticsReport:(NSMenuItem *)sender;
- (void)deviceSelected:(NSMenuItem *)sender;

// Menu delegate methods
- (void)menuWillOpenWithStats;
- (void)menuDidClose;

@end

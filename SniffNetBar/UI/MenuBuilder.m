//
//  MenuBuilder.m
//  SniffNetBar
//

#import "MenuBuilder.h"
#import "MenuBuilder+ThreatDisplay.h"
#import "ByteFormatter.h"
#import "ConfigurationManager.h"
#import "MapMenuView.h"
#import "TrafficGraphView.h"
#import "NetworkDevice.h"
#import "ThreatIntelModels.h"
#import "TrafficStatistics.h"
#import "UserDefaultsKeys.h"
#import "NetworkAssetMonitor.h"
#import "IPAddressUtilities.h"
#import <ifaddrs.h>
#import <arpa/inet.h>
#import "Logger.h"
#import "SNBBadgeRegistry.h"
#import "TrustedIPStore.h"
#import "TrustLearningEngine.h"
#import "TrustFeatureExtractor.h"
#import "TrustLearningModels.h"
#import "ProcessRiskEvaluator.h"
#import "ProcessRiskModels.h"
#import "PromotionAgent/SNBPromotionDecision.h"

static const CGFloat kMenuDotFontSize = 9.0;
static const CGFloat kStatusAlertDotFontSize = 7.0;
static const NSUInteger kNetworkActivityGraphSampleCount = 30;
static const NSUInteger kPromotionSuggestionDisplayLimit = 5;

static NSString *SNBStoredDeviceName(void) {
    NSString *storedName = [[NSUserDefaults standardUserDefaults] stringForKey:SNBUserDefaultsKeySelectedNetworkDevice];
    if (storedName.length > 0) {
        return storedName;
    }

    NSArray<NSString *> *paths = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory,
                                                                      NSUserDomainMask,
                                                                      YES);
    if (paths.count == 0) {
        return nil;
    }
    NSString *directory = [paths.firstObject stringByAppendingPathComponent:@"SniffNetBar"];
    NSString *path = [directory stringByAppendingPathComponent:@"SelectedNetworkDevice.plist"];
    NSDictionary<NSString *, id> *stored = [NSDictionary dictionaryWithContentsOfFile:path];
    NSString *fileName = stored[@"name"];
    if (fileName.length > 0) {
        [[NSUserDefaults standardUserDefaults] setObject:fileName forKey:SNBUserDefaultsKeySelectedNetworkDevice];
        return fileName;
    }
    return nil;
}

@interface MenuBuilder ()
@property (nonatomic, strong) NSMenu *statusMenu;
@property (nonatomic, strong) NSStatusItem *statusItem;
@property (nonatomic, strong) ConfigurationManager *configuration;
@property (nonatomic, strong) MapMenuView *mapMenuView;
@property (nonatomic, strong) NSMenuItem *mapMenuItem;
@property (nonatomic, weak) NSMenu *visualizationSubmenu;
@property (nonatomic, copy, readwrite) NSString *mapProviderName;
@property (nonatomic, assign, readwrite) BOOL menuIsOpen;
@property (nonatomic, assign) uint64_t lastTotalBytes;
@property (nonatomic, assign) uint64_t lastBytesPerSecond;
@property (nonatomic, assign) NSUInteger lastTopHostsCount;
@property (nonatomic, assign) NSUInteger lastTopConnectionsCount;
@property (nonatomic, assign) NSUInteger lastGeolocatedConnectionCount;
@property (nonatomic, strong) NSMutableDictionary<NSString *, NSDictionary<NSString *, id> *> *dynamicStatItemInfo;
@property (nonatomic, assign) BOOL needsFullVisualizationRefresh;

// Performance: Cache menu items to avoid recreation
@property (nonatomic, strong) NSMutableDictionary<NSString *, NSMenuItem *> *cachedMenuItems;
@property (nonatomic, assign) BOOL menuStructureBuilt;
@property (nonatomic, assign) NSUInteger lastDeviceCount;
@property (nonatomic, assign) BOOL lastThreatIntelEnabled;
@property (nonatomic, assign) BOOL lastAssetMonitorEnabled;
@property (nonatomic, copy) NSString *selectedDeviceDisplayName;

// Details submenu helpers
@property (nonatomic, strong) NSMenu *detailsSubmenu;
@property (nonatomic, strong) NSMenuItem *topHostsSectionHeader;
@property (nonatomic, strong) NSMenuItem *topHostsSectionSeparator;
@property (nonatomic, strong) NSMenuItem *topConnectionsSectionHeader;
@property (nonatomic, strong) NSMenuItem *topConnectionsSectionSeparator;
@property (nonatomic, strong) NSMenuItem *maliciousConnectionsHeader;
@property (nonatomic, strong) NSMenuItem *maliciousConnectionsSeparator;
@property (nonatomic, strong) NSMenuItem *cleanConnectionsHeader;
@property (nonatomic, strong) NSMenuItem *cleanConnectionsSeparator;
@property (nonatomic, strong) NSMutableDictionary<NSString *, NSDictionary<NSString *, id> *> *detailStatItemInfo;
@property (nonatomic, strong) NSMutableDictionary<NSString *, NSColor *> *hostColorMap;
@property (nonatomic, strong) NSMenuItem *processActivityHeader;
@property (nonatomic, strong) NSMenuItem *processActivitySeparator;
@property (nonatomic, strong) NSMutableArray<NSMenuItem *> *processActivityItems;
@property (nonatomic, strong) NSDateFormatter *captureDateFormatter;

// Threat alert tracking for status bar
@property (nonatomic, assign) NSUInteger activeMaliciousCount;
@property (nonatomic, assign) NSUInteger activeSuspiciousCount;

// Performance: Status bar caching to skip redundant updates
@property (nonatomic, assign) uint64_t lastStatusIncomingBytes;
@property (nonatomic, assign) uint64_t lastStatusOutgoingBytes;
@property (nonatomic, copy) NSString *lastStatusDeviceName;
@property (nonatomic, assign) NSUInteger lastStatusMaliciousCount;
@property (nonatomic, assign) NSUInteger lastStatusSuspiciousCount;
@property (nonatomic, strong) ThreatInfo *selectedThreatInfo;
@property (nonatomic, strong) ConnectionTraffic *selectedThreatConnection;
@property (nonatomic, strong) SNBTrustedIPStore *trustedStore;
@property (nonatomic, strong) NSMutableSet<NSString *> *blockedIPs;

// Section tracking for in-place updates
@property (nonatomic, strong) NSMenuItem *networkActivitySectionHeader;
@property (nonatomic, strong) NSMenuItem *networkActivitySectionSeparator;
@property (nonatomic, strong) NSMutableArray<NSMenuItem *> *networkActivitySectionItems;
@property (nonatomic, strong) NSMenuItem *networkActivityGraphItem;
@property (nonatomic, strong) SNBTrafficGraphView *networkActivityGraphView;
@property (nonatomic, strong) NSMutableArray<NSNumber *> *incomingRateHistory;
@property (nonatomic, strong) NSMutableArray<NSNumber *> *outgoingRateHistory;
@property (nonatomic, assign) uint64_t lastIncomingBytesSample;
@property (nonatomic, assign) uint64_t lastOutgoingBytesSample;
@property (nonatomic, assign) CFAbsoluteTime lastRateSampleTime;
@property (nonatomic, strong) NSMenuItem *networkDevicesSectionHeader;
@property (nonatomic, strong) NSMenuItem *networkDevicesSectionSeparator;
@property (nonatomic, strong) NSMutableArray<NSMenuItem *> *networkDevicesSectionItems;

// Last stats for highlighting updates
@property (nonatomic, strong) TrafficStats *lastTrafficStats;
@property (nonatomic, copy) NSDictionary<NSString *, TIEnrichmentResponse *> *lastThreatIntelResults;
@property (nonatomic, assign) CFAbsoluteTime lastStatsTimestampForMapConnections;
@property (nonatomic, assign) CFAbsoluteTime lastStatsTimestampForHighlights;
@property (nonatomic, copy) NSArray<ConnectionTraffic *> *cachedMapConnections;

// Fix 3: Track when selection-triggered refresh occurred to avoid redundant refreshes
@property (nonatomic, assign) NSTimeInterval lastSelectionRefreshTime;

// Helper method for provider summary (used by category)
- (NSString *)providerSummaryForResponse:(TIEnrichmentResponse *)response;
@end

@implementation MenuBuilder

// Performance: Increase refresh interval to reduce menu rebuilds
static const CFAbsoluteTime kLocalIPCacheTTLSeconds = 60.0;

static NSString * const SNBMenuItemKeyNetworkRate = @"networkRate";
static NSString * const SNBMenuItemKeyNetworkTotal = @"networkTotal";
static NSString * const SNBMenuItemKeyActiveConnections = @"activeConnections";
static NSString * const SNBMenuItemKeyHosts = @"hosts";
static NSString * const SNBMenuItemKeyNetworkDevicesTotal = @"networkDevicesTotal";
static NSString * const SNBMenuItemKeyDetailIncoming = @"detailIncoming";
static NSString * const SNBMenuItemKeyDetailOutgoing = @"detailOutgoing";
static NSString * const SNBMenuItemKeyDetailTotal = @"detailTotal";
static NSString * const SNBMenuItemKeyDetailPackets = @"detailPackets";
static NSString * const SNBMenuItemKeyCaptureStart = @"detailCaptureStart";

static NSSet<NSString *> *SNBLocalIPAddresses(void) {
    static NSSet<NSString *> *cached = nil;
    static CFAbsoluteTime lastFetch = 0;
    CFAbsoluteTime now = CFAbsoluteTimeGetCurrent();
    if (cached && (now - lastFetch) < kLocalIPCacheTTLSeconds) {
        return cached;
    }

    NSMutableSet<NSString *> *addresses = [NSMutableSet set];
    struct ifaddrs *interfaces = NULL;
    if (getifaddrs(&interfaces) == 0) {
        for (struct ifaddrs *ifa = interfaces; ifa != NULL; ifa = ifa->ifa_next) {
            if (!ifa->ifa_addr) continue;
            int family = ifa->ifa_addr->sa_family;
            if (family == AF_INET) {
                char addr[INET_ADDRSTRLEN];
                struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
                if (inet_ntop(AF_INET, &sin->sin_addr, addr, sizeof(addr))) {
                    [addresses addObject:[NSString stringWithUTF8String:addr]];
                }
            } else if (family == AF_INET6) {
                char addr[INET6_ADDRSTRLEN];
                struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
                if (inet_ntop(AF_INET6, &sin6->sin6_addr, addr, sizeof(addr))) {
                    [addresses addObject:[NSString stringWithUTF8String:addr]];
                }
            }
        }
        freeifaddrs(interfaces);
    }

    [addresses addObject:@"127.0.0.1"];
    [addresses addObject:@"::1"];

    cached = [addresses copy];
    lastFetch = now;
    return cached;
}

- (instancetype)initWithMenu:(NSMenu *)menu
                  statusItem:(NSStatusItem *)statusItem
               configuration:(ConfigurationManager *)configuration {
    self = [super init];
    if (self) {
        _statusMenu = menu;
        _statusItem = statusItem;
        _configuration = configuration;
        _statsReportAvailable = NO;
        _cachedMenuItems = [NSMutableDictionary dictionary];
        _dynamicStatItemInfo = [NSMutableDictionary dictionary];
        _detailStatItemInfo = [NSMutableDictionary dictionary];
        _hostColorMap = [NSMutableDictionary dictionary];
        _needsFullVisualizationRefresh = NO;
        _menuStructureBuilt = NO;
        _incomingRateHistory = [NSMutableArray arrayWithCapacity:kNetworkActivityGraphSampleCount];
        _outgoingRateHistory = [NSMutableArray arrayWithCapacity:kNetworkActivityGraphSampleCount];

        // Expandable sections - collapsed by default for cleaner UI
        _showCleanConnections = NO;
        _showTrustedIPs = NO;
        _showAllAssets = NO;
        _showProviderDetails = NO;
        _trustedStore = [SNBTrustedIPStore sharedStore];
        _blockedIPs = [NSMutableSet set];

        // Load persisted settings from NSUserDefaults
        NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];

        // Load visualization settings (default: YES for top hosts/connections, NO for map)
        if ([defaults objectForKey:SNBUserDefaultsKeyShowTopHosts]) {
            _showTopHosts = [defaults boolForKey:SNBUserDefaultsKeyShowTopHosts];
        } else {
            _showTopHosts = YES;
        }

        if ([defaults objectForKey:SNBUserDefaultsKeyShowTopConnections]) {
            _showTopConnections = [defaults boolForKey:SNBUserDefaultsKeyShowTopConnections];
        } else {
            _showTopConnections = YES;
        }

        if ([defaults objectForKey:SNBUserDefaultsKeyShowMap]) {
            _showMap = [defaults boolForKey:SNBUserDefaultsKeyShowMap];
        } else {
            _showMap = NO;
        }

        if ([defaults objectForKey:SNBUserDefaultsKeyShowProcessActivity]) {
            _showProcessActivity = [defaults boolForKey:SNBUserDefaultsKeyShowProcessActivity];
        } else {
            _showProcessActivity = YES;
        }

        if ([defaults objectForKey:SNBUserDefaultsKeyDailyStatisticsEnabled]) {
            _dailyStatsEnabled = [defaults boolForKey:SNBUserDefaultsKeyDailyStatisticsEnabled];
        } else {
            _dailyStatsEnabled = YES;
        }

        if ([defaults objectForKey:SNBUserDefaultsKeyDebugEnabled]) {
            _debugEnabled = [defaults boolForKey:SNBUserDefaultsKeyDebugEnabled];
        } else {
            _debugEnabled = NO;
        }

        NSString *savedProvider = [defaults stringForKey:SNBUserDefaultsKeyMapProvider];
        _mapProviderName = savedProvider.length > 0 ? savedProvider : configuration.defaultMapProvider;
        _captureDateFormatter = [[NSDateFormatter alloc] init];
        _captureDateFormatter.dateStyle = NSDateFormatterShortStyle;
        _captureDateFormatter.timeStyle = NSDateFormatterShortStyle;
        _captureDateFormatter.doesRelativeDateFormatting = YES;

        // Load section expansion states (default: all expanded)
        if ([defaults objectForKey:SNBUserDefaultsKeySectionThreatsExpanded]) {
            _sectionThreatsExpanded = [defaults boolForKey:SNBUserDefaultsKeySectionThreatsExpanded];
        } else {
            _sectionThreatsExpanded = YES;
        }

        if ([defaults objectForKey:SNBUserDefaultsKeySectionNetworkActivityExpanded]) {
            _sectionNetworkActivityExpanded = [defaults boolForKey:SNBUserDefaultsKeySectionNetworkActivityExpanded];
        } else {
            _sectionNetworkActivityExpanded = YES;
        }

        if ([defaults objectForKey:SNBUserDefaultsKeySectionNetworkDevicesExpanded]) {
            _sectionNetworkDevicesExpanded = [defaults boolForKey:SNBUserDefaultsKeySectionNetworkDevicesExpanded];
        } else {
            _sectionNetworkDevicesExpanded = YES;
        }

        if ([defaults objectForKey:SNBUserDefaultsKeySectionTopHostsExpanded]) {
            _sectionTopHostsExpanded = [defaults boolForKey:SNBUserDefaultsKeySectionTopHostsExpanded];
        } else {
            _sectionTopHostsExpanded = YES;
        }

        if ([defaults objectForKey:SNBUserDefaultsKeySectionTopConnectionsExpanded]) {
            _sectionTopConnectionsExpanded = [defaults boolForKey:SNBUserDefaultsKeySectionTopConnectionsExpanded];
        } else {
            _sectionTopConnectionsExpanded = YES;
        }

    if ([defaults objectForKey:SNBUserDefaultsKeySectionNetworkAssetsExpanded]) {
        _sectionNetworkAssetsExpanded = [defaults boolForKey:SNBUserDefaultsKeySectionNetworkAssetsExpanded];
    } else {
        _sectionNetworkAssetsExpanded = YES;
    }

    if ([defaults objectForKey:SNBUserDefaultsKeySectionProcessActivityExpanded]) {
        _sectionProcessActivityExpanded = [defaults boolForKey:SNBUserDefaultsKeySectionProcessActivityExpanded];
    } else {
        _sectionProcessActivityExpanded = YES;
    }
}
    return self;
}

#pragma mark - Property Setters with Persistence

- (void)setShowTopHosts:(BOOL)showTopHosts {
    if (_showTopHosts != showTopHosts) {
        _showTopHosts = showTopHosts;
        [[NSUserDefaults standardUserDefaults] setBool:showTopHosts forKey:SNBUserDefaultsKeyShowTopHosts];
    }
}

- (void)setShowTopConnections:(BOOL)showTopConnections {
    if (_showTopConnections != showTopConnections) {
        _showTopConnections = showTopConnections;
        [[NSUserDefaults standardUserDefaults] setBool:showTopConnections forKey:SNBUserDefaultsKeyShowTopConnections];
    }
}

- (void)setShowMap:(BOOL)showMap {
    if (_showMap != showMap) {
        _showMap = showMap;
        [[NSUserDefaults standardUserDefaults] setBool:showMap forKey:SNBUserDefaultsKeyShowMap];
    }
}

- (void)setShowProcessActivity:(BOOL)showProcessActivity {
    if (_showProcessActivity != showProcessActivity) {
        _showProcessActivity = showProcessActivity;
        [[NSUserDefaults standardUserDefaults] setBool:showProcessActivity forKey:SNBUserDefaultsKeyShowProcessActivity];
    }
}

- (void)setDebugEnabled:(BOOL)debugEnabled {
    if (_debugEnabled != debugEnabled) {
        _debugEnabled = debugEnabled;
        [[NSUserDefaults standardUserDefaults] setBool:debugEnabled forKey:SNBUserDefaultsKeyDebugEnabled];
    }
}

- (void)setDailyStatsEnabled:(BOOL)dailyStatsEnabled {
    if (_dailyStatsEnabled != dailyStatsEnabled) {
        _dailyStatsEnabled = dailyStatsEnabled;
        [[NSUserDefaults standardUserDefaults] setBool:dailyStatsEnabled forKey:SNBUserDefaultsKeyDailyStatisticsEnabled];
    }
}

- (void)setSectionThreatsExpanded:(BOOL)sectionThreatsExpanded {
    if (_sectionThreatsExpanded != sectionThreatsExpanded) {
        _sectionThreatsExpanded = sectionThreatsExpanded;
        [[NSUserDefaults standardUserDefaults] setBool:sectionThreatsExpanded forKey:SNBUserDefaultsKeySectionThreatsExpanded];
    }
}

- (void)setSectionNetworkActivityExpanded:(BOOL)sectionNetworkActivityExpanded {
    if (_sectionNetworkActivityExpanded != sectionNetworkActivityExpanded) {
        _sectionNetworkActivityExpanded = sectionNetworkActivityExpanded;
        [[NSUserDefaults standardUserDefaults] setBool:sectionNetworkActivityExpanded forKey:SNBUserDefaultsKeySectionNetworkActivityExpanded];
    }
}

- (void)setSectionNetworkDevicesExpanded:(BOOL)sectionNetworkDevicesExpanded {
    if (_sectionNetworkDevicesExpanded != sectionNetworkDevicesExpanded) {
        _sectionNetworkDevicesExpanded = sectionNetworkDevicesExpanded;
        [[NSUserDefaults standardUserDefaults] setBool:sectionNetworkDevicesExpanded forKey:SNBUserDefaultsKeySectionNetworkDevicesExpanded];
    }
}

- (void)setSectionTopHostsExpanded:(BOOL)sectionTopHostsExpanded {
    if (_sectionTopHostsExpanded != sectionTopHostsExpanded) {
        _sectionTopHostsExpanded = sectionTopHostsExpanded;
        [[NSUserDefaults standardUserDefaults] setBool:sectionTopHostsExpanded forKey:SNBUserDefaultsKeySectionTopHostsExpanded];
    }
}

- (void)setSectionTopConnectionsExpanded:(BOOL)sectionTopConnectionsExpanded {
    if (_sectionTopConnectionsExpanded != sectionTopConnectionsExpanded) {
        _sectionTopConnectionsExpanded = sectionTopConnectionsExpanded;
        [[NSUserDefaults standardUserDefaults] setBool:sectionTopConnectionsExpanded forKey:SNBUserDefaultsKeySectionTopConnectionsExpanded];
    }
}

- (void)setSectionNetworkAssetsExpanded:(BOOL)sectionNetworkAssetsExpanded {
    if (_sectionNetworkAssetsExpanded != sectionNetworkAssetsExpanded) {
        _sectionNetworkAssetsExpanded = sectionNetworkAssetsExpanded;
        [[NSUserDefaults standardUserDefaults] setBool:sectionNetworkAssetsExpanded forKey:SNBUserDefaultsKeySectionNetworkAssetsExpanded];
    }
}

- (void)setSectionProcessActivityExpanded:(BOOL)sectionProcessActivityExpanded {
    if (_sectionProcessActivityExpanded != sectionProcessActivityExpanded) {
        _sectionProcessActivityExpanded = sectionProcessActivityExpanded;
        [[NSUserDefaults standardUserDefaults] setBool:sectionProcessActivityExpanded forKey:SNBUserDefaultsKeySectionProcessActivityExpanded];
    }
}

#pragma mark - Helper Methods

- (NSString *)truncatedMenuTitle:(NSString *)title maxWidth:(CGFloat)maxWidth {
    if (title.length == 0 || maxWidth <= 0) {
        return title;
    }
    NSFont *font = [NSFont menuFontOfSize:0.0];
    NSDictionary *attributes = @{ NSFontAttributeName: font };
    CGFloat availableWidth = maxWidth - 60.0;
    if (availableWidth <= 0) {
        return title;
    }
    if ([title sizeWithAttributes:attributes].width <= availableWidth) {
        return title;
    }
    NSString *ellipsis = @"...";
    CGFloat ellipsisWidth = [ellipsis sizeWithAttributes:attributes].width;
    if (ellipsisWidth >= availableWidth) {
        return ellipsis;
    }
    NSUInteger low = 0;
    NSUInteger high = title.length;
    while (low < high) {
        NSUInteger mid = (low + high + 1) / 2;
        NSString *candidate = [[title substringToIndex:mid] stringByAppendingString:ellipsis];
        if ([candidate sizeWithAttributes:attributes].width <= availableWidth) {
            low = mid;
        } else {
            high = mid - 1;
        }
    }
    if (low == 0) {
        return ellipsis;
    }
    NSString *prefix = [title substringToIndex:low];
    return [prefix stringByAppendingString:ellipsis];
}

- (void)truncateMenuItemsInMenu:(NSMenu *)menu maxWidth:(CGFloat)maxWidth {
    if (maxWidth <= 0 || !menu) {
        return;
    }
    for (NSMenuItem *item in menu.itemArray) {
        if (item.isSeparatorItem) {
            continue;
        }
        if (item.submenu) {
            [self truncateMenuItemsInMenu:item.submenu maxWidth:maxWidth];
        }
        if (item.view || item.title.length == 0) {
            continue;
        }
        item.title = [self truncatedMenuTitle:item.title maxWidth:maxWidth];
    }
}

- (NSMenuItem *)fixedWidthTitleItemWithTitle:(NSString *)title width:(CGFloat)width {
    if (width <= 0) {
        NSMenuItem *item = [[NSMenuItem alloc] initWithTitle:title ?: @"" action:nil keyEquivalent:@""];
        item.enabled = NO;
        return item;
    }

    NSFont *font = [NSFont menuFontOfSize:0.0];
    NSTextField *label = [NSTextField labelWithString:title ?: @""];
    label.font = font;
    label.alignment = NSTextAlignmentLeft;
    label.lineBreakMode = NSLineBreakByTruncatingTail;
    [label sizeToFit];

    CGFloat paddingX = 12.0;
    CGFloat paddingY = 3.0;
    CGFloat viewHeight = label.frame.size.height + paddingY * 2.0;
    NSView *container = [[NSView alloc] initWithFrame:NSMakeRect(0, 0, width, viewHeight)];

    CGFloat labelWidth = MAX(0.0, width - paddingX * 2.0);
    label.frame = NSMakeRect(paddingX, paddingY, labelWidth, label.frame.size.height);
    [container addSubview:label];

    NSMenuItem *item = [[NSMenuItem alloc] initWithTitle:@"" action:nil keyEquivalent:@""];
    item.view = container;
    item.enabled = NO;
    return item;
}

- (void)appendRateSample:(double)rate toArray:(NSMutableArray<NSNumber *> *)array {
    [array addObject:@(rate)];
    if (array.count > kNetworkActivityGraphSampleCount) {
        [array removeObjectAtIndex:0];
    }
}

- (void)updateNetworkActivityRateHistoryWithStats:(TrafficStats *)stats {
    if (!stats) {
        return;
    }

    CFAbsoluteTime now = CFAbsoluteTimeGetCurrent();
    if (self.lastRateSampleTime == 0) {
        self.lastRateSampleTime = now;
        self.lastIncomingBytesSample = stats.incomingBytes;
        self.lastOutgoingBytesSample = stats.outgoingBytes;
        return;
    }

    CFAbsoluteTime delta = now - self.lastRateSampleTime;
    if (delta < 0.2) {
        return;
    }

    uint64_t incoming = stats.incomingBytes;
    uint64_t outgoing = stats.outgoingBytes;
    uint64_t incomingDelta = incoming >= self.lastIncomingBytesSample ? (incoming - self.lastIncomingBytesSample) : 0;
    uint64_t outgoingDelta = outgoing >= self.lastOutgoingBytesSample ? (outgoing - self.lastOutgoingBytesSample) : 0;

    double incomingRate = delta > 0 ? (double)incomingDelta / delta : 0.0;
    double outgoingRate = delta > 0 ? (double)outgoingDelta / delta : 0.0;

    [self appendRateSample:incomingRate toArray:self.incomingRateHistory];
    [self appendRateSample:outgoingRate toArray:self.outgoingRateHistory];

    self.lastRateSampleTime = now;
    self.lastIncomingBytesSample = incoming;
    self.lastOutgoingBytesSample = outgoing;
}

- (void)updateModelCachesWithStats:(TrafficStats *)stats
                threatIntelResults:(NSDictionary<NSString *, TIEnrichmentResponse *> *)threatIntelResults {
    if (!stats) {
        return;
    }
    self.lastTrafficStats = stats;
    self.lastThreatIntelResults = threatIntelResults ?: @{};
    [self updateNetworkActivityRateHistoryWithStats:stats];

    if (stats.timestamp != self.lastStatsTimestampForHighlights) {
        [self updateProcessHighlightColorsWithSummaries:stats.processSummaries ?: @[]];
        self.lastStatsTimestampForHighlights = stats.timestamp;
    }
    if (stats.timestamp != self.lastStatsTimestampForMapConnections || !self.cachedMapConnections) {
        self.cachedMapConnections = [self connectionsForMapFromStats:stats];
        self.lastStatsTimestampForMapConnections = stats.timestamp;
    }
}

- (NSArray<ConnectionTraffic *> *)cachedMapConnectionsForStats:(TrafficStats *)stats {
    if (!stats) {
        return @[];
    }
    if (stats.timestamp != self.lastStatsTimestampForMapConnections || !self.cachedMapConnections) {
        self.cachedMapConnections = [self connectionsForMapFromStats:stats];
        self.lastStatsTimestampForMapConnections = stats.timestamp;
    }
    return self.cachedMapConnections ?: @[];
}

- (NSMenuItem *)networkActivityGraphMenuItemWithWidth:(CGFloat)width {
    if (!self.networkActivityGraphItem) {
        CGFloat paddingX = 12.0;
        CGFloat paddingY = 6.0;
        CGFloat viewHeight = 58.0;
        CGFloat graphWidth = MIN(300.0, MAX(140.0, width - 110.0));

        NSView *container = [[NSView alloc] initWithFrame:NSMakeRect(0, 0, width, viewHeight)];
        NSTextField *label = [NSTextField labelWithString:@"Traffic"];
        label.font = [NSFont systemFontOfSize:12.0];
        label.textColor = [NSColor secondaryLabelColor];
        label.alignment = NSTextAlignmentLeft;
        [label sizeToFit];

        CGFloat labelWidth = MIN(label.frame.size.width, width - graphWidth - paddingX * 2.0);
        CGFloat labelY = paddingY + (viewHeight - paddingY * 2.0 - label.frame.size.height) * 0.5;
        label.frame = NSMakeRect(paddingX, labelY, labelWidth, label.frame.size.height);
        [container addSubview:label];

        CGFloat graphX = paddingX + labelWidth + 12.0;
        CGFloat graphHeight = viewHeight - paddingY * 2.0;
        self.networkActivityGraphView = [[SNBTrafficGraphView alloc] initWithFrame:NSMakeRect(graphX, paddingY, graphWidth, graphHeight)];
        [container addSubview:self.networkActivityGraphView];

        self.networkActivityGraphItem = [[NSMenuItem alloc] initWithTitle:@"" action:nil keyEquivalent:@""];
        self.networkActivityGraphItem.view = container;
        self.networkActivityGraphItem.enabled = NO;
    }

    [self.networkActivityGraphView updateWithIncomingRates:self.incomingRateHistory
                                            outgoingRates:self.outgoingRateHistory];
    return self.networkActivityGraphItem;
}

- (NSArray<ConnectionTraffic *> *)connectionsForMapFromStats:(TrafficStats *)stats {
    NSArray<ConnectionTraffic *> *allConnections = stats.topConnections ?: @[];
    if (allConnections.count == 0) {
        return @[];
    }

    // Deduplicate connections by destination IP and filter to public IPs only
    // Map visualization only shows connections to public (geolocatable) IPs
    // This count matches what's actually displayed on the map
    NSMutableDictionary<NSString *, ConnectionTraffic *> *uniquePublicDestinations = [NSMutableDictionary dictionary];
    for (ConnectionTraffic *conn in allConnections) {
        NSString *destIP = conn.destinationAddress;
        if (destIP.length > 0 && [IPAddressUtilities isPublicIPAddress:destIP]) {
            if (!uniquePublicDestinations[destIP]) {
                uniquePublicDestinations[destIP] = conn;
            }
        }
    }

    // Return deduplicated public connections (matching map display)
    return [uniquePublicDestinations allValues];
}

#pragma mark - Threat Sorting Helpers

- (NSInteger)severityRankForVerdict:(TIThreatVerdict)verdict {
    switch (verdict) {
        case TIThreatVerdictMalicious:
            return 3;
        case TIThreatVerdictSuspicious:
            return 2;
        case TIThreatVerdictUnknown:
            return 1;
        case TIThreatVerdictClean:
            return 0;
    }
}

- (NSArray<NSString *> *)sortedThreatIPsFromResults:(NSDictionary<NSString *, TIEnrichmentResponse *> *)results {
    NSArray<NSString *> *ips = [results allKeys];
    return [ips sortedArrayUsingComparator:^NSComparisonResult(NSString *ip1, NSString *ip2) {
        TIScoringResult *score1 = results[ip1].scoringResult;
        TIScoringResult *score2 = results[ip2].scoringResult;
        NSInteger rank1 = score1 ? [self severityRankForVerdict:score1.verdict] : -1;
        NSInteger rank2 = score2 ? [self severityRankForVerdict:score2.verdict] : -1;
        if (rank1 != rank2) {
            return rank1 > rank2 ? NSOrderedAscending : NSOrderedDescending;
        }
        NSInteger scoreValue1 = score1 ? score1.finalScore : 0;
        NSInteger scoreValue2 = score2 ? score2.finalScore : 0;
        if (scoreValue1 != scoreValue2) {
            return scoreValue1 > scoreValue2 ? NSOrderedAscending : NSOrderedDescending;
        }
        return [ip1 compare:ip2];
    }];
}

- (NSArray<NSDictionary *> *)maliciousConnectionsFromStats:(TrafficStats *)stats
                                      threatIntelResults:(NSDictionary<NSString *, TIEnrichmentResponse *> *)threatIntelResults {
    if (!stats || threatIntelResults.count == 0) {
        return @[];
    }
    NSMutableArray<NSDictionary *> *malicious = [NSMutableArray array];
    for (ConnectionTraffic *connection in stats.topConnections) {
        TIEnrichmentResponse *srcResponse = threatIntelResults[connection.sourceAddress];
        TIEnrichmentResponse *dstResponse = threatIntelResults[connection.destinationAddress];
        TIScoringResult *srcScore = srcResponse.scoringResult;
        TIScoringResult *dstScore = dstResponse.scoringResult;

        TIEnrichmentResponse *bestResponse = nil;
        NSString *indicator = nil;
        NSInteger bestScore = 0;

        if (dstScore && dstScore.finalScore > 0) {
            bestResponse = dstResponse;
            indicator = connection.destinationAddress;
            bestScore = dstScore.finalScore;
        }
        if (srcScore && srcScore.finalScore > 0 && srcScore.finalScore > bestScore) {
            bestResponse = srcResponse;
            indicator = connection.sourceAddress;
            bestScore = srcScore.finalScore;
        }

        if (bestResponse) {
            [malicious addObject:@{
                @"connection": connection,
                @"response": bestResponse,
                @"indicator": indicator ?: @"",
                @"score": @(bestScore)
            }];
        }
    }

    if (malicious.count == 0) {
        return @[];
    }
    return [malicious sortedArrayUsingComparator:^NSComparisonResult(NSDictionary *obj1, NSDictionary *obj2) {
        NSInteger score1 = [obj1[@"score"] integerValue];
        NSInteger score2 = [obj2[@"score"] integerValue];
        if (score1 == score2) {
            return NSOrderedSame;
        }
        return score1 > score2 ? NSOrderedAscending : NSOrderedDescending;
    }];
}

- (NSString *)providerSummaryForResponse:(TIEnrichmentResponse *)response {
    if (!response || response.providerResults.count == 0) {
        return @"Unknown";
    }
    NSMutableArray<NSString *> *providers = [NSMutableArray array];
    for (TIResult *result in response.providerResults) {
        if (result.providerName.length == 0) {
            continue;
        }
        if (result.verdict) {
            NSString *hitLabel = result.verdict.hit ? @"hit" : @"no hit";
            [providers addObject:[NSString stringWithFormat:@"%@ (%@ %ld%%)",
                                  result.providerName,
                                  hitLabel,
                                  (long)result.verdict.confidence]];
        } else {
            [providers addObject:result.providerName];
        }
    }
    if (providers.count == 0) {
        return @"Unknown";
    }
    return [providers componentsJoinedByString:@", "];
}

- (NSString *)severityBadgeForVerdict:(TIThreatVerdict)verdict {
    switch (verdict) {
        case TIThreatVerdictMalicious:
            return @"[HIGH]";
        case TIThreatVerdictSuspicious:
            return @"[MED]";
        case TIThreatVerdictUnknown:
            return @"[LOW]";
        case TIThreatVerdictClean:
            return @"[OK]";
    }
}

- (NSMenuItem *)threatBadgeItemWithIP:(NSString *)ip scoring:(TIScoringResult *)scoring {
    NSString *badge = [self severityBadgeForVerdict:scoring.verdict];
    NSString *title = [NSString stringWithFormat:@"%@ %@ (%ld)", badge, ip, (long)scoring.finalScore];
    NSMenuItem *item = [[NSMenuItem alloc] initWithTitle:title action:nil keyEquivalent:@""];
    item.enabled = NO;

    NSMutableAttributedString *attrString = [[NSMutableAttributedString alloc] initWithString:title];
    NSFont *font = [NSFont systemFontOfSize:12.0 weight:NSFontWeightSemibold];
    [attrString addAttribute:NSFontAttributeName value:font range:NSMakeRange(0, title.length)];
    [attrString addAttribute:NSForegroundColorAttributeName value:[scoring verdictColor] range:NSMakeRange(0, title.length)];
    item.attributedTitle = attrString;

    return item;
}

#pragma mark - Styled Menu Item Helpers

- (NSMenuItem *)collapsibleSectionHeaderWithTitle:(NSString *)title
                                        expanded:(BOOL)expanded
                                          action:(SEL)action
                                          target:(id)target {
    NSString *indicator = expanded ? @"▼" : @"▶";
    NSString *fullTitle = [NSString stringWithFormat:@"%@ %@", indicator, title];
    NSMenuItem *item = [[NSMenuItem alloc] initWithTitle:fullTitle action:action keyEquivalent:@""];
    item.target = target;
    item.enabled = YES;

    NSFont *font = [NSFont systemFontOfSize:12.0 weight:NSFontWeightSemibold];
    NSColor *color = [NSColor labelColor];

    NSMutableAttributedString *attrString = [[NSMutableAttributedString alloc] initWithString:fullTitle];
    [attrString addAttribute:NSFontAttributeName value:font range:NSMakeRange(0, fullTitle.length)];
    [attrString addAttribute:NSForegroundColorAttributeName value:color range:NSMakeRange(0, fullTitle.length)];
    item.attributedTitle = attrString;

    return item;
}

- (NSMenuItem *)styledMenuItemWithTitle:(NSString *)title style:(NSString *)style {
    NSMenuItem *item = [[NSMenuItem alloc] initWithTitle:title action:nil keyEquivalent:@""];
    item.enabled = NO;

    NSFont *font;
    NSColor *color;

    if ([style isEqualToString:@"header"]) {
        font = [NSFont systemFontOfSize:12.0 weight:NSFontWeightSemibold];
        color = [NSColor labelColor];
    } else if ([style isEqualToString:@"subheader"]) {
        font = [NSFont systemFontOfSize:11.0 weight:NSFontWeightMedium];
        color = [NSColor secondaryLabelColor];
    } else if ([style isEqualToString:@"data"]) {
        font = [NSFont monospacedSystemFontOfSize:11.0 weight:NSFontWeightRegular];
        color = [NSColor secondaryLabelColor];
    } else {
        font = [NSFont menuFontOfSize:0.0];
        color = [NSColor labelColor];
    }

    NSMutableAttributedString *attrString = [[NSMutableAttributedString alloc] initWithString:title];
    [attrString addAttribute:NSFontAttributeName value:font range:NSMakeRange(0, title.length)];
    [attrString addAttribute:NSForegroundColorAttributeName value:color range:NSMakeRange(0, title.length)];
    item.attributedTitle = attrString;

    return item;
}

- (void)configureStatItem:(NSMenuItem *)item
                    label:(NSString *)label
                    value:(NSString *)value
                    color:(NSColor *)color {
    [self configureStatItem:item label:label value:value color:color icon:nil showBadge:NO];
}

- (void)configureStatItem:(NSMenuItem *)item
                    label:(NSString *)label
                    value:(NSString *)value
                    color:(NSColor *)color
                     icon:(NSString *)icon {
    [self configureStatItem:item label:label value:value color:color icon:icon showBadge:NO];
}

- (void)configureStatItem:(NSMenuItem *)item
                    label:(NSString *)label
                    value:(NSString *)value
                    color:(NSColor *)color
                     icon:(NSString *)icon
                showBadge:(BOOL)showBadge
            highlightText:(BOOL)highlightText {
    if (!item || label.length == 0) {
        return;
    }
    NSColor *markerColor = color ?: [NSColor labelColor];
    NSMutableAttributedString *attrString = [[NSMutableAttributedString alloc] init];

    if (showBadge && markerColor) {
        NSFont *markerFont = [NSFont systemFontOfSize:kMenuDotFontSize weight:NSFontWeightMedium];
        NSAttributedString *dot = [[NSAttributedString alloc] initWithString:@"● "
            attributes:@{NSFontAttributeName: markerFont, NSForegroundColorAttributeName: markerColor}];
        [attrString appendAttributedString:dot];
        if (icon.length > 0) {
            NSString *badgeText = [NSString stringWithFormat:@"[%@] ", [icon uppercaseString]];
            NSColor *badgeColor = [NSColor secondaryLabelColor];
            NSAttributedString *badge = [[NSAttributedString alloc] initWithString:badgeText
                attributes:@{NSFontAttributeName: markerFont,
                             NSForegroundColorAttributeName: badgeColor}];
            [attrString appendAttributedString:badge];
        }
    }

    NSFont *labelFont = [NSFont systemFontOfSize:12.0 weight:NSFontWeightMedium];
    NSColor *labelTextColor = [NSColor labelColor];
    NSAttributedString *labelAttr = [[NSAttributedString alloc] initWithString:label
        attributes:@{NSFontAttributeName: labelFont,
                     NSForegroundColorAttributeName: labelTextColor}];
    [attrString appendAttributedString:labelAttr];

    if (value.length > 0) {
        NSString *valueText = [NSString stringWithFormat:@"  %@", value];
        NSFont *valueFont = [NSFont monospacedSystemFontOfSize:12.0 weight:NSFontWeightSemibold];
        NSColor *valueTextColor = [NSColor secondaryLabelColor];
        NSAttributedString *valueAttr = [[NSAttributedString alloc] initWithString:valueText
            attributes:@{NSFontAttributeName: valueFont,
                         NSForegroundColorAttributeName: valueTextColor}];
        [attrString appendAttributedString:valueAttr];
    }

    item.attributedTitle = attrString;
}

- (void)configureStatItem:(NSMenuItem *)item
                    label:(NSString *)label
                    value:(NSString *)value
                    color:(NSColor *)color
                     icon:(NSString *)icon
                showBadge:(BOOL)showBadge {
    [self configureStatItem:item label:label value:value color:color icon:icon showBadge:showBadge highlightText:NO];
}

- (NSMenuItem *)styledStatItemWithLabel:(NSString *)label value:(NSString *)value color:(NSColor *)color {
    NSString *fullText = [NSString stringWithFormat:@"%@  %@", label, value];
    NSMenuItem *item = [[NSMenuItem alloc] initWithTitle:fullText action:nil keyEquivalent:@""];
    item.enabled = NO;
    [self configureStatItem:item label:label value:value color:color icon:nil];
    return item;
}

 - (NSMenuItem *)styledStatItemWithLabel:(NSString *)label
                                   value:(NSString *)value
                                   color:(NSColor *)color
                                    icon:(NSString *)icon {
    return [self styledStatItemWithLabel:label value:value color:color icon:icon showBadge:YES];
}

- (NSMenuItem *)styledStatItemWithLabel:(NSString *)label
                                  value:(NSString *)value
                                  color:(NSColor *)color
                                   icon:(NSString *)icon
                              showBadge:(BOOL)showBadge {
    NSString *fullText = [NSString stringWithFormat:@"%@  %@", label, value];
    NSMenuItem *item = [[NSMenuItem alloc] initWithTitle:fullText action:nil keyEquivalent:@""];
    item.enabled = NO;
    [self configureStatItem:item label:label value:value color:color icon:icon showBadge:showBadge];
    return item;
}

- (NSMenuItem *)styledListItemWithText:(NSString *)text color:(NSColor *)color {
    NSMenuItem *item = [[NSMenuItem alloc] initWithTitle:text action:nil keyEquivalent:@""];
    item.enabled = NO;
    NSMutableAttributedString *attrString = [[NSMutableAttributedString alloc] initWithString:text];
    NSFont *font = [NSFont systemFontOfSize:12.0 weight:NSFontWeightMedium];
    NSColor *textColor = color ?: [NSColor secondaryLabelColor];
    [attrString addAttribute:NSFontAttributeName value:font range:NSMakeRange(0, text.length)];
    [attrString addAttribute:NSForegroundColorAttributeName value:textColor range:NSMakeRange(0, text.length)];
    item.attributedTitle = attrString;
    return item;
}

- (NSString *)promotionDecisionSummary:(SNBPromotionDecision *)decision {
    if (!decision) {
        return @"None yet";
    }
    NSString *action = [decision actionDescription] ?: @"Decision";
    NSString *identifier = decision.processName.length > 0 ? decision.processName : decision.clusterID;
    if (identifier.length > 0) {
        return [NSString stringWithFormat:@"%@ (%@)", action, identifier];
    }
    return action;
}

- (NSString *)promotionSuggestionTitleForDecision:(SNBPromotionDecision *)decision {
    NSString *label = decision.processName.length > 0 ? decision.processName : decision.clusterID;
    if (label.length == 0) {
        label = @"unknown";
    }
    NSString *reason = decision.reason.length > 0 ? decision.reason : [decision actionDescription];
    if (reason.length == 0) {
        reason = @"suggestion";
    }
    return [NSString stringWithFormat:@"  %@ - %@", label, reason];
}

- (void)appendPromotionAgentSectionToMenu:(NSMenu *)visualizationSubmenu {
    if (!self.promotionAgentEnabled) {
        return;
    }

    [visualizationSubmenu addItem:[self styledMenuItemWithTitle:@"PROMOTION AGENT" style:@"subheader"]];

    NSString *statusText = self.promotionAgentOperational ? @"Operational" : @"Offline";
    NSColor *statusColor = self.promotionAgentOperational ? [NSColor systemGreenColor] : [NSColor systemRedColor];
    NSMenuItem *statusItem = [self styledStatItemWithLabel:@"Status"
                                                     value:statusText
                                                     color:statusColor
                                                      icon:nil
                                                 showBadge:YES];
    [visualizationSubmenu addItem:statusItem];

    NSString *decisionSummary = [self promotionDecisionSummary:self.promotionAgentLastDecision];
    NSMenuItem *decisionItem = [self styledStatItemWithLabel:@"Last Decision"
                                                       value:decisionSummary
                                                       color:[NSColor labelColor]];
    [visualizationSubmenu addItem:decisionItem];

    NSArray<SNBPromotionDecision *> *suggestions = self.promotionAgentSuggestions ?: @[];
    NSString *suggestionHeader = [NSString stringWithFormat:@"Suggestions (%lu)",
                                  (unsigned long)suggestions.count];
    [visualizationSubmenu addItem:[self styledMenuItemWithTitle:suggestionHeader style:@"subheader"]];

    if (suggestions.count == 0) {
        [visualizationSubmenu addItem:[self styledMenuItemWithTitle:@"  None" style:@"data"]];
        return;
    }

    NSUInteger displayLimit = MIN(kPromotionSuggestionDisplayLimit, suggestions.count);
    for (NSUInteger idx = 0; idx < displayLimit; idx++) {
        SNBPromotionDecision *decision = suggestions[idx];
        NSString *itemTitle = [self promotionSuggestionTitleForDecision:decision];
        [visualizationSubmenu addItem:[self styledMenuItemWithTitle:itemTitle style:@"data"]];
    }

    if (suggestions.count > displayLimit) {
        NSUInteger remaining = suggestions.count - displayLimit;
        NSString *moreTitle = [NSString stringWithFormat:@"  ... +%lu more", (unsigned long)remaining];
        [visualizationSubmenu addItem:[self styledMenuItemWithTitle:moreTitle style:@"data"]];
    }
}

- (NSMenuItem *)serviceHealthItemWithLabel:(NSString *)label ok:(BOOL)ok {
    NSString *value = ok ? @"Operational" : @"Offline";
    NSColor *color = ok ? [NSColor systemGreenColor] : [NSColor systemRedColor];
    return [self styledStatItemWithLabel:label value:value color:color icon:nil showBadge:YES];
}

- (void)appendServiceHealthSectionToDetailsMenu:(NSMenu *)detailsSubmenu {
    [detailsSubmenu addItem:[NSMenuItem separatorItem]];
    [detailsSubmenu addItem:[self styledMenuItemWithTitle:@"SERVICE HEALTH" style:@"subheader"]];
    [detailsSubmenu addItem:[self serviceHealthItemWithLabel:@"Connectivity Helper" ok:self.helperOperational]];
    [detailsSubmenu addItem:[self serviceHealthItemWithLabel:@"Behavioral moodeling system" ok:self.modelingXpcOperational]];
}

- (void)cacheStatItem:(NSMenuItem *)item label:(NSString *)label color:(NSColor *)color forKey:(NSString *)key {
    if (!item || key.length == 0) {
        return;
    }
    self.dynamicStatItemInfo[key] = @{@"item": item, @"label": label, @"color": color ?: [NSColor labelColor]};
}

- (void)updateStatItemForKey:(NSString *)key value:(NSString *)value {
    NSDictionary *info = self.dynamicStatItemInfo[key];
    if (!info) {
        return;
    }
    NSMenuItem *item = info[@"item"];
    NSString *label = info[@"label"];
    NSColor *color = info[@"color"];
    [self configureStatItem:item label:label value:value color:color];
}

- (void)cacheDetailItem:(NSMenuItem *)item label:(NSString *)label color:(NSColor *)color forKey:(NSString *)key {
    if (!item || key.length == 0) {
        return;
    }
    self.detailStatItemInfo[key] = @{@"item": item, @"label": label, @"color": color ?: [NSColor labelColor]};
}

- (void)updateDetailItemForKey:(NSString *)key value:(NSString *)value {
    NSDictionary *info = self.detailStatItemInfo[key];
    if (!info) {
        return;
    }
    NSMenuItem *item = info[@"item"];
    NSString *label = info[@"label"];
    NSColor *color = info[@"color"];
    [self configureStatItem:item label:label value:value color:color];
}

- (NSString *)captureStartDisplayValue {
    if (self.captureStartDate) {
        return [self.captureDateFormatter stringFromDate:self.captureStartDate];
    }
    return @"Not capturing";
}

- (NSColor *)highlightColorForProcessSummary:(ProcessTrafficSummary *)summary {
    // Fix 5: Use enhanced method that also checks incoming traffic via topConnections
    if ([self isProcessSummaryRelatedToSelectedConnection:summary]) {
        return [NSColor systemYellowColor];
    }

    return [[SNBBadgeRegistry sharedRegistry] colorForProcessName:summary.processName
                                                              pid:summary.processPID
                                             createIfMissing:YES];
}

- (void)updateProcessHighlightColorsWithSummaries:(NSArray<ProcessTrafficSummary *> *)summaries {
    [self.hostColorMap removeAllObjects];
    for (ProcessTrafficSummary *summary in summaries) {
        NSColor *color = [self highlightColorForProcessSummary:summary];
        for (NSString *destination in summary.destinations) {
            if (destination.length > 0 && !self.hostColorMap[destination]) {
                self.hostColorMap[destination] = color;
            }
        }
    }
}

- (NSColor *)processHighlightColorForConnection:(ConnectionTraffic *)connection {
    // Check if this connection is selected from the map
    if ([self isConnectionSelected:connection]) {
        return [NSColor systemYellowColor];
    }

    if (!connection.processName.length && connection.processPID == 0) {
        return [NSColor labelColor];
    }
    return [[SNBBadgeRegistry sharedRegistry] colorForProcessName:connection.processName
                                                              pid:connection.processPID
                                             createIfMissing:YES];
}

- (NSString *)badgeIconForConnection:(ConnectionTraffic *)connection {
    NSString *fallback = connection.destinationAddress.length > 0 ? connection.destinationAddress : connection.sourceAddress;
    return [[SNBBadgeRegistry sharedRegistry] badgeIconForProcessName:connection.processName
                                                                 pid:connection.processPID
                                                      fallbackLabel:fallback];
}

- (NSString *)badgeIconForHost:(HostTraffic *)host {
    NSString *label = host.hostname.length > 0 ? host.hostname : host.address;
    return [[SNBBadgeRegistry sharedRegistry] badgeIconForLabel:label fallback:host.address];
}

- (NSColor *)highlightColorForHostAddress:(NSString *)address {
    // Check if this host is part of the selected connection from the map
    if (self.selectedSourceIP && self.selectedDestinationIP) {
        if ([address isEqualToString:self.selectedSourceIP] ||
            [address isEqualToString:self.selectedDestinationIP]) {
            return [NSColor systemYellowColor];
        }
    }

    NSColor *color = self.hostColorMap[address];
    if (!color) {
        color = [[SNBBadgeRegistry sharedRegistry] colorForLabel:address createIfMissing:YES];
    }
    return color ?: [NSColor labelColor];
}

- (BOOL)isHostAddressSelected:(NSString *)address {
    if (!self.selectedSourceIP || !self.selectedDestinationIP) {
        return NO;
    }
    return [address isEqualToString:self.selectedSourceIP] ||
           [address isEqualToString:self.selectedDestinationIP];
}

- (BOOL)isConnectionSelected:(ConnectionTraffic *)connection {
    if (!self.selectedSourceIP || !self.selectedDestinationIP) {
        return NO;
    }
    // Match in either direction
    return ([connection.sourceAddress isEqualToString:self.selectedSourceIP] &&
            [connection.destinationAddress isEqualToString:self.selectedDestinationIP]) ||
           ([connection.sourceAddress isEqualToString:self.selectedDestinationIP] &&
            [connection.destinationAddress isEqualToString:self.selectedSourceIP]);
}

- (BOOL)isProcessRelatedToSelectedConnection:(NSArray<NSString *> *)destinations {
    if (!self.selectedSourceIP || !self.selectedDestinationIP) {
        return NO;
    }
    for (NSString *dest in destinations) {
        if ([dest isEqualToString:self.selectedSourceIP] ||
            [dest isEqualToString:self.selectedDestinationIP]) {
            return YES;
        }
    }
    return NO;
}

// Fix 5: Enhanced process correlation that also checks connections for incoming traffic
- (BOOL)isProcessSummaryRelatedToSelectedConnection:(ProcessTrafficSummary *)summary {
    if (!self.selectedSourceIP || !self.selectedDestinationIP) {
        return NO;
    }

    // First check destinations (outgoing traffic) - existing logic
    for (NSString *dest in summary.destinations) {
        if ([dest isEqualToString:self.selectedSourceIP] ||
            [dest isEqualToString:self.selectedDestinationIP]) {
            return YES;
        }
    }

    // Also check if any of this process's connections in topConnections matches the selection
    // This handles incoming traffic where the process is the destination
    if (self.lastTrafficStats.topConnections) {
        for (ConnectionTraffic *conn in self.lastTrafficStats.topConnections) {
            // Check if this connection belongs to this process
            if (![conn.processName isEqualToString:summary.processName] ||
                conn.processPID != summary.processPID) {
                continue;
            }
            // Check if this connection matches the selected IPs (in either direction)
            if ([self isConnectionSelected:conn]) {
                return YES;
            }
        }
    }

    return NO;
}

- (void)requestFullVisualizationRefresh {
    self.needsFullVisualizationRefresh = YES;
    if ([self.delegate respondsToSelector:@selector(menuBuilderNeedsVisualizationRefresh:)]) {
        [self.delegate menuBuilderNeedsVisualizationRefresh:self];
    }
}

- (NSMenuItem *)coloredStatItemWithLabel:(NSString *)label value:(NSString *)value color:(NSColor *)color {
    NSString *fullText = [NSString stringWithFormat:@"%@  %@", label, value];
    NSMenuItem *item = [[NSMenuItem alloc] initWithTitle:fullText action:nil keyEquivalent:@""];
    item.enabled = NO;

    NSMutableAttributedString *attrString = [[NSMutableAttributedString alloc] initWithString:fullText];

    // Label (including arrow) in colored font
    NSFont *labelFont = [NSFont systemFontOfSize:12.0 weight:NSFontWeightMedium];
    [attrString addAttribute:NSFontAttributeName value:labelFont range:NSMakeRange(0, label.length)];
    [attrString addAttribute:NSForegroundColorAttributeName value:color range:NSMakeRange(0, label.length)];

    // Value in monospaced font with same color
    NSFont *valueFont = [NSFont monospacedSystemFontOfSize:12.0 weight:NSFontWeightSemibold];
    NSRange valueRange = NSMakeRange(label.length, value.length + 2); // +2 for the spaces
    [attrString addAttribute:NSFontAttributeName value:valueFont range:valueRange];
    [attrString addAttribute:NSForegroundColorAttributeName value:color range:valueRange];

    item.attributedTitle = attrString;
    return item;
}

- (void)updateStatusWithStats:(TrafficStats *)stats selectedDevice:(NetworkDevice *)selectedDevice {
    // Performance: Skip update if nothing has changed
    NSString *deviceName = selectedDevice.name ?: SNBStoredDeviceName();
    BOOL deviceNameChanged = ![deviceName isEqualToString:self.lastStatusDeviceName ?: @""];
    BOOL incomingChanged = (stats.incomingBytes != self.lastStatusIncomingBytes);
    BOOL outgoingChanged = (stats.outgoingBytes != self.lastStatusOutgoingBytes);
    BOOL maliciousChanged = (self.activeMaliciousCount != self.lastStatusMaliciousCount);
    BOOL suspiciousChanged = (self.activeSuspiciousCount != self.lastStatusSuspiciousCount);

    if (!deviceNameChanged && !incomingChanged && !outgoingChanged &&
        !maliciousChanged && !suspiciousChanged) {
        return;  // Nothing changed, skip expensive status bar update
    }

    // Update cached values
    self.lastStatusDeviceName = deviceName;
    self.lastStatusIncomingBytes = stats.incomingBytes;
    self.lastStatusOutgoingBytes = stats.outgoingBytes;
    self.lastStatusMaliciousCount = self.activeMaliciousCount;
    self.lastStatusSuspiciousCount = self.activeSuspiciousCount;

    // Create attributed string with colored arrows for incoming/outgoing traffic
    NSMutableAttributedString *statusDisplay = [[NSMutableAttributedString alloc] init];

    // Add device name if available
    if (deviceName.length > 0) {
        NSString *prefix = [NSString stringWithFormat:@"[%@] ", deviceName];
        NSAttributedString *deviceAttr = [[NSAttributedString alloc] initWithString:prefix];
        [statusDisplay appendAttributedString:deviceAttr];
    }

    // Add threat alert indicator if there are active threats
    if (self.activeMaliciousCount > 0) {
        // Red alert for malicious connections
        NSColor *alertColor = [NSColor colorWithCalibratedRed:0.9 green:0.1 blue:0.1 alpha:1.0];
        NSAttributedString *dotAttr = [[NSAttributedString alloc]
            initWithString:@"●"
            attributes:@{NSForegroundColorAttributeName: alertColor,
                         NSFontAttributeName: [NSFont systemFontOfSize:kStatusAlertDotFontSize weight:NSFontWeightMedium]}];
        NSAttributedString *countAttr = [[NSAttributedString alloc]
            initWithString:[NSString stringWithFormat:@"%lu ", (unsigned long)self.activeMaliciousCount]
            attributes:@{NSForegroundColorAttributeName: alertColor,
                         NSFontAttributeName: [NSFont systemFontOfSize:12.0 weight:NSFontWeightSemibold]}];
        [statusDisplay appendAttributedString:dotAttr];
        [statusDisplay appendAttributedString:countAttr];
    } else if (self.activeSuspiciousCount > 0) {
        // Orange alert for suspicious connections
        NSColor *alertColor = [NSColor colorWithCalibratedRed:1.0 green:0.6 blue:0.0 alpha:1.0];
        NSAttributedString *dotAttr = [[NSAttributedString alloc]
            initWithString:@"●"
            attributes:@{NSForegroundColorAttributeName: alertColor,
                         NSFontAttributeName: [NSFont systemFontOfSize:kStatusAlertDotFontSize weight:NSFontWeightMedium]}];
        NSAttributedString *countAttr = [[NSAttributedString alloc]
            initWithString:[NSString stringWithFormat:@"%lu ", (unsigned long)self.activeSuspiciousCount]
            attributes:@{NSForegroundColorAttributeName: alertColor,
                         NSFontAttributeName: [NSFont systemFontOfSize:12.0 weight:NSFontWeightSemibold]}];
        [statusDisplay appendAttributedString:dotAttr];
        [statusDisplay appendAttributedString:countAttr];
    }

    // Add download arrow in green
    NSString *downloadArrow = @"↓ ";
    NSColor *downloadColor = [NSColor colorWithCalibratedRed:0.2 green:0.7 blue:0.3 alpha:1.0];
    NSAttributedString *downloadAttr = [[NSAttributedString alloc]
        initWithString:downloadArrow
        attributes:@{NSForegroundColorAttributeName: downloadColor}];
    [statusDisplay appendAttributedString:downloadAttr];

    // Add incoming bytes
    NSString *incomingStr = [SNBByteFormatter stringFromBytes:stats.incomingBytes];
    NSAttributedString *incomingAttr = [[NSAttributedString alloc] initWithString:incomingStr];
    [statusDisplay appendAttributedString:incomingAttr];

    // Add separator
    NSAttributedString *separatorAttr = [[NSAttributedString alloc] initWithString:@"  "];
    [statusDisplay appendAttributedString:separatorAttr];

    // Add upload arrow in blue
    NSString *uploadArrow = @"↑ ";
    NSColor *uploadColor = [NSColor colorWithCalibratedRed:0.2 green:0.5 blue:1.0 alpha:1.0];
    NSAttributedString *uploadAttr = [[NSAttributedString alloc]
        initWithString:uploadArrow
        attributes:@{NSForegroundColorAttributeName: uploadColor}];
    [statusDisplay appendAttributedString:uploadAttr];

    // Add outgoing bytes
    NSString *outgoingStr = [SNBByteFormatter stringFromBytes:stats.outgoingBytes];
    NSAttributedString *outgoingAttr = [[NSAttributedString alloc] initWithString:outgoingStr];
    [statusDisplay appendAttributedString:outgoingAttr];

    self.statusItem.button.attributedTitle = statusDisplay;
}

// Performance: Check if menu data needs updating
- (BOOL)shouldRefreshMenuDataWithStats:(TrafficStats *)stats {
    // When menu is closed, only update every 10% change to reduce work
    if (!self.menuIsOpen) {
        if (self.lastTotalBytes > 0) {
            double changePercent = fabs((double)(stats.totalBytes - self.lastTotalBytes) / (double)self.lastTotalBytes);
            return changePercent > 0.10;  // 10% threshold
        }
        return YES;
    }

    // When menu is open, always refresh (but throttled by caller)
    return YES;
}

- (void)updateMenuWithStats:(TrafficStats *)stats
                    devices:(NSArray<NetworkDevice *> *)devices
             selectedDevice:(NetworkDevice *)selectedDevice
         threatIntelEnabled:(BOOL)threatIntelEnabled
     threatIntelStatusMessage:(NSString *)threatIntelStatusMessage
        threatIntelResults:(NSDictionary<NSString *, TIEnrichmentResponse *> *)threatIntelResults
                 cacheStats:(NSDictionary *)cacheStats
          openAtLoginEnabled:(BOOL)openAtLoginEnabled
        assetMonitorEnabled:(BOOL)assetMonitorEnabled
             networkAssets:(NSArray<SNBNetworkAsset *> *)networkAssets
           recentNewAssets:(NSArray<SNBNetworkAsset *> *)recentNewAssets
                     target:(id)target {

    // Performance: Skip rebuild when menu is closed and no significant changes
    if (!self.menuIsOpen && ![self shouldRefreshMenuDataWithStats:stats]) {
        return;
    }

    self.lastThreatIntelResults = threatIntelResults ?: @{};

    // Update tracking values
    self.lastTotalBytes = stats.totalBytes;
    self.lastBytesPerSecond = stats.bytesPerSecond;
    self.lastTopHostsCount = stats.topHosts.count;
    self.lastTopConnectionsCount = stats.topConnections.count;

    [self.statusMenu removeAllItems];

    ConfigurationManager *config = self.configuration;

    NSMenuItem *settingsItem = [[NSMenuItem alloc] initWithTitle:@"Settings" action:nil keyEquivalent:@""];
    NSMenu *settingsSubmenu = [[NSMenu alloc] init];
    settingsItem.submenu = settingsSubmenu;
    [self.statusMenu addItem:settingsItem];

    NSMenuItem *deviceMenu = [[NSMenuItem alloc] initWithTitle:@"Network Interface" action:nil keyEquivalent:@""];
    NSMenu *deviceSubmenu = [[NSMenu alloc] init];
    NSString *uiSelectedDeviceName = selectedDevice.name ?: SNBStoredDeviceName();
    NSString *selectedInterfaceTitle = nil;
    if (selectedDevice) {
        selectedInterfaceTitle = selectedDevice.displayName ?: selectedDevice.name;
    }
    if (selectedInterfaceTitle.length == 0) {
        selectedInterfaceTitle = SNBStoredDeviceName();
    }
    self.selectedDeviceDisplayName = selectedInterfaceTitle;
    NSArray<NetworkDevice *> *deviceList = devices ?: @[];

    SNBLogUIDebug("Building device menu: selectedDevice=%s, storedDevice=%s, uiSelectedDeviceName=%s",
                  selectedDevice.name ? selectedDevice.name.UTF8String : "(nil)",
                  SNBStoredDeviceName() ? SNBStoredDeviceName().UTF8String : "(nil)",
                  uiSelectedDeviceName ? uiSelectedDeviceName.UTF8String : "(nil)");

    for (NetworkDevice *device in deviceList) {
        NSMenuItem *deviceItem = [[NSMenuItem alloc] initWithTitle:[device displayName]
                                                            action:@selector(deviceSelected:)
                                                     keyEquivalent:@""];
        deviceItem.target = target;
        deviceItem.representedObject = device;
        if (uiSelectedDeviceName.length > 0 && [device.name isEqualToString:uiSelectedDeviceName]) {
            deviceItem.state = NSControlStateValueOn;
            SNBLogUIDebug("Set checkmark on device: %s", device.name.UTF8String);
        }
        [deviceSubmenu addItem:deviceItem];
    }

    deviceMenu.submenu = deviceSubmenu;
    [settingsSubmenu addItem:deviceMenu];
    NSMenuItem *providerItem = [[NSMenuItem alloc] initWithTitle:@"GeoLocation Provider" action:nil keyEquivalent:@""];
    NSMenu *providerSubmenu = [[NSMenu alloc] init];
    NSArray<NSString *> *providers = @[@"ip-api.com", @"ipinfo.io", @"Custom (UserDefaults)"];
    for (NSString *provider in providers) {
        NSMenuItem *providerMenuItem = [[NSMenuItem alloc] initWithTitle:provider
                                                                  action:@selector(selectMapProvider:)
                                                           keyEquivalent:@""];
        providerMenuItem.target = target;
        providerMenuItem.representedObject = provider;
        NSString *providerValue = [provider isEqualToString:@"Custom (UserDefaults)"] ? @"custom" : provider;
        if ([self.mapProviderName isEqualToString:providerValue]) {
            providerMenuItem.state = NSControlStateValueOn;
        }
        [providerSubmenu addItem:providerMenuItem];
    }
    providerItem.submenu = providerSubmenu;
    [settingsSubmenu addItem:providerItem];
    [settingsSubmenu addItem:[NSMenuItem separatorItem]];

    NSMenuItem *toggleHosts = [[NSMenuItem alloc] initWithTitle:@"Show Top Hosts by Traffic"
                                                         action:@selector(toggleShowTopHosts:)
                                                  keyEquivalent:@""];
    toggleHosts.target = target;
    toggleHosts.state = self.showTopHosts ? NSControlStateValueOn : NSControlStateValueOff;
    NSMenuItem *toggleConnections = [[NSMenuItem alloc] initWithTitle:@"Show Top Connections by Traffic"
                                                               action:@selector(toggleShowTopConnections:)
                                                        keyEquivalent:@""];
    toggleConnections.target = target;
    toggleConnections.state = self.showTopConnections ? NSControlStateValueOn : NSControlStateValueOff;
    NSMenuItem *toggleMap = [[NSMenuItem alloc] initWithTitle:@"Show Map Visualization"
                                                       action:@selector(toggleShowMap:)
                                                keyEquivalent:@""];
    toggleMap.target = target;
    toggleMap.state = self.showMap ? NSControlStateValueOn : NSControlStateValueOff;

    [settingsSubmenu addItem:toggleHosts];
    [settingsSubmenu addItem:toggleConnections];
    NSMenuItem *toggleProcessActivity = [[NSMenuItem alloc] initWithTitle:@"Show Process Activity"
                                                                     action:@selector(toggleShowProcessActivity:)
                                                              keyEquivalent:@""];
    toggleProcessActivity.target = target;
    toggleProcessActivity.state = self.showProcessActivity ? NSControlStateValueOn : NSControlStateValueOff;
    [settingsSubmenu addItem:toggleProcessActivity];
    [settingsSubmenu addItem:toggleMap];
    [settingsSubmenu addItem:[NSMenuItem separatorItem]];

    NSMenuItem *toggleThreatIntel = [[NSMenuItem alloc] initWithTitle:@"Enable Threat Intelligence"
                                                               action:@selector(toggleThreatIntel:)
                                                        keyEquivalent:@""];
    toggleThreatIntel.target = target;
    toggleThreatIntel.state = threatIntelEnabled ? NSControlStateValueOn : NSControlStateValueOff;
    [settingsSubmenu addItem:toggleThreatIntel];

    if (threatIntelEnabled) {
        NSMenuItem *threatProviderItem = [[NSMenuItem alloc] initWithTitle:@"Threat Intel Providers"
                                                                    action:nil
                                                             keyEquivalent:@""];
        NSMenu *threatProviderSubmenu = [[NSMenu alloc] init];
        threatProviderItem.submenu = threatProviderSubmenu;

        NSMenuItem *toggleVirusTotal = [[NSMenuItem alloc] initWithTitle:@"VirusTotal"
                                                                  action:@selector(toggleThreatIntelProvider:)
                                                           keyEquivalent:@""];
        toggleVirusTotal.target = target;
        toggleVirusTotal.state = [[NSUserDefaults standardUserDefaults] boolForKey:SNBUserDefaultsKeyVirusTotalOptIn]
            ? NSControlStateValueOn : NSControlStateValueOff;
        toggleVirusTotal.representedObject = SNBUserDefaultsKeyVirusTotalOptIn;
        [threatProviderSubmenu addItem:toggleVirusTotal];

        NSMenuItem *toggleAbuseIPDB = [[NSMenuItem alloc] initWithTitle:@"AbuseIPDB"
                                                                 action:@selector(toggleThreatIntelProvider:)
                                                          keyEquivalent:@""];
        toggleAbuseIPDB.target = target;
        toggleAbuseIPDB.state = [[NSUserDefaults standardUserDefaults] boolForKey:SNBUserDefaultsKeyAbuseIPDBOptIn]
            ? NSControlStateValueOn : NSControlStateValueOff;
        toggleAbuseIPDB.representedObject = SNBUserDefaultsKeyAbuseIPDBOptIn;
        [threatProviderSubmenu addItem:toggleAbuseIPDB];

        NSMenuItem *toggleGreyNoise = [[NSMenuItem alloc] initWithTitle:@"GreyNoise"
                                                                 action:@selector(toggleThreatIntelProvider:)
                                                          keyEquivalent:@""];
        toggleGreyNoise.target = target;
        toggleGreyNoise.state = [[NSUserDefaults standardUserDefaults] boolForKey:SNBUserDefaultsKeyGreyNoiseOptIn]
            ? NSControlStateValueOn : NSControlStateValueOff;
        toggleGreyNoise.representedObject = SNBUserDefaultsKeyGreyNoiseOptIn;
        [threatProviderSubmenu addItem:toggleGreyNoise];

        NSMenuItem *toggleShodan = [[NSMenuItem alloc] initWithTitle:@"Shodan"
                                                             action:@selector(toggleThreatIntelProvider:)
                                                      keyEquivalent:@""];
        toggleShodan.target = target;
        toggleShodan.state = [[NSUserDefaults standardUserDefaults] boolForKey:SNBUserDefaultsKeyShodanOptIn]
            ? NSControlStateValueOn : NSControlStateValueOff;
        toggleShodan.representedObject = SNBUserDefaultsKeyShodanOptIn;
        [threatProviderSubmenu addItem:toggleShodan];

        [settingsSubmenu addItem:threatProviderItem];
    }

    NSMenuItem *togglePromotionAgent = [[NSMenuItem alloc] initWithTitle:@"Enable Promotion Agent"
                                                                  action:@selector(togglePromotionAgent:)
                                                           keyEquivalent:@""];
    togglePromotionAgent.target = target;
    togglePromotionAgent.state = self.promotionAgentEnabled ? NSControlStateValueOn : NSControlStateValueOff;
    [settingsSubmenu addItem:togglePromotionAgent];

    [settingsSubmenu addItem:[NSMenuItem separatorItem]];

    NSMenuItem *toggleAssetMonitor = [[NSMenuItem alloc] initWithTitle:@"Monitor Network Assets"
                                                                action:@selector(toggleAssetMonitor:)
                                                         keyEquivalent:@""];
    toggleAssetMonitor.target = target;
    toggleAssetMonitor.state = assetMonitorEnabled ? NSControlStateValueOn : NSControlStateValueOff;
    [settingsSubmenu addItem:toggleAssetMonitor];

    [settingsSubmenu addItem:[NSMenuItem separatorItem]];

    NSMenuItem *toggleDailyStats = [[NSMenuItem alloc] initWithTitle:@"Enable Daily Statistics"
                                                              action:@selector(toggleDailyStatistics:)
                                                       keyEquivalent:@""];
    toggleDailyStats.target = target;
    toggleDailyStats.state = self.dailyStatsEnabled ? NSControlStateValueOn : NSControlStateValueOff;
    [settingsSubmenu addItem:toggleDailyStats];

    NSMenuItem *openReport = [[NSMenuItem alloc] initWithTitle:@"Open Statistics Report"
                                                        action:@selector(openStatisticsReport:)
                                                 keyEquivalent:@""];
    openReport.target = target;
    openReport.enabled = self.statsReportAvailable;
    [settingsSubmenu addItem:openReport];

    [settingsSubmenu addItem:[NSMenuItem separatorItem]];

    NSMenuItem *toggleOpenAtLogin = [[NSMenuItem alloc] initWithTitle:@"Open at Login"
                                                               action:@selector(toggleOpenAtLogin:)
                                                        keyEquivalent:@""];
    toggleOpenAtLogin.target = target;
    toggleOpenAtLogin.state = openAtLoginEnabled ? NSControlStateValueOn : NSControlStateValueOff;
    [settingsSubmenu addItem:toggleOpenAtLogin];

    [settingsSubmenu addItem:[NSMenuItem separatorItem]];

    NSMenuItem *developerItem = [[NSMenuItem alloc] initWithTitle:@"Developer"
                                                           action:nil
                                                    keyEquivalent:@""];
    NSMenu *developerSubmenu = [[NSMenu alloc] init];
    developerItem.submenu = developerSubmenu;

    NSMenuItem *toggleDebug = [[NSMenuItem alloc] initWithTitle:@"Enable Debug"
                                                         action:@selector(toggleDebugMode:)
                                                  keyEquivalent:@""];
    toggleDebug.target = target;
    toggleDebug.state = self.debugEnabled ? NSControlStateValueOn : NSControlStateValueOff;
    [developerSubmenu addItem:toggleDebug];

    [developerSubmenu addItem:[NSMenuItem separatorItem]];

    NSMenuItem *resetItem = [[NSMenuItem alloc] initWithTitle:@"Reset Statistics"
                                                       action:@selector(resetStatistics:)
                                                keyEquivalent:@""];
    resetItem.target = target;
    [developerSubmenu addItem:resetItem];

    [settingsSubmenu addItem:developerItem];

    NSMenuItem *visualizationItem = [[NSMenuItem alloc] initWithTitle:@"Visualization" action:nil keyEquivalent:@""];
    NSMenu *visualizationSubmenu = [[NSMenu alloc] init];
    visualizationItem.submenu = visualizationSubmenu;
    self.visualizationSubmenu = visualizationSubmenu;
    [self.statusMenu addItem:visualizationItem];
    [self.statusMenu addItem:[NSMenuItem separatorItem]];
    [self rebuildVisualizationMenuWithStats:stats
                        threatIntelEnabled:threatIntelEnabled
                   threatIntelStatusMessage:threatIntelStatusMessage
                       threatIntelResults:threatIntelResults
                                cacheStats:cacheStats
                      assetMonitorEnabled:assetMonitorEnabled
                           networkAssets:networkAssets
                         recentNewAssets:recentNewAssets];

    [self.statusMenu addItem:[NSMenuItem separatorItem]];
    NSMenuItem *aboutItem = [[NSMenuItem alloc] initWithTitle:@"About" action:nil keyEquivalent:@""];
    NSMenu *aboutSubmenu = [[NSMenu alloc] init];
    NSString *versionTitle = [NSString stringWithFormat:@"Version %@", config.appVersion];
    NSMenuItem *versionItem = [[NSMenuItem alloc] initWithTitle:versionTitle action:nil keyEquivalent:@""];
    versionItem.enabled = NO;
    [aboutSubmenu addItem:versionItem];
    aboutItem.submenu = aboutSubmenu;
    [self.statusMenu addItem:aboutItem];

    [self.statusMenu addItem:[NSMenuItem separatorItem]];
    NSMenuItem *quitItem = [[NSMenuItem alloc] initWithTitle:@"Quit" action:@selector(terminate:) keyEquivalent:@"q"];
    [self.statusMenu addItem:quitItem];

    [self updateStatusWithStats:stats selectedDevice:selectedDevice];
    [self truncateMenuItemsInMenu:self.statusMenu maxWidth:config.menuFixedWidth];

    if (self.showMap && self.mapMenuView && (self.menuIsOpen || self.mapMenuView.detachedWindowVisible)) {
        [self.mapMenuView updateWithConnections:[self connectionsForMapFromStats:stats]
                             threatIntelResults:threatIntelResults
                                      blockedIPs:self.blockedIPs];
    }
}

- (NSMenuItem *)mapMenuItemIfNeeded {
    if (!self.menuIsOpen) {
        return nil;
    }
    if (!self.mapMenuItem) {
        ConfigurationManager *config = self.configuration;
        self.mapMenuView = [[MapMenuView alloc] initWithFrame:NSMakeRect(0, 0, config.menuFixedWidth, config.mapMenuViewHeight)];
        self.mapMenuView.providerName = self.mapProviderName;
        self.mapMenuView.delegate = self;
        self.mapMenuView.translatesAutoresizingMaskIntoConstraints = NO;

        self.mapMenuItem = [[NSMenuItem alloc] initWithTitle:@"" action:nil keyEquivalent:@""];
        self.mapMenuItem.view = self.mapMenuView;

        [self.mapMenuView addConstraint:[NSLayoutConstraint constraintWithItem:self.mapMenuView
                                                                     attribute:NSLayoutAttributeWidth
                                                                     relatedBy:NSLayoutRelationEqual
                                                                        toItem:nil
                                                                     attribute:NSLayoutAttributeNotAnAttribute
                                                                    multiplier:1.0
                                                                      constant:config.menuFixedWidth]];
        [self.mapMenuView addConstraint:[NSLayoutConstraint constraintWithItem:self.mapMenuView
                                                                     attribute:NSLayoutAttributeHeight
                                                                     relatedBy:NSLayoutRelationEqual
                                                                        toItem:nil
                                                                     attribute:NSLayoutAttributeNotAnAttribute
                                                                    multiplier:1.0
                                                                      constant:config.mapMenuViewHeight]];

        SNBLogUIDebug("Map menu view created with constraints: width=%.0f, height=%.0f",
               config.menuFixedWidth, config.mapMenuViewHeight);
    }
    return self.mapMenuItem;
}

- (void)tearDownMapMenuItem {
    if (self.mapMenuItem) {
        self.mapMenuItem.view = nil;
        self.mapMenuItem = nil;
    self.mapMenuView = nil;
    self.lastGeolocatedConnectionCount = 0;
    SNBLogUIDebug("Map menu view released");
}
}

- (void)menuWillOpenWithStats:(TrafficStats *)stats {
    self.menuIsOpen = YES;
    SNBLogUIDebug("Status menu opened");
    if (self.showMap && self.mapMenuView) {
        NSArray<ConnectionTraffic *> *mapConnections = [self cachedMapConnectionsForStats:stats];
        [self.mapMenuView updateWithConnections:mapConnections
                             threatIntelResults:self.lastThreatIntelResults ?: @{}
                                      blockedIPs:self.blockedIPs];
    }
}

- (void)refreshVisualizationWithStats:(TrafficStats *)stats
                  threatIntelEnabled:(BOOL)threatIntelEnabled
              threatIntelStatusMessage:(NSString *)threatIntelStatusMessage
                 threatIntelResults:(NSDictionary<NSString *, TIEnrichmentResponse *> *)threatIntelResults
                          cacheStats:(NSDictionary *)cacheStats
                assetMonitorEnabled:(BOOL)assetMonitorEnabled
                     networkAssets:(NSArray<SNBNetworkAsset *> *)networkAssets
                   recentNewAssets:(NSArray<SNBNetworkAsset *> *)recentNewAssets {
    // Model update phase (cache heavy computations)
    [self updateModelCachesWithStats:stats threatIntelResults:threatIntelResults];
    if (!self.menuIsOpen || !self.visualizationSubmenu) {
        return;
    }

    NSArray<ConnectionTraffic *> *mapConnections = [self cachedMapConnectionsForStats:stats];
    if (self.showMap && self.mapMenuView) {
        [self.mapMenuView updateWithConnections:mapConnections
                             threatIntelResults:threatIntelResults
                                      blockedIPs:self.blockedIPs];
        self.lastGeolocatedConnectionCount = self.mapMenuView.drawnConnectionCount;
    } else {
        self.lastGeolocatedConnectionCount = 0;
    }

    // Dynamic stat items (network rate, totals) are always updated - they're in the main status bar
    [self refreshDynamicStatItemsWithStats:stats
                             mapConnections:mapConnections
                              networkAssets:networkAssets
                            recentNewAssets:recentNewAssets];

    // Check if full rebuild is needed BEFORE doing incremental section updates
    // This prevents wasted work when section toggles trigger a full rebuild
    if (self.needsFullVisualizationRefresh) {
        self.needsFullVisualizationRefresh = NO;
        SNBLogUIDebug("Full visualization rebuild requested");
        [self updateVisualizationMenuWithStats:stats
                            threatIntelEnabled:threatIntelEnabled
                       threatIntelStatusMessage:threatIntelStatusMessage
                           threatIntelResults:threatIntelResults
                                    cacheStats:cacheStats
                          assetMonitorEnabled:assetMonitorEnabled
                               networkAssets:networkAssets
                             recentNewAssets:recentNewAssets];
        [self truncateMenuItemsInMenu:self.visualizationSubmenu maxWidth:self.configuration.menuFixedWidth];
        return;
    }

    // Incremental section updates - only run when menu is stable (no full rebuild needed)
    [self refreshDetailStatsWithStats:stats];

    // Fix 3: Skip highlighting sections if they were just refreshed by selection change (within 100ms)
    NSTimeInterval timeSinceSelectionRefresh = [NSDate timeIntervalSinceReferenceDate] - self.lastSelectionRefreshTime;
    BOOL skipHighlightingSections = (timeSinceSelectionRefresh < 0.1);

    if (!skipHighlightingSections) {
        [self refreshTopHostsSectionWithStats:stats];
        [self refreshTopConnectionsSectionWithStats:stats];
        [self refreshProcessActivitySectionWithStats:stats];
    } else {
        SNBLogUIDebug("Skipping highlighting sections - just refreshed by selection change");
    }

    [self refreshMaliciousConnectionsSectionWithStats:stats
                                 threatIntelResults:threatIntelResults];

    [self refreshCleanConnectionsSectionWithStats:stats
                               threatIntelResults:threatIntelResults];

    [self refreshNetworkDevicesSectionWithAssets:networkAssets
                                 recentNewAssets:recentNewAssets
                             assetMonitorEnabled:assetMonitorEnabled];

    if (self.networkActivityGraphView) {
        [self.networkActivityGraphView updateWithIncomingRates:self.incomingRateHistory
                                                 outgoingRates:self.outgoingRateHistory];
    }

    SNBLogUIDebug("Incremental visualization refresh completed");
}

- (void)refreshDynamicStatItemsWithStats:(TrafficStats *)stats
                          mapConnections:(NSArray<ConnectionTraffic *> *)mapConnections
                           networkAssets:(NSArray<SNBNetworkAsset *> *)networkAssets
                         recentNewAssets:(NSArray<SNBNetworkAsset *> *)recentNewAssets {
    NSString *rateStr = [SNBByteFormatter stringFromBytes:stats.bytesPerSecond];
    [self updateStatItemForKey:SNBMenuItemKeyNetworkRate value:[NSString stringWithFormat:@"%@/s", rateStr]];

    NSString *totalBytesStr = [SNBByteFormatter stringFromBytes:stats.totalBytes];
    [self updateStatItemForKey:SNBMenuItemKeyNetworkTotal value:totalBytesStr];

    NSUInteger totalPublicConnections = mapConnections.count;
    NSUInteger geolocatedConnections = MIN(self.lastGeolocatedConnectionCount, totalPublicConnections);
    NSString *connectionsValue = [NSString stringWithFormat:@"%lu  (%lu Geolocated)",
                                  (unsigned long)totalPublicConnections,
                                  (unsigned long)geolocatedConnections];
    [self updateStatItemForKey:SNBMenuItemKeyActiveConnections value:connectionsValue];

    NSString *hostsStr = [NSString stringWithFormat:@"%lu", (unsigned long)stats.topHosts.count];
    [self updateStatItemForKey:SNBMenuItemKeyHosts value:hostsStr];

    NSUInteger deviceCount = networkAssets.count;
    NSString *newBadge = (recentNewAssets.count > 0)
        ? [NSString stringWithFormat:@" (%lu new)", (unsigned long)recentNewAssets.count]
        : @"";
    NSString *deviceSummary = [NSString stringWithFormat:@"%lu Device%@%@",
                               (unsigned long)deviceCount,
                               deviceCount == 1 ? @"" : @"s",
                               newBadge];
    [self updateStatItemForKey:SNBMenuItemKeyNetworkDevicesTotal value:deviceSummary];
}

- (NSArray<NSMenuItem *> *)menuItemsForNetworkDevicesSectionWithAssets:(NSArray<SNBNetworkAsset *> *)networkAssets
                                                       recentNewAssets:(NSArray<SNBNetworkAsset *> *)recentNewAssets
                                                  assetMonitorEnabled:(BOOL)assetMonitorEnabled {
    NSMutableArray<NSMenuItem *> *items = [NSMutableArray array];
    if (!self.sectionNetworkDevicesExpanded) {
        return items;
    }

    if (!assetMonitorEnabled) {
        return items;
    }

    if (networkAssets.count == 0) {
        return items;
    }

    NSString *newBadge = recentNewAssets.count > 0
        ? [NSString stringWithFormat:@" (%lu new)", (unsigned long)recentNewAssets.count]
        : @"";
    NSString *summaryStr = [NSString stringWithFormat:@"%lu Device%@%@",
                           (unsigned long)networkAssets.count,
                           networkAssets.count == 1 ? @"" : @"s",
                           newBadge];
    NSMenuItem *devicesTotalItem = [self styledStatItemWithLabel:@"Total" value:summaryStr
                                                          color:[NSColor labelColor]];
    [items addObject:devicesTotalItem];

    NSSet<NSString *> *localIPs = SNBLocalIPAddresses();
    if (recentNewAssets.count > 0) {
        [items addObject:[self styledMenuItemWithTitle:@"New Devices" style:@"subheader"]];
        NSUInteger limit = MIN(3, recentNewAssets.count);
        for (NSUInteger i = 0; i < limit; i++) {
            SNBNetworkAsset *asset = recentNewAssets[i];

            NSString *line;
            BOOL isLocal = [localIPs containsObject:asset.ipAddress];
            NSString *suffix = isLocal ? @" (This Mac)" : @"";

            if (asset.hostname.length > 0 && asset.vendor.length > 0) {
                line = [NSString stringWithFormat:@"  🆕 %@ (%@) - %@%@",
                       asset.hostname, asset.vendor, asset.ipAddress, suffix];
            } else if (asset.hostname.length > 0) {
                line = [NSString stringWithFormat:@"  🆕 %@ - %@%@", asset.hostname, asset.ipAddress, suffix];
            } else if (asset.vendor.length > 0) {
                line = [NSString stringWithFormat:@"  🆕 %@ - %@%@", asset.vendor, asset.ipAddress, suffix];
            } else {
                line = [NSString stringWithFormat:@"  🆕 %@%@", asset.ipAddress, suffix];
            }
            NSMenuItem *item = [self styledListItemWithText:line
                                                     color:[NSColor secondaryLabelColor]];
            [items addObject:item];
        }
        if (recentNewAssets.count > limit) {
            NSString *moreText = [NSString stringWithFormat:@"  ... and %lu more new",
                                  (unsigned long)(recentNewAssets.count - limit)];
            NSMenuItem *moreNewItem = [self styledListItemWithText:moreText
                                                            color:[NSColor secondaryLabelColor]];
            [items addObject:moreNewItem];
        }
    }

    return items;
}

- (void)replaceMenuItemsAfterHeader:(NSMenuItem *)header
                       beforeItem:(NSMenuItem *)stopItem
                             inMenu:(NSMenu *)menu
                          withItems:(NSArray<NSMenuItem *> *)newItems {
    if (!menu || !header) {
        return;
    }

    NSInteger headerIndex = [menu indexOfItem:header];
    if (headerIndex == NSNotFound) {
        return;
    }

    NSInteger insertionIndex = headerIndex + 1;
    NSInteger stopIndex = stopItem ? [menu indexOfItem:stopItem] : menu.numberOfItems;
    if (stopItem && stopIndex == NSNotFound) {
        stopIndex = menu.numberOfItems;
    }

    while (insertionIndex < stopIndex) {
        [menu removeItemAtIndex:insertionIndex];
        stopIndex -= 1;
    }

    for (NSMenuItem *item in newItems) {
        [menu insertItem:item atIndex:insertionIndex++];
    }
}

- (void)appendProcessActivitySectionWithSummaries:(NSArray<ProcessTrafficSummary *> *)summaries
                                     detailsMenu:(NSMenu *)detailsMenu {
    if (!detailsMenu) {
        return;
    }
    if (!self.showProcessActivity) {
        self.processActivityHeader = nil;
        self.processActivitySeparator = nil;
        self.processActivityItems = [NSMutableArray array];
        return;
    }

    NSMenuItem *lastItem = detailsMenu.itemArray.lastObject;
    if (lastItem && !lastItem.isSeparatorItem) {
        [detailsMenu addItem:[NSMenuItem separatorItem]];
    }

    NSUInteger displayCount = self.configuration.maxTopConnectionsToShow;
    NSString *headerTitle = [NSString stringWithFormat:@"PROCESS ACTIVITY (top %lu)",
                             (unsigned long)displayCount];
    NSMenuItem *processHeader = [self collapsibleSectionHeaderWithTitle:headerTitle
                                                                expanded:self.sectionProcessActivityExpanded
                                                                  action:@selector(toggleSectionProcessActivity)
                                                                  target:self];
    self.processActivityHeader = processHeader;
    [detailsMenu addItem:processHeader];

    NSArray<NSMenuItem *> *items = @[];
    if (self.sectionProcessActivityExpanded) {
        items = [self menuItemsForProcessActivitySectionWithSummaries:summaries];
        for (NSMenuItem *item in items) {
            [detailsMenu addItem:item];
        }
    }
    self.processActivityItems = items.count > 0 ? [items mutableCopy] : [NSMutableArray array];

    NSMenuItem *separator = [NSMenuItem separatorItem];
    self.processActivitySeparator = separator;
    [detailsMenu addItem:separator];
}

- (NSArray<NSMenuItem *> *)menuItemsForProcessActivitySectionWithSummaries:(NSArray<ProcessTrafficSummary *> *)summaries {
    NSMutableArray<NSMenuItem *> *items = [NSMutableArray array];
    NSUInteger destLimit = 3;
    for (ProcessTrafficSummary *summary in summaries) {
        NSString *processLabel = summary.processName.length > 0 ? summary.processName : @"Unknown Process";
        if (summary.processPID > 0) {
            processLabel = [processLabel stringByAppendingFormat:@" (PID %d)", summary.processPID];
        }
        NSString *bytesStr = [SNBByteFormatter stringFromBytes:summary.bytes];
        NSColor *color = [self highlightColorForProcessSummary:summary];
        NSString *icon = [[SNBBadgeRegistry sharedRegistry] badgeIconForProcessName:summary.processName
                                                                                pid:summary.processPID
                                                                     fallbackLabel:processLabel];
        NSMenuItem *processItem = [self styledStatItemWithLabel:processLabel
                                                         value:bytesStr
                                                         color:color
                                                          icon:icon
                                                     showBadge:YES];
        // Fix 5: Add checkmark for processes related to selected connection (including incoming traffic)
        if ([self isProcessSummaryRelatedToSelectedConnection:summary]) {
            processItem.state = NSControlStateValueOn;
        }
        [items addObject:processItem];

        NSMutableArray<NSString *> *details = [NSMutableArray array];
        [details addObject:[NSString stringWithFormat:@"%lu connection%@", (unsigned long)summary.connectionCount,
                            summary.connectionCount == 1 ? @"" : @"s"]];

        // Add direction indicators (↓ incoming, ↑ outgoing)
        NSString *inStr = [SNBByteFormatter stringFromBytes:summary.incomingBytes];
        NSString *outStr = [SNBByteFormatter stringFromBytes:summary.outgoingBytes];
        [details addObject:[NSString stringWithFormat:@"↓%@  ↑%@", inStr, outStr]];

        if (summary.destinations.count > 0) {
            NSUInteger showCount = MIN(destLimit, summary.destinations.count);
            NSArray<NSString *> *destinations = [summary.destinations subarrayWithRange:NSMakeRange(0, showCount)];
            NSString *destList = [destinations componentsJoinedByString:@", "];
            NSString *destComponent = [NSString stringWithFormat:@"dest: %@", destList];
            if (summary.destinations.count > showCount) {
                destComponent = [destComponent stringByAppendingFormat:@" …+%lu", (unsigned long)(summary.destinations.count - showCount)];
            }
            [details addObject:destComponent];
        }
        NSString *detailText = [NSString stringWithFormat:@"  %@", [details componentsJoinedByString:@"  •  "]];
        NSMenuItem *detailItem = [self styledListItemWithText:detailText color:[NSColor secondaryLabelColor]];
        [items addObject:detailItem];
    }
    return [items copy];
}

- (NSString *)sourceLabelForConnection:(ConnectionTraffic *)connection {
    NSString *sourceAddress = connection.sourceAddress ?: @"";
    if (connection.processName.length == 0) {
        return sourceAddress;
    }
    NSString *pidSuffix = connection.processPID > 0 ? [NSString stringWithFormat:@" (PID %d)", (int)connection.processPID] : @"";
    return [NSString stringWithFormat:@"%@%@ @ %@", connection.processName, pidSuffix, sourceAddress];
}

- (NSArray<NSMenuItem *> *)menuItemsForTopHostsSectionWithHosts:(NSArray<HostTraffic *> *)hosts {
    if (!self.sectionTopHostsExpanded) {
        return @[];
    }
    if (hosts.count == 0) {
        NSMenuItem *emptyItem = [self styledStatItemWithLabel:@"No hosts captured yet"
                                                       value:@""
                                                       color:[NSColor secondaryLabelColor]];
        return @[emptyItem];
    }
    NSInteger limit = MIN(self.configuration.maxTopHostsToShow, hosts.count);
    if (limit == 0) {
        return @[];
    }

    NSMutableArray<NSMenuItem *> *items = [NSMutableArray arrayWithCapacity:limit];
    for (NSInteger i = 0; i < limit; i++) {
        HostTraffic *host = hosts[i];
        NSString *hostName = host.hostname.length > 0 ? host.hostname : @"";
        NSString *hostDisplay = hostName.length > 0 ? [NSString stringWithFormat:@"%@ (%@)", hostName, host.address] : host.address;
        NSString *bytesStr = [SNBByteFormatter stringFromBytes:host.bytes];
        NSColor *hostColor = [self highlightColorForHostAddress:host.address];
        NSString *icon = [self badgeIconForHost:host];
        NSMenuItem *hostItem = [self styledStatItemWithLabel:hostDisplay
                                                      value:bytesStr
                                                      color:hostColor
                                                       icon:icon];
        // Add checkmark for selected hosts from map
        if ([self isHostAddressSelected:host.address]) {
            hostItem.state = NSControlStateValueOn;
        }
        [items addObject:hostItem];
    }
    return items;
}

- (NSArray<NSMenuItem *> *)menuItemsForTopConnectionsSectionWithConnections:(NSArray<ConnectionTraffic *> *)connections {
    if (!self.sectionTopConnectionsExpanded) {
        return @[];
    }
    if (connections.count == 0) {
        NSMenuItem *emptyItem = [self styledStatItemWithLabel:@"No connections captured yet"
                                                       value:@""
                                                       color:[NSColor secondaryLabelColor]];
        return @[emptyItem];
    }
    NSInteger limit = MIN(self.configuration.maxTopConnectionsToShow, connections.count);
    if (limit == 0) {
        return @[];
    }

    NSMutableArray<NSMenuItem *> *items = [NSMutableArray arrayWithCapacity:limit];
    for (NSInteger i = 0; i < limit; i++) {
        ConnectionTraffic *connection = connections[i];
        // Show direction indicators (↓ incoming, ↑ outgoing)
        NSString *inStr = [SNBByteFormatter stringFromBytes:connection.incomingBytes];
        NSString *outStr = [SNBByteFormatter stringFromBytes:connection.outgoingBytes];
        NSString *bytesStr = [NSString stringWithFormat:@"↓%@  ↑%@", inStr, outStr];
        NSString *sourceLabel = [self sourceLabelForConnection:connection];
        NSString *connectionLabel = [NSString stringWithFormat:@"%@:%ld → %@:%ld",
                                     sourceLabel,
                                     (long)connection.sourcePort,
                                     connection.destinationAddress,
                                     (long)connection.destinationPort];
        if (connection.processName.length == 0) {
            SNBLogUIDebug("Top connection without processName: %@:%ld -> %@:%ld bytes=%@", connection.sourceAddress,
                          (long)connection.sourcePort, connection.destinationAddress,
                          (long)connection.destinationPort, bytesStr);
        } else {
            SNBLogUIDebug("Top connection uses process %@ (PID %d)", connection.processName, connection.processPID);
        }
        NSColor *connColor = [self processHighlightColorForConnection:connection];
        NSString *connectionIcon = [self badgeIconForConnection:connection];
        NSMenuItem *connectionItem = [self styledStatItemWithLabel:connectionLabel
                                                           value:bytesStr
                                                           color:connColor
                                                            icon:connectionIcon];
        // Add checkmark for selected connection from map
        if ([self isConnectionSelected:connection]) {
            connectionItem.state = NSControlStateValueOn;
        }
        [items addObject:connectionItem];
    }
    return items;
}

- (void)refreshTopHostsSectionWithStats:(TrafficStats *)stats {
    if (!self.detailsSubmenu || !self.topHostsSectionHeader) {
        return;
    }
    NSArray<NSMenuItem *> *items = [self menuItemsForTopHostsSectionWithHosts:stats.topHosts];
    [self replaceMenuItemsAfterHeader:self.topHostsSectionHeader
                          beforeItem:self.topHostsSectionSeparator
                                inMenu:self.detailsSubmenu
                             withItems:items];
}

- (void)refreshTopConnectionsSectionWithStats:(TrafficStats *)stats {
    if (!self.detailsSubmenu || !self.topConnectionsSectionHeader) {
        return;
    }
    NSArray<NSMenuItem *> *items = [self menuItemsForTopConnectionsSectionWithConnections:stats.topConnections];
    [self replaceMenuItemsAfterHeader:self.topConnectionsSectionHeader
                          beforeItem:self.topConnectionsSectionSeparator
                                inMenu:self.detailsSubmenu
                             withItems:items];
}

- (void)refreshProcessActivitySectionWithStats:(TrafficStats *)stats {
    SNBLogUIDebug("refreshProcessActivitySection: detailsSubmenu=%p, processActivityHeader=%p",
                  self.detailsSubmenu, self.processActivityHeader);
    if (!self.detailsSubmenu || !self.processActivityHeader) {
        SNBLogUIDebug("refreshProcessActivitySection: EARLY RETURN - missing submenu or header");
        return;
    }
    if (!self.showProcessActivity) {
        SNBLogUIDebug("refreshProcessActivitySection: EARLY RETURN - showProcessActivity is NO");
        return;
    }
    if (!self.sectionProcessActivityExpanded) {
        SNBLogUIDebug("refreshProcessActivitySection: section collapsed, clearing items");
        [self replaceMenuItemsAfterHeader:self.processActivityHeader
                              beforeItem:self.processActivitySeparator
                                    inMenu:self.detailsSubmenu
                                 withItems:@[]];
        self.processActivityItems = [NSMutableArray array];
        return;
    }
    SNBLogUIDebug("refreshProcessActivitySection: rebuilding with selection src=%{public}@ dst=%{public}@",
                  self.selectedSourceIP, self.selectedDestinationIP);
    NSArray<NSMenuItem *> *items = [self menuItemsForProcessActivitySectionWithSummaries:stats.processSummaries ?: @[]];
    SNBLogUIDebug("refreshProcessActivitySection: created %lu items", (unsigned long)items.count);
    [self replaceMenuItemsAfterHeader:self.processActivityHeader
                          beforeItem:self.processActivitySeparator
                                inMenu:self.detailsSubmenu
                             withItems:items];
    self.processActivityItems = items.count > 0 ? [items mutableCopy] : [NSMutableArray array];
    SNBLogUIDebug("refreshProcessActivitySection: completed replacement");
}

- (NSArray<NSMenuItem *> *)menuItemsForMaliciousConnectionsSectionWithEntries:(NSArray<NSDictionary *> *)entries {
    if (entries.count == 0) {
        return @[];
    }
    NSMutableArray<NSMenuItem *> *items = [NSMutableArray array];
    NSInteger limit = MIN(self.configuration.maxTopConnectionsToShow, entries.count);
    for (NSInteger i = 0; i < limit; i++) {
        NSDictionary *entry = entries[i];
        ConnectionTraffic *connection = entry[@"connection"];
        TIEnrichmentResponse *response = entry[@"response"];
        NSString *indicator = entry[@"indicator"] ?: @"";
        TIScoringResult *scoring = response.scoringResult;
        NSString *bytesStr = [SNBByteFormatter stringFromBytes:connection.bytes];
        NSString *providers = [self providerSummaryForResponse:response];
        NSString *indicatorText = indicator.length > 0 ? [NSString stringWithFormat:@"indicator %@", indicator] : @"indicator unknown";
        NSString *sourceLabel = [self sourceLabelForConnection:connection];
        NSString *displayStr = [NSString stringWithFormat:@"  %@:%ld -> %@:%ld - %@ - score %ld - %@",
                                sourceLabel,
                                (long)connection.sourcePort,
                                connection.destinationAddress,
                                (long)connection.destinationPort,
                                bytesStr,
                                (long)scoring.finalScore,
                                indicatorText];
        NSMenuItem *maliciousItem = [[NSMenuItem alloc] initWithTitle:displayStr
                                                              action:nil
                                                       keyEquivalent:@""];
        maliciousItem.enabled = NO;
        [items addObject:maliciousItem];

        NSString *providerLine = [NSString stringWithFormat:@"    Providers: %@", providers];
        NSMenuItem *providersItem = [[NSMenuItem alloc] initWithTitle:providerLine
                                                               action:nil
                                                        keyEquivalent:@""];
        providersItem.enabled = NO;
        [items addObject:providersItem];
    }
    if (entries.count > limit) {
        NSMenuItem *moreItem = [[NSMenuItem alloc] initWithTitle:[NSString stringWithFormat:@"  ... and %lu more",
                                                                 (unsigned long)(entries.count - limit)]
                                                         action:nil
                                                  keyEquivalent:@""];
        moreItem.enabled = NO;
        [items addObject:moreItem];
    }
    return items;
}

- (NSArray<NSString *> *)activeCleanConnectionsFromStats:(TrafficStats *)stats
                                        threatIntelResults:(NSDictionary<NSString *, TIEnrichmentResponse *> *)threatIntelResults {
    if (!stats || !threatIntelResults) {
        return @[];
    }
    NSSet<NSString *> *activeDestIPs = stats.allActiveDestinationIPs ?: [NSSet set];
    NSMutableArray<NSString *> *activeCleanIPs = [NSMutableArray array];
    for (NSString *ip in threatIntelResults) {
        TIEnrichmentResponse *response = threatIntelResults[ip];
        TIScoringResult *scoring = response.scoringResult;
        if (scoring && scoring.verdict == TIThreatVerdictClean && [activeDestIPs containsObject:ip]) {
            [activeCleanIPs addObject:ip];
        }
    }
    return activeCleanIPs;
}

- (NSArray<NSMenuItem *> *)menuItemsForCleanConnectionsSectionWithStats:(TrafficStats *)stats
                                                          threatIntelResults:(NSDictionary<NSString *, TIEnrichmentResponse *> *)threatIntelResults {
    if (!self.showCleanConnections) {
        return @[];
    }
    NSArray<NSString *> *activeCleanIPs = [self activeCleanConnectionsFromStats:stats threatIntelResults:threatIntelResults];
    NSUInteger count = activeCleanIPs.count;
    if (count == 0) {
        return @[];
    }

    NSMutableArray<NSMenuItem *> *items = [NSMutableArray array];
    NSUInteger limit = MIN(10, count);
    for (NSUInteger i = 0; i < limit; i++) {
        NSString *ip = activeCleanIPs[i];
        TIEnrichmentResponse *response = threatIntelResults[ip];
        ThreatInfo *cleanInfo = [[ThreatInfo alloc] init];
        cleanInfo.ipAddress = ip;
        cleanInfo.response = response;
        cleanInfo.severityLevel = ThreatSeverityNone;
        cleanInfo.score = response.scoringResult ? response.scoringResult.finalScore : 0;
        cleanInfo.isActive = YES;
        cleanInfo.totalBytes = [self totalBytesForIP:ip inStats:stats];

        NSArray<ConnectionTraffic *> *connections = [self connectionsForIP:ip inStats:stats];
        cleanInfo.connectionCount = connections.count;
        if (connections.count > 0) {
            cleanInfo.primaryConnection = connections[0];
        }

        [items addObject:[self enhancedThreatItemForThreat:cleanInfo]];
        [items addObject:[self threatDetailItemForThreat:cleanInfo]];
        NSMenuItem *connItem = [self threatConnectionItemForThreat:cleanInfo];
        if (connItem) {
            [items addObject:connItem];
        }
    }

    if (count > limit) {
        NSMenuItem *moreItem = [[NSMenuItem alloc] initWithTitle:[NSString stringWithFormat:@"  ... and %lu more",
                                                                 (unsigned long)(count - limit)]
                                                         action:nil
                                                  keyEquivalent:@""];
        moreItem.enabled = NO;
        [items addObject:moreItem];
    }
    return items;
}

- (NSArray<NSMenuItem *> *)menuItemsForThreatDetails:(ThreatInfo *)threat
                                          connection:(ConnectionTraffic *)connection {
    if (!threat) {
        return @[];
    }

    NSMutableArray<NSMenuItem *> *items = [NSMutableArray array];
    NSDictionary *persisted = connection ? [self persistedConnectionDetailsForConnection:connection] : @{};
    NSDictionary *persistedByIP = [self persistedConnectionDetailsForIP:threat.ipAddress];
    NSDictionary *anomalyDetails = [self persistedAnomalyDetailsForIP:threat.ipAddress];
    TIEnrichmentResponse *response = [self cachedThreatIntelResponseForIP:threat.ipAddress
                                                                 existing:threat.response];
    TIScoringResult *scoring = response.scoringResult;

    [items addObject:[self styledMenuItemWithTitle:[NSString stringWithFormat:@"Indicator: %@",
                                                    threat.ipAddress ?: @"Unknown"]
                                            style:@"data"]];

    NSString *sourceAddress = connection.sourceAddress ?: persistedByIP[@"sourceAddress"] ?: @"Unknown";
    NSNumber *sourcePort = connection.sourcePort > 0 ? @(connection.sourcePort) : persistedByIP[@"sourcePort"];
    NSString *destinationAddress = connection.destinationAddress ?: persistedByIP[@"destinationAddress"] ?: @"Unknown";
    NSNumber *destinationPort = connection.destinationPort > 0 ? @(connection.destinationPort) : persistedByIP[@"destinationPort"];
    if (sourceAddress.length > 0 || destinationAddress.length > 0) {
        [items addObject:[self styledMenuItemWithTitle:[NSString stringWithFormat:@"Connection: %@:%@ -> %@:%@",
                                                        sourceAddress,
                                                        sourcePort ?: @"?",
                                                        destinationAddress,
                                                        destinationPort ?: @"?"]
                                                style:@"data"]];
    }

    NSString *processName = connection.processName.length > 0 ? connection.processName : persisted[@"processName"];
    if (processName.length == 0) {
        processName = persistedByIP[@"processName"];
    }
    NSNumber *persistedPID = persisted[@"processPID"];
    if (!persistedPID) {
        persistedPID = persistedByIP[@"processPID"];
    }
    pid_t pid = connection.processPID > 0 ? connection.processPID : (pid_t)persistedPID.intValue;
    NSString *processLine = nil;
    if (processName.length > 0 && pid > 0) {
        processLine = [NSString stringWithFormat:@"Process: %@ [%d]", processName, pid];
    } else if (processName.length > 0) {
        processLine = [NSString stringWithFormat:@"Process: %@ [N/A]", processName];
    } else if (pid > 0) {
        processLine = [NSString stringWithFormat:@"Process: N/A [%d]", pid];
    } else {
        processLine = @"Process: N/A [N/A]";
    }
    [items addObject:[self styledMenuItemWithTitle:processLine style:@"data"]];

    if (pid > 0 || processName.length > 0) {
        [items addObject:[NSMenuItem separatorItem]];
        [items addObject:[self styledMenuItemWithTitle:@"Process Risk" style:@"subheader"]];
        if (pid > 0) {
            SNBProcessRiskReport *report = [[SNBProcessRiskEvaluator sharedEvaluator] evaluatePID:pid
                                                                                     processName:processName
                                                                                      connection:connection
                                                                                          threat:threat];
            if (report) {
                [items addObject:[self styledMenuItemWithTitle:[NSString stringWithFormat:@"Risk: %@",
                                                               report.summary ?: @"Unknown"]
                                                        style:@"data"]];
                for (NSString *line in report.infoLines) {
                    if (line.length > 0) {
                        [items addObject:[self styledMenuItemWithTitle:line style:@"data"]];
                    }
                }
                NSInteger maxSignals = MIN((NSInteger)report.signals.count, 4);
                for (NSInteger i = 0; i < maxSignals; i++) {
                    SNBRiskSignal *signal = report.signals[i];
                    NSString *line = [NSString stringWithFormat:@"Signal: %@ (%ld)",
                                      signal.title ?: @"Unknown", (long)signal.score];
                    [items addObject:[self styledMenuItemWithTitle:line style:@"data"]];
                }
            } else {
                [items addObject:[self styledMenuItemWithTitle:@"Risk: Unavailable"
                                                        style:@"data"]];
            }
        } else {
            [items addObject:[self styledMenuItemWithTitle:@"Risk: Unavailable (missing PID)"
                                                    style:@"data"]];
        }
    }

    return items;
}

- (NSArray<NSMenuItem *> *)menuItemsForSelectedThreatDetails:(ThreatInfo *)threat {
    ConnectionTraffic *connection = self.selectedThreatConnection ?: threat.primaryConnection;
    return [self menuItemsForThreatDetails:threat connection:connection];
}

- (void)refreshCleanConnectionsSectionWithStats:(TrafficStats *)stats
                               threatIntelResults:(NSDictionary<NSString *, TIEnrichmentResponse *> *)threatIntelResults {
    if (!self.visualizationSubmenu || !self.cleanConnectionsHeader) {
        return;
    }
    NSArray<NSString *> *activeCleanIPs = [self activeCleanConnectionsFromStats:stats
                                                               threatIntelResults:threatIntelResults];
    NSString *expandIndicator = self.showCleanConnections ? @"▼" : @"▶";
    NSString *cleanTitle = [NSString stringWithFormat:@"%@ Observed Connections (%lu)",
                            expandIndicator, (unsigned long)activeCleanIPs.count];
    self.cleanConnectionsHeader.title = cleanTitle;
    NSArray<NSMenuItem *> *items = [self menuItemsForCleanConnectionsSectionWithStats:stats
                                                                     threatIntelResults:threatIntelResults];
    [self replaceMenuItemsAfterHeader:self.cleanConnectionsHeader
                          beforeItem:self.cleanConnectionsSeparator
                                inMenu:self.visualizationSubmenu
                             withItems:items];
}

- (void)refreshDetailStatsWithStats:(TrafficStats *)stats {
    NSString *captureValue = [self captureStartDisplayValue];
    [self updateDetailItemForKey:SNBMenuItemKeyCaptureStart value:captureValue];

    [self updateDetailItemForKey:SNBMenuItemKeyDetailIncoming value:[SNBByteFormatter stringFromBytes:stats.incomingBytes]];
    [self updateDetailItemForKey:SNBMenuItemKeyDetailOutgoing value:[SNBByteFormatter stringFromBytes:stats.outgoingBytes]];
    [self updateDetailItemForKey:SNBMenuItemKeyDetailTotal value:[SNBByteFormatter stringFromBytes:stats.totalBytes]];
    [self updateDetailItemForKey:SNBMenuItemKeyDetailPackets value:[NSString stringWithFormat:@"%llu", stats.totalPackets]];
}

- (void)refreshMaliciousConnectionsSectionWithStats:(TrafficStats *)stats
                                 threatIntelResults:(NSDictionary<NSString *, TIEnrichmentResponse *> *)threatIntelResults {
    if (!self.detailsSubmenu || !self.maliciousConnectionsHeader) {
        return;
    }
    NSArray<NSDictionary *> *maliciousConnections = [self maliciousConnectionsFromStats:stats
                                                                     threatIntelResults:threatIntelResults];
    NSArray<NSMenuItem *> *items = [self menuItemsForMaliciousConnectionsSectionWithEntries:maliciousConnections];
    [self replaceMenuItemsAfterHeader:self.maliciousConnectionsHeader
                          beforeItem:self.maliciousConnectionsSeparator
                                inMenu:self.detailsSubmenu
                             withItems:items];
}

- (void)refreshNetworkDevicesSectionWithAssets:(NSArray<SNBNetworkAsset *> *)networkAssets
                                recentNewAssets:(NSArray<SNBNetworkAsset *> *)recentNewAssets
                            assetMonitorEnabled:(BOOL)assetMonitorEnabled {
    if (!self.networkDevicesSectionHeader || !self.visualizationSubmenu) {
        return;
    }
    NSArray<NSMenuItem *> *newItems = [self menuItemsForNetworkDevicesSectionWithAssets:networkAssets
                                                                       recentNewAssets:recentNewAssets
                                                                   assetMonitorEnabled:assetMonitorEnabled];
    [self replaceMenuItemsAfterHeader:self.networkDevicesSectionHeader
                          beforeItem:self.networkDevicesSectionSeparator
                                inMenu:self.visualizationSubmenu
                             withItems:newItems];
    self.networkDevicesSectionItems = newItems.count > 0 ? [newItems mutableCopy] : [NSMutableArray array];
}

- (void)menuDidClose {
    self.menuIsOpen = NO;
    SNBLogUIDebug("Status menu closed");
    if (!self.mapMenuView.detachedWindowVisible) {
        [self tearDownMapMenuItem];
    }
    self.visualizationSubmenu = nil;
    self.detailsSubmenu = nil;
    self.topHostsSectionHeader = nil;
    self.topHostsSectionSeparator = nil;
    self.topConnectionsSectionHeader = nil;
    self.topConnectionsSectionSeparator = nil;
    self.maliciousConnectionsHeader = nil;
    self.maliciousConnectionsSeparator = nil;
    self.cleanConnectionsHeader = nil;
    self.cleanConnectionsSeparator = nil;
    self.processActivityHeader = nil;
    self.processActivitySeparator = nil;
    self.processActivityItems = nil;
    [self.detailStatItemInfo removeAllObjects];
}

- (void)selectMapProviderWithName:(NSString *)providerName stats:(TrafficStats *)stats {
    if (providerName.length == 0) {
        return;
    }
    NSString *providerValue = [providerName isEqualToString:@"Custom (UserDefaults)"] ? @"custom" : providerName;
    self.mapProviderName = providerValue;
    [[NSUserDefaults standardUserDefaults] setObject:self.mapProviderName
                                              forKey:SNBUserDefaultsKeyMapProvider];
    SNBLogUIDebug("Map provider selected: %{public}@", self.mapProviderName);
    if (self.mapMenuView) {
        self.mapMenuView.providerName = self.mapProviderName;
        if (self.showMap && stats) {
            NSArray<ConnectionTraffic *> *mapConnections = [self cachedMapConnectionsForStats:stats];
            [self.mapMenuView updateWithConnections:mapConnections
                                 threatIntelResults:self.lastThreatIntelResults ?: @{}
                                          blockedIPs:self.blockedIPs];
        }
    }
}

// Performance: Wrapper that adds caching and throttling to rebuild
- (void)updateVisualizationMenuWithStats:(TrafficStats *)stats
                      threatIntelEnabled:(BOOL)threatIntelEnabled
                 threatIntelStatusMessage:(NSString *)threatIntelStatusMessage
                     threatIntelResults:(NSDictionary<NSString *, TIEnrichmentResponse *> *)threatIntelResults
                              cacheStats:(NSDictionary *)cacheStats
                    assetMonitorEnabled:(BOOL)assetMonitorEnabled
                         networkAssets:(NSArray<SNBNetworkAsset *> *)networkAssets
                       recentNewAssets:(NSArray<SNBNetworkAsset *> *)recentNewAssets {
    [self updateModelCachesWithStats:stats threatIntelResults:threatIntelResults];
    // Performance: Just call rebuild with reduced frequency (10s instead of 5s)
    // The real optimization is in refreshVisualizationWithStats throttling
    [self rebuildVisualizationMenuWithStats:stats
                        threatIntelEnabled:threatIntelEnabled
                   threatIntelStatusMessage:threatIntelStatusMessage
                       threatIntelResults:threatIntelResults
                                cacheStats:cacheStats
                      assetMonitorEnabled:assetMonitorEnabled
                           networkAssets:networkAssets
                         recentNewAssets:recentNewAssets];
    [self truncateMenuItemsInMenu:self.visualizationSubmenu maxWidth:self.configuration.menuFixedWidth];
}

- (void)rebuildVisualizationMenuWithStats:(TrafficStats *)stats
                      threatIntelEnabled:(BOOL)threatIntelEnabled
                 threatIntelStatusMessage:(NSString *)threatIntelStatusMessage
                     threatIntelResults:(NSDictionary<NSString *, TIEnrichmentResponse *> *)threatIntelResults
                              cacheStats:(NSDictionary *)cacheStats
                    assetMonitorEnabled:(BOOL)assetMonitorEnabled
                         networkAssets:(NSArray<SNBNetworkAsset *> *)networkAssets
                       recentNewAssets:(NSArray<SNBNetworkAsset *> *)recentNewAssets {
    NSMenu *visualizationSubmenu = self.visualizationSubmenu;
    if (!visualizationSubmenu) {
        return;
    }
    [self updateModelCachesWithStats:stats threatIntelResults:threatIntelResults];
    self.networkActivityGraphItem.view = nil;
    self.networkActivityGraphItem = nil;
    self.networkActivityGraphView = nil;

    [self.dynamicStatItemInfo removeAllObjects];
    [self.detailStatItemInfo removeAllObjects];

    if (self.showMap && self.menuIsOpen) {
        [self mapMenuItemIfNeeded];
    }

    [visualizationSubmenu removeAllItems];
    ConfigurationManager *config = self.configuration;

    NSMenu *detailsSubmenu = [[NSMenu alloc] init];
    NSMenuItem *detailsItem = [[NSMenuItem alloc] initWithTitle:@"Details" action:nil keyEquivalent:@""];
    detailsItem.submenu = detailsSubmenu;
    self.detailsSubmenu = detailsSubmenu;
    self.topHostsSectionHeader = nil;
    self.topHostsSectionSeparator = nil;
    self.topConnectionsSectionHeader = nil;
    self.topConnectionsSectionSeparator = nil;
    self.maliciousConnectionsHeader = nil;
    self.maliciousConnectionsSeparator = nil;
    self.cleanConnectionsHeader = nil;
    self.cleanConnectionsSeparator = nil;

    // ============================================================================
    // PHASE 1 & 2: Unified Threat Display with Severity Grouping
    // ============================================================================

    [visualizationSubmenu addItem:[self collapsibleSectionHeaderWithTitle:@"ACTIVE UNCLASSIFIED"
                                                                  expanded:self.sectionThreatsExpanded
                                                                    action:@selector(toggleSectionThreats)
                                                                    target:self]];

    // Reset threat counts (will be updated if threats are found)
    self.activeMaliciousCount = 0;
    self.activeSuspiciousCount = 0;

    if (self.sectionThreatsExpanded) {
        if (!threatIntelEnabled) {
            NSMenuItem *disabledItem = [[NSMenuItem alloc] initWithTitle:@"✓ Threat Intel: Off"
                                                                 action:nil
                                                          keyEquivalent:@""];
            disabledItem.enabled = NO;
            [visualizationSubmenu addItem:disabledItem];
        } else if (threatIntelStatusMessage.length > 0 && (threatIntelResults == nil || threatIntelResults.count == 0)) {
            NSMenuItem *unavailableItem = [[NSMenuItem alloc] initWithTitle:threatIntelStatusMessage
                                                                     action:nil
                                                              keyEquivalent:@""];
            unavailableItem.enabled = NO;
            [visualizationSubmenu addItem:unavailableItem];
        } else if (threatIntelResults == nil || threatIntelResults.count == 0) {
            NSMenuItem *scanningItem = [[NSMenuItem alloc] initWithTitle:@"⟳ Scanning connections..."
                                                              action:nil
                                                       keyEquivalent:@""];
            scanningItem.enabled = NO;
            [visualizationSubmenu addItem:scanningItem];
        } else {
        // Get ALL active destination IPs for accurate threat detection
        NSSet<NSString *> *activeDestIPs = stats.allActiveDestinationIPs ?: [NSSet set];

        // Categorize threats by severity level (High/Medium/Low)
        NSDictionary<NSNumber *, NSArray<ThreatInfo *> *> *categorizedThreats =
            [self categorizeThreats:threatIntelResults activeIPs:activeDestIPs stats:stats];

        NSArray<ThreatInfo *> *highThreats = categorizedThreats[@(ThreatSeverityHigh)] ?: @[];
        NSArray<ThreatInfo *> *mediumThreats = categorizedThreats[@(ThreatSeverityMedium)] ?: @[];
        NSArray<ThreatInfo *> *lowThreats = categorizedThreats[@(ThreatSeverityLow)] ?: @[];

        // Separate active from historical
        NSMutableArray<ThreatInfo *> *activeHighThreats = [NSMutableArray array];
        NSMutableArray<ThreatInfo *> *historicalThreats = [NSMutableArray array];
        for (ThreatInfo *threat in highThreats) {
            if (threat.isActive) {
                [activeHighThreats addObject:threat];
            } else {
                [historicalThreats addObject:threat];
            }
        }

        NSMutableArray<ThreatInfo *> *activeMediumThreats = [NSMutableArray array];
        for (ThreatInfo *threat in mediumThreats) {
            if (threat.isActive) {
                [activeMediumThreats addObject:threat];
            } else {
                [historicalThreats addObject:threat];
            }
        }

        NSMutableArray<ThreatInfo *> *activeLowThreats = [NSMutableArray array];
        for (ThreatInfo *threat in lowThreats) {
            if (threat.isActive) {
                [activeLowThreats addObject:threat];
            } else {
                [historicalThreats addObject:threat];
            }
        }

        NSUInteger totalActiveThreats = activeHighThreats.count + activeMediumThreats.count + activeLowThreats.count;

        // Update status bar alert counts (High = Malicious, Medium = Suspicious)
        self.activeMaliciousCount = activeHighThreats.count;
        self.activeSuspiciousCount = activeMediumThreats.count;

        // Show threat summary
        if (totalActiveThreats > 0) {
            // Summary count with breakdown
            NSString *summaryTitle;
            if (activeHighThreats.count > 0 && activeMediumThreats.count > 0) {
                summaryTitle = [NSString stringWithFormat:@"%lu Active Unclassified (%lu High, %lu Med)",
                               (unsigned long)totalActiveThreats,
                               (unsigned long)activeHighThreats.count,
                               (unsigned long)activeMediumThreats.count];
            } else if (activeHighThreats.count > 0) {
                summaryTitle = [NSString stringWithFormat:@"%lu High Severity Unclassified",
                               (unsigned long)activeHighThreats.count];
            } else {
                summaryTitle = [NSString stringWithFormat:@"%lu Active Unclassified",
                               (unsigned long)totalActiveThreats];
            }

            NSMenuItem *alertItem = [[NSMenuItem alloc] initWithTitle:summaryTitle
                                                              action:nil
                                                       keyEquivalent:@""];
            alertItem.enabled = NO;
            NSImage *alertIcon = [NSImage imageWithSystemSymbolName:@"exclamationmark.triangle"
                                            accessibilityDescription:nil];
            if (alertIcon) {
                NSImageSymbolConfiguration *config =
                    [NSImageSymbolConfiguration configurationWithPointSize:12.0 weight:NSFontWeightSemibold];
                alertIcon = [alertIcon imageWithSymbolConfiguration:config] ?: alertIcon;
                alertIcon.template = YES;
                alertItem.image = alertIcon;
            }
            NSFont *boldFont = [NSFont boldSystemFontOfSize:13.0];
            NSDictionary *attributes = @{NSFontAttributeName: boldFont,
                                       NSForegroundColorAttributeName: [NSColor systemRedColor]};
            alertItem.attributedTitle = [[NSAttributedString alloc] initWithString:summaryTitle
                                                                        attributes:attributes];
            [visualizationSubmenu addItem:alertItem];

            // HIGH SEVERITY THREATS (Always visible)
            if (activeHighThreats.count > 0) {
                [visualizationSubmenu addItem:[self severityHeaderForLevel:ThreatSeverityHigh count:activeHighThreats.count]];

                for (ThreatInfo *threat in activeHighThreats) {
                    [visualizationSubmenu addItem:[self enhancedThreatItemForThreat:threat]];
                    [visualizationSubmenu addItem:[self threatDetailItemForThreat:threat]];
                    NSArray<NSMenuItem *> *connItems = [self selectableThreatConnectionItemsForThreat:threat stats:stats];
                    for (NSMenuItem *item in connItems) {
                        [visualizationSubmenu addItem:item];
                    }
                }
            }

            // MEDIUM SEVERITY THREATS (Always visible)
            if (activeMediumThreats.count > 0) {
                [visualizationSubmenu addItem:[self severityHeaderForLevel:ThreatSeverityMedium count:activeMediumThreats.count]];

                for (ThreatInfo *threat in activeMediumThreats) {
                    [visualizationSubmenu addItem:[self enhancedThreatItemForThreat:threat]];
                    [visualizationSubmenu addItem:[self threatDetailItemForThreat:threat]];
                    NSArray<NSMenuItem *> *connItems = [self selectableThreatConnectionItemsForThreat:threat stats:stats];
                    for (NSMenuItem *item in connItems) {
                        [visualizationSubmenu addItem:item];
                    }
                }
            }

            // LOW SEVERITY THREATS (Expandable - collapsed by default)
            if (activeLowThreats.count > 0) {
                NSString *expandIndicator = self.showLowSeverityThreats ? @"▼" : @"▶";
                NSString *lowTitle = [NSString stringWithFormat:@"%@ LOW SEVERITY (%lu)",
                                     expandIndicator, (unsigned long)activeLowThreats.count];
                NSMenuItem *lowToggle = [[NSMenuItem alloc] initWithTitle:lowTitle
                                                                  action:@selector(toggleShowLowSeverityThreats)
                                                           keyEquivalent:@""];
                lowToggle.target = self;
                [visualizationSubmenu addItem:lowToggle];

                if (self.showLowSeverityThreats) {
                    for (ThreatInfo *threat in activeLowThreats) {
                        [visualizationSubmenu addItem:[self enhancedThreatItemForThreat:threat]];
                        [visualizationSubmenu addItem:[self threatDetailItemForThreat:threat]];
                        NSArray<NSMenuItem *> *connItems = [self selectableThreatConnectionItemsForThreat:threat stats:stats];
                        for (NSMenuItem *item in connItems) {
                            [visualizationSubmenu addItem:item];
                        }
                    }
                }
            }

        } else {
        NSMenuItem *cleanItem = [[NSMenuItem alloc] initWithTitle:@"No Active Unclassified"
                                                              action:nil
                                                       keyEquivalent:@""];
        cleanItem.enabled = NO;
        NSImage *cleanIcon = [NSImage imageWithSystemSymbolName:@"checkmark.circle"
                                        accessibilityDescription:nil];
        if (cleanIcon) {
            NSImageSymbolConfiguration *config =
                [NSImageSymbolConfiguration configurationWithPointSize:12.0 weight:NSFontWeightSemibold];
            cleanIcon = [cleanIcon imageWithSymbolConfiguration:config] ?: cleanIcon;
            cleanIcon.template = YES;
            cleanItem.image = cleanIcon;
        }
        NSFont *systemFont = [NSFont systemFontOfSize:[NSFont systemFontSize]];
        NSDictionary *attributes = @{NSFontAttributeName: systemFont,
                                       NSForegroundColorAttributeName: [NSColor labelColor]};
        cleanItem.attributedTitle = [[NSAttributedString alloc] initWithString:cleanItem.title
                                                                    attributes:attributes];
        [visualizationSubmenu addItem:cleanItem];
        }

        // HISTORICAL THREATS (Expandable - collapsed by default)
        if (historicalThreats.count > 0) {
            NSString *expandIndicator = self.showHistoricalThreats ? @"▼" : @"▶";
            NSString *histTitle = [NSString stringWithFormat:@"%@ Closed Unclassified (%lu closed)",
                                  expandIndicator, (unsigned long)historicalThreats.count];
            NSMenuItem *histToggle = [[NSMenuItem alloc] initWithTitle:histTitle
                                                                action:@selector(toggleShowHistoricalThreats)
                                                         keyEquivalent:@""];
            histToggle.target = self;
            [visualizationSubmenu addItem:histToggle];

            if (self.showHistoricalThreats) {
                for (ThreatInfo *threat in historicalThreats) {
                    [visualizationSubmenu addItem:[self enhancedThreatItemForThreat:threat]];
                    [visualizationSubmenu addItem:[self threatDetailItemForThreat:threat]];
                    NSArray<NSMenuItem *> *connItems = [self selectableThreatConnectionItemsForThreat:threat stats:stats];
                    for (NSMenuItem *item in connItems) {
                        [visualizationSubmenu addItem:item];
                    }
                }
            }
        }

        if (self.selectedThreatInfo) {
            NSArray<NSMenuItem *> *detailItems = [self menuItemsForSelectedThreatDetails:self.selectedThreatInfo];
            if (detailItems.count > 0) {
                NSMenuItem *detailsItem = [[NSMenuItem alloc] initWithTitle:@"Selected Unclassified Details"
                                                                     action:nil
                                                              keyEquivalent:@""];
                detailsItem.enabled = YES;
                NSMenu *detailsMenu = [[NSMenu alloc] initWithTitle:@"Selected Unclassified Details"];
                [detailsMenu addItem:[self styledMenuItemWithTitle:@"Selected Unclassified Details" style:@"header"]];
                for (NSMenuItem *item in detailItems) {
                    [detailsMenu addItem:item];
                }
                detailsItem.submenu = detailsMenu;
                [visualizationSubmenu addItem:[NSMenuItem separatorItem]];
                [visualizationSubmenu addItem:detailsItem];
            }
        }

        // CLEAN CONNECTIONS (Expandable - collapsed by default)
        NSMutableArray<NSString *> *activeCleanIPs = [NSMutableArray array];
        for (NSString *ip in threatIntelResults) {
            TIEnrichmentResponse *response = threatIntelResults[ip];
            TIScoringResult *scoring = response.scoringResult;
            if (scoring && scoring.verdict == TIThreatVerdictClean && [activeDestIPs containsObject:ip]) {
                [activeCleanIPs addObject:ip];
            }
        }

        if (activeCleanIPs.count > 0) {
            NSString *expandIndicator = self.showCleanConnections ? @"▼" : @"▶";
            NSString *cleanTitle = [NSString stringWithFormat:@"%@ Observed Connections (%lu)",
                                   expandIndicator, (unsigned long)activeCleanIPs.count];
            NSMenuItem *cleanToggle = [[NSMenuItem alloc] initWithTitle:cleanTitle
                                                                action:@selector(toggleShowCleanConnections)
                                                         keyEquivalent:@""];
            cleanToggle.target = self;
            [visualizationSubmenu addItem:cleanToggle];
            self.cleanConnectionsHeader = cleanToggle;

            if (self.showCleanConnections) {
                NSArray<NSMenuItem *> *cleanItems = [self menuItemsForCleanConnectionsSectionWithStats:stats
                                                                                 threatIntelResults:threatIntelResults];
                for (NSMenuItem *item in cleanItems) {
                    [visualizationSubmenu addItem:item];
                }
            }
            NSMenuItem *cleanSeparator = [NSMenuItem separatorItem];
            self.cleanConnectionsSeparator = cleanSeparator;
            [visualizationSubmenu addItem:cleanSeparator];
        } else {
            self.cleanConnectionsHeader = nil;
            self.cleanConnectionsSeparator = nil;
        }

        if (self.promotionAgentEnabled) {
            [self appendPromotionAgentSectionToMenu:visualizationSubmenu];
            [visualizationSubmenu addItem:[NSMenuItem separatorItem]];
        }

        // LEGITIMATE CONNECTIONS SECTION (Expandable)
        NSArray<SNBTrustContext *> *trustedContexts = [self.trustedStore allTrustedIPContexts];
        if (trustedContexts.count > 0) {
            NSString *expandIndicator = self.showTrustedIPs ? @"▼" : @"▶";
            NSString *trustedTitle = [NSString stringWithFormat:@"%@ Legitimate Connections (%lu)",
                                     expandIndicator, (unsigned long)trustedContexts.count];
            NSMenuItem *trustedToggle = [[NSMenuItem alloc] initWithTitle:trustedTitle
                                                                  action:@selector(toggleShowTrustedIPs)
                                                           keyEquivalent:@""];
            trustedToggle.target = self;

            NSMutableAttributedString *trustedAttr = [[NSMutableAttributedString alloc] initWithString:trustedTitle];
            [trustedAttr addAttribute:NSForegroundColorAttributeName
                                value:[NSColor labelColor]
                                range:NSMakeRange(0, trustedTitle.length)];
            trustedToggle.attributedTitle = trustedAttr;

            [visualizationSubmenu addItem:trustedToggle];

            if (self.showTrustedIPs) {
                for (SNBTrustContext *ctx in trustedContexts) {
                    NSString *reasonStr = [SNBTrustContext displayStringForReason:ctx.reason];
                    NSString *itemTitle = [NSString stringWithFormat:@"  %@ (%@)", ctx.ipAddress, reasonStr];

                    NSMenuItem *ipItem = [[NSMenuItem alloc] initWithTitle:itemTitle
                                                                    action:nil
                                                             keyEquivalent:@""];
                    ipItem.state = NSControlStateValueOn;  // Checkmark shows it's trusted

                    // Style trusted items
                    NSMutableAttributedString *ipAttr = [[NSMutableAttributedString alloc] initWithString:itemTitle];
                    [ipAttr addAttribute:NSForegroundColorAttributeName
                                   value:[NSColor secondaryLabelColor]
                                   range:NSMakeRange(0, itemTitle.length)];
                    [ipAttr addAttribute:NSFontAttributeName
                                   value:[NSFont systemFontOfSize:11.0]
                                   range:NSMakeRange(0, itemTitle.length)];
                    ipItem.attributedTitle = ipAttr;

                    NSMenu *trustedSubmenu = [[NSMenu alloc] initWithTitle:@"Legitimate Connection Actions"];
                    NSMenuItem *untrustItem = [[NSMenuItem alloc] initWithTitle:@"Untrust"
                                                                         action:@selector(moveTrustedIPToPreviousThreats:)
                                                                  keyEquivalent:@""];
                    untrustItem.target = self;
                    untrustItem.representedObject = ctx.ipAddress;
                    NSMutableAttributedString *untrustAttr = [[NSMutableAttributedString alloc] initWithString:@"Untrust"];
                    [untrustAttr addAttribute:NSForegroundColorAttributeName
                                        value:[NSColor systemRedColor]
                                        range:NSMakeRange(0, untrustAttr.length)];
                    untrustItem.attributedTitle = untrustAttr;
                    [trustedSubmenu addItem:untrustItem];
                    ipItem.submenu = trustedSubmenu;

                    [visualizationSubmenu addItem:ipItem];
                }
            }
            [visualizationSubmenu addItem:[NSMenuItem separatorItem]];
        }

        // Provider status (expandable)
        if (self.showProviderDetails) {
            [visualizationSubmenu addItem:[NSMenuItem separatorItem]];
            [visualizationSubmenu addItem:[self styledMenuItemWithTitle:@"Provider Details" style:@"subheader"]];
            if (cacheStats) {
                NSString *sizeStr = [NSString stringWithFormat:@"%@", cacheStats[@"size"]];
                NSString *hitRateStr = [NSString stringWithFormat:@"%.1f%%", [cacheStats[@"hitRate"] doubleValue] * 100];
                NSString *statsStr = [NSString stringWithFormat:@"  Cache: %@ entries, %@ hit rate", sizeStr, hitRateStr];
                NSMenuItem *statsItem = [[NSMenuItem alloc] initWithTitle:statsStr action:nil keyEquivalent:@""];
                statsItem.enabled = NO;
                [visualizationSubmenu addItem:statsItem];
            }
        }
        }
    }

    [visualizationSubmenu addItem:[NSMenuItem separatorItem]];

    // Network Snapshot - Current Activity (everything above shows ONLY active connections)
    NSMenuItem *networkActivityHeader = [self collapsibleSectionHeaderWithTitle:@"NETWORK ACTIVITY"
                                                                       expanded:self.sectionNetworkActivityExpanded
                                                                         action:@selector(toggleSectionNetworkActivity)
                                                                         target:self];
    self.networkActivitySectionHeader = networkActivityHeader;
    [visualizationSubmenu addItem:networkActivityHeader];

    if (self.sectionNetworkActivityExpanded) {
        NSMenuItem *graphItem = [self networkActivityGraphMenuItemWithWidth:self.configuration.menuFixedWidth];
        [visualizationSubmenu addItem:graphItem];
        NSString *rateStr = [SNBByteFormatter stringFromBytes:stats.bytesPerSecond];
        NSMenuItem *rateItem = [self styledStatItemWithLabel:@"Rate" value:[NSString stringWithFormat:@"%@/s", rateStr]
                                                      color:[NSColor labelColor]];
        [self cacheStatItem:rateItem label:@"Rate" color:[NSColor labelColor] forKey:SNBMenuItemKeyNetworkRate];
        [visualizationSubmenu addItem:rateItem];
        NSString *totalBytesStr = [SNBByteFormatter stringFromBytes:stats.totalBytes];
        NSMenuItem *totalBytesItem = [self styledStatItemWithLabel:@"Total" value:totalBytesStr
                                                          color:[NSColor labelColor]];
        [self cacheStatItem:totalBytesItem label:@"Total" color:[NSColor labelColor] forKey:SNBMenuItemKeyNetworkTotal];
        [visualizationSubmenu addItem:totalBytesItem];

        // Active connection counts - show both total and geolocated on same line
        NSArray<ConnectionTraffic *> *mapConnections = [self connectionsForMapFromStats:stats];
        NSUInteger totalPublicConnections = mapConnections.count;

        // Update map with current connections. Note: drawnConnectionCount is updated
        // asynchronously on a background queue, so we cache the value to avoid blocking
        // the main thread. The count may be briefly stale but will converge as geolocation completes.
        if (self.showMap && self.mapMenuView) {
            [self.mapMenuView updateWithConnections:mapConnections
                                 threatIntelResults:self.lastThreatIntelResults ?: @{}
                                          blockedIPs:self.blockedIPs];
            self.lastGeolocatedConnectionCount = self.mapMenuView.drawnConnectionCount;
        }
        if (mapConnections.count == 0) {
            self.lastGeolocatedConnectionCount = 0;
        }
        NSUInteger geolocatedConnections = MIN(self.lastGeolocatedConnectionCount, totalPublicConnections);

        // Combine connections and geolocated on one line: "Connections  8  (6 Geolocated)"
        NSString *connectionsValue = [NSString stringWithFormat:@"%lu  (%lu Geolocated)",
                                      (unsigned long)totalPublicConnections,
                                      (unsigned long)geolocatedConnections];
        NSMenuItem *connectionsItem = [self styledStatItemWithLabel:@"Active Connections" value:connectionsValue
                                                             color:[NSColor secondaryLabelColor]];
        [self cacheStatItem:connectionsItem label:@"Active Connections"
                      color:[NSColor secondaryLabelColor] forKey:SNBMenuItemKeyActiveConnections];
        [visualizationSubmenu addItem:connectionsItem];

        NSString *hostsStr = [NSString stringWithFormat:@"%lu", (unsigned long)stats.topHosts.count];
        NSMenuItem *hostsItem = [self styledStatItemWithLabel:@"Hosts" value:hostsStr
                                                       color:[NSColor secondaryLabelColor]];
        [self cacheStatItem:hostsItem label:@"Hosts" color:[NSColor secondaryLabelColor] forKey:SNBMenuItemKeyHosts];
        [visualizationSubmenu addItem:hostsItem];
        self.networkActivitySectionItems = [NSMutableArray arrayWithObjects:graphItem, rateItem, totalBytesItem, connectionsItem, hostsItem, nil];
    } else {
        self.networkActivitySectionItems = [NSMutableArray array];
    }

    NSMenuItem *networkActivitySeparator = [NSMenuItem separatorItem];
    self.networkActivitySectionSeparator = networkActivitySeparator;
    [visualizationSubmenu addItem:networkActivitySeparator];

    if (assetMonitorEnabled) {
        // Asset Monitor - Collapsible
        NSMenuItem *networkDevicesHeader = [self collapsibleSectionHeaderWithTitle:@"NETWORK DEVICES"
                                                                        expanded:self.sectionNetworkDevicesExpanded
                                                                          action:@selector(toggleSectionNetworkDevices)
                                                                          target:self];
        self.networkDevicesSectionHeader = networkDevicesHeader;
        [visualizationSubmenu addItem:networkDevicesHeader];

        NSMutableArray<NSMenuItem *> *networkDevicesItems = [NSMutableArray array];
        if (self.sectionNetworkDevicesExpanded) {
            if (networkAssets.count == 0) {
                NSMenuItem *emptyItem = [[NSMenuItem alloc] initWithTitle:@"⟳ Scanning network..."
                                                                  action:nil
                                                           keyEquivalent:@""];
                emptyItem.enabled = NO;
                [visualizationSubmenu addItem:emptyItem];
                [networkDevicesItems addObject:emptyItem];
            } else {
                // Show device count summary
                NSString *newBadge = recentNewAssets.count > 0 ? [NSString stringWithFormat:@" (%lu new)",
                                                                    (unsigned long)recentNewAssets.count] : @"";
                NSString *summaryStr = [NSString stringWithFormat:@"%lu Device%@%@",
                                       (unsigned long)networkAssets.count,
                                       networkAssets.count == 1 ? @"" : @"s",
                                       newBadge];
                NSMenuItem *devicesTotalItem = [self styledStatItemWithLabel:@"Total" value:summaryStr
                                                                      color:[NSColor labelColor]];
                [self cacheStatItem:devicesTotalItem label:@"Total" color:[NSColor labelColor]
                              forKey:SNBMenuItemKeyNetworkDevicesTotal];
                [visualizationSubmenu addItem:devicesTotalItem];
                [networkDevicesItems addObject:devicesTotalItem];

                // Always show new devices (important!)
                if (recentNewAssets.count > 0) {
                    NSMenuItem *newDevicesHeader = [self styledMenuItemWithTitle:@"New Devices" style:@"subheader"];
                    [visualizationSubmenu addItem:newDevicesHeader];
                    [networkDevicesItems addObject:newDevicesHeader];
                    NSUInteger limit = MIN(3, recentNewAssets.count);
                    for (NSUInteger i = 0; i < limit; i++) {
                        SNBNetworkAsset *asset = recentNewAssets[i];

                        // Build display name with hostname, vendor, and IP
                        NSString *line;
                        if (asset.hostname.length > 0 && asset.vendor.length > 0) {
                            line = [NSString stringWithFormat:@"  🆕 %@ (%@)", asset.hostname, asset.vendor];
                        } else if (asset.hostname.length > 0) {
                            line = [NSString stringWithFormat:@"  🆕 %@", asset.hostname];
                        } else if (asset.vendor.length > 0) {
                            line = [NSString stringWithFormat:@"  🆕 %@ - %@", asset.vendor, asset.ipAddress];
                        } else {
                            line = [NSString stringWithFormat:@"  🆕 %@", asset.ipAddress];
                        }

                        NSMenuItem *item = [[NSMenuItem alloc] initWithTitle:line action:nil keyEquivalent:@""];
                        item.enabled = NO;
                        [visualizationSubmenu addItem:item];
                        [networkDevicesItems addObject:item];
                    }
                    if (recentNewAssets.count > limit) {
                        NSMenuItem *moreNewItem = [[NSMenuItem alloc] initWithTitle:[NSString stringWithFormat:@"  ... and %lu more new",
                                                                                    (unsigned long)(recentNewAssets.count - limit)]
                                                                            action:nil
                                                                     keyEquivalent:@""];
                        moreNewItem.enabled = NO;
                        [visualizationSubmenu addItem:moreNewItem];
                        [networkDevicesItems addObject:moreNewItem];
                    }
                }
            }
        }
        self.networkDevicesSectionItems = networkDevicesItems;

        NSMenuItem *networkDevicesSeparator = [NSMenuItem separatorItem];
        self.networkDevicesSectionSeparator = networkDevicesSeparator;
        [visualizationSubmenu addItem:networkDevicesSeparator];
    } else {
        self.networkDevicesSectionHeader = nil;
        self.networkDevicesSectionSeparator = nil;
        self.networkDevicesSectionItems = [NSMutableArray array];
    }
    [visualizationSubmenu addItem:detailsItem];

    // Details submenu content
    if (self.showMap && self.menuIsOpen && !self.mapMenuView.detachedWindowVisible) {
        if (self.mapMenuItem.menu && self.mapMenuItem.menu != detailsSubmenu) {
            [self.mapMenuItem.menu removeItem:self.mapMenuItem];
        }
        NSMenuItem *mapItem = [self mapMenuItemIfNeeded];
        if (mapItem) {
            [detailsSubmenu addItem:mapItem];
            [detailsSubmenu addItem:[NSMenuItem separatorItem]];
        }
    } else {
        if (self.mapMenuItem.menu) {
            [self.mapMenuItem.menu removeItem:self.mapMenuItem];
        }
        if (!self.mapMenuView.detachedWindowVisible) {
            [self tearDownMapMenuItem];
        }
    }

    NSString *captureValue = [self captureStartDisplayValue];
    NSMenuItem *captureItem = [self styledStatItemWithLabel:@"Capture started:" value:captureValue color:[NSColor labelColor]];
    [self cacheDetailItem:captureItem label:@"Capture started:" color:[NSColor labelColor] forKey:SNBMenuItemKeyCaptureStart];
    [detailsSubmenu addItem:captureItem];

    NSString *incomingStr = [SNBByteFormatter stringFromBytes:stats.incomingBytes];
    NSMenuItem *incomingItem = [self styledStatItemWithLabel:@"↓ Incoming:" value:incomingStr color:[NSColor labelColor]];
    [self cacheDetailItem:incomingItem label:@"↓ Incoming:" color:[NSColor labelColor] forKey:SNBMenuItemKeyDetailIncoming];
    [detailsSubmenu addItem:incomingItem];

    NSString *outgoingStr = [SNBByteFormatter stringFromBytes:stats.outgoingBytes];
    NSMenuItem *outgoingItem = [self styledStatItemWithLabel:@"↑ Outgoing:" value:outgoingStr color:[NSColor labelColor]];
    [self cacheDetailItem:outgoingItem label:@"↑ Outgoing:" color:[NSColor labelColor] forKey:SNBMenuItemKeyDetailOutgoing];
    [detailsSubmenu addItem:outgoingItem];

    NSString *totalBytesStr = [SNBByteFormatter stringFromBytes:stats.totalBytes];
    NSMenuItem *bytesItem = [self styledStatItemWithLabel:@"Total:" value:totalBytesStr color:[NSColor labelColor]];
    [self cacheDetailItem:bytesItem label:@"Total:" color:[NSColor labelColor] forKey:SNBMenuItemKeyDetailTotal];
    [detailsSubmenu addItem:bytesItem];

    NSString *packetsStr = [NSString stringWithFormat:@"%llu", stats.totalPackets];
    NSMenuItem *packetsItem = [self styledStatItemWithLabel:@"Packets:" value:packetsStr color:[NSColor labelColor]];
    [self cacheDetailItem:packetsItem label:@"Packets:" color:[NSColor labelColor] forKey:SNBMenuItemKeyDetailPackets];
    [detailsSubmenu addItem:packetsItem];

    if (self.showTopHosts) {
        [detailsSubmenu addItem:[NSMenuItem separatorItem]];
        NSString *topHostsTitle = [NSString stringWithFormat:@"TOP %lu HOSTS by Traffic",
                                    (unsigned long)self.configuration.maxTopHostsToShow];
        NSMenuItem *topHostsHeader = [self collapsibleSectionHeaderWithTitle:topHostsTitle
                                                                    expanded:self.sectionTopHostsExpanded
                                                                      action:@selector(toggleSectionTopHosts)
                                                                      target:self];
        self.topHostsSectionHeader = topHostsHeader;
        [detailsSubmenu addItem:topHostsHeader];

            if (self.sectionTopHostsExpanded) {
                if (stats.topHosts.count == 0) {
                    NSMenuItem *emptyItem = [self styledStatItemWithLabel:@"No hosts captured yet"
                                                                   value:@""
                                                                   color:[NSColor secondaryLabelColor]];
                    [detailsSubmenu addItem:emptyItem];
                } else {
                    NSInteger count = MIN(config.maxTopHostsToShow, stats.topHosts.count);
                    for (NSInteger i = 0; i < count; i++) {
                        HostTraffic *host = stats.topHosts[i];
                        NSString *hostName = host.hostname.length > 0 ? host.hostname : @"";
                        NSString *hostDisplay = hostName.length > 0 ? [NSString stringWithFormat:@"%@ (%@)", hostName, host.address] : host.address;
                        NSString *bytesStr = [SNBByteFormatter stringFromBytes:host.bytes];
                        NSMenuItem *hostItem = [self styledStatItemWithLabel:hostDisplay
                                                                       value:bytesStr
                                                                       color:[NSColor labelColor]];
                        [detailsSubmenu addItem:hostItem];
                    }
                }
            }

        NSMenuItem *hostsTerminator = [NSMenuItem separatorItem];
        self.topHostsSectionSeparator = hostsTerminator;
        [detailsSubmenu addItem:hostsTerminator];
    } else {
        self.topHostsSectionHeader = nil;
        self.topHostsSectionSeparator = nil;
    }

    if (self.showTopConnections) {
        if (!self.topHostsSectionHeader) {
            [detailsSubmenu addItem:[NSMenuItem separatorItem]];
        }
        NSString *topConnectionsTitle = [NSString stringWithFormat:@"TOP %lu CONNECTIONS by Traffic",
                                         (unsigned long)self.configuration.maxTopConnectionsToShow];
        NSMenuItem *topConnectionsHeader = [self collapsibleSectionHeaderWithTitle:topConnectionsTitle
                                                                        expanded:self.sectionTopConnectionsExpanded
                                                                          action:@selector(toggleSectionTopConnections)
                                                                          target:self];
        self.topConnectionsSectionHeader = topConnectionsHeader;
        [detailsSubmenu addItem:topConnectionsHeader];

        if (self.sectionTopConnectionsExpanded) {
            if (stats.topConnections.count == 0) {
                NSMenuItem *emptyItem = [self styledStatItemWithLabel:@"No connections captured yet"
                                                               value:@""
                                                               color:[NSColor secondaryLabelColor]];
                [detailsSubmenu addItem:emptyItem];
            } else {
                NSInteger count = MIN(config.maxTopConnectionsToShow, stats.topConnections.count);
                for (NSInteger i = 0; i < count; i++) {
                    ConnectionTraffic *connection = stats.topConnections[i];
                    // Show direction indicators (↓ incoming, ↑ outgoing)
                    NSString *inStr = [SNBByteFormatter stringFromBytes:connection.incomingBytes];
                    NSString *outStr = [SNBByteFormatter stringFromBytes:connection.outgoingBytes];
                    NSString *bytesStr = [NSString stringWithFormat:@"↓%@  ↑%@", inStr, outStr];
                    NSString *connectionLabel = [NSString stringWithFormat:@"%@:%ld → %@:%ld",
                                                 connection.sourceAddress,
                                                 (long)connection.sourcePort,
                                                 connection.destinationAddress,
                                                 (long)connection.destinationPort];
                    NSMenuItem *connectionItem = [self styledStatItemWithLabel:connectionLabel
                                                                          value:bytesStr
                                                                          color:[NSColor labelColor]];
                    [detailsSubmenu addItem:connectionItem];
                }
            }
        }

        NSMenuItem *connectionsTerminator = [NSMenuItem separatorItem];
        self.topConnectionsSectionSeparator = connectionsTerminator;
        [detailsSubmenu addItem:connectionsTerminator];
    } else {
        self.topConnectionsSectionHeader = nil;
        self.topConnectionsSectionSeparator = nil;
    }

    if (self.showProcessActivity) {
        [self appendProcessActivitySectionWithSummaries:stats.processSummaries detailsMenu:detailsSubmenu];
    } else {
        self.processActivityHeader = nil;
        self.processActivitySeparator = nil;
        self.processActivityItems = [NSMutableArray array];
    }

    if (assetMonitorEnabled && networkAssets.count > 0) {
        if (!self.topConnectionsSectionSeparator) {
            [detailsSubmenu addItem:[NSMenuItem separatorItem]];
        }
        NSString *networkDevicesTitle = @"NETWORK DEVICES";
        if (self.selectedDeviceDisplayName.length > 0) {
            networkDevicesTitle = [NSString stringWithFormat:@"NETWORK DEVICES (%@)", self.selectedDeviceDisplayName];
        }
        [detailsSubmenu addItem:[self collapsibleSectionHeaderWithTitle:networkDevicesTitle
                                                                expanded:self.sectionNetworkAssetsExpanded
                                                                  action:@selector(toggleSectionNetworkAssets)
                                                                  target:self]];

        if (self.sectionNetworkAssetsExpanded) {
            NSSet<NSString *> *localIPs = SNBLocalIPAddresses();
            NSUInteger limit = MIN(10, networkAssets.count);
            for (NSUInteger i = 0; i < limit; i++) {
                SNBNetworkAsset *asset = networkAssets[i];

                // Build display name with hostname and vendor
                NSString *line;
                BOOL isLocal = [localIPs containsObject:asset.ipAddress];
                NSString *suffix = isLocal ? @" (This Mac)" : @"";

                if (asset.hostname.length > 0 && asset.vendor.length > 0) {
                    // Show: hostname (vendor) - IP
                    line = [NSString stringWithFormat:@"  %@ (%@) - %@%@",
                           asset.hostname, asset.vendor, asset.ipAddress, suffix];
                } else if (asset.hostname.length > 0) {
                    // Show: hostname - IP
                    line = [NSString stringWithFormat:@"  %@ - %@%@",
                           asset.hostname, asset.ipAddress, suffix];
                } else if (asset.vendor.length > 0) {
                    // Show: vendor - IP
                    line = [NSString stringWithFormat:@"  %@ - %@%@",
                           asset.vendor, asset.ipAddress, suffix];
                } else {
                    // Show: IP only (no duplicate)
                    line = [NSString stringWithFormat:@"  %@%@", asset.ipAddress, suffix];
                }
                NSMenuItem *assetItem = [[NSMenuItem alloc] initWithTitle:line action:nil keyEquivalent:@""];
                assetItem.enabled = NO;
                [detailsSubmenu addItem:assetItem];
            }
        }
    }

    if (threatIntelEnabled && threatIntelStatusMessage.length > 0 &&
        (threatIntelResults == nil || threatIntelResults.count == 0)) {
        [detailsSubmenu addItem:[NSMenuItem separatorItem]];
        NSMenuItem *threatTitle = [[NSMenuItem alloc] initWithTitle:@"THREAT INTELLIGENCE" action:nil keyEquivalent:@""];
        threatTitle.enabled = NO;
        [detailsSubmenu addItem:threatTitle];

        NSMenuItem *statusItem = [[NSMenuItem alloc] initWithTitle:[NSString stringWithFormat:@"  %@", threatIntelStatusMessage]
                                                            action:nil
                                                     keyEquivalent:@""];
        statusItem.enabled = NO;
        [detailsSubmenu addItem:statusItem];
    } else if (threatIntelEnabled && threatIntelResults.count > 0) {
        // Build set of active destination IPs
        // Note: The old THREAT INTELLIGENCE display has been removed.
        // See the new "ACTIVE UNCLASSIFIED" section in the main Visualization menu
        // for the enhanced severity-based threat display.

        NSArray<NSDictionary *> *maliciousConnections = [self maliciousConnectionsFromStats:stats
                                                                        threatIntelResults:threatIntelResults];
        if (maliciousConnections.count > 0) {
            [detailsSubmenu addItem:[NSMenuItem separatorItem]];
            NSMenuItem *maliciousTitle = [[NSMenuItem alloc] initWithTitle:@"SUSPICIOUS NETWORK ACTIVITY (UNCONFIRMED)"
                                                                    action:nil
                                                             keyEquivalent:@""];
            maliciousTitle.enabled = NO;
            self.maliciousConnectionsHeader = maliciousTitle;
            [detailsSubmenu addItem:maliciousTitle];

            NSArray<NSMenuItem *> *maliciousItems = [self menuItemsForMaliciousConnectionsSectionWithEntries:maliciousConnections];
            for (NSMenuItem *item in maliciousItems) {
                [detailsSubmenu addItem:item];
            }

            NSMenuItem *maliciousSeparator = [NSMenuItem separatorItem];
            self.maliciousConnectionsSeparator = maliciousSeparator;
            [detailsSubmenu addItem:maliciousSeparator];
        } else {
            self.maliciousConnectionsHeader = nil;
            self.maliciousConnectionsSeparator = nil;
        }

        if (cacheStats && self.debugEnabled) {
            [detailsSubmenu addItem:[NSMenuItem separatorItem]];
            NSString *sizeStr = [NSString stringWithFormat:@"%@", cacheStats[@"size"]];
            NSString *hitRateStr = [NSString stringWithFormat:@"%.1f%%", [cacheStats[@"hitRate"] doubleValue] * 100];
            NSString *statsStr = [NSString stringWithFormat:@"Cache: %@ entries - %@ hit rate", sizeStr, hitRateStr];

            NSMenuItem *statsItem = [[NSMenuItem alloc] initWithTitle:statsStr action:nil keyEquivalent:@""];
            statsItem.enabled = NO;
            [detailsSubmenu addItem:statsItem];
        }
    }

    [self appendServiceHealthSectionToDetailsMenu:detailsSubmenu];
}

#pragma mark - Expandable Section Toggles

- (void)toggleShowCleanConnections {
    self.showCleanConnections = !self.showCleanConnections;
    SNBLogUIDebug("Toggled clean connections: %d", self.showCleanConnections);
    [self requestFullVisualizationRefresh];
}

- (void)selectThreatConnection:(NSMenuItem *)sender {
    id payload = sender.representedObject;
    ThreatInfo *threat = nil;
    ConnectionTraffic *connection = nil;
    if ([payload isKindOfClass:[NSDictionary class]]) {
        NSDictionary *info = (NSDictionary *)payload;
        threat = [info[@"threat"] isKindOfClass:[ThreatInfo class]] ? info[@"threat"] : nil;
        connection = [info[@"connection"] isKindOfClass:[ConnectionTraffic class]] ? info[@"connection"] : nil;
    } else if ([payload isKindOfClass:[ThreatInfo class]]) {
        threat = (ThreatInfo *)payload;
    }
    if (!threat) {
        return;
    }
    self.selectedThreatInfo = threat;
    self.selectedThreatConnection = connection;
    [self requestFullVisualizationRefresh];
}

- (SNBTrustFeatureVector *)trustFeatureVectorForThreat:(ThreatInfo *)threat
                                            connection:(ConnectionTraffic *)connection {
    SNBTrustFeatureVector *vector = [[SNBTrustFeatureVector alloc] init];
    if (!threat || threat.ipAddress.length == 0) {
        return vector;
    }

    TIEnrichmentResponse *response = [self cachedThreatIntelResponseForIP:threat.ipAddress
                                                                 existing:threat.response];
    SNBTrustFeatureExtractor *extractor = [[SNBTrustFeatureExtractor alloc] init];
    vector = [extractor featureVectorForIP:threat.ipAddress
                                  response:response
                                connection:connection ?: threat.primaryConnection
                                totalBytes:threat.totalBytes
                           connectionCount:threat.connectionCount];
    return vector;
}

- (void)toggleTrustedIP:(NSMenuItem *)sender {
    id represented = sender.representedObject;
    NSString *ip = nil;
    ThreatInfo *threat = nil;
    ConnectionTraffic *connection = nil;
    if ([represented isKindOfClass:[NSDictionary class]]) {
        NSDictionary *info = (NSDictionary *)represented;
        ip = [info[@"ip"] isKindOfClass:[NSString class]] ? info[@"ip"] : nil;
        threat = [info[@"threat"] isKindOfClass:[ThreatInfo class]] ? info[@"threat"] : nil;
        connection = [info[@"connection"] isKindOfClass:[ConnectionTraffic class]] ? info[@"connection"] : nil;
    } else if ([represented isKindOfClass:[NSString class]]) {
        ip = (NSString *)represented;
    }
    if (!ip.length) {
        return;
    }

    BOOL isTrusted = [self.trustedStore isTrustedIP:ip];
    BOOL shouldTrust = !isTrusted;

    SNBTrustContext *context = nil;
    if (shouldTrust && threat) {
        context = [[SNBTrustContext alloc] init];
        context.ipAddress = ip;
        context.reason = SNBTrustReasonUnspecified;
        context.threatScoreAtDecision = threat.score;
        TIScoringResult *scoring = threat.response.scoringResult;
        context.verdictAtDecision = scoring ? [scoring verdictString] : nil;
        if (connection) {
            context.processName = connection.processName;
            context.processPID = connection.processPID;
            context.destinationPort = connection.destinationPort;
        } else if (threat.primaryConnection) {
            context.processName = threat.primaryConnection.processName;
            context.processPID = threat.primaryConnection.processPID;
            context.destinationPort = threat.primaryConnection.destinationPort;
        }
    } else if (!shouldTrust) {
        context = [self.trustedStore trustContextForIP:ip] ?: [[SNBTrustContext alloc] init];
        context.ipAddress = ip;
        if (context.reason == 0) {
            context.reason = SNBTrustReasonUnspecified;
        }
    }

    if (shouldTrust && !context) {
        SNBLogUIDebug("Toggle trusted: missing threat context for %s", ip.UTF8String);
        return;
    }

    if (context) {
        [self.trustedStore setTrusted:shouldTrust forIP:ip withContext:context];
    } else {
        [self.trustedStore setTrusted:shouldTrust forIP:ip];
    }

    if (threat) {
        SNBTrustFeatureVector *vector = [self trustFeatureVectorForThreat:threat connection:connection];
        [[SNBTrustLearningEngine sharedEngine] recordFeedbackForIP:ip
                                                           trusted:shouldTrust
                                                            reason:context ? context.reason : SNBTrustReasonUnspecified
                                                     featureVector:vector];
    } else if (!shouldTrust) {
        SNBTrustFeatureVector *vector = [[SNBTrustFeatureVector alloc] init];
        vector.ipAddress = ip;
        [[SNBTrustLearningEngine sharedEngine] recordFeedbackForIP:ip
                                                           trusted:NO
                                                            reason:SNBTrustReasonUnspecified
                                                     featureVector:vector];
    }

    sender.state = shouldTrust ? NSControlStateValueOn : NSControlStateValueOff;
    [self requestFullVisualizationRefresh];
}

- (void)toggleShowAllAssets {
    self.showAllAssets = !self.showAllAssets;
    SNBLogUIDebug("Toggled show all assets: %d", self.showAllAssets);
    [self requestFullVisualizationRefresh];
}

- (void)toggleShowProviderDetails {
    self.showProviderDetails = !self.showProviderDetails;
    SNBLogUIDebug("Toggled provider details: %d", self.showProviderDetails);
    [self requestFullVisualizationRefresh];
}

- (void)toggleShowLowSeverityThreats {
    self.showLowSeverityThreats = !self.showLowSeverityThreats;
    SNBLogUIDebug("Toggled low severity threats: %d", self.showLowSeverityThreats);
    [self requestFullVisualizationRefresh];
}

- (void)toggleShowHistoricalThreats {
    self.showHistoricalThreats = !self.showHistoricalThreats;
    SNBLogUIDebug("Toggled historical threats: %d", self.showHistoricalThreats);
    [self requestFullVisualizationRefresh];
}

- (void)toggleShowTrustedIPs {
    self.showTrustedIPs = !self.showTrustedIPs;
    SNBLogUIDebug("Toggled trusted IPs: %d", self.showTrustedIPs);
    [self requestFullVisualizationRefresh];
}

- (void)moveTrustedIPToPreviousThreats:(NSMenuItem *)sender {
    NSString *ip = [sender.representedObject isKindOfClass:[NSString class]] ? sender.representedObject : nil;
    if (!ip.length) {
        return;
    }

    SNBTrustContext *context = [self.trustedStore trustContextForIP:ip] ?: [[SNBTrustContext alloc] init];
    context.ipAddress = ip;
    if (context.reason == 0) {
        context.reason = SNBTrustReasonUnspecified;
    }

    [self.trustedStore setTrusted:NO forIP:ip withContext:context];
    [self requestFullVisualizationRefresh];
}

#pragma mark - Main Section Toggles

- (void)toggleSectionThreats {
    self.sectionThreatsExpanded = !self.sectionThreatsExpanded;
    SNBLogUIDebug("Toggled threats section: %d", self.sectionThreatsExpanded);
    [self requestFullVisualizationRefresh];
}

- (void)toggleSectionNetworkActivity {
    self.sectionNetworkActivityExpanded = !self.sectionNetworkActivityExpanded;
    SNBLogUIDebug("Toggled network activity section: %d", self.sectionNetworkActivityExpanded);
    [self requestFullVisualizationRefresh];
}

- (void)toggleSectionNetworkDevices {
    self.sectionNetworkDevicesExpanded = !self.sectionNetworkDevicesExpanded;
    SNBLogUIDebug("Toggled network devices section: %d", self.sectionNetworkDevicesExpanded);
    [self requestFullVisualizationRefresh];
}

- (void)toggleSectionTopHosts {
    self.sectionTopHostsExpanded = !self.sectionTopHostsExpanded;
    SNBLogUIDebug("Toggled top hosts section: %d", self.sectionTopHostsExpanded);

    // Fix 4: Use incremental refresh if menu structure exists, otherwise request full rebuild
    if (self.lastTrafficStats && self.topHostsSectionHeader) {
        [self refreshTopHostsSectionWithStats:self.lastTrafficStats];
    } else {
        [self requestFullVisualizationRefresh];
    }
}

- (void)toggleSectionTopConnections {
    self.sectionTopConnectionsExpanded = !self.sectionTopConnectionsExpanded;
    SNBLogUIDebug("Toggled top connections section: %d", self.sectionTopConnectionsExpanded);

    // Fix 4: Use incremental refresh if menu structure exists, otherwise request full rebuild
    if (self.lastTrafficStats && self.topConnectionsSectionHeader) {
        [self refreshTopConnectionsSectionWithStats:self.lastTrafficStats];
    } else {
        [self requestFullVisualizationRefresh];
    }
}

- (void)toggleSectionNetworkAssets {
    self.sectionNetworkAssetsExpanded = !self.sectionNetworkAssetsExpanded;
    SNBLogUIDebug("Toggled network assets section: %d", self.sectionNetworkAssetsExpanded);
    [self requestFullVisualizationRefresh];
}

- (void)toggleSectionProcessActivity {
    self.sectionProcessActivityExpanded = !self.sectionProcessActivityExpanded;
    SNBLogUIDebug("Toggled process activity section: %d", self.sectionProcessActivityExpanded);

    // Fix 4: Use incremental refresh if menu structure exists, otherwise request full rebuild
    if (self.lastTrafficStats && self.processActivityHeader) {
        [self refreshProcessActivitySectionWithStats:self.lastTrafficStats];
    } else {
        [self requestFullVisualizationRefresh];
    }
}

#pragma mark - MapMenuViewDelegate

- (void)mapMenuView:(MapMenuView *)mapView didSelectConnectionWithSource:(NSString *)sourceIP destination:(NSString *)destinationIP {
    self.selectedSourceIP = sourceIP;
    self.selectedDestinationIP = destinationIP;
    SNBLogUIDebug("Map selection changed: src=%{public}@ dst=%{public}@", sourceIP, destinationIP);
    SNBLogUIDebug("  lastTrafficStats=%p, detailsSubmenu=%p, processActivityHeader=%p",
                  self.lastTrafficStats, self.detailsSubmenu, self.processActivityHeader);

    // Directly refresh sections that show highlighting instead of requesting full rebuild
    // (full rebuild is skipped when menu is open to keep it stable)
    if (self.lastTrafficStats) {
        // Recalculate host color map based on new selection state
        [self updateProcessHighlightColorsWithSummaries:self.lastTrafficStats.processSummaries ?: @[]];

        SNBLogUIDebug("Calling refreshTopHostsSection...");
        [self refreshTopHostsSectionWithStats:self.lastTrafficStats];
        SNBLogUIDebug("Calling refreshTopConnectionsSection...");
        [self refreshTopConnectionsSectionWithStats:self.lastTrafficStats];
        SNBLogUIDebug("Calling refreshProcessActivitySection...");
        [self refreshProcessActivitySectionWithStats:self.lastTrafficStats];

        // Fix 3: Track when selection refresh occurred to avoid redundant refreshes
        self.lastSelectionRefreshTime = [NSDate timeIntervalSinceReferenceDate];
        SNBLogUIDebug("Refreshed sections with highlighting for selection");
    } else {
        SNBLogUIDebug("SKIPPED refresh - lastTrafficStats is nil");
    }
}

- (void)mapMenuViewDidClearSelection:(MapMenuView *)mapView {
    self.selectedSourceIP = nil;
    self.selectedDestinationIP = nil;
    SNBLogUIDebug("Map selection cleared");

    // Directly refresh sections to remove highlighting
    if (self.lastTrafficStats) {
        // Recalculate host color map now that selection is cleared
        [self updateProcessHighlightColorsWithSummaries:self.lastTrafficStats.processSummaries ?: @[]];

        [self refreshTopHostsSectionWithStats:self.lastTrafficStats];
        [self refreshTopConnectionsSectionWithStats:self.lastTrafficStats];
        [self refreshProcessActivitySectionWithStats:self.lastTrafficStats];

        // Fix 3: Track when selection refresh occurred to avoid redundant refreshes
        self.lastSelectionRefreshTime = [NSDate timeIntervalSinceReferenceDate];
        SNBLogUIDebug("Refreshed sections after clearing selection");
    }
}

- (void)mapMenuViewDidDetachMap:(MapMenuView *)mapView {
    [self requestFullVisualizationRefresh];
}

- (void)mapMenuViewDidAttachMap:(MapMenuView *)mapView {
    [self requestFullVisualizationRefresh];
}

- (void)mapMenuView:(MapMenuView *)mapView didRequestAction:(NSString *)action forIP:(NSString *)ipAddress {
    if (action.length == 0 || ipAddress.length == 0) {
        return;
    }
    NSString *normalizedAction = [action lowercaseString];
    if ([normalizedAction isEqualToString:@"label"]) {
        [self.trustedStore setTrusted:YES forIP:ipAddress];
        [self.blockedIPs removeObject:ipAddress];
    } else if ([normalizedAction isEqualToString:@"block"]) {
        [self.trustedStore setTrusted:NO forIP:ipAddress];
        [self.blockedIPs addObject:ipAddress];
    } else if ([normalizedAction isEqualToString:@"ignore"]) {
        [self.trustedStore setTrusted:NO forIP:ipAddress];
        [self.blockedIPs removeObject:ipAddress];
    }

    if ([self.delegate respondsToSelector:@selector(menuBuilder:didRequestMapAction:forIP:)]) {
        [self.delegate menuBuilder:self didRequestMapAction:normalizedAction forIP:ipAddress];
    }

    [self requestFullVisualizationRefresh];
}

@end

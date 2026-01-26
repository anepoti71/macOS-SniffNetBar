//
//  AppCoordinator.m
//  SniffNetBar
//
//  Main coordinator for orchestrating application subsystems
//

#import "AppCoordinator.h"
#import "ConfigurationManager.h"
#import "DeviceManager.h"
#import "MenuBuilder.h"
#import "NetworkDevice.h"
#import "PacketCaptureManager.h"
#import "PacketInfo.h"
#import "ThreatIntelCoordinator.h"
#import "Logger.h"
#import "TrafficStatistics.h"
#import "AnomalyDetector.h"
#import "AnomalyStore.h"
#import "AnomalyExplainabilityCoordinator.h"
#import "KeychainManager.h"
#import "NetworkAssetMonitor.h"
#import "UserDefaultsKeys.h"
#import "StatisticsHistory.h"
#import "SNBTimerCoordinator.h"
#import "SNBEventPublisher.h"
#import "SNBEventSchema.h"
#import "SNBModelingXPCService.h"
#import "PromotionAgent/SNBPromotionAgent.h"
#import "PromotionAgent/SNBPromotionDecision.h"
#import "PromotionAgent/SNBPromotionPolicy.h"
#import "SNBPrivilegedHelperClient.h"
#import "SNBStatusBarManager.h"
#import <ServiceManagement/ServiceManagement.h>
#import <AppKit/AppKit.h>

@interface AppCoordinator () <MenuBuilderDelegate, SNBPromotionAgentDelegate>
@property (nonatomic, strong, readwrite) TrafficStatistics *statistics;
@property (nonatomic, strong, readwrite) DeviceManager *deviceManager;
@property (nonatomic, strong, readwrite) MenuBuilder *menuBuilder;
@property (nonatomic, strong, readwrite) ThreatIntelCoordinator *threatIntelCoordinator;
@property (nonatomic, strong, readwrite) ConfigurationManager *configuration;
@property (nonatomic, strong) SNBAnomalyDetector *anomalyDetector;
@property (nonatomic, strong) SNBAnomalyExplainabilityCoordinator *anomalyExplainabilityCoordinator;
@property (nonatomic, copy) SNBTimerID updateTimerID;
@property (nonatomic, copy) SNBTimerID deviceRefreshTimerID;
@property (nonatomic, copy) SNBTimerID anomalyRetrainTimerID;
@property (nonatomic, assign) BOOL anomalyRetrainInProgress;
@property (nonatomic, strong) SNBStatusBarManager *statusBarManager;
@property (nonatomic, weak) NSMenu *statusMenu;
@property (nonatomic, assign) BOOL menuRefreshPending;
@property (nonatomic, strong) SNBNetworkAssetMonitor *assetMonitor;
@property (nonatomic, strong) SNBStatisticsHistory *statisticsHistory;
@property (nonatomic, strong) NSDate *captureWindowStartDate;
@property (nonatomic, strong) SNBEventPublisher *eventPublisher;
@property (nonatomic, strong) SNBHostContext *hostContext;
@property (nonatomic, strong) NSDate *lastModelPublishTime;
@property (nonatomic, strong) SNBPromotionAgent *promotionAgent;
@property (nonatomic, strong) SNBPromotionDecision *lastPromotionDecision;
@property (nonatomic, assign) BOOL helperOperational;
@property (nonatomic, assign) BOOL modelingXpcOperational;
@property (nonatomic, strong) NSDate *lastServiceHealthCheck;
@end

@implementation AppCoordinator

- (instancetype)initWithStatusBarManager:(SNBStatusBarManager *)statusBarManager
                              statusMenu:(NSMenu *)statusMenu {
    self = [super init];
    if (self) {
        _statusBarManager = statusBarManager;
        _statusMenu = statusMenu;
        _configuration = [ConfigurationManager sharedManager];
        [self registerDefaultPreferences];

        // Initialize subsystems
        PacketCaptureManager *packetManager = [[PacketCaptureManager alloc] init];
        _statistics = [[TrafficStatistics alloc] init];
        _deviceManager = [[DeviceManager alloc] initWithPacketManager:packetManager
                                                        configuration:_configuration];
        _menuBuilder = [[MenuBuilder alloc] initWithMenu:statusMenu
                                      statusBarManager:statusBarManager
                                           configuration:_configuration];
        _menuBuilder.delegate = self;
        _threatIntelCoordinator = [[ThreatIntelCoordinator alloc] initWithConfiguration:_configuration];
        NSTimeInterval anomalyWindowSeconds = _configuration.anomalyWindowSeconds;
        _anomalyDetector = [[SNBAnomalyDetector alloc] initWithWindowSeconds:anomalyWindowSeconds];
        _anomalyExplainabilityCoordinator = [[SNBAnomalyExplainabilityCoordinator alloc]
                                             initWithConfiguration:_configuration
                                             threatIntelCoordinator:_threatIntelCoordinator];
        _assetMonitor = [[SNBNetworkAssetMonitor alloc] init];
        _statisticsHistory = [[SNBStatisticsHistory alloc] init];
        _eventPublisher = [[SNBEventPublisher alloc] initWithServiceName:@"com.sniffnetbar.modelingxpc"];

        // Set up callback for packet updates
        __weak typeof(self) weakSelf = self;
        _deviceManager.packetManager.onPacketReceived = ^(PacketInfo *packetInfo) {
            [weakSelf.statistics processPacket:packetInfo];
            [weakSelf.anomalyDetector processPacket:packetInfo];
            [weakSelf.statisticsHistory processPacket:packetInfo];
        };
    }
    return self;
}

- (void)registerDefaultPreferences {
    NSDictionary<NSString *, id> *defaults = @{
        SNBUserDefaultsKeyEnableProactiveSuggestions: @YES,
        SNBUserDefaultsKeySuggestionConfidenceThreshold: @0.7,
        SNBUserDefaultsKeyAdaptiveProviderWeights: @NO,
        SNBUserDefaultsKeyOpenAtLogin: @NO,
        SNBUserDefaultsKeyThreatIntelOptInPromptShown: @NO
    };
    [[NSUserDefaults standardUserDefaults] registerDefaults:defaults];
}

- (void)syncCaptureStartDateForMenuBuilder {
    NSDate *packetStart = self.deviceManager.packetManager.captureStartDate;
    if (packetStart && (!self.captureWindowStartDate || [packetStart compare:self.captureWindowStartDate] == NSOrderedDescending)) {
        self.captureWindowStartDate = packetStart;
    }
    self.menuBuilder.captureStartDate = self.captureWindowStartDate;
}

- (void)refreshServiceHealthIfNeeded {
    NSDate *now = [NSDate date];
    if (self.lastServiceHealthCheck &&
        [now timeIntervalSinceDate:self.lastServiceHealthCheck] < 5.0) {
        return;
    }
    self.lastServiceHealthCheck = now;
    self.helperOperational = [[SNBPrivilegedHelperClient sharedClient] isConnected];
    __weak typeof(self) weakSelf = self;
    [self.eventPublisher pingWithCompletion:^(BOOL ok) {
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) {
            return;
        }
        strongSelf.modelingXpcOperational = ok;
        [strongSelf scheduleMenuRefresh];
    }];
}

- (void)syncPromotionAgentStateForMenuBuilder {
    BOOL enabled = [[NSUserDefaults standardUserDefaults] boolForKey:SNBUserDefaultsKeyEnableProactiveSuggestions];
    self.menuBuilder.promotionAgentEnabled = enabled;
    self.menuBuilder.promotionAgentLastDecision = self.lastPromotionDecision;

    if (enabled && self.promotionAgent) {
        // Agent is operational if running - AI is optional (enhances decisions but not required)
        self.menuBuilder.promotionAgentOperational = self.promotionAgent.isRunning;
        self.menuBuilder.promotionAgentAIAvailable = self.promotionAgent.aiAvailable;
        NSArray<SNBPromotionDecision *> *suggestions = [self.promotionAgent pendingSuggestions];
        self.menuBuilder.promotionAgentSuggestions = suggestions ?: @[];
        return;
    }

    self.menuBuilder.promotionAgentOperational = NO;
    self.menuBuilder.promotionAgentSuggestions = @[];
}

- (void)syncServiceHealthForMenuBuilder {
    [self refreshServiceHealthIfNeeded];
    self.menuBuilder.helperOperational = self.helperOperational;
    self.menuBuilder.modelingXpcOperational = self.modelingXpcOperational;
}

- (void)start {
    // Load available devices and restore selected device
    [self.deviceManager loadAvailableDevices];
    [self.deviceManager restoreSelectedDevice];

    // Keep the asset monitor aligned with the selected capture interface
    self.assetMonitor.interfaceName = self.deviceManager.selectedDevice.name;

    // Update menu after devices are loaded
    [self updateMenu];

    [self presentThreatIntelOptInIfNeeded];

    __weak typeof(self) weakSelfPublisher = self;
    [self.eventPublisher pingWithCompletion:^(BOOL ok) {
        if (!ok) {
            SNBLogWarn("Modeling XPC service unavailable, falling back to in-process model");
            SNBModelingXPCService *localModeling = [[SNBModelingXPCService alloc] init];
            [weakSelfPublisher.eventPublisher setLocalServiceFallback:localModeling];
        }
    }];
    [self ensureBehavioralDatabaseAvailable];

    BOOL proactiveSuggestionsEnabled = [[NSUserDefaults standardUserDefaults] boolForKey:SNBUserDefaultsKeyEnableProactiveSuggestions];
    SNBLogInfo("Proactive suggestions enabled: %d", proactiveSuggestionsEnabled);

    if (proactiveSuggestionsEnabled) {
        SNBLogInfo("Creating and starting promotion agent...");
        SNBPromotionPolicy *policy = [SNBPromotionPolicy defaultPolicy];
        self.promotionAgent = [[SNBPromotionAgent alloc] initWithEventPublisher:self.eventPublisher
                                                                         policy:policy];
        self.promotionAgent.delegate = self;
        [self.promotionAgent start];
        SNBLogInfo("Promotion agent started, isRunning=%d", self.promotionAgent.isRunning);
    } else {
        SNBLogInfo("Promotion agent disabled by user preference");
    }

    // Start packet capture
    [self startCaptureWithCurrentDevice];

    // Start asset monitor if enabled
    BOOL assetMonitorEnabled = [[NSUserDefaults standardUserDefaults] boolForKey:SNBUserDefaultsKeyAssetMonitorEnabled];
    self.assetMonitor.enabled = assetMonitorEnabled;
    NSNumber *dailyStatsValue = [[NSUserDefaults standardUserDefaults] objectForKey:SNBUserDefaultsKeyDailyStatisticsEnabled];
    BOOL dailyStatsEnabled = dailyStatsValue ? [dailyStatsValue boolValue] : YES;
    self.statisticsHistory.enabled = dailyStatsEnabled;
    __weak typeof(self) weakSelfAsset = self;
    self.assetMonitor.onAssetsUpdated = ^(NSArray<SNBNetworkAsset *> *assets, NSArray<SNBNetworkAsset *> *newAssets) {
        [weakSelfAsset scheduleMenuRefresh];
    };

    // Set up timers via centralized coordinator (better battery efficiency with leeway)
    __weak typeof(self) weakSelf = self;
    SNBTimerCoordinator *coordinator = [SNBTimerCoordinator sharedCoordinator];

    // UI update timer
    self.updateTimerID = [coordinator scheduleRepeatingTimerWithInterval:self.configuration.menuUpdateInterval
                                                                   queue:dispatch_get_main_queue()
                                                                 handler:^{
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (strongSelf) {
            [strongSelf updateMenuIfNeeded];
            [strongSelf.anomalyDetector flushIfNeeded];
            [strongSelf.anomalyExplainabilityCoordinator processPendingExplanations];
        }
    }];

    // Device list refresh timer
    self.deviceRefreshTimerID = [coordinator scheduleRepeatingTimerWithInterval:self.configuration.deviceListRefreshInterval
                                                                          queue:dispatch_get_main_queue()
                                                                        handler:^{
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (strongSelf) {
            [strongSelf.deviceManager refreshDeviceList];
        }
    }];

    // Set up periodic anomaly retraining
    [self scheduleAnomalyRetrain];
}

- (void)presentThreatIntelOptInIfNeeded {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    if ([defaults boolForKey:SNBUserDefaultsKeyThreatIntelOptInPromptShown]) {
        return;
    }

    dispatch_async(dispatch_get_main_queue(), ^{
        NSAlert *alert = [[NSAlert alloc] init];
        alert.messageText = @"Enable Threat Intelligence Providers?";
        alert.informativeText = @"SniffNetBar can send destination IPs to selected threat intelligence providers to assess risk. "
                                @"This may share IPs with third parties. Choose which providers to enable.";
        [alert addButtonWithTitle:@"Enable Selected"];
        [alert addButtonWithTitle:@"Not Now"];

        NSStackView *stack = [[NSStackView alloc] initWithFrame:NSMakeRect(0, 0, 320, 80)];
        stack.orientation = NSUserInterfaceLayoutOrientationVertical;
        stack.alignment = NSLayoutAttributeLeading;
        stack.spacing = 6.0;

        NSButton *vt = [NSButton checkboxWithTitle:@"VirusTotal" target:nil action:nil];
        NSButton *abuse = [NSButton checkboxWithTitle:@"AbuseIPDB" target:nil action:nil];
        NSButton *grey = [NSButton checkboxWithTitle:@"GreyNoise" target:nil action:nil];
        NSButton *shodan = [NSButton checkboxWithTitle:@"Shodan" target:nil action:nil];

        [stack addArrangedSubview:vt];
        [stack addArrangedSubview:abuse];
        [stack addArrangedSubview:grey];
        [stack addArrangedSubview:shodan];
        alert.accessoryView = stack;

        NSModalResponse response = [alert runModal];
        BOOL enableSelected = (response == NSAlertFirstButtonReturn);

        if (enableSelected) {
            BOOL vtEnabled = (vt.state == NSControlStateValueOn);
            BOOL abuseEnabled = (abuse.state == NSControlStateValueOn);
            BOOL greyEnabled = (grey.state == NSControlStateValueOn);
            BOOL shodanEnabled = (shodan.state == NSControlStateValueOn);

            [defaults setBool:vtEnabled forKey:SNBUserDefaultsKeyVirusTotalOptIn];
            [defaults setBool:abuseEnabled forKey:SNBUserDefaultsKeyAbuseIPDBOptIn];
            [defaults setBool:greyEnabled forKey:SNBUserDefaultsKeyGreyNoiseOptIn];
            [defaults setBool:shodanEnabled forKey:SNBUserDefaultsKeyShodanOptIn];

            BOOL anyEnabled = (vtEnabled || abuseEnabled || greyEnabled || shodanEnabled);
            [defaults setBool:anyEnabled forKey:SNBUserDefaultsKeyThreatIntelEnabled];
        }

        [defaults setBool:YES forKey:SNBUserDefaultsKeyThreatIntelOptInPromptShown];

        [self.threatIntelCoordinator reloadProviders];
        [self updateMenu];
    });
}

- (void)stop {
    SNBTimerCoordinator *coordinator = [SNBTimerCoordinator sharedCoordinator];
    [coordinator cancelTimer:self.updateTimerID];
    self.updateTimerID = nil;
    [coordinator cancelTimer:self.deviceRefreshTimerID];
    self.deviceRefreshTimerID = nil;
    [coordinator cancelTimer:self.anomalyRetrainTimerID];
    self.anomalyRetrainTimerID = nil;
    [self.deviceManager.packetManager stopCapture];
    [self.anomalyDetector flushIfNeeded];
    [self.assetMonitor stop];
    [self.statisticsHistory flush];
}

- (void)startCaptureWithCurrentDevice {
    NSError *error = nil;
    BOOL started = [self.deviceManager startCaptureWithError:&error];
    if (!started) {
        if (!self.deviceManager.selectedDevice ||
            [self.deviceManager.selectedDevice.name isEqualToString:@"(no device)"]) {
            [self.statusBarManager updateButtonTitle:@"❌ No Device"];
        } else {
            [self.statusBarManager updateButtonTitle:@"❌"];
        }
    }
}

- (void)selectDevice:(NetworkDevice *)device {
    NSError *error = nil;
    self.assetMonitor.interfaceName = device.name;
    BOOL changed = [self.deviceManager selectDevice:device error:&error];
    if (changed) {
        [self.statistics reset];
        if (error) {
            [self.statusBarManager updateButtonTitle:@"❌"];
        }
    }
}

- (void)updateMenuIfNeeded {
    __weak typeof(self) weakSelf = self;
    [self.statistics getCurrentStatsWithCompletion:^(TrafficStats *stats) {
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) {
            return;
        }

        // Proactively enrich IPs for threat intel (regardless of menu state)
        [strongSelf enrichStatsForThreatIntel:stats];

        [strongSelf syncCaptureStartDateForMenuBuilder];
        [strongSelf.menuBuilder updateStatusWithStats:stats selectedDevice:strongSelf.deviceManager.selectedDevice];
        if (strongSelf.menuBuilder.menuIsOpen) {
            [strongSelf.menuBuilder refreshVisualizationWithStats:stats
                                             threatIntelEnabled:strongSelf.threatIntelCoordinator.isEnabled
                                    threatIntelStatusMessage:[strongSelf.threatIntelCoordinator availabilityMessage]
                                            threatIntelResults:[strongSelf.threatIntelCoordinator resultsSnapshot]
                                                     cacheStats:[strongSelf.threatIntelCoordinator cacheStats]
                                           assetMonitorEnabled:strongSelf.assetMonitor.isEnabled
                                                networkAssets:[strongSelf.assetMonitor assetsSnapshot]
                                              recentNewAssets:[strongSelf.assetMonitor recentNewAssetsSnapshot]];
        } else {
            [strongSelf updateMenuWithStats:stats];
        }
    }];
}

- (void)enrichStatsForThreatIntel:(TrafficStats *)stats {
    if (!self.threatIntelCoordinator.isEnabled) {
        return;
    }

    // Get ALL unique destination IPs (not just top connections) for comprehensive threat detection
    __weak typeof(self) weakSelf = self;
    [self.statistics getAllDestinationIPsWithCompletion:^(NSSet<NSString *> *destinationIPs) {
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) {
            return;
        }

        // Enrich every destination IP for threat intelligence
        // enrichIPIfNeeded uses caching, so this won't overwhelm the API
        for (NSString *ip in destinationIPs) {
            [strongSelf.threatIntelCoordinator enrichIPIfNeeded:ip completion:^{
                [strongSelf scheduleMenuRefresh];
            }];
        }
    }];
}

- (void)updateMenu {
    __weak typeof(self) weakSelf = self;
    [self.statistics getCurrentStatsWithCompletion:^(TrafficStats *stats) {
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) {
            return;
        }
        [strongSelf updateMenuWithStats:stats];
    }];
}

- (void)updateMenuWithStats:(TrafficStats *)stats {
    [self syncCaptureStartDateForMenuBuilder];
    self.menuBuilder.dailyStatsEnabled = self.statisticsHistory.isEnabled;
    self.menuBuilder.statsReportAvailable = [self.statisticsHistory reportExists];
    [self syncPromotionAgentStateForMenuBuilder];
    [self syncServiceHealthForMenuBuilder];

    [self.statisticsHistory updateConnectionProcessInfoWithStats:stats];
    [self publishBehavioralEventsFromStats:stats];

    [self.menuBuilder updateMenuWithStats:stats
                                  devices:self.deviceManager.availableDevices
                           selectedDevice:self.deviceManager.selectedDevice
                       threatIntelEnabled:self.threatIntelCoordinator.isEnabled
                   threatIntelStatusMessage:[self.threatIntelCoordinator availabilityMessage]
                      threatIntelResults:[self.threatIntelCoordinator resultsSnapshot]
                               cacheStats:[self.threatIntelCoordinator cacheStats]
                         openAtLoginEnabled:[self isOpenAtLoginEnabled]
                       assetMonitorEnabled:self.assetMonitor.isEnabled
                            networkAssets:[self.assetMonitor assetsSnapshot]
                          recentNewAssets:[self.assetMonitor recentNewAssetsSnapshot]
                                  target:self];
}

- (void)publishBehavioralEventsFromStats:(TrafficStats *)stats {
    if (!stats) {
        return;
    }
    NSDate *now = [NSDate date];
    if (self.lastModelPublishTime && [now timeIntervalSinceDate:self.lastModelPublishTime] < 2.0) {
        return;
    }
    self.lastModelPublishTime = now;

    SNBHostContext *context = [self hostContextForCurrentDevice];
    NSArray<ConnectionTraffic *> *connections = stats.allConnections ?: @[];
    NSUInteger limit = MIN(200, connections.count);
    NSMutableArray<SNBFlowEvent *> *events = [NSMutableArray arrayWithCapacity:limit];

    for (NSUInteger i = 0; i < limit; i++) {
        ConnectionTraffic *connection = connections[i];
        SNBFlowEvent *event = [[SNBFlowEvent alloc] init];
        NSDate *lastActivity = [NSDate dateWithTimeIntervalSinceReferenceDate:connection.lastActivity];
        event.start = lastActivity;
        event.end = lastActivity;
        event.direction = (connection.outgoingBytes >= connection.incomingBytes) ? @"out" : @"in";
        event.protocolName = @"";
        event.srcIP = connection.sourceAddress ?: @"";
        event.dstIP = connection.destinationAddress ?: @"";
        event.srcPort = connection.sourcePort;
        event.dstPort = connection.destinationPort;
        event.bytesIn = connection.incomingBytes;
        event.bytesOut = connection.outgoingBytes;
        event.packets = connection.packetCount;
        event.duration = 0.0;
        event.dnsQuery = @"";
        event.sni = @"";
        event.ja3 = @"";
        event.ja4 = @"";
        event.httpHost = @"";
        event.processName = connection.processName ?: @"";
        event.bundleID = @"";
        event.parentProcess = @"";
        event.signingStatus = @"";
        event.codeHash = @"";
        event.outcome = @"";
        event.asn = @"";
        event.org = @"";
        event.country = @"";
        event.region = @"";
        event.hosting = NO;
        event.vpn = NO;
        event.relay = NO;
        event.vtScore = nil;
        event.abuseScore = nil;
        event.greyNoiseClass = @"";
        [events addObject:event];
    }

    [self.eventPublisher enqueueEvents:events context:context completion:nil];
}

- (SNBHostContext *)hostContextForCurrentDevice {
    if (!self.hostContext) {
        self.hostContext = [[SNBHostContext alloc] init];
    }
    NetworkDevice *device = self.deviceManager.selectedDevice;
    self.hostContext.deviceID = device.name ?: @"";
    self.hostContext.hostname = [[NSHost currentHost] localizedName] ?: @"";
    self.hostContext.osVersion = [[NSProcessInfo processInfo] operatingSystemVersionString] ?: @"";
    self.hostContext.timezone = [NSTimeZone localTimeZone].name ?: @"";
    self.hostContext.networkType = @"unknown";
    self.hostContext.vpnActive = NO;
    self.hostContext.proxyActive = NO;
    return self.hostContext;
}

- (void)ensureBehavioralDatabaseAvailable {
    NSString *dbPath = [[SNBAnomalyStore applicationSupportDirectoryPath]
                        stringByAppendingPathComponent:@"behavioral.sqlite"];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        if (![[NSFileManager defaultManager] fileExistsAtPath:dbPath]) {
            SNBLogWarn("Behavioral DB missing, forcing in-process model fallback");
            SNBModelingXPCService *localModeling = [[SNBModelingXPCService alloc] init];
            [self.eventPublisher setLocalServiceFallback:localModeling];
        }
    });
}

- (void)deviceSelected:(NSMenuItem *)sender {
    NetworkDevice *device = sender.representedObject;
    if (device) {
        [self selectDevice:device];
        [self updateMenu];
    }
}

- (void)toggleShowTopHosts:(NSMenuItem *)sender {
    self.menuBuilder.showTopHosts = !self.menuBuilder.showTopHosts;
    [self updateMenu];
}

- (void)toggleShowTopConnections:(NSMenuItem *)sender {
    self.menuBuilder.showTopConnections = !self.menuBuilder.showTopConnections;
    [self updateMenu];
}

- (void)toggleShowMap:(NSMenuItem *)sender {
    self.menuBuilder.showMap = !self.menuBuilder.showMap;
    SNBLogInfo("Map visualization toggled: %{public}@", self.menuBuilder.showMap ? @"ON" : @"OFF");
    [self updateMenu];
}

- (void)toggleShowProcessActivity:(NSMenuItem *)sender {
    self.menuBuilder.showProcessActivity = !self.menuBuilder.showProcessActivity;
    [self updateMenu];
}

- (void)toggleDebugMode:(NSMenuItem *)sender {
    self.menuBuilder.debugEnabled = !self.menuBuilder.debugEnabled;
    [self updateMenu];
}

- (void)toggleThreatIntelProvider:(NSMenuItem *)sender {
    SNBUserDefaultsKey key = sender.representedObject;
    if (key.length == 0) {
        return;
    }
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    BOOL enabled = ![defaults boolForKey:key];
    [defaults setBool:enabled forKey:key];

    BOOL anyEnabled =
        [defaults boolForKey:SNBUserDefaultsKeyVirusTotalOptIn] ||
        [defaults boolForKey:SNBUserDefaultsKeyAbuseIPDBOptIn] ||
        [defaults boolForKey:SNBUserDefaultsKeyGreyNoiseOptIn] ||
        [defaults boolForKey:SNBUserDefaultsKeyShodanOptIn];

    [defaults setBool:anyEnabled forKey:SNBUserDefaultsKeyThreatIntelEnabled];
    [self.threatIntelCoordinator reloadProviders];
    [self updateMenu];
}

- (void)selectMapProvider:(NSMenuItem *)sender {
    NSString *provider = sender.representedObject;
    __weak typeof(self) weakSelf = self;
    [self.statistics getCurrentStatsWithCompletion:^(TrafficStats *stats) {
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) {
            return;
        }
        [strongSelf.menuBuilder selectMapProviderWithName:provider stats:stats];
        [strongSelf updateMenuWithStats:stats];
    }];
}

- (void)toggleThreatIntel:(NSMenuItem *)sender {
    [self.threatIntelCoordinator toggleEnabled];
    [self updateMenu];
}

- (void)togglePromotionAgent:(NSMenuItem *)sender {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    BOOL enabled = ![defaults boolForKey:SNBUserDefaultsKeyEnableProactiveSuggestions];
    [defaults setBool:enabled forKey:SNBUserDefaultsKeyEnableProactiveSuggestions];

    if (enabled) {
        if (!self.promotionAgent) {
            SNBPromotionPolicy *policy = [SNBPromotionPolicy defaultPolicy];
            self.promotionAgent = [[SNBPromotionAgent alloc] initWithEventPublisher:self.eventPublisher
                                                                             policy:policy];
            self.promotionAgent.delegate = self;
        }
        [self.promotionAgent start];
    } else {
        [self.promotionAgent stop];
        self.promotionAgent = nil;
        self.lastPromotionDecision = nil;
    }

    [self updateMenu];
}

- (void)toggleDailyStatistics:(NSMenuItem *)sender {
    BOOL enabled = !self.statisticsHistory.isEnabled;
    self.statisticsHistory.enabled = enabled;
    [[NSUserDefaults standardUserDefaults] setBool:enabled forKey:SNBUserDefaultsKeyDailyStatisticsEnabled];
    [self updateMenu];
}

- (BOOL)isOpenAtLoginEnabled {
    if (@available(macOS 13.0, *)) {
        SMAppService *service = SMAppService.mainAppService;
        return service.status == SMAppServiceStatusEnabled;
    }
    return [[NSUserDefaults standardUserDefaults] boolForKey:SNBUserDefaultsKeyOpenAtLogin];
}

- (void)toggleOpenAtLogin:(NSMenuItem *)sender {
    BOOL shouldEnable = ![self isOpenAtLoginEnabled];
    BOOL success = NO;
    if (@available(macOS 13.0, *)) {
        SMAppService *service = SMAppService.mainAppService;
        NSError *error = nil;
        success = shouldEnable
            ? [service registerAndReturnError:&error]
            : [service unregisterAndReturnError:&error];
        if (!success) {
            SNBLogWarn("Open at login change failed: %s", error.localizedDescription.UTF8String);
            if (service.status == SMAppServiceStatusRequiresApproval) {
                NSAlert *alert = [[NSAlert alloc] init];
                alert.messageText = @"Open at Login requires approval";
                alert.informativeText = @"Enable SniffNetBar in System Settings > Login Items.";
                [alert addButtonWithTitle:@"Open System Settings"];
                [alert addButtonWithTitle:@"Cancel"];
                if ([alert runModal] == NSAlertFirstButtonReturn) {
                    [[NSWorkspace sharedWorkspace] openURL:[NSURL URLWithString:
                        @"x-apple.systempreferences:com.apple.LoginItems-Settings.extension"]];
                }
            }
        }
    } else {
        NSAlert *alert = [[NSAlert alloc] init];
        alert.messageText = @"Open at Login is unavailable";
        alert.informativeText = @"This feature requires macOS 13 or later.";
        [alert addButtonWithTitle:@"OK"];
        [alert runModal];
    }

    if (success) {
        [[NSUserDefaults standardUserDefaults] setBool:[self isOpenAtLoginEnabled]
                                                forKey:SNBUserDefaultsKeyOpenAtLogin];
    }
    [self updateMenu];
}

- (void)openStatisticsReport:(NSMenuItem *)sender {
    [self.statisticsHistory generateReport];
    NSString *path = [self.statisticsHistory reportPath];
    if ([[NSFileManager defaultManager] fileExistsAtPath:path]) {
        [[NSWorkspace sharedWorkspace] openFile:path];
    } else {
        SNBLogWarn("Statistics report not found at %{public}@", path);
    }
}

- (void)toggleAssetMonitor:(NSMenuItem *)sender {
    BOOL enabled = !self.assetMonitor.isEnabled;
    self.assetMonitor.enabled = enabled;
    [[NSUserDefaults standardUserDefaults] setBool:enabled forKey:SNBUserDefaultsKeyAssetMonitorEnabled];
    [self updateMenu];
}

- (void)resetStatistics:(NSMenuItem *)sender {
    [self.statistics reset];
    self.captureWindowStartDate = [NSDate date];
    self.menuBuilder.captureStartDate = self.captureWindowStartDate;
    [self updateMenu];
}

- (void)menuWillOpenWithStats {
    __weak typeof(self) weakSelf = self;
    [self.statistics getCurrentStatsWithCompletion:^(TrafficStats *stats) {
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) {
            return;
        }
        [strongSelf.menuBuilder menuWillOpenWithStats:stats];
        [strongSelf updateMenuWithStats:stats];
    }];
}

- (void)menuDidClose {
    [self.menuBuilder menuDidClose];
}

#pragma mark - MenuBuilderDelegate

- (void)menuBuilderNeedsVisualizationRefresh:(id)sender {
    __weak typeof(self) weakSelf = self;
    [self.statistics getCurrentStatsWithCompletion:^(TrafficStats *stats) {
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf || !strongSelf.menuBuilder.menuIsOpen) {
            return;
        }
        [strongSelf syncPromotionAgentStateForMenuBuilder];
        [strongSelf syncServiceHealthForMenuBuilder];
        [strongSelf.menuBuilder refreshVisualizationWithStats:stats
                                         threatIntelEnabled:strongSelf.threatIntelCoordinator.isEnabled
                                   threatIntelStatusMessage:[strongSelf.threatIntelCoordinator availabilityMessage]
                                       threatIntelResults:[strongSelf.threatIntelCoordinator resultsSnapshot]
                                                cacheStats:[strongSelf.threatIntelCoordinator cacheStats]
                                      assetMonitorEnabled:strongSelf.assetMonitor.isEnabled
                                           networkAssets:[strongSelf.assetMonitor assetsSnapshot]
                                         recentNewAssets:[strongSelf.assetMonitor recentNewAssetsSnapshot]];
    }];
}

- (void)menuBuilder:(id)sender didRequestMapAction:(NSString *)action forIP:(NSString *)ipAddress {
    if (action.length == 0 || ipAddress.length == 0 || !self.eventPublisher) {
        return;
    }
    NSString *normalizedAction = [action lowercaseString];
    NSString *label = nil;
    if ([normalizedAction isEqualToString:@"label"]) {
        label = @"Trusted";
    } else if ([normalizedAction isEqualToString:@"block"]) {
        label = @"Blocked";
    } else if ([normalizedAction isEqualToString:@"ignore"]) {
        label = @"Safe";
    }
    if (!label) {
        return;
    }
    [self.eventPublisher applyPromotion:ipAddress
                                   label:label
                                  reason:@"Map quick action"
                              completion:nil];
}

#pragma mark - SNBPromotionAgentDelegate

- (void)promotionAgent:(SNBPromotionAgent *)agent didAutoPromote:(SNBPromotionDecision *)decision {
    self.lastPromotionDecision = decision;
    [self scheduleMenuRefresh];
}

- (void)promotionAgent:(SNBPromotionAgent *)agent didAutoBlock:(SNBPromotionDecision *)decision {
    self.lastPromotionDecision = decision;
    [self scheduleMenuRefresh];
}

- (void)promotionAgent:(SNBPromotionAgent *)agent hasSuggestion:(SNBPromotionDecision *)decision {
    self.lastPromotionDecision = decision;
    [self scheduleMenuRefresh];
}

- (void)promotionAgent:(SNBPromotionAgent *)agent needsReview:(SNBPromotionDecision *)decision {
    self.lastPromotionDecision = decision;
    [self scheduleMenuRefresh];
}

- (void)promotionAgent:(SNBPromotionAgent *)agent didEncounterError:(NSError *)error {
    SNBLogAgentWarn("Promotion agent error: %{public}@", error.localizedDescription);
    [self scheduleMenuRefresh];
}

- (void)promotionAgentDidCompleteEvaluation:(SNBPromotionAgent *)agent {
    [self scheduleMenuRefresh];
}

#pragma mark - Menu refresh

- (void)scheduleMenuRefresh {
    if (self.menuRefreshPending) {
        return;
    }
    if (self.menuBuilder.menuIsOpen) {
        return;
    }

    self.menuRefreshPending = YES;
    __weak typeof(self) weakSelf = self;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.15 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) {
            return;
        }
        strongSelf.menuRefreshPending = NO;
        if (strongSelf.menuBuilder.menuIsOpen) {
            [strongSelf updateMenu];
        }
    });
}

#pragma mark - Anomaly retraining

- (void)scheduleAnomalyRetrain {
    NSTimeInterval retrainInterval = self.configuration.anomalyRetrainInterval;
    __weak typeof(self) weakSelf = self;
    SNBTimerCoordinator *coordinator = [SNBTimerCoordinator sharedCoordinator];
    self.anomalyRetrainTimerID = [coordinator scheduleRepeatingTimerWithInterval:retrainInterval
                                                                           queue:dispatch_get_main_queue()
                                                                         handler:^{
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (strongSelf) {
            [strongSelf triggerAnomalyRetrain];
        }
    }];
}

- (void)triggerAnomalyRetrain {
    if (self.anomalyRetrainInProgress) {
        return;
    }
    self.anomalyRetrainInProgress = YES;

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        SNBLogInfo("Starting anomaly retrain");
        NSString *trainScript = [[NSBundle mainBundle] pathForResource:@"anomaly_train" ofType:@"py"];
        NSString *convertScript = [[NSBundle mainBundle] pathForResource:@"convert_iforest_to_coreml" ofType:@"py"];
        NSString *dbPath = [SNBAnomalyStore defaultDatabasePath];
        NSString *modelPath = [SNBAnomalyStore defaultModelPath];
        NSString *supportDir = [SNBAnomalyStore applicationSupportDirectoryPath];
        NSString *coreMLModelPath = [supportDir stringByAppendingPathComponent:@"anomaly_model.mlmodel"];

        BOOL trained = [self runPythonScript:trainScript
                                   arguments:@[@"--db", dbPath, @"--out", modelPath]];

        if (trained && convertScript.length > 0) {
            [self runPythonScript:convertScript
                        arguments:@[@"--db", dbPath, @"--out", coreMLModelPath, @"--compile"]];
        }

        dispatch_async(dispatch_get_main_queue(), ^{
            self.anomalyRetrainInProgress = NO;
            if (trained) {
                SNBLogInfo("Anomaly retrain completed");
                [self.anomalyDetector reloadModels];
            } else {
                SNBLogWarn("Anomaly retrain failed");
            }
        });
    });
}

- (BOOL)runPythonScript:(NSString *)scriptPath arguments:(NSArray<NSString *> *)arguments {
    if (scriptPath.length == 0) {
        return NO;
    }
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:scriptPath]) {
        return NO;
    }

    NSTask *task = [[NSTask alloc] init];
    task.launchPath = @"/usr/bin/python3";
    task.arguments = [@[scriptPath] arrayByAddingObjectsFromArray:arguments];

    NSPipe *outputPipe = [NSPipe pipe];
    NSPipe *errorPipe = [NSPipe pipe];
    task.standardOutput = outputPipe;
    task.standardError = errorPipe;

    // Read pipes asynchronously to prevent deadlock if output exceeds buffer size
    NSMutableData *outputData = [NSMutableData data];
    NSMutableData *errorData = [NSMutableData data];

    outputPipe.fileHandleForReading.readabilityHandler = ^(NSFileHandle *handle) {
        NSData *data = [handle availableData];
        if (data.length > 0) {
            [outputData appendData:data];
        }
    };

    errorPipe.fileHandleForReading.readabilityHandler = ^(NSFileHandle *handle) {
        NSData *data = [handle availableData];
        if (data.length > 0) {
            [errorData appendData:data];
        }
    };

    @try {
        [task launch];
        [task waitUntilExit];

        // Clean up handlers after task completes
        outputPipe.fileHandleForReading.readabilityHandler = nil;
        errorPipe.fileHandleForReading.readabilityHandler = nil;

        // Log output if task failed
        if (task.terminationStatus != 0 && errorData.length > 0) {
            NSString *errorString = [[NSString alloc] initWithData:errorData encoding:NSUTF8StringEncoding];
            if (errorString) {
                SNBLogWarn("Python script failed with error: %{public}@", errorString);
            }
        }
    } @catch (NSException *exception) {
        outputPipe.fileHandleForReading.readabilityHandler = nil;
        errorPipe.fileHandleForReading.readabilityHandler = nil;
        return NO;
    }

    return task.terminationStatus == 0;
}

@end

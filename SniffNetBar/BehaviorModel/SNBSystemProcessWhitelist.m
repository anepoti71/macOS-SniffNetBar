//
//  SNBSystemProcessWhitelist.m
//  SniffNetBar
//
//  Configurable whitelist of known system processes to reduce false positives

#import "SNBSystemProcessWhitelist.h"

@interface SNBSystemProcessWhitelist ()
@property (nonatomic, strong) NSMutableSet<NSString *> *whitelist;
@property (nonatomic, strong) NSMutableSet<NSString *> *wildcardPatterns;
@property (nonatomic, strong) NSDictionary<NSString *, NSNumber *> *trustLevels;
@property (nonatomic, copy, nullable) NSString *configFilePath;
@end

@implementation SNBSystemProcessWhitelist

#pragma mark - Default System Processes

/// Returns the default list of macOS system processes that should be whitelisted
+ (NSArray<NSString *> *)defaultSystemProcesses {
    return @[
        // Core macOS System Daemons
        @"mDNSResponder",           // DNS resolution
        @"trustd",                  // Certificate trust evaluation
        @"securityd",               // Security framework daemon
        @"syspolicyd",              // System policy daemon
        @"kernelmanagerd",          // Kernel extension management
        @"launchd",                 // System launcher
        @"configd",                 // System configuration daemon
        @"discoveryd",              // Service discovery
        @"distnoted",               // Distributed notification daemon
        @"notifyd",                 // Notification daemon

        // Network System Services
        @"nsurlsessiond",           // URL session daemon
        @"networkd",                // Network daemon
        @"symptomsd",               // Network diagnostics
        @"WiFiAgent",               // WiFi management
        @"airportd",                // Airport/WiFi daemon
        @"netbiosd",                // NetBIOS daemon
        @"mDNSResponderHelper",     // DNS helper
        @"networkserviceproxy",     // Network service proxy

        // Apple Services
        @"apsd",                    // Apple Push Service daemon
        @"akd",                     // AuthKit daemon
        @"amsaccountsd",            // Apple Media Services
        @"amsengagementd",          // Apple Media engagement
        @"analyticsd",              // Analytics daemon
        @"bird",                    // iCloud sync
        @"cloudd",                  // iCloud daemon
        @"cloudpaird",              // iCloud pairing
        @"cloudphotod",             // iCloud Photos
        @"CommCenter",              // Communications center
        @"identityservicesd",       // Apple ID services
        @"imtransferagent",         // iMessage transfer
        @"itunescloudd",            // iTunes/Music cloud sync
        @"mediaanalysisd",          // Media analysis
        @"nsurlstoraged",           // URL storage daemon
        @"parsecd",                 // Siri parsing
        @"rapportd",                // Rapport daemon (Continuity)
        @"remindd",                 // Reminders daemon
        @"searchpartyd",            // Find My daemon
        @"sharingd",                // AirDrop/sharing
        @"siriknowledged",          // Siri knowledge
        @"suggestd",                // Suggestions daemon
        @"translationd",            // Translation daemon
        @"assistantd",              // Siri assistant
        @"callservicesd",           // FaceTime/calls

        // System Utilities
        @"softwareupdated",         // Software Update
        @"mobileassetd",            // Mobile asset downloads
        @"nsurlsessiond",           // URL sessions
        @"com.apple.WebKit.Networking", // WebKit networking
        @"com.apple.Safari.SafeBrowsing.Service", // Safe browsing
        @"CrashReporter",           // Crash reporting
        @"ReportCrash",             // Crash reporting
        @"spindump",                // Performance diagnostics
        @"syslogd",                 // System logging
        @"logd",                    // Unified logging
        @"diagnosticd",             // Diagnostics daemon
        @"tailspind",               // Tailspin daemon

        // Time & Location
        @"timed",                   // Time daemon
        @"locationd",               // Location services
        @"geod",                    // Geo services

        // Security & Privacy
        @"taskgated",               // Task gate daemon
        @"coreauthd",               // Core authentication
        @"SecurityAgent",           // Security prompts
        @"authd",                   // Authorization daemon
        @"kcm",                     // Kerberos credential manager
        @"pabortnmsd",              // Parental controls

        // Storage & File System
        @"fseventsd",               // File system events
        @"mds",                     // Metadata server (Spotlight)
        @"mds_stores",              // Spotlight stores
        @"mdworker",                // Spotlight worker
        @"mdworker_shared",         // Spotlight shared worker
        @"revisiond",               // Document revisions
        @"fileproviderd",           // File provider
        @"filecoordinationd",       // File coordination

        // Developer Tools (common for devs)
        @"Xcode",                   // Xcode IDE
        @"xcodebuild",              // Xcode build tool
        @"lldb",                    // Debugger
        @"clang",                   // Compiler
        @"sourcekit-lsp",           // Language server
        @"SourceKitService",        // SourceKit

        // Common Applications (Apple)
        @"Safari",                  // Safari browser
        @"Mail",                    // Mail app
        @"Calendar",                // Calendar app
        @"Notes",                   // Notes app
        @"Finder",                  // Finder
        @"SystemUIServer",          // System UI
        @"Dock",                    // Dock
        @"loginwindow",             // Login window
        @"WindowServer",            // Window server

        // Kernel & Low-level
        @"kernel_task",             // Kernel
        @"kextd",                   // Kernel extension daemon
        @"kernelmanagerd",          // Kernel manager
    ];
}

/// Returns trust levels for different process categories
/// 1.0 = highest trust (core system), 0.8 = high trust, 0.6 = moderate trust
+ (NSDictionary<NSString *, NSNumber *> *)defaultTrustLevels {
    return @{
        // Core system - highest trust
        @"kernel_task": @1.0,
        @"launchd": @1.0,
        @"mDNSResponder": @1.0,
        @"trustd": @1.0,
        @"securityd": @1.0,
        @"configd": @1.0,
        @"WindowServer": @1.0,
        @"loginwindow": @1.0,

        // System services - high trust
        @"nsurlsessiond": @0.9,
        @"apsd": @0.9,
        @"locationd": @0.9,
        @"softwareupdated": @0.9,
        @"cloudd": @0.9,
        @"identityservicesd": @0.9,
        @"mds": @0.9,
        @"fseventsd": @0.9,

        // Apple apps - high trust
        @"Safari": @0.85,
        @"Mail": @0.85,
        @"Finder": @0.85,

        // Network services - moderate-high trust
        @"networkd": @0.8,
        @"symptomsd": @0.8,
        @"rapportd": @0.8,
        @"sharingd": @0.8,

        // Developer tools - moderate trust
        @"Xcode": @0.7,
        @"xcodebuild": @0.7,
        @"clang": @0.7,
    };
}

/// Returns wildcard patterns for matching process families
+ (NSArray<NSString *> *)defaultWildcardPatterns {
    return @[
        @"com.apple.*",             // Apple service processes
        @"mdworker*",               // Spotlight workers
        @"xpc*",                    // XPC services
        @"XPC*",                    // XPC services (uppercase)
        @"*Helper",                 // Helper processes
        @"*.xpc",                   // XPC bundles
    ];
}

#pragma mark - Initialization

+ (instancetype)sharedWhitelist {
    static SNBSystemProcessWhitelist *shared = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        shared = [[SNBSystemProcessWhitelist alloc] initWithCustomEntries:nil];
    });
    return shared;
}

- (instancetype)init {
    return [self initWithCustomEntries:nil];
}

- (instancetype)initWithCustomEntries:(NSArray<NSString *> *)customEntries {
    self = [super init];
    if (self) {
        _includeDefaults = YES;
        _whitelist = [NSMutableSet set];
        _wildcardPatterns = [NSMutableSet set];
        _trustLevels = [[self class] defaultTrustLevels];

        // Add default system processes
        for (NSString *process in [[self class] defaultSystemProcesses]) {
            [_whitelist addObject:[process lowercaseString]];
        }

        // Add default wildcard patterns
        for (NSString *pattern in [[self class] defaultWildcardPatterns]) {
            [_wildcardPatterns addObject:[pattern lowercaseString]];
        }

        // Add custom entries
        if (customEntries) {
            for (NSString *entry in customEntries) {
                if ([entry containsString:@"*"]) {
                    [_wildcardPatterns addObject:[entry lowercaseString]];
                } else {
                    [_whitelist addObject:[entry lowercaseString]];
                }
            }
        }
    }
    return self;
}

- (instancetype)initWithConfigFile:(NSString *)configPath {
    self = [self initWithCustomEntries:nil];
    if (self && configPath) {
        _configFilePath = [configPath copy];
        NSError *error = nil;
        [self reloadFromConfigFile:configPath error:&error];
        if (error) {
            NSLog(@"SNBSystemProcessWhitelist: Failed to load config from %@: %@", configPath, error);
        }
    }
    return self;
}

#pragma mark - Whitelist Checking

- (BOOL)isProcessWhitelisted:(NSString *)processName {
    if (!processName || processName.length == 0) {
        return NO;
    }

    NSString *lowercaseName = [processName lowercaseString];

    // Direct match
    if ([self.whitelist containsObject:lowercaseName]) {
        return YES;
    }

    // Check wildcard patterns
    return [self processMatchesWildcard:lowercaseName];
}

- (BOOL)processMatchesWhitelist:(NSString *)processName {
    return [self isProcessWhitelisted:processName];
}

- (BOOL)processMatchesWildcard:(NSString *)lowercaseName {
    for (NSString *pattern in self.wildcardPatterns) {
        if ([self name:lowercaseName matchesPattern:pattern]) {
            return YES;
        }
    }
    return NO;
}

/// Simple wildcard matching (* matches any sequence of characters)
- (BOOL)name:(NSString *)name matchesPattern:(NSString *)pattern {
    if ([pattern isEqualToString:@"*"]) {
        return YES;
    }

    // Handle prefix wildcard: *suffix
    if ([pattern hasPrefix:@"*"]) {
        NSString *suffix = [pattern substringFromIndex:1];
        return [name hasSuffix:suffix];
    }

    // Handle suffix wildcard: prefix*
    if ([pattern hasSuffix:@"*"]) {
        NSString *prefix = [pattern substringToIndex:pattern.length - 1];
        return [name hasPrefix:prefix];
    }

    // Handle middle wildcard: prefix*suffix
    NSRange wildcardRange = [pattern rangeOfString:@"*"];
    if (wildcardRange.location != NSNotFound) {
        NSString *prefix = [pattern substringToIndex:wildcardRange.location];
        NSString *suffix = [pattern substringFromIndex:wildcardRange.location + 1];
        return [name hasPrefix:prefix] && [name hasSuffix:suffix];
    }

    // No wildcard, exact match
    return [name isEqualToString:pattern];
}

- (double)trustLevelForProcess:(NSString *)processName {
    if (!processName || processName.length == 0) {
        return 0.0;
    }

    if (![self isProcessWhitelisted:processName]) {
        return 0.0;
    }

    // Check for specific trust level
    NSNumber *trustLevel = self.trustLevels[processName];
    if (trustLevel) {
        return trustLevel.doubleValue;
    }

    // Check case-insensitive
    for (NSString *key in self.trustLevels) {
        if ([key caseInsensitiveCompare:processName] == NSOrderedSame) {
            return self.trustLevels[key].doubleValue;
        }
    }

    // Default trust level for whitelisted processes
    return 0.6;
}

#pragma mark - Whitelist Management

- (void)addProcess:(NSString *)processName {
    if (!processName || processName.length == 0) {
        return;
    }

    if ([processName containsString:@"*"]) {
        [self.wildcardPatterns addObject:[processName lowercaseString]];
    } else {
        [self.whitelist addObject:[processName lowercaseString]];
    }
}

- (void)removeProcess:(NSString *)processName {
    if (!processName || processName.length == 0) {
        return;
    }

    NSString *lowercaseName = [processName lowercaseString];
    [self.whitelist removeObject:lowercaseName];
    [self.wildcardPatterns removeObject:lowercaseName];
}

- (NSArray<NSString *> *)allWhitelistedProcesses {
    NSMutableArray *all = [NSMutableArray arrayWithArray:[self.whitelist allObjects]];
    [all addObjectsFromArray:[self.wildcardPatterns allObjects]];
    return [all sortedArrayUsingSelector:@selector(compare:)];
}

#pragma mark - Configuration File

- (BOOL)saveToConfigFile:(NSString *)configPath error:(NSError **)error {
    NSMutableArray *entries = [NSMutableArray array];

    // Add direct entries
    [entries addObjectsFromArray:[self.whitelist allObjects]];

    // Add wildcard patterns
    [entries addObjectsFromArray:[self.wildcardPatterns allObjects]];

    // Sort for readability
    [entries sortUsingSelector:@selector(compare:)];

    NSDictionary *config = @{
        @"version": @1,
        @"includeDefaults": @(self.includeDefaults),
        @"processes": entries
    };

    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:config
                                                       options:NSJSONWritingPrettyPrinted
                                                         error:error];
    if (!jsonData) {
        return NO;
    }

    return [jsonData writeToFile:configPath options:NSDataWritingAtomic error:error];
}

- (BOOL)reloadFromConfigFile:(NSString *)configPath error:(NSError **)error {
    if (!configPath || ![[NSFileManager defaultManager] fileExistsAtPath:configPath]) {
        if (error) {
            *error = [NSError errorWithDomain:@"SNBSystemProcessWhitelist"
                                         code:404
                                     userInfo:@{NSLocalizedDescriptionKey: @"Config file not found"}];
        }
        return NO;
    }

    NSData *data = [NSData dataWithContentsOfFile:configPath options:0 error:error];
    if (!data) {
        return NO;
    }

    NSDictionary *config = [NSJSONSerialization JSONObjectWithData:data options:0 error:error];
    if (!config || ![config isKindOfClass:[NSDictionary class]]) {
        if (error && !*error) {
            *error = [NSError errorWithDomain:@"SNBSystemProcessWhitelist"
                                         code:400
                                     userInfo:@{NSLocalizedDescriptionKey: @"Invalid config format"}];
        }
        return NO;
    }

    // Check for includeDefaults setting
    NSNumber *includeDefaults = config[@"includeDefaults"];
    if (includeDefaults) {
        self.includeDefaults = includeDefaults.boolValue;
    }

    // Clear existing custom entries (keep defaults if includeDefaults is YES)
    if (!self.includeDefaults) {
        [self.whitelist removeAllObjects];
        [self.wildcardPatterns removeAllObjects];
    } else {
        // Reset to defaults
        [self.whitelist removeAllObjects];
        [self.wildcardPatterns removeAllObjects];
        for (NSString *process in [[self class] defaultSystemProcesses]) {
            [self.whitelist addObject:[process lowercaseString]];
        }
        for (NSString *pattern in [[self class] defaultWildcardPatterns]) {
            [self.wildcardPatterns addObject:[pattern lowercaseString]];
        }
    }

    // Add entries from config
    NSArray *processes = config[@"processes"];
    if ([processes isKindOfClass:[NSArray class]]) {
        for (id entry in processes) {
            if ([entry isKindOfClass:[NSString class]]) {
                [self addProcess:entry];
            }
        }
    }

    _configFilePath = [configPath copy];
    return YES;
}

@end

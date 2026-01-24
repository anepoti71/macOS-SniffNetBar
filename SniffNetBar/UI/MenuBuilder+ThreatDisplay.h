//
//  MenuBuilder+ThreatDisplay.h
//  SniffNetBar
//
//  Threat display helpers for Phase 1 & 2 improvements
//

#import "MenuBuilder.h"

@class TrafficStats, TIEnrichmentResponse, TIScoringResult, ConnectionTraffic, SNBTrustSuggestion;

// Severity level for grouping
typedef NS_ENUM(NSInteger, ThreatSeverityLevel) {
    ThreatSeverityHigh = 3,    // Score 70+
    ThreatSeverityMedium = 2,  // Score 40-69
    ThreatSeverityLow = 1,     // Score 1-39
    ThreatSeverityNone = 0     // Score 0
};

// Threat information container
@interface ThreatInfo : NSObject
@property (nonatomic, strong) NSString *ipAddress;
@property (nonatomic, strong) TIEnrichmentResponse *response;
@property (nonatomic, assign) ThreatSeverityLevel severityLevel;
@property (nonatomic, assign) NSInteger score;
@property (nonatomic, assign) BOOL isActive;
@property (nonatomic, strong, nullable) ConnectionTraffic *primaryConnection;
@property (nonatomic, assign) uint64_t totalBytes;
@property (nonatomic, assign) NSInteger connectionCount;
@property (nonatomic, strong, nullable) SNBTrustSuggestion *trustSuggestion;
@end

@interface MenuBuilder (ThreatDisplay)

// Categorize threats by severity
- (NSDictionary<NSNumber *, NSArray<ThreatInfo *> *> *)categorizeThreats:(NSDictionary<NSString *, TIEnrichmentResponse *> *)threatIntelResults
                                                               activeIPs:(NSSet<NSString *> *)activeIPs
                                                                   stats:(TrafficStats *)stats;

// Get severity level from score
- (ThreatSeverityLevel)severityLevelForScore:(NSInteger)score;

// Find all connections for a given IP
- (NSArray<ConnectionTraffic *> *)connectionsForIP:(NSString *)ip inStats:(TrafficStats *)stats;

// Get traffic volume for an IP
- (uint64_t)totalBytesForIP:(NSString *)ip inStats:(TrafficStats *)stats;

// Create enhanced threat menu item with full context
- (NSMenuItem *)enhancedThreatItemForThreat:(ThreatInfo *)threat;

// Create threat detail menu item (verdict, score, bytes, connections)
- (NSMenuItem *)threatDetailItemForThreat:(ThreatInfo *)threat;

// Create threat connection menu item (source:port → dest:port)
- (NSMenuItem *)threatConnectionItemForThreat:(ThreatInfo *)threat;
// Create selectable threat connection menu item with details submenu
- (NSMenuItem *)selectableThreatConnectionItemForThreat:(ThreatInfo *)threat;
// Create selectable threat connection menu item that updates menu section
- (NSMenuItem *)selectableThreatConnectionSelectionItemForThreat:(ThreatInfo *)threat;
// Create selectable threat connection menu items for all connections
- (NSArray<NSMenuItem *> *)selectableThreatConnectionItemsForThreat:(ThreatInfo *)threat
                                                             stats:(TrafficStats *)stats;

// Persisted details helpers
- (NSDictionary<NSString *, id> *)persistedConnectionDetailsForConnection:(ConnectionTraffic *)conn;
- (NSDictionary<NSString *, id> *)persistedConnectionDetailsForIP:(NSString *)ipAddress;
- (TIEnrichmentResponse * _Nullable)cachedThreatIntelResponseForIP:(NSString *)ip
                                                          existing:(TIEnrichmentResponse * _Nullable)existing;
- (NSDictionary<NSString *, id> *)persistedAnomalyDetailsForIP:(NSString *)ipAddress;

// Create severity section header
- (NSMenuItem *)severityHeaderForLevel:(ThreatSeverityLevel)level count:(NSUInteger)count;

// Get severity color
- (NSColor *)colorForSeverityLevel:(ThreatSeverityLevel)level;

// Get severity label
- (NSString *)labelForSeverityLevel:(ThreatSeverityLevel)level;

// Helper method for provider summary (from main MenuBuilder implementation)
- (NSString *)providerSummaryForResponse:(TIEnrichmentResponse *)response;

#pragma mark - Trust Management UI

// Create trust action menu item for threat details submenu
- (NSMenuItem *)trustActionItemForThreat:(ThreatInfo *)threat
                              connection:(nullable ConnectionTraffic *)connection;

// Create trust reason selector submenu
- (NSMenu *)trustReasonSubmenuForIP:(NSString *)ipAddress
                             threat:(ThreatInfo *)threat
                         connection:(nullable ConnectionTraffic *)connection;

// Create trust history section for threat details
- (NSArray<NSMenuItem *> *)trustHistoryItemsForIP:(NSString *)ipAddress;

// Check if IP is currently trusted
- (BOOL)isIPTrusted:(NSString *)ipAddress;

@end

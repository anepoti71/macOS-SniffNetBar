//
//  MenuBuilder+ThreatDisplay.m
//  SniffNetBar
//
//  Threat display helpers for Phase 1 & 2 improvements
//

#import "MenuBuilder+ThreatDisplay.h"
#import "TrafficStatistics.h"
#import "ThreatIntelModels.h"
#import "ThreatIntelStore.h"
#import "AnomalyStore.h"
#import "TrustedIPStore.h"
#import "TrustLearningEngine.h"
#import "TrustFeatureExtractor.h"
#import "TrustLearningModels.h"
#import "ByteFormatter.h"
#import <sqlite3.h>

@implementation ThreatInfo
@end

@interface MenuBuilder (ThreatDetailsPrivate)
- (NSArray<NSMenuItem *> *)menuItemsForThreatDetails:(ThreatInfo *)threat
                                          connection:(ConnectionTraffic *)connection;
@end

#import <objc/runtime.h>

@implementation MenuBuilder (ThreatDisplay)

static const NSInteger kTrustedDetailsPlaceholderTag = 9201;
static void *kTrustedDetailsMenuInfoKey = &kTrustedDetailsMenuInfoKey;

// Helper to get shared trusted store instance
- (SNBTrustedIPStore *)_trustedStore {
    return [SNBTrustedIPStore sharedStore];
}

#pragma mark - Severity Helpers

- (ThreatSeverityLevel)severityLevelForScore:(NSInteger)score {
    if (score >= 70) {
        return ThreatSeverityHigh;
    } else if (score >= 40) {
        return ThreatSeverityMedium;
    } else if (score > 0) {
        return ThreatSeverityLow;
    }
    return ThreatSeverityNone;
}

- (NSColor *)colorForSeverityLevel:(ThreatSeverityLevel)level {
    switch (level) {
        case ThreatSeverityHigh:
            return [NSColor systemRedColor];
        case ThreatSeverityMedium:
            return [NSColor systemOrangeColor];
        case ThreatSeverityLow:
            return [NSColor systemYellowColor];
        case ThreatSeverityNone:
            return [NSColor systemGreenColor];
    }
}

- (NSString *)labelForSeverityLevel:(ThreatSeverityLevel)level {
    switch (level) {
        case ThreatSeverityHigh:
            return @"HIGH SEVERITY";
        case ThreatSeverityMedium:
            return @"MEDIUM SEVERITY";
        case ThreatSeverityLow:
            return @"LOW SEVERITY";
        case ThreatSeverityNone:
            return @"CLEAN";
    }
}

- (NSImage *)symbolForSeverityLevel:(ThreatSeverityLevel)level {
    NSString *symbolName = nil;
    switch (level) {
        case ThreatSeverityHigh:
            symbolName = @"exclamationmark.triangle";
            break;
        case ThreatSeverityMedium:
            symbolName = @"exclamationmark.circle";
            break;
        case ThreatSeverityLow:
            symbolName = @"info.circle";
            break;
        case ThreatSeverityNone:
            symbolName = @"checkmark.circle";
            break;
    }
    NSImage *image = [NSImage imageWithSystemSymbolName:symbolName accessibilityDescription:nil];
    if (!image) {
        return nil;
    }
    NSImageSymbolConfiguration *config = [NSImageSymbolConfiguration configurationWithPointSize:12.0
                                                                                          weight:NSFontWeightSemibold];
    image = [image imageWithSymbolConfiguration:config] ?: image;
    image.template = YES;
    return image;
}

#pragma mark - Connection Analysis

- (NSArray<ConnectionTraffic *> *)connectionsForIP:(NSString *)ip inStats:(TrafficStats *)stats {
    NSArray<ConnectionTraffic *> *sourceConnections = stats.allConnections.count > 0
        ? stats.allConnections
        : stats.topConnections;
    NSMutableArray<ConnectionTraffic *> *connections = [NSMutableArray array];
    for (ConnectionTraffic *conn in sourceConnections) {
        if ([conn.sourceAddress isEqualToString:ip] || [conn.destinationAddress isEqualToString:ip]) {
            [connections addObject:conn];
        }
    }
    [connections sortUsingComparator:^NSComparisonResult(ConnectionTraffic *a, ConnectionTraffic *b) {
        if (a.bytes == b.bytes) {
            return NSOrderedSame;
        }
        return a.bytes > b.bytes ? NSOrderedAscending : NSOrderedDescending;
    }];
    return connections;
}

- (uint64_t)totalBytesForIP:(NSString *)ip inStats:(TrafficStats *)stats {
    uint64_t totalBytes = 0;

    // Check hosts
    for (HostTraffic *host in stats.topHosts) {
        if ([host.address isEqualToString:ip]) {
            totalBytes += host.bytes;
            break;
        }
    }

    // If not found in hosts, sum from connections
    if (totalBytes == 0) {
        for (ConnectionTraffic *conn in stats.topConnections) {
            if ([conn.sourceAddress isEqualToString:ip] || [conn.destinationAddress isEqualToString:ip]) {
                totalBytes += conn.bytes;
            }
        }
    }

    return totalBytes;
}

#pragma mark - Threat Categorization

- (NSDictionary<NSNumber *, NSArray<ThreatInfo *> *> *)categorizeThreats:(NSDictionary<NSString *, TIEnrichmentResponse *> *)threatIntelResults
                                                               activeIPs:(NSSet<NSString *> *)activeIPs
                                                                   stats:(TrafficStats *)stats {

    NSMutableDictionary<NSNumber *, NSMutableArray<ThreatInfo *> *> *categorized = [NSMutableDictionary dictionary];
    categorized[@(ThreatSeverityHigh)] = [NSMutableArray array];
    categorized[@(ThreatSeverityMedium)] = [NSMutableArray array];
    categorized[@(ThreatSeverityLow)] = [NSMutableArray array];

    for (NSString *ip in threatIntelResults) {
        TIEnrichmentResponse *response = threatIntelResults[ip];
        TIScoringResult *scoring = response.scoringResult;

        if (ip.length > 0 && [[self _trustedStore] isTrustedIP:ip]) {
            continue;
        }

        if (!scoring || scoring.verdict == TIThreatVerdictClean) {
            continue;
        }

        NSInteger score = scoring.finalScore;
        ThreatSeverityLevel level = [self severityLevelForScore:score];

        if (level == ThreatSeverityNone) {
            continue;
        }

        ThreatInfo *threat = [[ThreatInfo alloc] init];
        threat.ipAddress = ip;
        threat.response = response;
        threat.severityLevel = level;
        threat.score = score;
        threat.isActive = [activeIPs containsObject:ip];
        threat.totalBytes = [self totalBytesForIP:ip inStats:stats];

        // Find primary connection (highest bytes)
        NSArray<ConnectionTraffic *> *connections = [self connectionsForIP:ip inStats:stats];
        threat.connectionCount = connections.count;
        if (connections.count > 0) {
            threat.primaryConnection = connections[0]; // Already sorted by bytes
        }
        threat.trustSuggestion = [self trustSuggestionForThreat:threat connection:threat.primaryConnection];

        [categorized[@(level)] addObject:threat];
    }

    // Sort each category by score (highest first)
    for (NSNumber *levelKey in categorized) {
        [categorized[levelKey] sortUsingComparator:^NSComparisonResult(ThreatInfo *t1, ThreatInfo *t2) {
            if (t1.score != t2.score) {
                return t1.score > t2.score ? NSOrderedAscending : NSOrderedDescending;
            }
            return [t1.ipAddress compare:t2.ipAddress];
        }];
    }

    return categorized;
}

#pragma mark - Menu Item Creation

- (NSMenuItem *)severityHeaderForLevel:(ThreatSeverityLevel)level count:(NSUInteger)count {
    NSString *label = [self labelForSeverityLevel:level];
    NSString *title = [NSString stringWithFormat:@"%@ (%lu)", label, (unsigned long)count];

    NSMenuItem *item = [[NSMenuItem alloc] initWithTitle:title action:nil keyEquivalent:@""];
    item.enabled = NO;
    item.image = [self symbolForSeverityLevel:level];

    NSMutableAttributedString *attrString = [[NSMutableAttributedString alloc] initWithString:title];
    NSFont *font = [NSFont boldSystemFontOfSize:12.0];
    NSColor *color = [self colorForSeverityLevel:level];

    [attrString addAttribute:NSFontAttributeName value:font range:NSMakeRange(0, title.length)];
    [attrString addAttribute:NSForegroundColorAttributeName value:color range:NSMakeRange(0, title.length)];

    item.attributedTitle = attrString;
    return item;
}

- (NSMenuItem *)enhancedThreatItemForThreat:(ThreatInfo *)threat {
    TIScoringResult *scoring = threat.response.scoringResult;
    NSString *verdict = [scoring verdictString];
    ConnectionTraffic *conn = threat.primaryConnection;

    // Line 1: IP + Port + Process
    NSMutableString *line1 = [NSMutableString string];
    if (conn) {
        [line1 appendFormat:@"  %@:%ld", threat.ipAddress, (long)conn.destinationPort];
        if (conn.processName.length > 0) {
            [line1 appendFormat:@" ← %@ [%d]", conn.processName, conn.processPID];
        }
    } else {
        [line1 appendFormat:@"  %@", threat.ipAddress];
    }
    if (!threat.isActive) {
        [line1 appendString:@" [CLOSED]"];
    }
    if (threat.trustSuggestion) {
        NSString *suggestionBadge = [NSString stringWithFormat:@" [SUGGEST %.0f%%]",
                                     threat.trustSuggestion.confidence * 100.0];
        [line1 appendString:suggestionBadge];
    }

    NSMenuItem *item1 = [[NSMenuItem alloc] initWithTitle:line1 action:nil keyEquivalent:@""];
    item1.enabled = NO;

    // Style line 1
    NSMutableAttributedString *attr1 = [[NSMutableAttributedString alloc] initWithString:line1];
    NSFont *font1 = threat.isActive ? [NSFont systemFontOfSize:12.0 weight:NSFontWeightSemibold] : [NSFont systemFontOfSize:12.0];
    NSColor *color1 = threat.isActive ? [NSColor labelColor] : [NSColor secondaryLabelColor];

    [attr1 addAttribute:NSFontAttributeName value:font1 range:NSMakeRange(0, line1.length)];
    [attr1 addAttribute:NSForegroundColorAttributeName value:color1 range:NSMakeRange(0, line1.length)];

    item1.attributedTitle = attr1;

    return item1;
}

- (NSMenuItem *)threatDetailItemForThreat:(ThreatInfo *)threat {
    TIScoringResult *scoring = threat.response.scoringResult;
    NSString *verdict = [scoring verdictString];

    // Line 2: Verdict + Score + Traffic + Providers
    NSMutableString *line2 = [NSMutableString stringWithFormat:@"    %@ (score %ld)", verdict, (long)threat.score];

    if (threat.totalBytes > 0) {
        NSString *bytesStr = [SNBByteFormatter stringFromBytes:threat.totalBytes];
        [line2 appendFormat:@" • %@", bytesStr];
    }

    if (threat.connectionCount > 0) {
        [line2 appendFormat:@" • %ld conn%@", (long)threat.connectionCount, threat.connectionCount == 1 ? @"" : @"s"];
    }
    if (threat.trustSuggestion) {
        [line2 appendFormat:@" • Suggest trust (%.0f%%)", threat.trustSuggestion.confidence * 100.0];
    }

    // Add provider info
    NSString *providers = [self providerSummaryForResponse:threat.response];
    if (providers.length > 0 && ![providers isEqualToString:@"Unknown"]) {
        [line2 appendFormat:@" • %@", providers];
    }

    NSMenuItem *item2 = [[NSMenuItem alloc] initWithTitle:line2 action:nil keyEquivalent:@""];
    item2.enabled = NO;

    // Style line 2
    NSMutableAttributedString *attr2 = [[NSMutableAttributedString alloc] initWithString:line2];
    NSFont *font2 = [NSFont systemFontOfSize:11.0];
    NSColor *color2 = [NSColor secondaryLabelColor];

    [attr2 addAttribute:NSFontAttributeName value:font2 range:NSMakeRange(0, line2.length)];
    [attr2 addAttribute:NSForegroundColorAttributeName value:color2 range:NSMakeRange(0, line2.length)];

    item2.attributedTitle = attr2;

    return item2;
}

- (NSMenuItem *)threatConnectionItemForThreat:(ThreatInfo *)threat {
    ConnectionTraffic *conn = threat.primaryConnection;
    if (!conn) {
        return nil;
    }

    // Line 3: Connection details
    NSString *line3 = [NSString stringWithFormat:@"    %@:%ld → %@:%ld",
                      conn.sourceAddress, (long)conn.sourcePort,
                      conn.destinationAddress, (long)conn.destinationPort];

    NSMenuItem *item3 = [[NSMenuItem alloc] initWithTitle:line3 action:nil keyEquivalent:@""];
    item3.enabled = NO;

    // Style line 3
    NSMutableAttributedString *attr3 = [[NSMutableAttributedString alloc] initWithString:line3];
    NSFont *font3 = [NSFont monospacedSystemFontOfSize:10.0 weight:NSFontWeightRegular];
    NSColor *color3 = [NSColor tertiaryLabelColor];

    [attr3 addAttribute:NSFontAttributeName value:font3 range:NSMakeRange(0, line3.length)];
    [attr3 addAttribute:NSForegroundColorAttributeName value:color3 range:NSMakeRange(0, line3.length)];

    item3.attributedTitle = attr3;

    return item3;
}

- (NSMenuItem *)selectableThreatConnectionItemForThreat:(ThreatInfo *)threat {
    ConnectionTraffic *conn = threat.primaryConnection;
    if (!conn) {
        return nil;
    }

    NSString *line3 = [NSString stringWithFormat:@"    %@:%ld → %@:%ld",
                       conn.sourceAddress, (long)conn.sourcePort,
                       conn.destinationAddress, (long)conn.destinationPort];

    NSMenuItem *item3 = [[NSMenuItem alloc] initWithTitle:line3 action:nil keyEquivalent:@""];
    item3.submenu = [self threatDetailsSubmenuForThreat:threat];

    NSMutableAttributedString *attr3 = [[NSMutableAttributedString alloc] initWithString:line3];
    NSFont *font3 = [NSFont monospacedSystemFontOfSize:10.0 weight:NSFontWeightRegular];
    NSColor *color3 = [NSColor tertiaryLabelColor];

    [attr3 addAttribute:NSFontAttributeName value:font3 range:NSMakeRange(0, line3.length)];
    [attr3 addAttribute:NSForegroundColorAttributeName value:color3 range:NSMakeRange(0, line3.length)];

    item3.attributedTitle = attr3;

    return item3;
}

- (NSMenuItem *)selectableThreatConnectionSelectionItemForThreat:(ThreatInfo *)threat {
    ConnectionTraffic *conn = threat.primaryConnection;
    if (!conn) {
        return nil;
    }

    NSString *line3 = [NSString stringWithFormat:@"    %@:%ld → %@:%ld",
                       conn.sourceAddress, (long)conn.sourcePort,
                       conn.destinationAddress, (long)conn.destinationPort];

    NSMenuItem *item3 = [[NSMenuItem alloc] initWithTitle:line3
                                                   action:@selector(selectThreatConnection:)
                                            keyEquivalent:@""];
    item3.target = self;
    item3.representedObject = threat;
    item3.enabled = YES;

    NSMutableAttributedString *attr3 = [[NSMutableAttributedString alloc] initWithString:line3];
    NSFont *font3 = [NSFont monospacedSystemFontOfSize:10.0 weight:NSFontWeightRegular];
    NSColor *color3 = [NSColor labelColor];

    [attr3 addAttribute:NSFontAttributeName value:font3 range:NSMakeRange(0, line3.length)];
    [attr3 addAttribute:NSForegroundColorAttributeName value:color3 range:NSMakeRange(0, line3.length)];

    item3.attributedTitle = attr3;

    return item3;
}

- (NSMenuItem *)selectableThreatConnectionSelectionItemForThreat:(ThreatInfo *)threat
                                                     connection:(ConnectionTraffic *)conn {
    if (!conn) {
        return nil;
    }

    NSString *line3 = [NSString stringWithFormat:@"    %@:%ld → %@:%ld",
                       conn.sourceAddress, (long)conn.sourcePort,
                       conn.destinationAddress, (long)conn.destinationPort];

    NSMenuItem *item3 = [[NSMenuItem alloc] initWithTitle:line3 action:nil keyEquivalent:@""];
    item3.enabled = YES;

    NSMutableAttributedString *attr3 = [[NSMutableAttributedString alloc] initWithString:line3];
    NSFont *font3 = [NSFont monospacedSystemFontOfSize:10.0 weight:NSFontWeightRegular];
    NSColor *color3 = [NSColor labelColor];

    [attr3 addAttribute:NSFontAttributeName value:font3 range:NSMakeRange(0, line3.length)];
    [attr3 addAttribute:NSForegroundColorAttributeName value:color3 range:NSMakeRange(0, line3.length)];

    item3.attributedTitle = attr3;
    item3.submenu = [self threatDetailsSubmenuForThreat:threat connection:conn];

    return item3;
}

- (NSArray<NSMenuItem *> *)selectableThreatConnectionItemsForThreat:(ThreatInfo *)threat
                                                             stats:(TrafficStats *)stats {
    if (!threat || threat.ipAddress.length == 0) {
        return @[];
    }
    NSArray<ConnectionTraffic *> *connections = [self connectionsForIP:threat.ipAddress inStats:stats];
    NSMutableArray<NSMenuItem *> *items = [NSMutableArray array];
    if (connections.count == 0) {
        NSString *line = [NSString stringWithFormat:@"    %@ (no active connection)", threat.ipAddress];
        NSMenuItem *item = [[NSMenuItem alloc] initWithTitle:line action:nil keyEquivalent:@""];
        item.enabled = YES;
        NSMutableAttributedString *attr = [[NSMutableAttributedString alloc] initWithString:line];
        NSFont *font = [NSFont systemFontOfSize:10.0 weight:NSFontWeightRegular];
        NSColor *color = [NSColor secondaryLabelColor];
        [attr addAttribute:NSFontAttributeName value:font range:NSMakeRange(0, line.length)];
        [attr addAttribute:NSForegroundColorAttributeName value:color range:NSMakeRange(0, line.length)];
        item.attributedTitle = attr;
        item.submenu = [self threatDetailsSubmenuForThreat:threat connection:nil];
        [items addObject:item];
        return items;
    }

    for (ConnectionTraffic *conn in connections) {
        NSMenuItem *item = [self selectableThreatConnectionSelectionItemForThreat:threat connection:conn];
        if (item) {
            [items addObject:item];
        }
    }
    return items;
}

- (NSMenu *)threatDetailsSubmenuForThreat:(ThreatInfo *)threat
                               connection:(ConnectionTraffic *)conn {
    NSMenu *menu = [[NSMenu alloc] initWithTitle:@"Unclassified Details"];
    if (!threat) {
        return menu;
    }

    [menu addItem:[self detailHeaderMenuItemWithTitle:@"Unclassified Details"]];
    NSArray<NSMenuItem *> *detailItems = [self menuItemsForThreatDetails:threat connection:conn];
    for (NSMenuItem *item in detailItems) {
        [menu addItem:item];
    }

    // Add trust action section
    [menu addItem:[NSMenuItem separatorItem]];
    NSMenuItem *trustItem = [self trustActionItemForThreat:threat connection:conn];
    if (trustItem) {
        [menu addItem:trustItem];
    }

    // Add trust history if available
    NSArray<NSMenuItem *> *historyItems = [self trustHistoryItemsForIP:threat.ipAddress];
    if (historyItems.count > 0) {
        [menu addItem:[NSMenuItem separatorItem]];
        for (NSMenuItem *item in historyItems) {
            [menu addItem:item];
        }
    }

    return menu;
}

- (NSMenu *)threatDetailsSubmenuForThreat:(ThreatInfo *)threat {
    NSMenu *menu = [[NSMenu alloc] init];
    if (!threat) {
        return menu;
    }

    ConnectionTraffic *conn = threat.primaryConnection;
    NSDictionary *persisted = conn ? [self persistedConnectionDetailsForConnection:conn] : nil;
    NSString *persistedProcessName = persisted[@"processName"];
    NSNumber *persistedProcessPID = persisted[@"processPID"];
    NSNumber *persistedBytes = persisted[@"bytes"];
    NSNumber *persistedPackets = persisted[@"packets"];
    NSString *persistedDay = persisted[@"day"];

    TIEnrichmentResponse *response = [self cachedThreatIntelResponseForIP:threat.ipAddress existing:threat.response];
    TIScoringResult *scoring = response.scoringResult;

    [menu addItem:[self detailMenuItemWithTitle:[NSString stringWithFormat:@"Indicator: %@",
                                                 threat.ipAddress ?: @"Unknown"]]];
    if (scoring) {
        [menu addItem:[self detailMenuItemWithTitle:[NSString stringWithFormat:@"Verdict: %@",
                                                     [scoring verdictString] ?: @"Unknown"]]];
        [menu addItem:[self detailMenuItemWithTitle:[NSString stringWithFormat:@"Score: %ld",
                                                     (long)scoring.finalScore]]];
    }

    if (conn) {
        [menu addItem:[NSMenuItem separatorItem]];
        NSString *source = conn.sourceAddress ?: @"Unknown";
        NSString *destination = conn.destinationAddress ?: @"Unknown";
        [menu addItem:[self detailMenuItemWithTitle:[NSString stringWithFormat:@"Connection: %@:%ld -> %@:%ld",
                                                     source, (long)conn.sourcePort,
                                                     destination, (long)conn.destinationPort]]];
    }

    NSString *processName = conn.processName.length > 0 ? conn.processName : persistedProcessName;
    pid_t pid = conn.processPID > 0 ? conn.processPID : (pid_t)persistedProcessPID.intValue;
    if (processName.length > 0 || pid > 0) {
        if (processName.length > 0 && pid > 0) {
            [menu addItem:[self detailMenuItemWithTitle:[NSString stringWithFormat:@"Process: %@ [%d]",
                                                         processName, pid]]];
        } else if (processName.length > 0) {
            [menu addItem:[self detailMenuItemWithTitle:[NSString stringWithFormat:@"Process: %@",
                                                         processName]]];
        } else {
            [menu addItem:[self detailMenuItemWithTitle:[NSString stringWithFormat:@"Process PID: %d",
                                                         pid]]];
        }
    }

    uint64_t bytes = conn.bytes > 0 ? conn.bytes : (uint64_t)persistedBytes.unsignedLongLongValue;
    uint64_t packets = conn.packetCount > 0 ? conn.packetCount : (uint64_t)persistedPackets.unsignedLongLongValue;
    if (bytes > 0 || packets > 0) {
        [menu addItem:[NSMenuItem separatorItem]];
        if (bytes > 0) {
            [menu addItem:[self detailMenuItemWithTitle:[NSString stringWithFormat:@"Traffic: %@",
                                                         [SNBByteFormatter stringFromBytes:bytes]]]];
        }
        if (packets > 0) {
            [menu addItem:[self detailMenuItemWithTitle:[NSString stringWithFormat:@"Packets: %llu",
                                                         (unsigned long long)packets]]];
        }
        if (persistedDay.length > 0) {
            [menu addItem:[self detailMenuItemWithTitle:[NSString stringWithFormat:@"Persisted day: %@", persistedDay]]];
        }
    }

    if (response.providerResults.count > 0) {
        [menu addItem:[NSMenuItem separatorItem]];
        [menu addItem:[self detailHeaderMenuItemWithTitle:@"Provider details"]];
        for (TIResult *result in response.providerResults) {
            NSString *provider = result.providerName ?: @"Unknown";
            NSString *hitValue = result.verdict.hit ? @"Hit" : @"No hit";
            NSString *line = [NSString stringWithFormat:@"%@: %@", provider, hitValue];
            [menu addItem:[self detailMenuItemWithTitle:line]];
        }
    }

    // Add trust action section
    [menu addItem:[NSMenuItem separatorItem]];
    NSMenuItem *trustItem = [self trustActionItemForThreat:threat connection:conn];
    if (trustItem) {
        [menu addItem:trustItem];
    }

    // Add trust history if available
    NSArray<NSMenuItem *> *historyItems = [self trustHistoryItemsForIP:threat.ipAddress];
    if (historyItems.count > 0) {
        [menu addItem:[NSMenuItem separatorItem]];
        for (NSMenuItem *item in historyItems) {
            [menu addItem:item];
        }
    }

    return menu;
}

- (NSMenuItem *)detailMenuItemWithTitle:(NSString *)title {
    NSMenuItem *item = [[NSMenuItem alloc] initWithTitle:title action:nil keyEquivalent:@""];
    item.enabled = NO;
    return item;
}

- (NSMenuItem *)detailHeaderMenuItemWithTitle:(NSString *)title {
    NSMenuItem *item = [[NSMenuItem alloc] initWithTitle:title action:nil keyEquivalent:@""];
    item.enabled = NO;
    NSFont *font = [NSFont boldSystemFontOfSize:12.0];
    NSDictionary *attributes = @{NSFontAttributeName: font,
                                 NSForegroundColorAttributeName: [NSColor secondaryLabelColor]};
    item.attributedTitle = [[NSAttributedString alloc] initWithString:title attributes:attributes];
    return item;
}

- (NSDictionary<NSString *, id> *)persistedConnectionDetailsForConnection:(ConnectionTraffic *)conn {
    NSString *source = conn.sourceAddress ?: @"";
    NSString *destination = conn.destinationAddress ?: @"";
    if (source.length == 0 || destination.length == 0) {
        return @{};
    }

    NSArray<NSString *> *paths = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory,
                                                                      NSUserDomainMask,
                                                                      YES);
    NSString *baseDir = paths.firstObject ?: NSTemporaryDirectory();
    NSString *appDir = [baseDir stringByAppendingPathComponent:@"SniffNetBar"];
    NSString *dbPath = [appDir stringByAppendingPathComponent:@"traffic_stats.sqlite"];

    sqlite3 *db = NULL;
    if (sqlite3_open_v2(dbPath.UTF8String, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        if (db) {
            sqlite3_close(db);
        }
        return @{};
    }

    NSDictionary *result = @{};
    const char *sql =
        "SELECT process_name, process_pid, bytes, packets, day "
        "FROM stats_connections "
        "WHERE src_addr = ? AND src_port = ? AND dst_addr = ? AND dst_port = ? "
        "ORDER BY day DESC LIMIT 1;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, source.UTF8String, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 2, (int)conn.sourcePort);
        sqlite3_bind_text(stmt, 3, destination.UTF8String, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 4, (int)conn.destinationPort);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const unsigned char *processName = sqlite3_column_text(stmt, 0);
            int processPID = sqlite3_column_int(stmt, 1);
            sqlite3_int64 bytes = sqlite3_column_int64(stmt, 2);
            sqlite3_int64 packets = sqlite3_column_int64(stmt, 3);
            const unsigned char *day = sqlite3_column_text(stmt, 4);
            result = @{
                @"processName": processName ? [NSString stringWithUTF8String:(const char *)processName] : @"",
                @"processPID": @(processPID),
                @"bytes": @(bytes),
                @"packets": @(packets),
                @"day": day ? [NSString stringWithUTF8String:(const char *)day] : @""
            };
        }
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db);
    return result;
}

- (NSDictionary<NSString *, id> *)persistedConnectionDetailsForIP:(NSString *)ipAddress {
    if (ipAddress.length == 0) {
        return @{};
    }

    NSArray<NSString *> *paths = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory,
                                                                      NSUserDomainMask,
                                                                      YES);
    NSString *baseDir = paths.firstObject ?: NSTemporaryDirectory();
    NSString *appDir = [baseDir stringByAppendingPathComponent:@"SniffNetBar"];
    NSString *dbPath = [appDir stringByAppendingPathComponent:@"traffic_stats.sqlite"];

    sqlite3 *db = NULL;
    if (sqlite3_open_v2(dbPath.UTF8String, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        if (db) {
            sqlite3_close(db);
        }
        return @{};
    }

    NSDictionary *result = @{};
    NSDictionary* (^runQuery)(const char *sql, BOOL bindTwice) = ^NSDictionary *(const char *sql, BOOL bindTwice) {
        NSDictionary *queryResult = @{};
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, ipAddress.UTF8String, -1, SQLITE_TRANSIENT);
            if (bindTwice) {
                sqlite3_bind_text(stmt, 2, ipAddress.UTF8String, -1, SQLITE_TRANSIENT);
            }
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                const unsigned char *srcAddr = sqlite3_column_text(stmt, 0);
                int srcPort = sqlite3_column_int(stmt, 1);
                const unsigned char *dstAddr = sqlite3_column_text(stmt, 2);
                int dstPort = sqlite3_column_int(stmt, 3);
                const unsigned char *processName = sqlite3_column_text(stmt, 4);
                int processPID = sqlite3_column_int(stmt, 5);
                sqlite3_int64 bytes = sqlite3_column_int64(stmt, 6);
                sqlite3_int64 packets = sqlite3_column_int64(stmt, 7);
                const unsigned char *day = sqlite3_column_text(stmt, 8);
                queryResult = @{
                    @"sourceAddress": srcAddr ? [NSString stringWithUTF8String:(const char *)srcAddr] : @"",
                    @"sourcePort": @(srcPort),
                    @"destinationAddress": dstAddr ? [NSString stringWithUTF8String:(const char *)dstAddr] : @"",
                    @"destinationPort": @(dstPort),
                    @"processName": processName ? [NSString stringWithUTF8String:(const char *)processName] : @"",
                    @"processPID": @(processPID),
                    @"bytes": @(bytes),
                    @"packets": @(packets),
                    @"day": day ? [NSString stringWithUTF8String:(const char *)day] : @""
                };
            }
            sqlite3_finalize(stmt);
        }
        return queryResult;
    };

    const char *dstSql =
        "SELECT src_addr, src_port, dst_addr, dst_port, process_name, process_pid, bytes, packets, day "
        "FROM stats_connections "
        "WHERE dst_addr = ? "
        "ORDER BY day DESC, bytes DESC LIMIT 1;";
    result = runQuery(dstSql, NO);
    if (result.count == 0) {
        const char *anySql =
            "SELECT src_addr, src_port, dst_addr, dst_port, process_name, process_pid, bytes, packets, day "
            "FROM stats_connections "
            "WHERE src_addr = ? OR dst_addr = ? "
            "ORDER BY day DESC, bytes DESC LIMIT 1;";
        result = runQuery(anySql, YES);
    }
    sqlite3_close(db);
    return result;
}

- (TIEnrichmentResponse *)cachedThreatIntelResponseForIP:(NSString *)ip
                                               existing:(TIEnrichmentResponse *)existing {
    if (existing) {
        return existing;
    }
    if (ip.length == 0) {
        return nil;
    }
    ThreatIntelStore *store = [ThreatIntelStore sharedStore];
    TIIndicator *indicator = [TIIndicator indicatorWithIP:ip];
    return indicator ? [store responseForIndicator:indicator] : nil;
}

- (NSDictionary<NSString *, id> *)persistedAnomalyDetailsForIP:(NSString *)ipAddress {
    if (ipAddress.length == 0) {
        return @{};
    }
    NSString *dbPath = [SNBAnomalyStore defaultDatabasePath];
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(dbPath.UTF8String, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        if (db) {
            sqlite3_close(db);
        }
        return @{};
    }

    NSMutableDictionary *result = [NSMutableDictionary dictionary];

    const char *windowSql =
        "SELECT window_start, dst_port, proto, score, is_new_dst, is_rare_dst, total_bytes, total_packets "
        "FROM anomaly_windows WHERE dst_ip = ? ORDER BY window_start DESC LIMIT 1;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, windowSql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, ipAddress.UTF8String, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            sqlite3_int64 windowStart = sqlite3_column_int64(stmt, 0);
            int dstPort = sqlite3_column_int(stmt, 1);
            int proto = sqlite3_column_int(stmt, 2);
            double score = sqlite3_column_double(stmt, 3);
            int isNew = sqlite3_column_int(stmt, 4);
            int isRare = sqlite3_column_int(stmt, 5);
            double totalBytes = sqlite3_column_double(stmt, 6);
            double totalPackets = sqlite3_column_double(stmt, 7);
            result[@"windowStart"] = @(windowStart);
            result[@"dstPort"] = @(dstPort);
            result[@"proto"] = @(proto);
            result[@"score"] = @(score);
            result[@"isNew"] = @(isNew != 0);
            result[@"isRare"] = @(isRare != 0);
            result[@"totalBytes"] = @(totalBytes);
            result[@"totalPackets"] = @(totalPackets);
        }
        sqlite3_finalize(stmt);
    }

    const char *statsSql =
        "SELECT seen_count, last_seen, avg_score FROM anomaly_ip_stats WHERE dst_ip = ? LIMIT 1;";
    stmt = NULL;
    if (sqlite3_prepare_v2(db, statsSql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, ipAddress.UTF8String, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            int seenCount = sqlite3_column_int(stmt, 0);
            sqlite3_int64 lastSeen = sqlite3_column_int64(stmt, 1);
            double avgScore = sqlite3_column_double(stmt, 2);
            result[@"seenCount"] = @(seenCount);
            result[@"lastSeen"] = @(lastSeen);
            result[@"avgScore"] = @(avgScore);
        }
        sqlite3_finalize(stmt);
    }

    const char *explainSql =
        "SELECT risk_band, summary, evidence_tags, window_start FROM anomaly_explanations "
        "WHERE dst_ip = ? ORDER BY window_start DESC LIMIT 1;";
    stmt = NULL;
    if (sqlite3_prepare_v2(db, explainSql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, ipAddress.UTF8String, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const unsigned char *riskBand = sqlite3_column_text(stmt, 0);
            const unsigned char *summary = sqlite3_column_text(stmt, 1);
            const unsigned char *evidence = sqlite3_column_text(stmt, 2);
            sqlite3_int64 windowStart = sqlite3_column_int64(stmt, 3);
            if (riskBand) {
                result[@"riskBand"] = [NSString stringWithUTF8String:(const char *)riskBand];
            }
            if (summary) {
                result[@"summary"] = [NSString stringWithUTF8String:(const char *)summary];
            }
            if (evidence) {
                result[@"evidence"] = [NSString stringWithUTF8String:(const char *)evidence];
            }
            result[@"explainWindowStart"] = @(windowStart);
        }
        sqlite3_finalize(stmt);
    }

    sqlite3_close(db);
    return result;
}

#pragma mark - Trust Management UI

- (BOOL)isIPTrusted:(NSString *)ipAddress {
    if (ipAddress.length == 0) {
        return NO;
    }
    return [[self _trustedStore] isTrustedIP:ipAddress];
}

- (SNBTrustContext *)trustContextForThreat:(ThreatInfo *)threat
                                connection:(ConnectionTraffic *)connection
                                    reason:(SNBTrustReason)reason {
    SNBTrustContext *context = [[SNBTrustContext alloc] init];
    context.ipAddress = threat.ipAddress;
    context.reason = reason;
    context.threatScoreAtDecision = threat.score;
    TIScoringResult *scoring = threat.response.scoringResult;
    context.verdictAtDecision = scoring ? [scoring verdictString] : nil;

    ConnectionTraffic *conn = connection ?: threat.primaryConnection;
    if (conn) {
        context.processName = conn.processName;
        context.processPID = conn.processPID;
        context.destinationPort = conn.destinationPort;
    }

    return context;
}

- (SNBTrustFeatureVector *)featureVectorForThreat:(ThreatInfo *)threat
                                       connection:(ConnectionTraffic *)connection {
    if (!threat) {
        return [[SNBTrustFeatureVector alloc] init];
    }

    TIEnrichmentResponse *response = [self cachedThreatIntelResponseForIP:threat.ipAddress
                                                                 existing:threat.response];
    SNBTrustFeatureExtractor *extractor = [[SNBTrustFeatureExtractor alloc] init];
    return [extractor featureVectorForIP:threat.ipAddress
                                response:response
                              connection:connection ?: threat.primaryConnection
                              totalBytes:threat.totalBytes
                         connectionCount:threat.connectionCount];
}

- (SNBTrustSuggestion *)trustSuggestionForThreat:(ThreatInfo *)threat
                                      connection:(ConnectionTraffic *)connection {
    if (!threat || threat.ipAddress.length == 0) {
        return nil;
    }
    if ([self isIPTrusted:threat.ipAddress]) {
        return nil;
    }
    SNBTrustFeatureVector *vector = [self featureVectorForThreat:threat connection:connection];
    return [[SNBTrustLearningEngine sharedEngine] suggestTrustForIP:threat.ipAddress
                                                     featureVector:vector];
}

- (void)recordTrustFeedbackForThreat:(ThreatInfo *)threat
                          connection:(ConnectionTraffic *)connection
                             trusted:(BOOL)trusted
                              reason:(SNBTrustReason)reason {
    if (!threat || threat.ipAddress.length == 0) {
        return;
    }
    SNBTrustFeatureVector *vector = [self featureVectorForThreat:threat connection:connection];
    [[SNBTrustLearningEngine sharedEngine] recordFeedbackForIP:threat.ipAddress
                                                       trusted:trusted
                                                        reason:reason
                                                 featureVector:vector];
}

- (NSMenuItem *)trustActionItemForThreat:(ThreatInfo *)threat
                              connection:(ConnectionTraffic *)connection {
    NSString *ip = threat.ipAddress;
    if (ip.length == 0) {
        return nil;
    }

    BOOL isTrusted = [self isIPTrusted:ip];

    if (isTrusted) {
        // Show "Remove Trust" option
        NSString *title = [NSString stringWithFormat:@"Remove Trust for %@", ip];
        NSMenuItem *item = [[NSMenuItem alloc] initWithTitle:title
                                                      action:@selector(removeTrustForIP:)
                                               keyEquivalent:@""];
        item.target = self;
        NSMutableDictionary *info = [NSMutableDictionary dictionaryWithDictionary:@{
            @"ip": ip,
            @"threat": threat
        }];
        if (connection) {
            info[@"connection"] = connection;
        }
        item.representedObject = info;

        // Style with red color
        NSMutableAttributedString *attr = [[NSMutableAttributedString alloc] initWithString:title];
        [attr addAttribute:NSForegroundColorAttributeName
                     value:[NSColor systemRedColor]
                     range:NSMakeRange(0, title.length)];
        item.attributedTitle = attr;

        return item;
    } else {
        // Show "Trust this IP" with reason submenu
        NSString *title = [NSString stringWithFormat:@"Trust %@...", ip];
        NSMenuItem *item = [[NSMenuItem alloc] initWithTitle:title action:nil keyEquivalent:@""];
        item.submenu = [self trustReasonSubmenuForIP:ip threat:threat connection:connection];

        NSMutableAttributedString *attr = [[NSMutableAttributedString alloc] initWithString:title];
        [attr addAttribute:NSForegroundColorAttributeName
                     value:[NSColor labelColor]
                     range:NSMakeRange(0, title.length)];
        item.attributedTitle = attr;

        return item;
    }
}

- (NSMenu *)trustReasonSubmenuForIP:(NSString *)ipAddress
                             threat:(ThreatInfo *)threat
                         connection:(ConnectionTraffic *)connection {
    NSMenu *menu = [[NSMenu alloc] initWithTitle:@"Trust Reason"];

    // Header
    NSMenuItem *header = [[NSMenuItem alloc] initWithTitle:@"Select reason for trusting:" action:nil keyEquivalent:@""];
    header.enabled = NO;
    NSFont *headerFont = [NSFont boldSystemFontOfSize:11.0];
    NSDictionary *headerAttrs = @{NSFontAttributeName: headerFont,
                                  NSForegroundColorAttributeName: [NSColor secondaryLabelColor]};
    header.attributedTitle = [[NSAttributedString alloc] initWithString:header.title attributes:headerAttrs];
    [menu addItem:header];
    [menu addItem:[NSMenuItem separatorItem]];

    SNBTrustSuggestion *suggestion = threat.trustSuggestion ?: [self trustSuggestionForThreat:threat connection:connection];
    if (suggestion) {
        NSString *title = [NSString stringWithFormat:@"Suggested: %@ (%.0f%%)",
                           suggestion.primaryReason ?: @"Unspecified",
                           suggestion.confidence * 100.0];
        NSMenuItem *suggestedItem = [[NSMenuItem alloc] initWithTitle:title
                                                               action:@selector(trustIPWithReason:)
                                                        keyEquivalent:@""];
        suggestedItem.target = self;
        SNBTrustContext *context = [self trustContextForThreat:threat
                                                    connection:connection
                                                        reason:suggestion.suggestedReason];
        suggestedItem.representedObject = @{
            @"ip": ipAddress,
            @"context": context,
            @"threat": threat,
            @"connection": connection ?: [NSNull null]
        };
        [menu addItem:suggestedItem];
        [menu addItem:[NSMenuItem separatorItem]];
    }

    // Reason options
    NSArray<NSNumber *> *reasons = [SNBTrustContext allReasons];
    for (NSNumber *reasonNum in reasons) {
        SNBTrustReason reason = reasonNum.integerValue;
        NSString *reasonStr = [SNBTrustContext displayStringForReason:reason];

        NSMenuItem *item = [[NSMenuItem alloc] initWithTitle:reasonStr
                                                      action:@selector(trustIPWithReason:)
                                               keyEquivalent:@""];
        item.target = self;

        // Create context for the action
        SNBTrustContext *context = [self trustContextForThreat:threat connection:connection reason:reason];

        item.representedObject = @{
            @"ip": ipAddress,
            @"context": context,
            @"threat": threat,
            @"connection": connection ?: [NSNull null]
        };

        [menu addItem:item];
    }

    return menu;
}

- (void)trustIPWithReason:(NSMenuItem *)sender {
    NSDictionary *info = sender.representedObject;
    NSString *ip = info[@"ip"];
    SNBTrustContext *context = info[@"context"];
    ThreatInfo *threat = info[@"threat"];
    ConnectionTraffic *connection = info[@"connection"];
    if ((id)connection == [NSNull null]) {
        connection = nil;
    }

    if (ip.length == 0 || !context) {
        return;
    }

    [[self _trustedStore] setTrusted:YES forIP:ip withContext:context];
    [self recordTrustFeedbackForThreat:threat
                            connection:connection
                               trusted:YES
                                reason:context.reason];
}

- (void)removeTrustForIP:(NSMenuItem *)sender {
    NSDictionary *info = sender.representedObject;
    NSString *ip = info[@"ip"];
    ThreatInfo *threat = info[@"threat"];
    ConnectionTraffic *connection = info[@"connection"];
    if ((id)connection == [NSNull null]) {
        connection = nil;
    }

    if (ip.length == 0) {
        return;
    }

    SNBTrustContext *context = threat
        ? [self trustContextForThreat:threat connection:connection reason:SNBTrustReasonUnspecified]
        : [[SNBTrustContext alloc] init];
    context.ipAddress = ip;

    [[self _trustedStore] setTrusted:NO forIP:ip withContext:context];
    [self recordTrustFeedbackForThreat:threat
                            connection:connection
                               trusted:NO
                                reason:context.reason];
}

- (NSArray<NSMenuItem *> *)trustHistoryItemsForIP:(NSString *)ipAddress {
    if (ipAddress.length == 0) {
        return @[];
    }

    NSArray<SNBTrustHistoryEntry *> *history = [[self _trustedStore] trustHistoryForIP:ipAddress];
    if (history.count == 0) {
        return @[];
    }

    NSMutableArray<NSMenuItem *> *items = [NSMutableArray array];

    // Header
    NSMenuItem *header = [self detailHeaderMenuItemWithTitle:@"Trust History"];
    [items addObject:header];

    // Date formatter
    NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
    formatter.dateStyle = NSDateFormatterShortStyle;
    formatter.timeStyle = NSDateFormatterShortStyle;

    // Show last 5 entries
    NSUInteger limit = MIN(history.count, 5);
    for (NSUInteger i = 0; i < limit; i++) {
        SNBTrustHistoryEntry *entry = history[i];

        NSString *action = entry.trusted ? @"Trusted" : @"Untrusted";
        if (entry.autoAction) {
            action = entry.trusted ? @"Auto-trusted" : @"Auto-untrusted";
        }

        NSString *reasonStr = @"";
        if (entry.trusted && entry.reason != SNBTrustReasonUnspecified) {
            reasonStr = [NSString stringWithFormat:@" (%@)", [SNBTrustContext displayStringForReason:entry.reason]];
        }

        NSString *dateStr = [formatter stringFromDate:entry.timestamp];
        NSString *scoreStr = entry.threatScoreAtDecision > 0
            ? [NSString stringWithFormat:@" [score: %ld]", (long)entry.threatScoreAtDecision]
            : @"";

        NSString *title = [NSString stringWithFormat:@"  %@: %@%@%@",
                          dateStr, action, reasonStr, scoreStr];

        NSMenuItem *item = [[NSMenuItem alloc] initWithTitle:title action:nil keyEquivalent:@""];
        item.enabled = NO;

        // Style based on action
        NSMutableAttributedString *attr = [[NSMutableAttributedString alloc] initWithString:title];
        NSColor *color = entry.trusted ? [NSColor secondaryLabelColor] : [NSColor systemOrangeColor];
        if (entry.autoAction && !entry.trusted) {
            color = [NSColor systemRedColor];  // Auto-untrust is red
        }
        NSFont *font = [NSFont systemFontOfSize:10.0];
        [attr addAttribute:NSFontAttributeName value:font range:NSMakeRange(0, title.length)];
        [attr addAttribute:NSForegroundColorAttributeName value:color range:NSMakeRange(0, title.length)];
        item.attributedTitle = attr;

        [items addObject:item];
    }

    if (history.count > 5) {
        NSString *moreStr = [NSString stringWithFormat:@"  ... and %lu more entries",
                            (unsigned long)(history.count - 5)];
        NSMenuItem *moreItem = [[NSMenuItem alloc] initWithTitle:moreStr action:nil keyEquivalent:@""];
        moreItem.enabled = NO;
        [items addObject:moreItem];
    }

    return items;
}

- (NSMenu *)trustedIPDetailsSubmenuForContext:(SNBTrustContext *)context
                                        stats:(nullable TrafficStats *)stats {
    NSMenu *menu = [[NSMenu alloc] initWithTitle:@"Legitimate Connection Details"];
    menu.autoenablesItems = NO;
    menu.delegate = self;
    objc_setAssociatedObject(menu, kTrustedDetailsMenuInfoKey, @{
        @"context": context ?: [NSNull null],
        @"stats": stats ?: [NSNull null]
    }, OBJC_ASSOCIATION_RETAIN_NONATOMIC);

    NSMenuItem *loadingItem = [[NSMenuItem alloc] initWithTitle:@"Loading details..." action:nil keyEquivalent:@""];
    loadingItem.tag = kTrustedDetailsPlaceholderTag;
    [menu addItem:loadingItem];

    return menu;
}

- (void)menuNeedsUpdate:(NSMenu *)menu {
    NSDictionary *info = objc_getAssociatedObject(menu, kTrustedDetailsMenuInfoKey);
    if (![info isKindOfClass:[NSDictionary class]]) {
        return;
    }
    if (!info[@"context"]) {
        return;
    }

    NSArray<NSMenuItem *> *items = menu.itemArray;
    if (items.count > 0 && items.firstObject.tag != kTrustedDetailsPlaceholderTag) {
        return;
    }

    [menu removeAllItems];

    SNBTrustContext *context = info[@"context"];
    if ((id)context == [NSNull null]) {
        context = nil;
    }
    TrafficStats *stats = info[@"stats"];
    if ((id)stats == [NSNull null]) {
        stats = nil;
    }

    [self populateTrustedIPDetailsMenu:menu context:context stats:stats];
}

- (void)populateTrustedIPDetailsMenu:(NSMenu *)menu
                             context:(SNBTrustContext *)context
                               stats:(nullable TrafficStats *)stats {
    [menu addItem:[self detailHeaderMenuItemWithTitle:@"Legitimate Connection Details"]];

    NSString *ipAddress = context.ipAddress ?: @"";
    if (ipAddress.length > 0) {
        [menu addItem:[self detailMenuItemWithTitle:[NSString stringWithFormat:@"IP: %@", ipAddress]]];
    }

    if (context.reason != SNBTrustReasonUnspecified) {
        NSString *reason = [SNBTrustContext displayStringForReason:context.reason];
        [menu addItem:[self detailMenuItemWithTitle:[NSString stringWithFormat:@"Reason: %@", reason]]];
    }

    if (context.customReasonNote.length > 0) {
        [menu addItem:[self detailMenuItemWithTitle:[NSString stringWithFormat:@"Note: %@", context.customReasonNote]]];
    }

    if (context.hostname.length > 0) {
        [menu addItem:[self detailMenuItemWithTitle:[NSString stringWithFormat:@"Hostname: %@", context.hostname]]];
    }

    if (context.processName.length > 0 && context.processPID > 0) {
        [menu addItem:[self detailMenuItemWithTitle:[NSString stringWithFormat:@"Process: %@ [%d]",
                                                     context.processName, context.processPID]]];
    } else if (context.processName.length > 0) {
        [menu addItem:[self detailMenuItemWithTitle:[NSString stringWithFormat:@"Process: %@",
                                                     context.processName]]];
    } else if (context.processPID > 0) {
        [menu addItem:[self detailMenuItemWithTitle:[NSString stringWithFormat:@"Process PID: %d",
                                                     context.processPID]]];
    }

    if (context.destinationPort > 0) {
        [menu addItem:[self detailMenuItemWithTitle:[NSString stringWithFormat:@"Destination port: %ld",
                                                     (long)context.destinationPort]]];
    }

    if (context.trustedAt) {
        NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
        formatter.dateStyle = NSDateFormatterMediumStyle;
        formatter.timeStyle = NSDateFormatterShortStyle;
        NSString *trustedAt = [formatter stringFromDate:context.trustedAt];
        [menu addItem:[self detailMenuItemWithTitle:[NSString stringWithFormat:@"Trusted at: %@", trustedAt]]];
    }

    if (stats && ipAddress.length > 0) {
        NSArray<ConnectionTraffic *> *connections = [self connectionsForIP:ipAddress inStats:stats];
        uint64_t totalBytes = [self totalBytesForIP:ipAddress inStats:stats];
        if (connections.count > 0 || totalBytes > 0) {
            [menu addItem:[NSMenuItem separatorItem]];
            [menu addItem:[self detailHeaderMenuItemWithTitle:@"Active traffic"]];
            if (connections.count > 0) {
                [menu addItem:[self detailMenuItemWithTitle:[NSString stringWithFormat:@"Active connections: %lu",
                                                             (unsigned long)connections.count]]];
            }
            if (totalBytes > 0) {
                [menu addItem:[self detailMenuItemWithTitle:[NSString stringWithFormat:@"Active traffic: %@",
                                                             [SNBByteFormatter stringFromBytes:totalBytes]]]];
            }
        }
    }

    NSDictionary<NSString *, id> *persisted = ipAddress.length > 0
        ? [self persistedConnectionDetailsForIP:ipAddress]
        : @{};
    if (persisted.count > 0) {
        NSString *source = persisted[@"sourceAddress"];
        NSString *destination = persisted[@"destinationAddress"];
        NSNumber *sourcePort = persisted[@"sourcePort"];
        NSNumber *destinationPort = persisted[@"destinationPort"];
        NSString *processName = persisted[@"processName"];
        NSNumber *processPID = persisted[@"processPID"];
        NSNumber *bytes = persisted[@"bytes"];
        NSNumber *packets = persisted[@"packets"];
        NSString *day = persisted[@"day"];

        BOOL hasConnectionLine = (source.length > 0 && destination.length > 0);
        BOOL hasProcessLine = (processName.length > 0 || processPID.intValue > 0);
        BOOL hasTrafficLine = (bytes.unsignedLongLongValue > 0 || packets.unsignedLongLongValue > 0);

        if (hasConnectionLine || hasProcessLine || hasTrafficLine || day.length > 0) {
            [menu addItem:[NSMenuItem separatorItem]];
            [menu addItem:[self detailHeaderMenuItemWithTitle:@"Last seen connection"]];
            if (hasConnectionLine) {
                NSString *line = [NSString stringWithFormat:@"%@:%ld → %@:%ld",
                                  source,
                                  (long)sourcePort.integerValue,
                                  destination,
                                  (long)destinationPort.integerValue];
                [menu addItem:[self detailMenuItemWithTitle:line]];
            }
            if (hasProcessLine) {
                if (processName.length > 0 && processPID.intValue > 0) {
                    [menu addItem:[self detailMenuItemWithTitle:[NSString stringWithFormat:@"Process: %@ [%d]",
                                                                 processName, processPID.intValue]]];
                } else if (processName.length > 0) {
                    [menu addItem:[self detailMenuItemWithTitle:[NSString stringWithFormat:@"Process: %@",
                                                                 processName]]];
                } else {
                    [menu addItem:[self detailMenuItemWithTitle:[NSString stringWithFormat:@"Process PID: %d",
                                                                 processPID.intValue]]];
                }
            }
            if (hasTrafficLine) {
                if (bytes.unsignedLongLongValue > 0) {
                    [menu addItem:[self detailMenuItemWithTitle:[NSString stringWithFormat:@"Traffic: %@",
                                                                 [SNBByteFormatter stringFromBytes:bytes.unsignedLongLongValue]]]];
                }
                if (packets.unsignedLongLongValue > 0) {
                    [menu addItem:[self detailMenuItemWithTitle:[NSString stringWithFormat:@"Packets: %@",
                                                                 packets]]];
                }
            }
            if (day.length > 0) {
                [menu addItem:[self detailMenuItemWithTitle:[NSString stringWithFormat:@"Persisted day: %@", day]]];
            }
        }
    }

    NSArray<NSMenuItem *> *historyItems = [self trustHistoryItemsForIP:ipAddress];
    if (historyItems.count > 0) {
        [menu addItem:[NSMenuItem separatorItem]];
        for (NSMenuItem *item in historyItems) {
            [menu addItem:item];
        }
    }

    if (ipAddress.length > 0) {
        [menu addItem:[NSMenuItem separatorItem]];
        NSMenuItem *untrustItem = [[NSMenuItem alloc] initWithTitle:@"Untrust"
                                                             action:@selector(moveTrustedIPToPreviousThreats:)
                                                      keyEquivalent:@""];
        untrustItem.target = self;
        untrustItem.representedObject = ipAddress;
        NSMutableAttributedString *untrustAttr = [[NSMutableAttributedString alloc] initWithString:@"Untrust"];
        [untrustAttr addAttribute:NSForegroundColorAttributeName
                            value:[NSColor systemRedColor]
                            range:NSMakeRange(0, untrustAttr.length)];
        untrustItem.attributedTitle = untrustAttr;
        [menu addItem:untrustItem];
    }
}

@end

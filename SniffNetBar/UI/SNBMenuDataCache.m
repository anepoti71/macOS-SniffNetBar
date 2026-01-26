//
//  SNBMenuDataCache.m
//  SniffNetBar
//

#import "SNBMenuDataCache.h"
#import "TrafficStatistics.h"
#import "IPAddressUtilities.h"
#import "SNBBadgeRegistry.h"

@interface SNBMenuDataCache ()
@property (nonatomic, assign) CFAbsoluteTime lastStatsTimestampForMapConnections;
@property (nonatomic, assign) CFAbsoluteTime lastStatsTimestampForHighlights;
@property (nonatomic, copy) NSArray<ConnectionTraffic *> *cachedMapConnections;
@property (nonatomic, copy) NSDictionary<NSString *, NSColor *> *hostColorMap;
@property (nonatomic, copy) NSString *lastSelectedSourceIP;
@property (nonatomic, copy) NSString *lastSelectedDestinationIP;
@end

@implementation SNBMenuDataCache

- (NSArray<ConnectionTraffic *> *)mapConnections {
    return self.cachedMapConnections ?: @[];
}

- (void)updateWithStats:(TrafficStats *)stats
        selectedSourceIP:(NSString *)selectedSourceIP
   selectedDestinationIP:(NSString *)selectedDestinationIP {
    [self mapConnectionsForStats:stats];
    [self hostColorMapForStats:stats
              selectedSourceIP:selectedSourceIP
         selectedDestinationIP:selectedDestinationIP];
}

- (NSArray<ConnectionTraffic *> *)mapConnectionsForStats:(TrafficStats *)stats {
    if (!stats) {
        return @[];
    }
    if (stats.timestamp != self.lastStatsTimestampForMapConnections || !self.cachedMapConnections) {
        NSArray<ConnectionTraffic *> *allConnections = stats.topConnections ?: @[];
        if (allConnections.count == 0) {
            self.cachedMapConnections = @[];
            self.lastStatsTimestampForMapConnections = stats.timestamp;
            return self.cachedMapConnections;
        }

        NSMutableDictionary<NSString *, ConnectionTraffic *> *uniquePublicDestinations = [NSMutableDictionary dictionary];
        for (ConnectionTraffic *conn in allConnections) {
            NSString *destIP = conn.destinationAddress;
            if (destIP.length > 0 && [IPAddressUtilities isPublicIPAddress:destIP]) {
                if (!uniquePublicDestinations[destIP]) {
                    uniquePublicDestinations[destIP] = conn;
                }
            }
        }
        self.cachedMapConnections = [uniquePublicDestinations allValues];
        self.lastStatsTimestampForMapConnections = stats.timestamp;
    }
    return self.cachedMapConnections ?: @[];
}

- (NSDictionary<NSString *, NSColor *> *)hostColorMapForStats:(TrafficStats *)stats
                                              selectedSourceIP:(NSString *)selectedSourceIP
                                         selectedDestinationIP:(NSString *)selectedDestinationIP {
    if (!stats) {
        return @{};
    }
    BOOL selectionChanged = ![self.lastSelectedSourceIP isEqualToString:selectedSourceIP] ||
                            ![self.lastSelectedDestinationIP isEqualToString:selectedDestinationIP];
    if (stats.timestamp != self.lastStatsTimestampForHighlights || selectionChanged || !self.hostColorMap) {
        NSMutableDictionary<NSString *, NSColor *> *hostColorMap = [NSMutableDictionary dictionary];
        NSArray<ProcessTrafficSummary *> *summaries = stats.processSummaries ?: @[];
        for (ProcessTrafficSummary *summary in summaries) {
            NSColor *color = [self highlightColorForProcessSummary:summary
                                                             stats:stats
                                                   selectedSourceIP:selectedSourceIP
                                              selectedDestinationIP:selectedDestinationIP];
            for (NSString *destination in summary.destinations) {
                if (destination.length > 0 && !hostColorMap[destination]) {
                    hostColorMap[destination] = color;
                }
            }
        }
        self.hostColorMap = hostColorMap;
        self.lastStatsTimestampForHighlights = stats.timestamp;
        self.lastSelectedSourceIP = [selectedSourceIP copy];
        self.lastSelectedDestinationIP = [selectedDestinationIP copy];
    }
    return self.hostColorMap ?: @{};
}

- (NSColor *)highlightColorForProcessSummary:(ProcessTrafficSummary *)summary
                                       stats:(TrafficStats *)stats
                             selectedSourceIP:(NSString *)selectedSourceIP
                        selectedDestinationIP:(NSString *)selectedDestinationIP {
    if ([self isProcessSummaryRelatedToSelectedConnection:summary
                                                    stats:stats
                                          selectedSourceIP:selectedSourceIP
                                     selectedDestinationIP:selectedDestinationIP]) {
        return [NSColor systemYellowColor];
    }
    return [[SNBBadgeRegistry sharedRegistry] colorForProcessName:summary.processName
                                                              pid:summary.processPID
                                                 createIfMissing:YES];
}

- (BOOL)isProcessSummaryRelatedToSelectedConnection:(ProcessTrafficSummary *)summary
                                              stats:(TrafficStats *)stats
                                    selectedSourceIP:(NSString *)selectedSourceIP
                               selectedDestinationIP:(NSString *)selectedDestinationIP {
    if (selectedSourceIP.length == 0 || selectedDestinationIP.length == 0) {
        return NO;
    }

    for (NSString *dest in summary.destinations) {
        if ([dest isEqualToString:selectedSourceIP] ||
            [dest isEqualToString:selectedDestinationIP]) {
            return YES;
        }
    }

    NSArray<ConnectionTraffic *> *topConnections = stats.topConnections ?: @[];
    for (ConnectionTraffic *conn in topConnections) {
        if (![conn.processName isEqualToString:summary.processName] ||
            conn.processPID != summary.processPID) {
            continue;
        }
        if ([self isConnectionSelected:conn
                       selectedSourceIP:selectedSourceIP
                  selectedDestinationIP:selectedDestinationIP]) {
            return YES;
        }
    }
    return NO;
}

- (BOOL)isConnectionSelected:(ConnectionTraffic *)connection
             selectedSourceIP:(NSString *)selectedSourceIP
        selectedDestinationIP:(NSString *)selectedDestinationIP {
    if (selectedSourceIP.length == 0 || selectedDestinationIP.length == 0) {
        return NO;
    }
    return ([connection.sourceAddress isEqualToString:selectedSourceIP] &&
            [connection.destinationAddress isEqualToString:selectedDestinationIP]) ||
           ([connection.sourceAddress isEqualToString:selectedDestinationIP] &&
            [connection.destinationAddress isEqualToString:selectedSourceIP]);
}

@end

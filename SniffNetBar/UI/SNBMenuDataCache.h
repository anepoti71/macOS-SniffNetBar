//
//  SNBMenuDataCache.h
//  SniffNetBar
//

#import <Foundation/Foundation.h>

@class TrafficStats;
@class ConnectionTraffic;
@class ProcessTrafficSummary;
@class NSColor;

NS_ASSUME_NONNULL_BEGIN

@interface SNBMenuDataCache : NSObject

@property (nonatomic, copy, readonly) NSArray<ConnectionTraffic *> *mapConnections;
@property (nonatomic, copy, readonly) NSDictionary<NSString *, NSColor *> *hostColorMap;

- (void)updateWithStats:(TrafficStats *)stats
        selectedSourceIP:(nullable NSString *)selectedSourceIP
   selectedDestinationIP:(nullable NSString *)selectedDestinationIP;
- (NSArray<ConnectionTraffic *> *)mapConnectionsForStats:(TrafficStats *)stats;
- (NSDictionary<NSString *, NSColor *> *)hostColorMapForStats:(TrafficStats *)stats
                                              selectedSourceIP:(nullable NSString *)selectedSourceIP
                                         selectedDestinationIP:(nullable NSString *)selectedDestinationIP;
- (NSColor *)highlightColorForProcessSummary:(ProcessTrafficSummary *)summary
                                       stats:(TrafficStats *)stats
                             selectedSourceIP:(nullable NSString *)selectedSourceIP
                        selectedDestinationIP:(nullable NSString *)selectedDestinationIP;
- (BOOL)isProcessSummaryRelatedToSelectedConnection:(ProcessTrafficSummary *)summary
                                              stats:(TrafficStats *)stats
                                    selectedSourceIP:(nullable NSString *)selectedSourceIP
                               selectedDestinationIP:(nullable NSString *)selectedDestinationIP;

@end

NS_ASSUME_NONNULL_END

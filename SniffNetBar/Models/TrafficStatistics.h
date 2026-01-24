//
//  TrafficStatistics.h
//  SniffNetBar
//
//  Traffic statistics tracking
//

#import <Foundation/Foundation.h>
#import <sys/types.h>

@class PacketInfo, TrafficStats, HostTraffic, ConnectionTraffic;

@interface TrafficStatistics : NSObject

- (void)processPacket:(PacketInfo *)packetInfo;
- (TrafficStats *)getCurrentStats;
- (void)getCurrentStatsWithCompletion:(void (^)(TrafficStats *stats))completion;
- (void)getAllDestinationIPsWithCompletion:(void (^)(NSSet<NSString *> *ips))completion;
- (void)reset;

@end

@class ProcessTrafficSummary;

@interface TrafficStats : NSObject

@property (nonatomic, assign) uint64_t totalBytes;
@property (nonatomic, assign) uint64_t incomingBytes;
@property (nonatomic, assign) uint64_t outgoingBytes;
@property (nonatomic, assign) uint64_t totalPackets;
@property (nonatomic, assign) uint64_t bytesPerSecond;
@property (nonatomic, strong) NSArray<HostTraffic *> *topHosts;
@property (nonatomic, strong) NSArray<ConnectionTraffic *> *topConnections;
@property (nonatomic, strong) NSArray<ConnectionTraffic *> *allConnections;
@property (nonatomic, strong) NSSet<NSString *> *allActiveDestinationIPs;
@property (nonatomic, strong) NSArray<ProcessTrafficSummary *> *processSummaries;

@end

@interface HostTraffic : NSObject

@property (nonatomic, strong) NSString *address;
@property (nonatomic, strong) NSString *hostname;
@property (nonatomic, assign) uint64_t bytes;
@property (nonatomic, assign) NSInteger packetCount;
@property (nonatomic, assign) CFAbsoluteTime lastActivity;  // For TTL-based cleanup

@end

@interface ConnectionTraffic : NSObject

@property (nonatomic, strong) NSString *sourceAddress;
@property (nonatomic, strong) NSString *destinationAddress;
@property (nonatomic, assign) NSInteger sourcePort;
@property (nonatomic, assign) NSInteger destinationPort;
@property (nonatomic, assign) uint64_t bytes;
@property (nonatomic, assign) uint64_t incomingBytes;   // Bytes received (response traffic)
@property (nonatomic, assign) uint64_t outgoingBytes;   // Bytes sent (request traffic)
@property (nonatomic, assign) NSInteger packetCount;
@property (nonatomic, strong, nullable) NSString *processName;
@property (nonatomic, assign) pid_t processPID;
@property (nonatomic, assign) CFAbsoluteTime lastActivity;

@end

@interface ProcessTrafficSummary : NSObject

@property (nonatomic, copy) NSString *processName;
@property (nonatomic, assign) pid_t processPID;
@property (nonatomic, assign) uint64_t bytes;
@property (nonatomic, assign) uint64_t incomingBytes;   // Total bytes received
@property (nonatomic, assign) uint64_t outgoingBytes;   // Total bytes sent
@property (nonatomic, assign) NSUInteger connectionCount;
@property (nonatomic, strong) NSArray<NSString *> *destinations;

@end

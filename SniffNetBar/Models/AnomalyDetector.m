//
//  AnomalyDetector.m
//  SniffNetBar
//
//  Windowed feature aggregation and anomaly scoring
//

#import "AnomalyDetector.h"
#import "AnomalyPythonScorer.h"
#import "AnomalyCoreMLScorer.h"
#import "AnomalyStore.h"
#import "IPAddressUtilities.h"
#import "PacketInfo.h"
#import <math.h>

@interface SNBAnomalyFlowStats : NSObject
@property (nonatomic, assign) uint64_t bytes;
@property (nonatomic, assign) uint64_t packets;
@end

@implementation SNBAnomalyFlowStats
@end

@interface SNBAnomalyAccumulator : NSObject
@property (nonatomic, assign) uint64_t totalBytes;
@property (nonatomic, assign) uint64_t totalPackets;
@property (nonatomic, strong) NSMutableSet<NSNumber *> *uniqueSrcPorts;
@property (nonatomic, strong) NSMutableDictionary<NSString *, SNBAnomalyFlowStats *> *flows;
@property (nonatomic, strong) NSMutableDictionary<NSNumber *, NSNumber *> *portCounts;
@property (nonatomic, strong) NSMutableDictionary<NSNumber *, NSNumber *> *protoCounts;
@end

@implementation SNBAnomalyAccumulator
- (instancetype)init {
    self = [super init];
    if (self) {
        _uniqueSrcPorts = [NSMutableSet set];
        _flows = [NSMutableDictionary dictionary];
        _portCounts = [NSMutableDictionary dictionary];
        _protoCounts = [NSMutableDictionary dictionary];
    }
    return self;
}
@end

@interface SNBAnomalyDetector ()
@property (nonatomic, strong) NSMutableDictionary<NSString *, SNBAnomalyAccumulator *> *accumulators;
@property (nonatomic, assign) NSTimeInterval windowSeconds;
@property (nonatomic, assign) NSTimeInterval currentWindowStart;
@property (nonatomic, assign) NSInteger rareThreshold;
@property (nonatomic, strong) SNBAnomalyStore *store;
@property (nonatomic, strong) SNBAnomalyPythonScorer *scorer;
@property (nonatomic, strong) SNBAnomalyCoreMLScorer *coreMLScorer;
@property (nonatomic, strong) dispatch_queue_t workQueue;
@end

@implementation SNBAnomalyDetector

- (instancetype)initWithWindowSeconds:(NSTimeInterval)windowSeconds {
    self = [super init];
    if (self) {
        _windowSeconds = windowSeconds;
        _currentWindowStart = floor([[NSDate date] timeIntervalSince1970] / windowSeconds) * windowSeconds;
        _accumulators = [NSMutableDictionary dictionary];
        _rareThreshold = 3;
        _store = [SNBAnomalyStore sharedStore];
        NSString *coreMLPath = [SNBAnomalyStore defaultCoreMLModelPath];
        _coreMLScorer = [[SNBAnomalyCoreMLScorer alloc] initWithModelPath:coreMLPath];

        NSString *scriptPath = [[NSBundle mainBundle] pathForResource:@"anomaly_score" ofType:@"py"];
        NSString *modelPath = [SNBAnomalyStore defaultModelPath];
        _scorer = [[SNBAnomalyPythonScorer alloc] initWithScriptPath:scriptPath modelPath:modelPath];
        _workQueue = dispatch_queue_create("com.sniffnetbar.anomaly", DISPATCH_QUEUE_SERIAL);
    }
    return self;
}

- (void)processPacket:(PacketInfo *)packetInfo {
    if (!packetInfo.destinationAddress.length) {
        return;
    }
    if ([IPAddressUtilities isPrivateIPAddress:packetInfo.destinationAddress]) {
        return;
    }

    dispatch_async(self.workQueue, ^{
        [self flushIfNeededLocked];
        SNBAnomalyAccumulator *acc = self.accumulators[packetInfo.destinationAddress];
        if (!acc) {
            acc = [[SNBAnomalyAccumulator alloc] init];
            self.accumulators[packetInfo.destinationAddress] = acc;
        }

        acc.totalBytes += packetInfo.totalBytes;
        acc.totalPackets += 1;

        if (packetInfo.sourcePort > 0) {
            [acc.uniqueSrcPorts addObject:@(packetInfo.sourcePort)];
        }

        NSString *flowKey = [NSString stringWithFormat:@"%@:%ld->%@:%ld/%ld",
                             packetInfo.sourceAddress ?: @"",
                             (long)packetInfo.sourcePort,
                             packetInfo.destinationAddress,
                             (long)packetInfo.destinationPort,
                             (long)packetInfo.protocol];

        SNBAnomalyFlowStats *flow = acc.flows[flowKey];
        if (!flow) {
            flow = [[SNBAnomalyFlowStats alloc] init];
            acc.flows[flowKey] = flow;
        }
        flow.bytes += packetInfo.totalBytes;
        flow.packets += 1;

        NSNumber *portKey = @(packetInfo.destinationPort);
        NSNumber *portCount = acc.portCounts[portKey] ?: @0;
        acc.portCounts[portKey] = @(portCount.integerValue + 1);

        NSNumber *protoKey = @(packetInfo.protocol);
        NSNumber *protoCount = acc.protoCounts[protoKey] ?: @0;
        acc.protoCounts[protoKey] = @(protoCount.integerValue + 1);
    });
}

- (void)flushIfNeeded {
    dispatch_async(self.workQueue, ^{
        [self flushIfNeededLocked];
    });
}

- (void)reloadModels {
    dispatch_async(self.workQueue, ^{
        NSString *coreMLPath = [SNBAnomalyStore defaultCoreMLModelPath];
        self.coreMLScorer = [[SNBAnomalyCoreMLScorer alloc] initWithModelPath:coreMLPath];

        NSString *scriptPath = [[NSBundle mainBundle] pathForResource:@"anomaly_score" ofType:@"py"];
        NSString *modelPath = [SNBAnomalyStore defaultModelPath];
        self.scorer = [[SNBAnomalyPythonScorer alloc] initWithScriptPath:scriptPath modelPath:modelPath];
    });
}

- (void)flushIfNeededLocked {
    NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
    if (now < self.currentWindowStart + self.windowSeconds) {
        return;
    }

    NSTimeInterval windowStart = self.currentWindowStart;
    self.currentWindowStart = floor(now / self.windowSeconds) * self.windowSeconds;

    NSDictionary<NSString *, SNBAnomalyAccumulator *> *snapshot = [self.accumulators copy];
    [self.accumulators removeAllObjects];

    for (NSString *dstIP in snapshot) {
        SNBAnomalyAccumulator *acc = snapshot[dstIP];
        if (!acc || acc.totalPackets == 0) {
            continue;
        }

        NSInteger dstPort = [self mostCommonKeyInCounts:acc.portCounts defaultValue:0];
        NSInteger proto = [self mostCommonKeyInCounts:acc.protoCounts defaultValue:0];

        double flowCount = (double)acc.flows.count;
        double avgPktSize = (double)acc.totalBytes / MAX(1.0, (double)acc.totalPackets);
        double bytesPerFlow = (double)acc.totalBytes / MAX(1.0, flowCount);
        double pktsPerFlow = (double)acc.totalPackets / MAX(1.0, flowCount);
        double burstiness = [self burstinessForFlows:acc.flows];

        NSInteger seenCount = [self.store seenCountForIP:dstIP];
        BOOL isNew = (seenCount == 0);
        BOOL isRare = (!isNew && seenCount < self.rareThreshold);

        NSDictionary<NSString *, NSNumber *> *payload = @{
            @"total_bytes": @(acc.totalBytes),
            @"total_packets": @(acc.totalPackets),
            @"unique_src_ports": @(acc.uniqueSrcPorts.count),
            @"flow_count": @(flowCount),
            @"avg_pkt_size": @(avgPktSize),
            @"bytes_per_flow": @(bytesPerFlow),
            @"pkts_per_flow": @(pktsPerFlow),
            @"burstiness": @(burstiness),
            @"port_well_known": @((dstPort >= 1 && dstPort <= 1023) ? 1 : 0),
            @"port_registered": @((dstPort >= 1024 && dstPort <= 49151) ? 1 : 0),
            @"port_dynamic": @((dstPort >= 49152 && dstPort <= 65535) ? 1 : 0),
            @"proto_tcp": @(proto == PacketProtocolTCP ? 1 : 0),
            @"proto_udp": @(proto == PacketProtocolUDP ? 1 : 0),
            @"proto_icmp": @(proto == PacketProtocolICMP ? 1 : 0),
            @"proto_other": @((proto != PacketProtocolTCP &&
                              proto != PacketProtocolUDP &&
                              proto != PacketProtocolICMP) ? 1 : 0)
        };

        NSError *scoreError = nil;
        NSNumber *scoreNumber = [self.coreMLScorer scoreFeaturePayload:payload error:&scoreError];
        if (!scoreNumber) {
            scoreNumber = [self.scorer scoreFeaturePayload:payload error:&scoreError];
        }
        BOOL scoringAvailable = (scoreNumber != nil);
        double score = scoringAvailable ? scoreNumber.doubleValue : 0.0;

        if (scoringAvailable) {
            if (isNew) {
                score = MAX(score, 0.98);
            } else if (isRare) {
                score = MAX(score, 0.95);
            }
        }

        [self.store recordWindowForIP:dstIP
                          windowStart:windowStart
                              dstPort:dstPort
                                proto:proto
                           totalBytes:(double)acc.totalBytes
                         totalPackets:(double)acc.totalPackets
                      uniqueSrcPorts:(double)acc.uniqueSrcPorts.count
                            flowCount:flowCount
                         avgPktSize:avgPktSize
                      bytesPerFlow:bytesPerFlow
                        pktsPerFlow:pktsPerFlow
                          burstiness:burstiness
                             isNewDst:isNew
                            isRareDst:isRare
                               score:score];
    }
}

- (NSInteger)mostCommonKeyInCounts:(NSDictionary<NSNumber *, NSNumber *> *)counts
                      defaultValue:(NSInteger)defaultValue {
    NSInteger bestKey = defaultValue;
    NSInteger bestCount = -1;
    for (NSNumber *key in counts) {
        NSInteger count = counts[key].integerValue;
        if (count > bestCount) {
            bestCount = count;
            bestKey = key.integerValue;
        }
    }
    return bestKey;
}

- (double)burstinessForFlows:(NSDictionary<NSString *, SNBAnomalyFlowStats *> *)flows {
    NSUInteger n = flows.count;
    if (n == 0) {
        return 0.0;
    }
    double mean = 0.0;
    for (SNBAnomalyFlowStats *flow in flows.allValues) {
        mean += (double)flow.bytes;
    }
    mean /= (double)n;
    double variance = 0.0;
    for (SNBAnomalyFlowStats *flow in flows.allValues) {
        double diff = (double)flow.bytes - mean;
        variance += diff * diff;
    }
    variance /= (double)n;
    return sqrt(variance);
}

@end

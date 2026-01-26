//
//  TrafficStatistics.m
//  SniffNetBar
//
//  Traffic statistics tracking
//

#import "TrafficStatistics.h"
#import "PacketInfo.h"
#import "ExpiringCache.h"
#import "Logger.h"
#import "ProcessLookup.h"
#import "SNBSocketPIDMap.h"
#import "ConfigurationManager.h"
#import "SNBTimerCoordinator.h"
#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <ifaddrs.h>
#import <netdb.h>
#import <SystemConfiguration/SystemConfiguration.h>
#import <CFNetwork/CFNetwork.h>
#import <string.h>

// Cache size limits
static const NSUInteger kMaxHostCacheSize = 1000;
static const NSUInteger kMaxConnectionCacheSize = 1000;
static const NSUInteger kMaxHostnameCacheSize = 500;
static const NSTimeInterval kCacheExpirationTime = 3600; // 1 hour
static const NSTimeInterval kCleanupInterval = 300; // 5 minutes
static const NSTimeInterval kConnectionRetentionSeconds = 10.0; // Remove stale connections after 10s of inactivity
static const NSTimeInterval kHostRetentionSeconds = 10.0; // Remove stale hosts after 10s of inactivity (same as connections)
static const NSTimeInterval kDNSLookupTimeout = 5.0; // 5 seconds
static const long kMaxConcurrentDNSLookups = 8;
static const NSUInteger kMaxProcessCacheSize = 1000;
static const NSTimeInterval kProcessCacheExpirationTime = 900.0; // 15 minutes
static const NSUInteger kMaxPortProcessCacheSize = 512;
static const NSTimeInterval kPortProcessCacheExpirationTime = 300.0; // 5 minutes
static const NSTimeInterval kProcessLookupRefreshInterval = 2.0; // Refresh PID mapping every 2s
static const NSTimeInterval kProcessLookupRetryInterval = 2.0; // Min retry interval per flow
static const NSTimeInterval kProcessLookupActivityWindow = 15.0; // Only refresh active flows
static const NSUInteger kMaxProcessLookupsPerPass = 40;
static const NSUInteger kMaxPendingDNSLookups = 100; // Max queued DNS lookups (prevents memory leak)
static const NSTimeInterval kDNSLockMaxAge = 60.0; // PERF-3: Max age for DNS lookup locks before cleanup

// Special marker for failed DNS lookups
static NSString * const kDNSLookupFailedMarker = @"__DNS_FAILED__";

@class SNBConnectionKey;

@interface TrafficStatistics ()
@property (nonatomic, strong) NSMutableDictionary<NSString *, HostTraffic *> *hostStats;
@property (nonatomic, strong) NSMutableDictionary *connectionStats;
@property (nonatomic, assign) uint64_t totalBytes;
@property (nonatomic, assign) uint64_t incomingBytes;
@property (nonatomic, assign) uint64_t outgoingBytes;
@property (nonatomic, assign) uint64_t totalPackets;
@property (nonatomic, strong) NSMutableSet<NSString *> *localAddresses;
@property (nonatomic, strong) SNBExpiringCache<NSString *, NSString *> *hostnameCache;
@property (nonatomic, strong) SNBExpiringCache<id, id> *processCache;
@property (nonatomic, strong) SNBExpiringCache<SNBConnectionKey *, ProcessInfo *> *lsofProcessCache;
@property (nonatomic, strong) SNBExpiringCache<NSNumber *, ProcessInfo *> *portProcessCache;
@property (nonatomic, strong) NSMutableDictionary<NSString *, NSObject *> *dnsLookupLocks;
@property (nonatomic, strong) NSMutableDictionary<NSString *, NSDate *> *dnsLookupLockTimestamps; // PERF-3: Track lock creation time
@property (nonatomic, strong) NSMutableDictionary *processLookupLocks;
@property (nonatomic, strong) dispatch_queue_t dnsLookupQueue;
@property (nonatomic, strong) dispatch_semaphore_t dnsLookupSemaphore;
@property (nonatomic, strong) dispatch_queue_t statsQueue;
@property (nonatomic, strong) NSDate *lastUpdateTime;
@property (nonatomic, assign) uint64_t lastTotalBytes;
@property (nonatomic, copy) SNBTimerID cleanupTimerID;
@property (nonatomic, strong) NSArray<HostTraffic *> *cachedTopHosts;
@property (nonatomic, strong) NSArray<ConnectionTraffic *> *cachedTopConnections;
@property (nonatomic, assign) BOOL statsCacheDirty;
@property (nonatomic, assign) uint64_t lastSampleTotalBytes;
@property (nonatomic, strong) NSDate *lastSampleTime;
@property (nonatomic, assign) uint64_t cachedBytesPerSecond;
@property (nonatomic, copy) SNBTimerID samplingTimerID;
@property (nonatomic, copy) SNBTimerID processRefreshTimerID;
@property (nonatomic, assign) NSUInteger pendingDNSLookupCount;
@property (nonatomic, strong) NSMutableDictionary<SNBConnectionKey *, ProcessInfo *> *pendingHelperProcessInfos;
@property (nonatomic, strong) NSMutableDictionary<SNBConnectionKey *, ProcessInfo *> *pendingLsofProcessInfos;
@property (nonatomic, strong) NSMutableDictionary<SNBConnectionKey *, NSNumber *> *processLookupLastAttempt;
// Performance: String-based connection key cache to avoid object creation for existing connections
@property (nonatomic, strong) NSMutableDictionary<NSString *, SNBConnectionKey *> *connectionKeyCache;
@property (nonatomic, strong) NSMutableDictionary<NSNumber *, NSMutableArray<SNBConnectionKey *> *> *connectionKeyHashCache;
@end

@interface SNBConnectionKey : NSObject <NSCopying>
@property (nonatomic, copy) NSString *source;
@property (nonatomic, copy) NSString *destination;
@property (nonatomic, assign) NSInteger sourcePort;
@property (nonatomic, assign) NSInteger destinationPort;
@property (nonatomic, assign) NSUInteger cachedHash; // Performance: Cache hash value
- (instancetype)initWithSource:(NSString *)source
                   sourcePort:(NSInteger)sourcePort
                   destination:(NSString *)destination
               destinationPort:(NSInteger)destinationPort;
- (NSString *)stringValue;
- (SNBConnectionKey *)reverseKey;  // For bidirectional flow matching
@end

@implementation SNBConnectionKey

- (instancetype)initWithSource:(NSString *)source
                   sourcePort:(NSInteger)sourcePort
                   destination:(NSString *)destination
               destinationPort:(NSInteger)destinationPort {
    self = [super init];
    if (self) {
        _source = [source copy] ?: @"";
        _destination = [destination copy] ?: @"";
        _sourcePort = sourcePort;
        _destinationPort = destinationPort;

        // Performance: Pre-compute and cache hash value since keys are immutable
        NSUInteger hash = _source.hash ^ _destination.hash;
        hash ^= (NSUInteger)sourcePort * 16777619u;
        hash ^= (NSUInteger)destinationPort * 2166136261u;
        _cachedHash = hash;
    }
    return self;
}

- (NSUInteger)hash {
    // Performance: Return pre-computed cached hash instead of recalculating
    return self.cachedHash;
}

- (BOOL)isEqual:(id)object {
    if (![object isKindOfClass:[SNBConnectionKey class]]) {
        return NO;
    }
    SNBConnectionKey *other = object;
    return self.sourcePort == other.sourcePort &&
        self.destinationPort == other.destinationPort &&
        [self.source isEqualToString:other.source] &&
        [self.destination isEqualToString:other.destination];
}

- (id)copyWithZone:(NSZone *)zone {
    return self;
}

- (NSString *)stringValue {
    return [NSString stringWithFormat:@"%@:%ld->%@:%ld",
            self.source, (long)self.sourcePort, self.destination, (long)self.destinationPort];
}

- (SNBConnectionKey *)reverseKey {
    // Create a key with swapped source/destination for bidirectional flow matching
    return [[SNBConnectionKey alloc] initWithSource:self.destination
                                         sourcePort:self.destinationPort
                                        destination:self.source
                                    destinationPort:self.sourcePort];
}

@end

// Performance: Helper function to build string key for connection lookup (avoids object creation)
static inline NSString *SNBConnectionStringKey(NSString *source, NSInteger sourcePort,
                                                NSString *dest, NSInteger destPort) {
    return [NSString stringWithFormat:@"%@:%ld>%@:%ld", source, (long)sourcePort, dest, (long)destPort];
}

static inline uint64_t SNBConnectionQuickHash(NSString *source, NSInteger sourcePort,
                                              NSString *dest, NSInteger destPort) {
    uint64_t sourceHash = (uint64_t)source.hash;
    uint64_t destHash = (uint64_t)dest.hash;
    uint64_t ports = ((uint64_t)(sourcePort & 0xffff) << 16) | (uint64_t)(destPort & 0xffff);
    return sourceHash ^ (destHash << 1) ^ (ports << 32);
}

static inline BOOL SNBConnectionKeyMatches(SNBConnectionKey *key,
                                           NSString *source,
                                           NSInteger sourcePort,
                                           NSString *dest,
                                           NSInteger destPort) {
    return key.sourcePort == sourcePort &&
        key.destinationPort == destPort &&
        [key.source isEqualToString:source] &&
        [key.destination isEqualToString:dest];
}

@interface ProcessTrafficSummary ()
@property (nonatomic, strong) NSMutableOrderedSet<NSString *> *mutableDestinations;
@end

@implementation ProcessTrafficSummary

- (instancetype)init {
    self = [super init];
    if (self) {
        _mutableDestinations = [NSMutableOrderedSet orderedSet];
    }
    return self;
}

- (void)addDestination:(NSString *)destination {
    if (destination.length > 0) {
        [self.mutableDestinations addObject:destination];
    }
}

- (void)finalizeDestinations {
    NSArray<NSString *> *destinations = [self.mutableDestinations array];
    if (destinations.count > 0) {
        self.destinations = [destinations sortedArrayUsingSelector:@selector(compare:)];
    } else {
        self.destinations = @[];
    }
    self.mutableDestinations = nil;
}

@end

typedef NS_ENUM(NSUInteger, SNBProcessLookupSource) {
    SNBProcessLookupSourceHelper,
    SNBProcessLookupSourceLsof
};

typedef struct {
    BOOL resolved;
    CFStringRef name;
} SNBDNSLookupContext;

static void SNBDNSHostCallback(CFHostRef host,
                               CFHostInfoType typeInfo,
                               const CFStreamError *error,
                               void *info) {
    SNBDNSLookupContext *context = (SNBDNSLookupContext *)info;
    if (!context || context->resolved) {
        return;
    }
    Boolean hasResult = false;
    CFArrayRef names = CFHostGetNames(host, &hasResult);
    if (hasResult && names && CFArrayGetCount(names) > 0) {
        CFStringRef name = CFArrayGetValueAtIndex(names, 0);
        if (name) {
            context->name = CFRetain(name);
        }
    }
    context->resolved = YES;
    CFRunLoopStop(CFRunLoopGetCurrent());
}

static NSString *SNBResolveHostname(NSString *address,
                                    NSTimeInterval timeout,
                                    BOOL *timedOut) {
    if (timedOut) {
        *timedOut = NO;
    }
    if (address.length == 0) {
        return nil;
    }

    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;
    NSData *addressData = nil;

    memset(&sin, 0, sizeof(sin));
    memset(&sin6, 0, sizeof(sin6));
    if (inet_pton(AF_INET, address.UTF8String, &sin.sin_addr) == 1) {
        sin.sin_family = AF_INET;
        addressData = [NSData dataWithBytes:&sin length:sizeof(sin)];
    } else if (inet_pton(AF_INET6, address.UTF8String, &sin6.sin6_addr) == 1) {
        sin6.sin6_family = AF_INET6;
        addressData = [NSData dataWithBytes:&sin6 length:sizeof(sin6)];
    } else {
        return nil;
    }

    CFHostRef host = CFHostCreateWithAddress(kCFAllocatorDefault, (__bridge CFDataRef)addressData);
    if (!host) {
        return nil;
    }

    SNBDNSLookupContext context = {0};
    CFHostClientContext clientContext = {0, &context, NULL, NULL, NULL};
    CFStreamError streamError = {0};
    BOOL started = (BOOL)CFHostSetClient(host, SNBDNSHostCallback, &clientContext);
    if (!started) {
        CFRelease(host);
        return nil;
    }

    CFHostScheduleWithRunLoop(host, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
    Boolean ok = CFHostStartInfoResolution(host, kCFHostNames, &streamError);
    if (!ok) {
        CFHostSetClient(host, NULL, NULL);
        CFHostUnscheduleFromRunLoop(host, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
        CFRelease(host);
        return nil;
    }

    CFAbsoluteTime deadline = CFAbsoluteTimeGetCurrent() + timeout;
    while (!context.resolved) {
        CFTimeInterval remaining = deadline - CFAbsoluteTimeGetCurrent();
        if (remaining <= 0) {
            if (timedOut) {
                *timedOut = YES;
            }
            break;
        }
        CFRunLoopRunInMode(kCFRunLoopDefaultMode, MIN(0.1, remaining), true);
    }

    if (!context.resolved) {
        CFHostCancelInfoResolution(host, kCFHostNames);
    }

    CFHostSetClient(host, NULL, NULL);
    CFHostUnscheduleFromRunLoop(host, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
    CFRelease(host);

    if (context.name) {
        return CFBridgingRelease(context.name);
    }
    return nil;
}

@implementation TrafficStatistics

- (instancetype)init {
    self = [super init];
    if (self) {
        _hostStats = [NSMutableDictionary dictionary];
        _connectionStats = [NSMutableDictionary dictionary];
        _hostnameCache = [[SNBExpiringCache alloc] initWithMaxSize:kMaxHostnameCacheSize
                                               expirationInterval:kCacheExpirationTime];
        _processCache = [[SNBExpiringCache alloc] initWithMaxSize:kMaxProcessCacheSize
                                             expirationInterval:kProcessCacheExpirationTime];
        _lsofProcessCache = [[SNBExpiringCache alloc] initWithMaxSize:kMaxProcessCacheSize
                                                 expirationInterval:kProcessCacheExpirationTime];
        _portProcessCache = [[SNBExpiringCache alloc] initWithMaxSize:kMaxPortProcessCacheSize
                                                   expirationInterval:kPortProcessCacheExpirationTime];
        _dnsLookupLocks = [NSMutableDictionary dictionary];
        _dnsLookupLockTimestamps = [NSMutableDictionary dictionary]; // PERF-3: Track lock timestamps
        _processLookupLocks = [NSMutableDictionary dictionary];
        _dnsLookupQueue = dispatch_queue_create("com.sniffnetbar.dnslookup", DISPATCH_QUEUE_CONCURRENT);
        _dnsLookupSemaphore = dispatch_semaphore_create(kMaxConcurrentDNSLookups);
        _statsQueue = dispatch_queue_create("com.sniffnetbar.stats", DISPATCH_QUEUE_SERIAL);
        _pendingHelperProcessInfos = [NSMutableDictionary dictionary];
        _pendingLsofProcessInfos = [NSMutableDictionary dictionary];
        _processLookupLastAttempt = [NSMutableDictionary dictionary];
        _connectionKeyCache = [NSMutableDictionary dictionary];  // Performance: Cache connection keys
        _connectionKeyHashCache = [NSMutableDictionary dictionary];
        _localAddresses = [NSMutableSet set];
        _statsCacheDirty = YES;
        [self loadLocalAddresses];

        // PERF-1: Start the global socket-to-PID map for O(1) process lookups
        [[SNBSocketPIDMap sharedMap] startPeriodicRefresh];

        // Set up periodic timers via centralized coordinator (better battery efficiency)
        __weak typeof(self) weakSelf = self;
        SNBTimerCoordinator *coordinator = [SNBTimerCoordinator sharedCoordinator];
        _cleanupTimerID = [coordinator scheduleRepeatingTimerWithInterval:kCleanupInterval
                                                                    queue:dispatch_get_main_queue()
                                                                  handler:^{
            [weakSelf performCacheCleanup];
        }];
        _samplingTimerID = [coordinator scheduleRepeatingTimerWithInterval:1.0
                                                                     queue:dispatch_get_main_queue()
                                                                   handler:^{
            [weakSelf sampleBytesPerSecond];
        }];
        _processRefreshTimerID = [coordinator scheduleRepeatingTimerWithInterval:kProcessLookupRefreshInterval
                                                                          queue:dispatch_get_main_queue()
                                                                        handler:^{
            [weakSelf refreshProcessLookups];
        }];
    }
    return self;
}

- (void)dealloc {
    SNBTimerCoordinator *coordinator = [SNBTimerCoordinator sharedCoordinator];
    [coordinator cancelTimer:_cleanupTimerID];
    [coordinator cancelTimer:_samplingTimerID];
    [coordinator cancelTimer:_processRefreshTimerID];
}

- (void)loadLocalAddresses {
    // Get local network interfaces
    struct ifaddrs *interfaces;
    if (getifaddrs(&interfaces) == 0) {
        struct ifaddrs *interface;
        for (interface = interfaces; interface != NULL; interface = interface->ifa_next) {
            if (interface->ifa_addr == NULL) continue;
            
            if (interface->ifa_addr->sa_family == AF_INET) {
                struct sockaddr_in *sin = (struct sockaddr_in *)interface->ifa_addr;
                char addr[INET_ADDRSTRLEN];
                if (inet_ntop(AF_INET, &sin->sin_addr, addr, INET_ADDRSTRLEN)) {
                    [self.localAddresses addObject:[NSString stringWithUTF8String:addr]];
                }
            } else if (interface->ifa_addr->sa_family == AF_INET6) {
                struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)interface->ifa_addr;
                char addr[INET6_ADDRSTRLEN];
                if (inet_ntop(AF_INET6, &sin6->sin6_addr, addr, INET6_ADDRSTRLEN)) {
                    [self.localAddresses addObject:[NSString stringWithUTF8String:addr]];
                }
            }
        }
        freeifaddrs(interfaces);
    }
    
    // Add loopback addresses
    [self.localAddresses addObject:@"127.0.0.1"];
    [self.localAddresses addObject:@"::1"];
}

- (BOOL)isLocalAddress:(NSString *)address {
    return [self.localAddresses containsObject:address];
}

- (void)removeStaleConnectionsLocked:(CFAbsoluteTime)now {
    if (now <= 0) {
        now = CFAbsoluteTimeGetCurrent();
    }

    // Remove stale connections
    NSMutableArray<SNBConnectionKey *> *staleConnections = [NSMutableArray array];
    [self.connectionStats enumerateKeysAndObjectsUsingBlock:^(SNBConnectionKey *key, ConnectionTraffic *connection, BOOL *stop) {
        if ((now - connection.lastActivity) > kConnectionRetentionSeconds) {
            [staleConnections addObject:key];
        }
    }];
    for (SNBConnectionKey *key in staleConnections) {
        [self.connectionStats removeObjectForKey:key];
        [self.processCache removeObjectForKey:key];
        [self.lsofProcessCache removeObjectForKey:key];
        [self.pendingHelperProcessInfos removeObjectForKey:key];
        [self.pendingLsofProcessInfos removeObjectForKey:key];
        [self.processLookupLastAttempt removeObjectForKey:key];
        uint64_t quickHash = SNBConnectionQuickHash(key.source, key.sourcePort, key.destination, key.destinationPort);
        NSNumber *hashKey = @(quickHash);
        NSMutableArray<SNBConnectionKey *> *bucket = self.connectionKeyHashCache[hashKey];
        if (bucket) {
            NSUInteger index = [bucket indexOfObjectPassingTest:^BOOL(SNBConnectionKey *candidate, NSUInteger idx, BOOL *stop) {
                return SNBConnectionKeyMatches(candidate, key.source, key.sourcePort, key.destination, key.destinationPort);
            }];
            if (index != NSNotFound) {
                [bucket removeObjectAtIndex:index];
                if (bucket.count == 0) {
                    [self.connectionKeyHashCache removeObjectForKey:hashKey];
                }
            }
        }
        // Performance: Also remove from connection key cache
        NSString *stringKey = SNBConnectionStringKey(key.source, key.sourcePort,
                                                      key.destination, key.destinationPort);
        [self.connectionKeyCache removeObjectForKey:stringKey];
    }

    // Remove stale hosts (same TTL as connections)
    NSMutableArray<NSString *> *staleHosts = [NSMutableArray array];
    [self.hostStats enumerateKeysAndObjectsUsingBlock:^(NSString *address, HostTraffic *host, BOOL *stop) {
        if ((now - host.lastActivity) > kHostRetentionSeconds) {
            [staleHosts addObject:address];
        }
    }];
    for (NSString *address in staleHosts) {
        [self.hostStats removeObjectForKey:address];
    }

    if (staleConnections.count > 0 || staleHosts.count > 0) {
        self.statsCacheDirty = YES;
    }
}

// PERF-3: Clean up stale DNS lookup locks to prevent unbounded memory growth
- (void)cleanupStaleDNSLookupLocks {
    NSDate *cutoff = [NSDate dateWithTimeIntervalSinceNow:-kDNSLockMaxAge];
    NSMutableArray<NSString *> *keysToRemove = [NSMutableArray array];

    @synchronized(self.dnsLookupLocks) {
        [self.dnsLookupLockTimestamps enumerateKeysAndObjectsUsingBlock:^(NSString *key, NSDate *timestamp, BOOL *stop) {
            if ([timestamp compare:cutoff] == NSOrderedAscending) {
                [keysToRemove addObject:key];
            }
        }];

        if (keysToRemove.count > 0) {
            [self.dnsLookupLocks removeObjectsForKeys:keysToRemove];
            [self.dnsLookupLockTimestamps removeObjectsForKeys:keysToRemove];
            SNBLogDebug("PERF-3: Cleaned up %lu stale DNS lookup locks (older than %.0fs)",
                       (unsigned long)keysToRemove.count, kDNSLockMaxAge);
        }
    }
}

- (void)performCacheCleanup {
    dispatch_async(self.statsQueue, ^{
        NSUInteger expiredCount = [self.hostnameCache cleanupAndReturnExpiredCount];
        CFAbsoluteTime now = CFAbsoluteTimeGetCurrent();

        // PERF-3: Clean up stale DNS lookup locks to prevent unbounded growth
        [self cleanupStaleDNSLookupLocks];

        // Remove stale TCP records that haven't seen activity recently
        [self removeStaleConnectionsLocked:now];

        // If host stats exceed max, remove entries with least traffic
        if (self.hostStats.count > kMaxHostCacheSize) {
            NSArray<HostTraffic *> *sortedHosts = [self.hostStats.allValues sortedArrayUsingComparator:^NSComparisonResult(HostTraffic *obj1, HostTraffic *obj2) {
                if (obj1.bytes < obj2.bytes) return NSOrderedAscending;
                if (obj1.bytes > obj2.bytes) return NSOrderedDescending;
                return NSOrderedSame;
            }];
            NSUInteger toRemove = self.hostStats.count - kMaxHostCacheSize;
            for (NSUInteger i = 0; i < toRemove && i < sortedHosts.count; i++) {
                [self.hostStats removeObjectForKey:sortedHosts[i].address];
            }
            self.statsCacheDirty = YES;
        }

        // If connection stats exceed max, remove entries with least traffic
        if (self.connectionStats.count > kMaxConnectionCacheSize) {
            NSArray *sortedKeys = [self.connectionStats keysSortedByValueUsingComparator:^NSComparisonResult(ConnectionTraffic *obj1, ConnectionTraffic *obj2) {
                if (obj1.bytes < obj2.bytes) return NSOrderedAscending;
                if (obj1.bytes > obj2.bytes) return NSOrderedDescending;
                return NSOrderedSame;
            }];
            NSUInteger toRemove = self.connectionStats.count - kMaxConnectionCacheSize;
            for (NSUInteger i = 0; i < toRemove && i < sortedKeys.count; i++) {
                [self.connectionStats removeObjectForKey:sortedKeys[i]];
            }
            self.statsCacheDirty = YES;
        }

        if (expiredCount > 0 || self.statsCacheDirty) {
            SNBLogDebug("Cache cleanup: removed %lu expired hostnames, %lu hosts, %lu connections",
                  (unsigned long)expiredCount,
                  (unsigned long)MAX(0, (NSInteger)self.hostStats.count - (NSInteger)kMaxHostCacheSize),
                  (unsigned long)MAX(0, (NSInteger)self.connectionStats.count - (NSInteger)kMaxConnectionCacheSize));
        }
    });
}

- (void)refreshProcessLookups {
    dispatch_async(self.statsQueue, ^{
        CFAbsoluteTime now = CFAbsoluteTimeGetCurrent();
        __block NSUInteger attempted = 0;

        [self.connectionStats enumerateKeysAndObjectsUsingBlock:^(SNBConnectionKey *key, ConnectionTraffic *connection, BOOL *stop) {
            if (attempted >= kMaxProcessLookupsPerPass) {
                *stop = YES;
                return;
            }
            if (!connection || connection.processName.length > 0 || connection.processPID > 0) {
                return;
            }
            if ((now - connection.lastActivity) > kProcessLookupActivityWindow) {
                return;
            }
            if (![self isLocalAddress:connection.sourceAddress]) {
                return;
            }
            NSNumber *lastAttempt = self.processLookupLastAttempt[key];
            if (lastAttempt && (now - lastAttempt.doubleValue) < kProcessLookupRetryInterval) {
                return;
            }
            if (self.processLookupLocks[key]) {
                return;
            }

            ProcessInfo *cachedByPort = [self cachedProcessInfoForPort:connection.sourcePort];
            if (cachedByPort) {
                [self assignProcessInfo:cachedByPort forConnectionKey:key];
                return;
            }

            self.processLookupLastAttempt[key] = @(now);
            attempted++;

            NSString *sourceAddress = connection.sourceAddress ?: @"";
            NSString *destinationAddress = connection.destinationAddress ?: @"";
            NSInteger sourcePort = connection.sourcePort;
            NSInteger destinationPort = connection.destinationPort;

            __weak typeof(self) weakSelf = self;
            [self performProcessLookup:sourceAddress
                            sourcePort:sourcePort
                           destination:destinationAddress
                       destinationPort:destinationPort
                             lookupKey:key
                              completion:^(ProcessInfo *processInfo) {
                __strong typeof(weakSelf) strongSelf = weakSelf;
                if (!strongSelf) {
                    return;
                }
                dispatch_async(strongSelf.statsQueue, ^{
                    [strongSelf handleProcessLookupResult:processInfo
                                             connectionKey:key
                                                    source:SNBProcessLookupSourceHelper];
                });
            }];

            [self scheduleNativeLookupForConnectionKey:key
                                               source:sourceAddress
                                           sourcePort:sourcePort
                                          destination:destinationAddress
                                      destinationPort:destinationPort];
        }];
    });
}

- (void)processPacket:(PacketInfo *)packetInfo {
    if (!packetInfo || packetInfo.totalBytes == 0) {
        return;
    }
    
    dispatch_async(self.statsQueue, ^{
        self.totalBytes += packetInfo.totalBytes;
        self.totalPackets++;
        self.statsCacheDirty = YES;  // Mark cache as dirty

        // Determine traffic direction
        BOOL isIncoming = [self isLocalAddress:packetInfo.destinationAddress];
        BOOL isOutgoing = [self isLocalAddress:packetInfo.sourceAddress];
        
        // If both are local or neither is local, use port comparison for loopback
        if (isIncoming && isOutgoing) {
            // Both local - use port comparison like the Rust code
            if (packetInfo.sourcePort > 0 && packetInfo.destinationPort > 0) {
                isIncoming = packetInfo.sourcePort < packetInfo.destinationPort;
                isOutgoing = !isIncoming;
            }
        } else if (!isIncoming && !isOutgoing) {
            // Neither local (shouldn't happen, but handle it)
            isIncoming = YES;
            isOutgoing = NO;
        }
        
        if (isIncoming) {
            self.incomingBytes += packetInfo.totalBytes;
        } else {
            self.outgoingBytes += packetInfo.totalBytes;
        }
        
        // Track host statistics
        NSString *remoteAddress = isIncoming ? packetInfo.sourceAddress : packetInfo.destinationAddress;
        if (remoteAddress && remoteAddress.length > 0) {
            HostTraffic *host = self.hostStats[remoteAddress];
            if (!host) {
                host = [[HostTraffic alloc] init];
                host.address = remoteAddress;
                NSString *cachedHostname = [self.hostnameCache objectForKey:remoteAddress];

                // Check if we have a cached result (including negative results)
                if (cachedHostname) {
                    // If it's a failed lookup marker, don't set hostname (leave it nil)
                    if (![cachedHostname isEqualToString:kDNSLookupFailedMarker]) {
                        host.hostname = cachedHostname;
                    }
                } else {
                    // Perform reverse DNS lookup asynchronously
                    __weak typeof(self) weakSelf = self;
                    [self performReverseDNSLookup:remoteAddress completion:^(NSString *hostname) {
                        __strong typeof(weakSelf) strongSelf = weakSelf;
                        if (!strongSelf) return;

                        dispatch_async(strongSelf.statsQueue, ^{
                            if (hostname) {
                                // Cache successful lookup
                                [strongSelf.hostnameCache setObject:hostname forKey:remoteAddress];
                                HostTraffic *h = strongSelf.hostStats[remoteAddress];
                                if (h) {
                                    h.hostname = hostname;
                                }
                            } else {
                                // Cache negative result to avoid repeated failed lookups
                                [strongSelf.hostnameCache setObject:kDNSLookupFailedMarker forKey:remoteAddress];
                            }
                        });
                    }];
                }
                self.hostStats[remoteAddress] = host;
            }
            host.bytes += packetInfo.totalBytes;
            host.packetCount++;
            host.lastActivity = CFAbsoluteTimeGetCurrent();
        }

        // Track connection statistics (use destination->source for inbound)
        NSString *connectionSource = isIncoming ? packetInfo.destinationAddress : packetInfo.sourceAddress;
        NSString *connectionDestination = isIncoming ? packetInfo.sourceAddress : packetInfo.destinationAddress;
        NSInteger connectionSourcePort = isIncoming ? packetInfo.destinationPort : packetInfo.sourcePort;
        NSInteger connectionDestinationPort = isIncoming ? packetInfo.sourcePort : packetInfo.destinationPort;

        if (connectionSource.length > 0 && connectionDestination.length > 0) {
            uint64_t quickHash = SNBConnectionQuickHash(connectionSource, connectionSourcePort,
                                                        connectionDestination, connectionDestinationPort);
            NSNumber *hashKey = @(quickHash);
            NSMutableArray<SNBConnectionKey *> *bucket = self.connectionKeyHashCache[hashKey];
            SNBConnectionKey *connectionKey = nil;
            if (bucket) {
                for (SNBConnectionKey *candidate in bucket) {
                    if (SNBConnectionKeyMatches(candidate, connectionSource, connectionSourcePort,
                                                connectionDestination, connectionDestinationPort)) {
                        connectionKey = candidate;
                        break;
                    }
                }
            }

            ConnectionTraffic *connection = nil;
            if (connectionKey) {
                connection = self.connectionStats[connectionKey];
            } else {
                // Only build the string key when we need to create a new connection key
                NSString *stringKey = SNBConnectionStringKey(connectionSource, connectionSourcePort,
                                                              connectionDestination, connectionDestinationPort);
                connectionKey = self.connectionKeyCache[stringKey];
                if (!connectionKey) {
                    connectionKey = [[SNBConnectionKey alloc] initWithSource:connectionSource
                                                                  sourcePort:connectionSourcePort
                                                                 destination:connectionDestination
                                                             destinationPort:connectionDestinationPort];
                    self.connectionKeyCache[stringKey] = connectionKey;
                    if (!bucket) {
                        bucket = [NSMutableArray array];
                        self.connectionKeyHashCache[hashKey] = bucket;
                    }
                    [bucket addObject:connectionKey];
                }
                connection = self.connectionStats[connectionKey];
            }

            if (!connection) {
                connection = [[ConnectionTraffic alloc] init];
                connection.sourceAddress = connectionSource;
                connection.destinationAddress = connectionDestination;
                connection.sourcePort = connectionSourcePort;
                connection.destinationPort = connectionDestinationPort;
                self.connectionStats[connectionKey] = connection;

                // Lookup process information asynchronously
                // Only lookup for outgoing connections (where source is local)
                if (!isIncoming && connectionSourcePort > 0 && connectionDestinationPort > 0) {
                    id cachedHelperObj = [self.processCache objectForKey:connectionKey];
                    BOOL hasHelperCache = cachedHelperObj != nil;
                    ProcessInfo *cachedHelper = (cachedHelperObj == [NSNull null]) ? nil : (ProcessInfo *)cachedHelperObj;
                    ProcessInfo *cachedLsof = [self.lsofProcessCache objectForKey:connectionKey];
                    ProcessInfo *finalCached = [self finalProcessInfoFromHelper:cachedHelper fallback:cachedLsof];
                    if (!finalCached) {
                        ProcessInfo *cachedByPort = [self cachedProcessInfoForPort:connectionSourcePort];
                        if (cachedByPort) {
                            SNBLogDebug("Port cache hit for source port %ld", (long)connectionSourcePort);
                            [self assignProcessInfo:cachedByPort forConnectionKey:connectionKey];
                            finalCached = cachedByPort;
                        }
                    }
                    if (finalCached) {
                        connection.processName = finalCached.processName;
                        connection.processPID = finalCached.pid;
                    }

                    BOOL shouldLookupHelper = !hasHelperCache;
                    BOOL shouldLookupFallback = cachedLsof == nil;

                    if (shouldLookupHelper) {
                        SNBLogDebug("Process lookup: %@:%ld -> %@:%ld",
                              connectionSource, (long)connectionSourcePort,
                              connectionDestination, (long)connectionDestinationPort);
                        __weak typeof(self) weakSelf = self;
                        [self performProcessLookup:connectionSource
                                        sourcePort:connectionSourcePort
                                       destination:connectionDestination
                                   destinationPort:connectionDestinationPort
                                        lookupKey:connectionKey
                                         completion:^(ProcessInfo *processInfo) {
                            __strong typeof(weakSelf) strongSelf = weakSelf;
                            if (!strongSelf) return;

                            dispatch_async(strongSelf.statsQueue, ^{
                                [strongSelf handleProcessLookupResult:processInfo
                                                         connectionKey:connectionKey
                                                                source:SNBProcessLookupSourceHelper];
                            });
                        }];
                    }

                    if (shouldLookupFallback) {
                        // For new connections, do immediate synchronous native lookup
                        // to catch short-lived connections before they close
                        ProcessInfo *immediateResult = [ProcessLookup lookupUsingNativeAPIForSource:connectionSource
                                                                                          sourcePort:connectionSourcePort
                                                                                         destination:connectionDestination
                                                                                     destinationPort:connectionDestinationPort];
                        if (immediateResult) {
                            SNBLogDebug("Immediate native lookup succeeded: %@ (PID %d)", immediateResult.processName, immediateResult.pid);
                            connection.processName = immediateResult.processName;
                            connection.processPID = immediateResult.pid;
                            [self.lsofProcessCache setObject:immediateResult forKey:connectionKey];
                            [self cacheProcessInfo:immediateResult forSourcePort:connectionSourcePort];
                        } else {
                            // If immediate lookup fails, schedule async lookup as backup
                            [self scheduleNativeLookupForConnectionKey:connectionKey
                                                                source:connectionSource
                                                            sourcePort:connectionSourcePort
                                                           destination:connectionDestination
                                                      destinationPort:connectionDestinationPort];
                        }
                    }
                } else if (isIncoming && connectionSourcePort > 0) {
                    // For incoming connections, try to find process from port cache first
                    ProcessInfo *cachedByPort = [self cachedProcessInfoForPort:connectionSourcePort];
                    if (cachedByPort) {
                        SNBLogDebug("Incoming connection: port cache hit for local port %ld -> %s",
                                    (long)connectionSourcePort, cachedByPort.processName.UTF8String);
                        connection.processName = cachedByPort.processName;
                        connection.processPID = cachedByPort.pid;
                    } else {
                        // Look up the process listening on this local port
                        ProcessInfo *listener = [ProcessLookup lookupListeningProcessOnPort:connectionSourcePort];
                        if (listener) {
                            SNBLogDebug("Incoming connection: found listener %s (PID %d) on port %ld",
                                        listener.processName.UTF8String, listener.pid, (long)connectionSourcePort);
                            connection.processName = listener.processName;
                            connection.processPID = listener.pid;
                            // Cache it for future lookups
                            [self cacheProcessInfo:listener forSourcePort:connectionSourcePort];
                        } else {
                            SNBLogDebug("Incoming connection: no listener found for port %ld", (long)connectionSourcePort);
                        }
                    }
                }
            }

            // Try to inherit process info from port cache if connection doesn't have it
            if (connection.processName.length == 0 && connectionSourcePort > 0) {
                ProcessInfo *cachedByPort = [self cachedProcessInfoForPort:connectionSourcePort];
                if (cachedByPort) {
                    connection.processName = cachedByPort.processName;
                    connection.processPID = cachedByPort.pid;
                } else if (isIncoming) {
                    // Last resort: try listening process lookup for incoming traffic
                    ProcessInfo *listener = [ProcessLookup lookupListeningProcessOnPort:connectionSourcePort];
                    if (listener) {
                        connection.processName = listener.processName;
                        connection.processPID = listener.pid;
                        [self cacheProcessInfo:listener forSourcePort:connectionSourcePort];
                    }
                }
            }

            // Track direction-specific bytes
            if (isIncoming) {
                connection.incomingBytes += packetInfo.totalBytes;
            } else {
                connection.outgoingBytes += packetInfo.totalBytes;
            }
            connection.bytes += packetInfo.totalBytes;
            connection.packetCount++;
            connection.lastActivity = CFAbsoluteTimeGetCurrent();
        }
    });
}

- (void)performReverseDNSLookup:(NSString *)address completion:(void (^)(NSString *))completion {
    // Performance: Limit pending DNS lookup queue depth to prevent memory leak
    NSObject *lock = nil;
    @synchronized(self.dnsLookupLocks) {
        if (self.pendingDNSLookupCount >= kMaxPendingDNSLookups) {
            SNBLogWarn("DNS lookup queue full (%lu pending), dropping lookup for %{" SNB_IP_PRIVACY "}@",
                      (unsigned long)self.pendingDNSLookupCount, address);
            [self.hostnameCache setObject:kDNSLookupFailedMarker forKey:address];
            if (completion) {
                completion(nil);
            }
            return;
        }
        self.pendingDNSLookupCount++;

        lock = self.dnsLookupLocks[address];
        if (!lock) {
            lock = [[NSObject alloc] init];
            self.dnsLookupLocks[address] = lock;
            // PERF-3: Track lock creation timestamp for cleanup
            self.dnsLookupLockTimestamps[address] = [NSDate date];
        }
    }

    dispatch_async(self.dnsLookupQueue, ^{
        // Performance: Use timeout to prevent semaphore starvation during slow DNS
        // If semaphore not acquired in 2s, skip this lookup to avoid queue backup
        dispatch_time_t timeout = dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC));
        if (dispatch_semaphore_wait(self.dnsLookupSemaphore, timeout) != 0) {
            // Semaphore not acquired - all DNS slots busy, skip this lookup
            SNBLogInfo("DNS lookup skipped for %{" SNB_IP_PRIVACY "}@ - all slots busy", address);

            @synchronized(self.dnsLookupLocks) {
                if (self.dnsLookupLocks[address] == lock) {
                    [self.dnsLookupLocks removeObjectForKey:address];
                    [self.dnsLookupLockTimestamps removeObjectForKey:address]; // PERF-3
                }
                if (self.pendingDNSLookupCount > 0) {
                    self.pendingDNSLookupCount--;
                }
            }
            if (completion) {
                completion(nil);
            }
            return;
        }

        BOOL timedOut = NO;
        NSString *hostname = SNBResolveHostname(address, kDNSLookupTimeout, &timedOut);
        dispatch_semaphore_signal(self.dnsLookupSemaphore);

        if (timedOut) {
            SNBLogWarn("DNS lookup timeout (%.0fs) for %{" SNB_IP_PRIVACY "}@", kDNSLookupTimeout, address);
        }

        if (completion) {
            completion(hostname);
        }

        @synchronized(self.dnsLookupLocks) {
            if (self.dnsLookupLocks[address] == lock) {
                [self.dnsLookupLocks removeObjectForKey:address];
                [self.dnsLookupLockTimestamps removeObjectForKey:address]; // PERF-3
            }
            if (self.pendingDNSLookupCount > 0) {
                self.pendingDNSLookupCount--;
            }
        }
    });
}

- (void)performProcessLookup:(NSString *)sourceAddress
                  sourcePort:(NSInteger)sourcePort
                 destination:(NSString *)destinationAddress
             destinationPort:(NSInteger)destinationPort
                   lookupKey:(SNBConnectionKey *)lookupKey
                  completion:(void (^)(ProcessInfo *))completion {

    // Get or create lock for this lookup
    NSObject *lock = nil;
    @synchronized(self.processLookupLocks) {
        lock = self.processLookupLocks[lookupKey];
        if (!lock) {
            lock = [[NSObject alloc] init];
            self.processLookupLocks[lookupKey] = lock;
        } else {
            // Lookup already in progress
            return;
        }
    }

    [ProcessLookup lookupProcessForConnectionWithSource:sourceAddress
                                             sourcePort:sourcePort
                                            destination:destinationAddress
                                        destinationPort:destinationPort
                                             completion:^(ProcessInfo *processInfo) {
        if (completion) {
            completion(processInfo);
        }

        // Clean up lock
        @synchronized(self.processLookupLocks) {
            if (self.processLookupLocks[lookupKey] == lock) {
        [self.processLookupLocks removeObjectForKey:lookupKey];
            }
        }
    }];
}

- (void)scheduleNativeLookupForConnectionKey:(SNBConnectionKey *)connectionKey
                                       source:(NSString *)sourceAddress
                                   sourcePort:(NSInteger)sourcePort
                                  destination:(NSString *)destinationAddress
                              destinationPort:(NSInteger)destinationPort {
    if (!connectionKey) {
        return;
    }
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        ProcessInfo *nativeInfo = [ProcessLookup lookupUsingNativeAPIForSource:sourceAddress
                                                                     sourcePort:sourcePort
                                                                    destination:destinationAddress
                                                                destinationPort:destinationPort];
        dispatch_async(self.statsQueue, ^{
            SNBLogDebug("Native lookup result: %@", nativeInfo ? nativeInfo.processName : @"<nil>");
            [self handleProcessLookupResult:nativeInfo
                              connectionKey:connectionKey
                                     source:SNBProcessLookupSourceLsof];
        });
    });
}

// Keep the old lsof method as a backup fallback option
- (void)scheduleLsofLookupForConnectionKey:(SNBConnectionKey *)connectionKey
                                     source:(NSString *)sourceAddress
                                sourcePort:(NSInteger)sourcePort
                               destination:(NSString *)destinationAddress
                          destinationPort:(NSInteger)destinationPort {
    if (!connectionKey) {
        return;
    }
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        ProcessInfo *lsofInfo = [ProcessLookup lookupUsingLsofForSource:sourceAddress
                                                              sourcePort:sourcePort
                                                             destination:destinationAddress
                                                        destinationPort:destinationPort];
        dispatch_async(self.statsQueue, ^{
            SNBLogDebug("lsof lookup result: %@", lsofInfo ? lsofInfo.processName : @"<nil>");
            [self handleProcessLookupResult:lsofInfo
                                 connectionKey:connectionKey
                                        source:SNBProcessLookupSourceLsof];
        });
    });
}

- (void)handleProcessLookupResult:(ProcessInfo *)processInfo
                     connectionKey:(SNBConnectionKey *)connectionKey
                            source:(SNBProcessLookupSource)source {
    if (!connectionKey) {
        return;
    }

    if (processInfo) {
        if (source == SNBProcessLookupSourceHelper) {
            self.pendingHelperProcessInfos[connectionKey] = processInfo;
        } else {
            self.pendingLsofProcessInfos[connectionKey] = processInfo;
        }
    } else if (source == SNBProcessLookupSourceHelper) {
        [self.processCache setObject:[NSNull null] forKey:connectionKey];
        SNBLogDebug("Helper lookup failed for %@ -> %@", connectionKey.source, connectionKey.destination);
    }

    ProcessInfo *helperInfo = self.pendingHelperProcessInfos[connectionKey];
    ProcessInfo *lsofInfo = self.pendingLsofProcessInfos[connectionKey];
    ProcessInfo *finalInfo = [self selectedProcessInfoWithHelper:helperInfo fallback:lsofInfo];

    if (!finalInfo) {
        return;
    }

    [self assignProcessInfo:finalInfo forConnectionKey:connectionKey];
    [self.pendingHelperProcessInfos removeObjectForKey:connectionKey];
    [self.pendingLsofProcessInfos removeObjectForKey:connectionKey];
}

- (ProcessInfo *)selectedProcessInfoWithHelper:(ProcessInfo *)helper fallback:(ProcessInfo *)fallback {
    if (helper && fallback) {
        if ([self processInfo:helper matchesProcessInfo:fallback]) {
            return helper;
        }
        SNBLogDebug("Process lookup mismatch: helper=%@ (%d) lsof=%@ (%d)",
                    helper.processName, helper.pid,
                    fallback.processName, fallback.pid);
        return helper;
    }
    return helper ?: fallback;
}

- (BOOL)processInfo:(ProcessInfo *)first matchesProcessInfo:(ProcessInfo *)second {
    if (!first || !second) {
        return NO;
    }
    if (first.pid > 0 && second.pid > 0 && first.pid == second.pid) {
        return YES;
    }
    if (first.processName.length > 0 && second.processName.length > 0 &&
        [first.processName isEqualToString:second.processName]) {
        return YES;
    }
    if (first.executablePath.length > 0 && second.executablePath.length > 0 &&
        [first.executablePath isEqualToString:second.executablePath]) {
        return YES;
    }
    return NO;
}

- (void)assignProcessInfo:(ProcessInfo *)processInfo forConnectionKey:(SNBConnectionKey *)connectionKey {
    if (!processInfo || !connectionKey) {
        return;
    }
    ConnectionTraffic *connection = self.connectionStats[connectionKey];
    if (!connection) {
        return;
    }
    if (processInfo.processName.length > 0) {
        connection.processName = processInfo.processName;
    }
    connection.processPID = processInfo.pid;

    [self.processCache setObject:processInfo forKey:connectionKey];
    [self.lsofProcessCache setObject:processInfo forKey:connectionKey];
    self.statsCacheDirty = YES;
    SNBLogDebug("Process info cached for %@: %@ (%d)", [connectionKey stringValue], connection.processName, connection.processPID);
    [self cacheProcessInfo:processInfo forSourcePort:connection.sourcePort];
}

- (ProcessInfo *)finalProcessInfoFromHelper:(ProcessInfo *)helper fallback:(ProcessInfo *)fallback {
    return [self selectedProcessInfoWithHelper:helper fallback:fallback];
}

- (ProcessInfo *)cachedProcessInfoForPort:(NSInteger)port {
    if (port <= 0) {
        return nil;
    }
    NSNumber *key = @(port);
    ProcessInfo *info = [self.portProcessCache objectForKey:key];
    if (info.processName.length == 0) {
        return nil;
    }
    return info;
}

- (void)cacheProcessInfo:(ProcessInfo *)processInfo forSourcePort:(NSInteger)port {
    if (port <= 0 || !processInfo || processInfo.processName.length == 0) {
        return;
    }
    NSNumber *key = @(port);
    [self.portProcessCache setObject:processInfo forKey:key];
}


- (NSArray<HostTraffic *> *)topHostsFromValues:(NSArray<HostTraffic *> *)values limit:(NSUInteger)limit {
    if (limit == 0 || values.count == 0) {
        return @[];
    }

    // Optimization: Use min-heap approach for top-K selection
    // Only sort once at the end instead of on every iteration: O(n log k) instead of O(n² log n)
    NSMutableArray<HostTraffic *> *top = [NSMutableArray arrayWithCapacity:limit];

    for (HostTraffic *host in values) {
        if (top.count < limit) {
            [top addObject:host];
        } else {
            // Only replace if current host has more bytes than the minimum in our top list
            HostTraffic *minHost = top[0]; // Will be minimum after sort
            if (host.bytes > minHost.bytes) {
                top[0] = host;
            } else {
                continue;
            }
        }

        // Only sort when we reach capacity or when we replace an item
        if (top.count == limit) {
            // Partial sort: just ensure minimum element is at index 0
            NSUInteger minIndex = 0;
            uint64_t minBytes = top[0].bytes;
            for (NSUInteger i = 1; i < top.count; i++) {
                if (top[i].bytes < minBytes) {
                    minBytes = top[i].bytes;
                    minIndex = i;
                }
            }
            if (minIndex != 0) {
                [top exchangeObjectAtIndex:0 withObjectAtIndex:minIndex];
            }
        }
    }

    // Final sort only once at the end
    [top sortUsingComparator:^NSComparisonResult(HostTraffic *obj1, HostTraffic *obj2) {
        if (obj1.bytes > obj2.bytes) {
            return NSOrderedAscending;
        }
        if (obj1.bytes < obj2.bytes) {
            return NSOrderedDescending;
        }
        return NSOrderedSame;
    }];

    return top;
}

- (NSArray<ConnectionTraffic *> *)topConnectionsFromValues:(NSArray<ConnectionTraffic *> *)values limit:(NSUInteger)limit {
    if (limit == 0 || values.count == 0) {
        return @[];
    }

    // Optimization: Use min-heap approach for top-K selection
    // Only sort once at the end instead of on every iteration: O(n log k) instead of O(n² log n)
    NSMutableArray<ConnectionTraffic *> *top = [NSMutableArray arrayWithCapacity:limit];

    for (ConnectionTraffic *connection in values) {
        if (top.count < limit) {
            [top addObject:connection];
        } else {
            // Only replace if current connection has more bytes than the minimum in our top list
            ConnectionTraffic *minConnection = top[0]; // Will be minimum after sort
            if (connection.bytes > minConnection.bytes) {
                top[0] = connection;
            } else {
                continue;
            }
        }

        // Only sort when we reach capacity or when we replace an item
        if (top.count == limit) {
            // Partial sort: just ensure minimum element is at index 0
            NSUInteger minIndex = 0;
            uint64_t minBytes = top[0].bytes;
            for (NSUInteger i = 1; i < top.count; i++) {
                if (top[i].bytes < minBytes) {
                    minBytes = top[i].bytes;
                    minIndex = i;
                }
            }
            if (minIndex != 0) {
                [top exchangeObjectAtIndex:0 withObjectAtIndex:minIndex];
            }
        }
    }

    // Final sort only once at the end
    [top sortUsingComparator:^NSComparisonResult(ConnectionTraffic *obj1, ConnectionTraffic *obj2) {
        if (obj1.bytes > obj2.bytes) {
            return NSOrderedAscending;
        }
        if (obj1.bytes < obj2.bytes) {
            return NSOrderedDescending;
        }
        return NSOrderedSame;
    }];

    return top;
}

- (NSArray<ProcessTrafficSummary *> *)processSummariesFromConnections:(NSArray<ConnectionTraffic *> *)connections
                                                               limit:(NSUInteger)limit {
    if (limit == 0 || connections.count == 0) {
        return @[];
    }

    NSMutableDictionary<NSString *, ProcessTrafficSummary *> *summariesDict = [NSMutableDictionary dictionary];
    for (ConnectionTraffic *connection in connections) {
        NSString *processName = connection.processName.length > 0 ? connection.processName : @"<unknown>";
        pid_t pid = connection.processPID;
        NSString *key = [NSString stringWithFormat:@"%@|%d", processName, (int)pid];
        ProcessTrafficSummary *summary = summariesDict[key];
        if (!summary) {
            summary = [[ProcessTrafficSummary alloc] init];
            summary.processName = processName;
            summary.processPID = pid;
            summariesDict[key] = summary;
        }
        summary.bytes += connection.bytes;
        summary.incomingBytes += connection.incomingBytes;
        summary.outgoingBytes += connection.outgoingBytes;
        summary.connectionCount += 1;
        if (connection.destinationAddress.length > 0) {
            [summary addDestination:connection.destinationAddress];
        }
    }

    NSMutableArray<ProcessTrafficSummary *> *summaries = [NSMutableArray arrayWithCapacity:summariesDict.count];
    for (ProcessTrafficSummary *summary in summariesDict.allValues) {
        [summary finalizeDestinations];
        [summaries addObject:summary];
    }

    [summaries sortUsingComparator:^NSComparisonResult(ProcessTrafficSummary *obj1, ProcessTrafficSummary *obj2) {
        if (obj1.bytes > obj2.bytes) {
            return NSOrderedAscending;
        }
        if (obj1.bytes < obj2.bytes) {
            return NSOrderedDescending;
        }
        return NSOrderedSame;
    }];

    if (summaries.count > limit) {
        [summaries removeObjectsInRange:NSMakeRange(limit, summaries.count - limit)];
    }

    return [summaries copy];
}

- (TrafficStats *)currentStatsLocked {
    TrafficStats *stats = [[TrafficStats alloc] init];
    stats.timestamp = CFAbsoluteTimeGetCurrent();
    stats.totalBytes = self.totalBytes;
    stats.incomingBytes = self.incomingBytes;
    stats.outgoingBytes = self.outgoingBytes;
    stats.totalPackets = self.totalPackets;
    stats.bytesPerSecond = self.cachedBytesPerSecond;

    CFAbsoluteTime now = CFAbsoluteTimeGetCurrent();
    [self removeStaleConnectionsLocked:now];

    ConfigurationManager *config = [ConfigurationManager sharedManager];
    // Use cached results if available and cache is clean
    if (self.statsCacheDirty || !self.cachedTopHosts || !self.cachedTopConnections) {
        NSUInteger hostLimit = MAX(1, config.maxTopHostsToShow);
        NSUInteger connectionLimit = MAX(1, config.maxTopConnectionsToShow);

        self.cachedTopHosts = [self topHostsFromValues:self.hostStats.allValues limit:hostLimit];
        self.cachedTopConnections = [self topConnectionsFromValues:self.connectionStats.allValues limit:connectionLimit];
        self.statsCacheDirty = NO;
    }

    stats.topHosts = self.cachedTopHosts;
    stats.topConnections = self.cachedTopConnections;
    stats.allConnections = [self.connectionStats.allValues copy];
    NSUInteger processLimit = MAX(1, config.maxTopConnectionsToShow);
    stats.processSummaries = [self processSummariesFromConnections:self.connectionStats.allValues limit:processLimit];

    // Collect active destination IPs ONLY from active connections (not hostStats)
    // This ensures "active threats" only shows IPs with current connections,
    // not historical host data that may no longer have associated processes
    NSMutableSet<NSString *> *allDestIPs = [NSMutableSet set];
    for (ConnectionTraffic *conn in self.connectionStats.allValues) {
        if (conn.destinationAddress.length > 0) {
            [allDestIPs addObject:conn.destinationAddress];
        }
    }
    stats.allActiveDestinationIPs = [allDestIPs copy];

    return stats;
}

- (TrafficStats *)getCurrentStats {
    // PERF-2 FIX: This method uses dispatch_sync which blocks the calling thread.
    // Using it from the main thread can freeze the UI for 10-50ms during stats computation.
    // Always prefer getCurrentStatsWithCompletion: when calling from the main thread.
#if DEBUG
    if ([NSThread isMainThread]) {
        // In debug builds, assert to catch main thread calls during development
        NSAssert(NO, @"PERF-2: getCurrentStats called from main thread! "
                 @"This blocks the UI. Use getCurrentStatsWithCompletion: instead.");
    }
#else
    // In release builds, log a warning (but don't crash)
    if ([NSThread isMainThread]) {
        static dispatch_once_t onceToken;
        dispatch_once(&onceToken, ^{
            SNBLogWarn("PERF-2: getCurrentStats called from main thread. "
                      "This may cause UI stuttering. Use getCurrentStatsWithCompletion: instead.");
        });
    }
#endif

    __block TrafficStats *stats = nil;

    dispatch_sync(self.statsQueue, ^{
        stats = [self currentStatsLocked];
    });

    return stats;
}

- (void)getCurrentStatsWithCompletion:(void (^)(TrafficStats *stats))completion {
    if (!completion) {
        return;
    }

    __weak typeof(self) weakSelf = self;
    dispatch_async(self.statsQueue, ^{
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) {
            return;
        }
        TrafficStats *stats = [strongSelf currentStatsLocked];
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(stats);
        });
    });
}

- (void)getAllDestinationIPsWithCompletion:(void (^)(NSSet<NSString *> *ips))completion {
    if (!completion) {
        return;
    }

    __weak typeof(self) weakSelf = self;
    dispatch_async(self.statsQueue, ^{
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) {
            return;
        }

        NSMutableSet<NSString *> *destinationIPs = [NSMutableSet set];

        // Collect destination IPs ONLY from active connections
        // This ensures we return IPs that have current processes attached
        for (ConnectionTraffic *connection in strongSelf.connectionStats.allValues) {
            if (connection.destinationAddress.length > 0) {
                [destinationIPs addObject:connection.destinationAddress];
            }
        }

        NSSet<NSString *> *result = [destinationIPs copy];
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(result);
        });
    });
}

- (void)reset {
    dispatch_async(self.statsQueue, ^{
        self.totalBytes = 0;
        self.incomingBytes = 0;
        self.outgoingBytes = 0;
        self.totalPackets = 0;
        [self.hostStats removeAllObjects];
        [self.connectionStats removeAllObjects];
        [self.connectionKeyCache removeAllObjects];  // Performance: Clear key cache with connections
        [self.connectionKeyHashCache removeAllObjects];
        self.lastUpdateTime = nil;
        self.lastTotalBytes = 0;
        self.cachedTopHosts = nil;
        self.cachedTopConnections = nil;
        self.statsCacheDirty = YES;
        self.lastSampleTime = nil;
        self.lastSampleTotalBytes = 0;
        self.cachedBytesPerSecond = 0;
    });
}

- (void)sampleBytesPerSecond {
    dispatch_async(self.statsQueue, ^{
        NSDate *now = [NSDate date];
        if (self.lastSampleTime) {
            NSTimeInterval elapsed = [now timeIntervalSinceDate:self.lastSampleTime];
            if (elapsed > 0) {
                uint64_t bytesDiff = self.totalBytes - self.lastSampleTotalBytes;
                self.cachedBytesPerSecond = (uint64_t)(bytesDiff / elapsed);
            }
        }
        self.lastSampleTime = now;
        self.lastSampleTotalBytes = self.totalBytes;
    });
}

@end

@implementation TrafficStats
@end

@implementation HostTraffic
@end

@implementation ConnectionTraffic
@end

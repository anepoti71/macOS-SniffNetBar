//
//  SNBSocketPIDMap.m
//  SniffNetBar
//
//  Global socket-to-PID mapping with periodic refresh for O(1) lookups.
//  Solves PERF-1: O(n*m) process lookup scanning all PIDs and FDs.
//

#import "SNBSocketPIDMap.h"
#import "ProcessLookup.h"
#import "SNBTimerCoordinator.h"
#import "Logger.h"
#import <libproc.h>
#import <sys/proc_info.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>

static const NSTimeInterval kDefaultRefreshInterval = 2.0;

#pragma mark - SNBSocketKey Implementation

@implementation SNBSocketKey {
    NSUInteger _cachedHash;
}

- (instancetype)initWithLocalAddress:(NSString *)localAddr
                           localPort:(uint16_t)localPort
                       remoteAddress:(NSString *)remoteAddr
                          remotePort:(uint16_t)remotePort
                              isIPv6:(BOOL)isIPv6 {
    self = [super init];
    if (self) {
        _localAddress = [localAddr copy] ?: @"";
        _remoteAddress = [remoteAddr copy] ?: @"";
        _localPort = localPort;
        _remotePort = remotePort;
        _isIPv6 = isIPv6;

        // Pre-compute hash for performance
        _cachedHash = _localAddress.hash;
        _cachedHash ^= _remoteAddress.hash;
        _cachedHash ^= (NSUInteger)localPort * 16777619u;
        _cachedHash ^= (NSUInteger)remotePort * 2166136261u;
    }
    return self;
}

+ (instancetype)listeningKeyWithLocalPort:(uint16_t)port isIPv6:(BOOL)isIPv6 {
    NSString *anyAddr = isIPv6 ? @"::" : @"0.0.0.0";
    return [[SNBSocketKey alloc] initWithLocalAddress:anyAddr
                                            localPort:port
                                        remoteAddress:anyAddr
                                           remotePort:0
                                               isIPv6:isIPv6];
}

- (NSUInteger)hash {
    return _cachedHash;
}

- (BOOL)isEqual:(id)object {
    if (![object isKindOfClass:[SNBSocketKey class]]) {
        return NO;
    }
    SNBSocketKey *other = object;
    return self.localPort == other.localPort &&
           self.remotePort == other.remotePort &&
           self.isIPv6 == other.isIPv6 &&
           [self.localAddress isEqualToString:other.localAddress] &&
           [self.remoteAddress isEqualToString:other.remoteAddress];
}

- (id)copyWithZone:(NSZone *)zone {
    return self; // Immutable
}

- (NSString *)description {
    return [NSString stringWithFormat:@"<%@: %@:%d -> %@:%d>",
            NSStringFromClass([self class]),
            self.localAddress, self.localPort,
            self.remoteAddress, self.remotePort];
}

@end


#pragma mark - SNBSocketPIDMap Implementation

@interface SNBSocketPIDMap ()
@property (nonatomic, strong) dispatch_queue_t mapQueue;
@property (nonatomic, strong) NSMutableDictionary<SNBSocketKey *, ProcessInfo *> *socketToProcess;
@property (nonatomic, strong) NSMutableDictionary<NSNumber *, ProcessInfo *> *listeningPorts;
@property (nonatomic, copy, nullable) SNBTimerID refreshTimerID;
@property (nonatomic, assign) NSUInteger totalSocketCount;
@property (nonatomic, assign) NSUInteger totalProcessCount;
@property (nonatomic, strong, nullable) NSDate *lastRefreshTime;
@property (nonatomic, assign) NSTimeInterval lastRefreshDuration;
@end

@implementation SNBSocketPIDMap

+ (instancetype)sharedMap {
    static SNBSocketPIDMap *shared = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        shared = [[SNBSocketPIDMap alloc] init];
    });
    return shared;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _mapQueue = dispatch_queue_create("com.sniffnetbar.socketpidmap", DISPATCH_QUEUE_SERIAL);
        _socketToProcess = [NSMutableDictionary dictionary];
        _listeningPorts = [NSMutableDictionary dictionary];
        _refreshInterval = kDefaultRefreshInterval;
    }
    return self;
}

- (void)dealloc {
    [self stopPeriodicRefresh];
}

#pragma mark - Timer Management

- (void)startPeriodicRefresh {
    [self stopPeriodicRefresh];

    // Do initial refresh synchronously
    [self refreshNow];

    // Schedule periodic refresh
    __weak typeof(self) weakSelf = self;
    SNBTimerCoordinator *coordinator = [SNBTimerCoordinator sharedCoordinator];
    self.refreshTimerID = [coordinator scheduleRepeatingTimerWithInterval:self.refreshInterval
                                                                    queue:nil
                                                                  handler:^{
        [weakSelf refreshNow];
    }];
    SNBLogInfo("SNBSocketPIDMap: Started periodic refresh (interval: %.1fs)", self.refreshInterval);
}

- (void)stopPeriodicRefresh {
    if (self.refreshTimerID) {
        [[SNBTimerCoordinator sharedCoordinator] cancelTimer:self.refreshTimerID];
        self.refreshTimerID = nil;
        SNBLogInfo("SNBSocketPIDMap: Stopped periodic refresh");
    }
}

#pragma mark - Map Building

- (void)refreshNow {
    CFAbsoluteTime startTime = CFAbsoluteTimeGetCurrent();

    // Build the entire socket-to-PID map in one pass
    NSMutableDictionary<SNBSocketKey *, ProcessInfo *> *newSocketMap = [NSMutableDictionary dictionary];
    NSMutableDictionary<NSNumber *, ProcessInfo *> *newListeningPorts = [NSMutableDictionary dictionary];
    NSMutableSet<NSNumber *> *seenPIDs = [NSMutableSet set];

    // Get list of all PIDs
    int numberOfPids = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
    if (numberOfPids <= 0) {
        SNBLogWarn("SNBSocketPIDMap: Failed to get PID count");
        return;
    }

    pid_t *pids = malloc(sizeof(pid_t) * numberOfPids);
    if (!pids) {
        SNBLogError("SNBSocketPIDMap: Failed to allocate memory for PIDs");
        return;
    }

    numberOfPids = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pid_t) * numberOfPids);
    if (numberOfPids <= 0) {
        free(pids);
        SNBLogWarn("SNBSocketPIDMap: Failed to list PIDs");
        return;
    }

    NSUInteger socketCount = 0;

    // Iterate through all PIDs and build the map
    for (int i = 0; i < numberOfPids; i++) {
        pid_t pid = pids[i];
        if (pid == 0) {
            continue;
        }

        // Get list of file descriptors for this process
        int fdBufferSize = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
        if (fdBufferSize <= 0) {
            continue;
        }

        struct proc_fdinfo *fdInfo = malloc(fdBufferSize);
        if (!fdInfo) {
            continue;
        }

        int fdCount = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fdInfo, fdBufferSize);
        if (fdCount <= 0) {
            free(fdInfo);
            continue;
        }

        int numFds = fdCount / sizeof(struct proc_fdinfo);
        BOOL processInfoCreated = NO;
        ProcessInfo *processInfo = nil;

        // Check each file descriptor for sockets
        for (int j = 0; j < numFds; j++) {
            if (fdInfo[j].proc_fdtype != PROX_FDTYPE_SOCKET) {
                continue;
            }

            // Get socket information
            struct socket_fdinfo socketFdInfo;
            int socketInfoSize = proc_pidfdinfo(pid, fdInfo[j].proc_fd, PROC_PIDFDSOCKETINFO,
                                               &socketFdInfo, sizeof(socketFdInfo));
            if (socketInfoSize <= 0) {
                continue;
            }

            // Only process TCP and UDP sockets
            if (socketFdInfo.psi.soi_kind != SOCKINFO_TCP &&
                socketFdInfo.psi.soi_kind != SOCKINFO_IN) {
                continue;
            }

            // Get socket address info
            const struct in_sockinfo *inInfo = NULL;
            if (socketFdInfo.psi.soi_kind == SOCKINFO_TCP) {
                inInfo = &socketFdInfo.psi.soi_proto.pri_tcp.tcpsi_ini;
            } else if (socketFdInfo.psi.soi_kind == SOCKINFO_IN) {
                inInfo = &socketFdInfo.psi.soi_proto.pri_in;
            }

            if (!inInfo) {
                continue;
            }

            // Lazily create ProcessInfo only when we find a socket
            if (!processInfoCreated) {
                processInfo = [self processInfoForPID:pid];
                processInfoCreated = YES;
                if (processInfo) {
                    [seenPIDs addObject:@(pid)];
                }
            }

            if (!processInfo) {
                continue;
            }

            BOOL isIPv6 = (inInfo->insi_vflag == INI_IPV6);
            NSString *localAddr = nil;
            NSString *remoteAddr = nil;
            uint16_t localPort = ntohs(inInfo->insi_lport);
            uint16_t remotePort = ntohs(inInfo->insi_fport);

            if (isIPv6) {
                char localBuf[INET6_ADDRSTRLEN] = {0};
                char remoteBuf[INET6_ADDRSTRLEN] = {0};
                inet_ntop(AF_INET6, &inInfo->insi_laddr.ina_6, localBuf, sizeof(localBuf));
                inet_ntop(AF_INET6, &inInfo->insi_faddr.ina_6, remoteBuf, sizeof(remoteBuf));
                localAddr = [NSString stringWithUTF8String:localBuf];
                remoteAddr = [NSString stringWithUTF8String:remoteBuf];
            } else {
                char localBuf[INET_ADDRSTRLEN] = {0};
                char remoteBuf[INET_ADDRSTRLEN] = {0};
                inet_ntop(AF_INET, &inInfo->insi_laddr.ina_46.i46a_addr4, localBuf, sizeof(localBuf));
                inet_ntop(AF_INET, &inInfo->insi_faddr.ina_46.i46a_addr4, remoteBuf, sizeof(remoteBuf));
                localAddr = [NSString stringWithUTF8String:localBuf];
                remoteAddr = [NSString stringWithUTF8String:remoteBuf];
            }

            // Create socket key and add to map
            SNBSocketKey *key = [[SNBSocketKey alloc] initWithLocalAddress:localAddr
                                                                 localPort:localPort
                                                             remoteAddress:remoteAddr
                                                                remotePort:remotePort
                                                                    isIPv6:isIPv6];
            newSocketMap[key] = processInfo;
            socketCount++;

            // Also track listening ports (for incoming connection lookup)
            if (socketFdInfo.psi.soi_kind == SOCKINFO_TCP) {
                int tcpState = socketFdInfo.psi.soi_proto.pri_tcp.tcpsi_state;
                if (tcpState == TSI_S_LISTEN && localPort > 0) {
                    newListeningPorts[@(localPort)] = processInfo;
                }
            }
        }

        free(fdInfo);
    }

    free(pids);

    // Atomically swap the maps
    dispatch_sync(self.mapQueue, ^{
        self.socketToProcess = newSocketMap;
        self.listeningPorts = newListeningPorts;
        self.totalSocketCount = socketCount;
        self.totalProcessCount = seenPIDs.count;
        self.lastRefreshTime = [NSDate date];
    });

    CFAbsoluteTime endTime = CFAbsoluteTimeGetCurrent();
    self.lastRefreshDuration = endTime - startTime;

    SNBLogDebug("SNBSocketPIDMap: Refreshed map with %lu sockets from %lu processes in %.1fms",
               (unsigned long)socketCount,
               (unsigned long)seenPIDs.count,
               self.lastRefreshDuration * 1000.0);
}

- (ProcessInfo *)processInfoForPID:(pid_t)pid {
    ProcessInfo *info = [[ProcessInfo alloc] init];
    info.pid = pid;

    char pathBuffer[PROC_PIDPATHINFO_MAXSIZE] = {0};
    int pathLen = proc_pidpath(pid, pathBuffer, sizeof(pathBuffer));

    if (pathLen > 0) {
        NSString *fullPath = [NSString stringWithUTF8String:pathBuffer];
        info.executablePath = fullPath;
        info.processName = [fullPath lastPathComponent];
    } else {
        // Fallback: try to get process name via proc_name
        char nameBuffer[PROC_PIDPATHINFO_MAXSIZE] = {0};
        if (proc_name(pid, nameBuffer, sizeof(nameBuffer)) > 0) {
            info.processName = [NSString stringWithUTF8String:nameBuffer];
        } else {
            info.processName = [NSString stringWithFormat:@"PID %d", pid];
        }
    }

    return info;
}

#pragma mark - O(1) Lookups

- (nullable ProcessInfo *)processForSource:(NSString *)sourceAddress
                                sourcePort:(NSInteger)sourcePort
                               destination:(NSString *)destinationAddress
                           destinationPort:(NSInteger)destinationPort {
    if (!sourceAddress || !destinationAddress) {
        return nil;
    }

    // Determine if IPv6
    BOOL isIPv6 = [sourceAddress containsString:@":"];

    SNBSocketKey *key = [[SNBSocketKey alloc] initWithLocalAddress:sourceAddress
                                                         localPort:(uint16_t)sourcePort
                                                     remoteAddress:destinationAddress
                                                        remotePort:(uint16_t)destinationPort
                                                            isIPv6:isIPv6];

    __block ProcessInfo *result = nil;
    dispatch_sync(self.mapQueue, ^{
        result = self.socketToProcess[key];
    });

    if (result) {
        SNBLogDebug("SNBSocketPIDMap: O(1) hit for %@:%ld -> %@:%ld = %@ (PID %d)",
                   sourceAddress, (long)sourcePort,
                   destinationAddress, (long)destinationPort,
                   result.processName, result.pid);
    }

    return result;
}

- (nullable ProcessInfo *)processListeningOnPort:(NSInteger)port {
    if (port <= 0 || port > 65535) {
        return nil;
    }

    __block ProcessInfo *result = nil;
    dispatch_sync(self.mapQueue, ^{
        result = self.listeningPorts[@(port)];
    });

    if (result) {
        SNBLogDebug("SNBSocketPIDMap: Found listener on port %ld = %@ (PID %d)",
                   (long)port, result.processName, result.pid);
    }

    return result;
}

@end

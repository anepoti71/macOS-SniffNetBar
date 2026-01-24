//
//  SNBHelperProcessLookup.m
//  SniffNetBarHelper
//

#import "SNBHelperProcessLookup.h"
#import "../SniffNetBar/Utils/ProcessLookup.h"
#import "../SniffNetBar/XPC/ProcessInfo+Serialization.h"
#import <libproc.h>
#import <sys/proc_info.h>
#import <netinet/in.h>
#import <netinet/tcp.h>
#import <arpa/inet.h>
#import <string.h>
#import <unistd.h>
#import <sys/socket.h>

static const NSTimeInterval kHelperProcessCacheTTL = 5.0;
static const NSUInteger kHelperProcessCacheMaxSize = 2048;
static const NSTimeInterval kHelperSocketMapRefreshInterval = 2.0;

@interface SNBHelperProcessCacheEntry : NSObject
@property (nonatomic, strong) ProcessInfo *processInfo;
@property (nonatomic, assign) NSTimeInterval lastSeen;
@property (nonatomic, assign) uint64_t startTime;
@end

@implementation SNBHelperProcessCacheEntry
@end

@interface SNBHelperSocketMap : NSObject
@property (nonatomic, strong) NSMutableDictionary<NSString *, id> *socketToProcess;
@property (nonatomic, assign) NSTimeInterval lastRefresh;
@end

@implementation SNBHelperSocketMap
@end

@interface SNBHelperSocketMapEntry : NSObject
@property (nonatomic, strong) ProcessInfo *processInfo;
@property (nonatomic, assign) uint64_t startTime;
@end

@implementation SNBHelperSocketMapEntry
@end

static dispatch_queue_t SNBHelperProcessLookupQueue(void) {
    static dispatch_queue_t queue;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        queue = dispatch_queue_create("com.sniffnetbar.helper.processlookup", DISPATCH_QUEUE_SERIAL);
    });
    return queue;
}

static NSMutableDictionary<NSString *, SNBHelperProcessCacheEntry *> *SNBHelperProcessCache(void) {
    static NSMutableDictionary<NSString *, SNBHelperProcessCacheEntry *> *cache = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        cache = [NSMutableDictionary dictionary];
    });
    return cache;
}

static SNBHelperSocketMap *SNBHelperSocketMapStore(void) {
    static SNBHelperSocketMap *map = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        map = [[SNBHelperSocketMap alloc] init];
        map.socketToProcess = [NSMutableDictionary dictionary];
        map.lastRefresh = 0;
    });
    return map;
}

static NSString *SNBHelperConnectionKey(NSString *sourceAddress,
                                        NSInteger sourcePort,
                                        NSString *destinationAddress,
                                        NSInteger destinationPort) {
    NSString *src = sourceAddress ?: @"";
    NSString *dst = destinationAddress ?: @"";
    return [NSString stringWithFormat:@"%@:%ld->%@:%ld", src, (long)sourcePort, dst, (long)destinationPort];
}

static void SNBHelperPurgeCacheIfNeeded(NSMutableDictionary<NSString *, SNBHelperProcessCacheEntry *> *cache) {
    NSTimeInterval now = [NSDate date].timeIntervalSince1970;
    NSMutableArray<NSString *> *expired = [NSMutableArray array];
    for (NSString *key in cache) {
        SNBHelperProcessCacheEntry *entry = cache[key];
        if (!entry || (now - entry.lastSeen) > kHelperProcessCacheTTL) {
            [expired addObject:key];
        }
    }
    if (expired.count > 0) {
        [cache removeObjectsForKeys:expired];
    }
    if (cache.count <= kHelperProcessCacheMaxSize) {
        return;
    }
    NSArray<NSString *> *sortedKeys = [cache keysSortedByValueUsingComparator:^NSComparisonResult(SNBHelperProcessCacheEntry *a,
                                                                                                 SNBHelperProcessCacheEntry *b) {
        if (a.lastSeen == b.lastSeen) {
            return NSOrderedSame;
        }
        return a.lastSeen < b.lastSeen ? NSOrderedAscending : NSOrderedDescending;
    }];
    NSUInteger overflow = cache.count - kHelperProcessCacheMaxSize;
    for (NSUInteger i = 0; i < overflow && i < sortedKeys.count; i++) {
        [cache removeObjectForKey:sortedKeys[i]];
    }
}

static BOOL SNBMatchAddress(const struct in_sockinfo *info,
                            BOOL matchLocal,
                            const struct in_addr *addr4,
                            const struct in6_addr *addr6,
                            BOOL has4,
                            BOOL has6) {
    if (info->insi_vflag & INI_IPV4) {
        if (!has4) {
            return NO;
        }
        const struct in_addr *candidate = matchLocal
            ? &info->insi_laddr.ina_46.i46a_addr4
            : &info->insi_faddr.ina_46.i46a_addr4;
        return memcmp(candidate, addr4, sizeof(struct in_addr)) == 0;
    }
    if (info->insi_vflag & INI_IPV6) {
        if (!has6) {
            return NO;
        }
        const struct in6_addr *candidate = matchLocal
            ? &info->insi_laddr.ina_6
            : &info->insi_faddr.ina_6;
        return memcmp(candidate, addr6, sizeof(struct in6_addr)) == 0;
    }
    return NO;
}

static const struct in_sockinfo *SNBInSockInfoForSocket(const struct socket_fdinfo *socketInfo) {
    if (socketInfo->psi.soi_kind == SOCKINFO_TCP) {
        return &socketInfo->psi.soi_proto.pri_tcp.tcpsi_ini;
    }
    if (socketInfo->psi.soi_kind == SOCKINFO_IN) {
        return &socketInfo->psi.soi_proto.pri_in;
    }
    return NULL;
}

static uint64_t SNBProcessStartTimeForPID(pid_t pid) {
    if (pid <= 0) {
        return 0;
    }
    struct proc_bsdinfo info;
    int ret = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info));
    if (ret <= 0) {
        return 0;
    }
    return ((uint64_t)info.pbi_start_tvsec * 1000000ULL) + (uint64_t)info.pbi_start_tvusec;
}

static NSString *SNBIPAddressFromSockaddr(const struct in_sockinfo *info, BOOL isLocal) {
    char buffer[INET6_ADDRSTRLEN] = {0};
    if (info->insi_vflag & INI_IPV4) {
        const struct in_addr *addr = isLocal
            ? &info->insi_laddr.ina_46.i46a_addr4
            : &info->insi_faddr.ina_46.i46a_addr4;
        if (inet_ntop(AF_INET, addr, buffer, sizeof(buffer))) {
            return [NSString stringWithUTF8String:buffer];
        }
        return @"";
    }
    if (info->insi_vflag & INI_IPV6) {
        const struct in6_addr *addr = isLocal ? &info->insi_laddr.ina_6 : &info->insi_faddr.ina_6;
        if (inet_ntop(AF_INET6, addr, buffer, sizeof(buffer))) {
            return [NSString stringWithUTF8String:buffer];
        }
        return @"";
    }
    return @"";
}

static ProcessInfo *SNBHelperFindProcessForConnection(NSString *sourceAddress,
                                                       NSInteger sourcePort,
                                                       NSString *destinationAddress,
                                                       NSInteger destinationPort) {
    struct in_addr src4;
    struct in_addr dst4;
    struct in6_addr src6;
    struct in6_addr dst6;
    BOOL hasSrc4 = sourceAddress.length > 0 &&
        inet_pton(AF_INET, sourceAddress.UTF8String, &src4) == 1;
    BOOL hasDst4 = destinationAddress.length > 0 &&
        inet_pton(AF_INET, destinationAddress.UTF8String, &dst4) == 1;
    BOOL hasSrc6 = sourceAddress.length > 0 &&
        inet_pton(AF_INET6, sourceAddress.UTF8String, &src6) == 1;
    BOOL hasDst6 = destinationAddress.length > 0 &&
        inet_pton(AF_INET6, destinationAddress.UTF8String, &dst6) == 1;

    int pidCount = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
    if (pidCount <= 0) {
        return nil;
    }

    pid_t *pids = malloc((size_t)pidCount);
    if (!pids) {
        return nil;
    }

    pidCount = proc_listpids(PROC_ALL_PIDS, 0, pids, pidCount);
    int pidTotal = pidCount / (int)sizeof(pid_t);
    ProcessInfo *result = nil;

    for (int i = 0; i < pidTotal; i++) {
        pid_t pid = pids[i];
        if (pid <= 0) {
            continue;
        }

        int fdSize = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
        if (fdSize <= 0) {
            continue;
        }

        struct proc_fdinfo *fdInfos = malloc((size_t)fdSize);
        if (!fdInfos) {
            continue;
        }

        fdSize = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fdInfos, fdSize);
        int fdCount = fdSize / (int)sizeof(struct proc_fdinfo);

        for (int f = 0; f < fdCount; f++) {
            if (fdInfos[f].proc_fdtype != PROX_FDTYPE_SOCKET) {
                continue;
            }

            struct socket_fdinfo socketInfo;
            int sockSize = proc_pidfdinfo(pid, fdInfos[f].proc_fd,
                                          PROC_PIDFDSOCKETINFO,
                                          &socketInfo,
                                          sizeof(socketInfo));
            if (sockSize <= 0) {
                continue;
            }

            const struct in_sockinfo *inInfo = SNBInSockInfoForSocket(&socketInfo);
            if (!inInfo) {
                continue;
            }

            int localPort = ntohs((uint16_t)inInfo->insi_lport);
            int remotePort = ntohs((uint16_t)inInfo->insi_fport);

            if (localPort != sourcePort || remotePort != destinationPort) {
                continue;
            }

            if (sourceAddress.length > 0 &&
                !SNBMatchAddress(inInfo, YES, &src4, &src6, hasSrc4, hasSrc6)) {
                continue;
            }
            if (destinationAddress.length > 0 &&
                !SNBMatchAddress(inInfo, NO, &dst4, &dst6, hasDst4, hasDst6)) {
                continue;
            }

            result = [[ProcessInfo alloc] init];
            result.pid = pid;
            result.processName = nil;
            break;
        }

        free(fdInfos);

        if (result) {
            break;
        }
    }

    free(pids);
    return result;
}

static ProcessInfo *SNBHelperProcessInfoForPID(pid_t pid) {
    ProcessInfo *info = [[ProcessInfo alloc] init];
    info.pid = pid;

    char pathBuffer[PROC_PIDPATHINFO_MAXSIZE];
    int ret = proc_pidpath(pid, pathBuffer, sizeof(pathBuffer));
    if (ret > 0) {
        info.executablePath = [NSString stringWithUTF8String:pathBuffer];
        info.processName = [info.executablePath lastPathComponent];
    } else {
        struct proc_bsdinfo procInfo;
        ret = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &procInfo, sizeof(procInfo));
        if (ret > 0) {
            info.processName = [NSString stringWithUTF8String:procInfo.pbi_name];
        } else {
            info.processName = [NSString stringWithFormat:@"PID %d", pid];
        }
    }

    return info;
}

static void SNBHelperRefreshSocketMapIfNeeded(void) {
    SNBHelperSocketMap *map = SNBHelperSocketMapStore();
    NSTimeInterval now = [NSDate date].timeIntervalSince1970;
    if ((now - map.lastRefresh) < kHelperSocketMapRefreshInterval) {
        return;
    }

    int pidCount = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
    if (pidCount <= 0) {
        return;
    }

    pid_t *pids = malloc((size_t)pidCount);
    if (!pids) {
        return;
    }

    pidCount = proc_listpids(PROC_ALL_PIDS, 0, pids, pidCount);
    int pidTotal = pidCount / (int)sizeof(pid_t);
    NSMutableDictionary<NSString *, id> *socketMap = [NSMutableDictionary dictionary];
    NSMutableDictionary<NSNumber *, ProcessInfo *> *pidCache = [NSMutableDictionary dictionary];
    NSMutableDictionary<NSNumber *, NSNumber *> *pidStartTimes = [NSMutableDictionary dictionary];

    for (int i = 0; i < pidTotal; i++) {
        pid_t pid = pids[i];
        if (pid <= 0) {
            continue;
        }

        int fdSize = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
        if (fdSize <= 0) {
            continue;
        }

        struct proc_fdinfo *fdInfos = malloc((size_t)fdSize);
        if (!fdInfos) {
            continue;
        }

        fdSize = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fdInfos, fdSize);
        int fdCount = fdSize / (int)sizeof(struct proc_fdinfo);

        for (int f = 0; f < fdCount; f++) {
            if (fdInfos[f].proc_fdtype != PROX_FDTYPE_SOCKET) {
                continue;
            }

            struct socket_fdinfo socketInfo;
            int sockSize = proc_pidfdinfo(pid, fdInfos[f].proc_fd,
                                          PROC_PIDFDSOCKETINFO,
                                          &socketInfo,
                                          sizeof(socketInfo));
            if (sockSize <= 0) {
                continue;
            }

            const struct in_sockinfo *inInfo = SNBInSockInfoForSocket(&socketInfo);
            if (!inInfo) {
                continue;
            }

            int localPort = ntohs((uint16_t)inInfo->insi_lport);
            int remotePort = ntohs((uint16_t)inInfo->insi_fport);
            if (localPort <= 0) {
                continue;
            }

            NSString *localAddress = SNBIPAddressFromSockaddr(inInfo, YES);
            NSString *remoteAddress = SNBIPAddressFromSockaddr(inInfo, NO);
            NSString *key = SNBHelperConnectionKey(localAddress, localPort, remoteAddress, remotePort);

            ProcessInfo *info = pidCache[@(pid)];
            if (!info) {
                info = SNBHelperProcessInfoForPID(pid);
                pidCache[@(pid)] = info;
            }
            if (info) {
                NSNumber *start = pidStartTimes[@(pid)];
                if (!start) {
                    start = @(SNBProcessStartTimeForPID(pid));
                    pidStartTimes[@(pid)] = start;
                }
                SNBHelperSocketMapEntry *entry = [[SNBHelperSocketMapEntry alloc] init];
                entry.processInfo = info;
                entry.startTime = start.unsignedLongLongValue;
                socketMap[key] = entry;
            }
        }

        free(fdInfos);
    }

    free(pids);
    map.socketToProcess = socketMap;
    map.lastRefresh = now;
}

@implementation SNBHelperProcessLookup

- (void)lookupProcessWithSourceAddress:(NSString *)sourceAddress
                            sourcePort:(NSInteger)sourcePort
                    destinationAddress:(NSString *)destinationAddress
                       destinationPort:(NSInteger)destinationPort
                             withReply:(void (^)(NSDictionary *processInfo, NSError *error))reply {
    if (sourcePort <= 0 || destinationPort <= 0) {
        reply(nil, nil);
        return;
    }

    __block ProcessInfo *result = nil;
    dispatch_sync(SNBHelperProcessLookupQueue(), ^{
        NSMutableDictionary<NSString *, SNBHelperProcessCacheEntry *> *cache = SNBHelperProcessCache();
        SNBHelperPurgeCacheIfNeeded(cache);
        NSString *key = SNBHelperConnectionKey(sourceAddress, sourcePort, destinationAddress, destinationPort);
        SNBHelperProcessCacheEntry *cached = cache[key];
        if (cached) {
            uint64_t currentStart = SNBProcessStartTimeForPID(cached.processInfo.pid);
            if (currentStart > 0 && currentStart == cached.startTime) {
                result = cached.processInfo;
                return;
            }
            [cache removeObjectForKey:key];
        }
        SNBHelperRefreshSocketMapIfNeeded();
        SNBHelperSocketMap *map = SNBHelperSocketMapStore();
        SNBHelperSocketMapEntry *mapped = map.socketToProcess[key];
        if (mapped) {
            uint64_t currentStart = SNBProcessStartTimeForPID(mapped.processInfo.pid);
            if (currentStart > 0 && currentStart == mapped.startTime) {
                result = mapped.processInfo;
                return;
            }
        }
        result = SNBHelperFindProcessForConnection(sourceAddress,
                                                   sourcePort,
                                                   destinationAddress,
                                                   destinationPort);
        if (!result) {
            usleep(100 * 1000);
            result = SNBHelperFindProcessForConnection(sourceAddress,
                                                       sourcePort,
                                                       destinationAddress,
                                                       destinationPort);
        }
    });

    if (!result) {
        reply(nil, nil);
        return;
    }

    ProcessInfo *info = SNBHelperProcessInfoForPID(result.pid);
    dispatch_sync(SNBHelperProcessLookupQueue(), ^{
        NSMutableDictionary<NSString *, SNBHelperProcessCacheEntry *> *cache = SNBHelperProcessCache();
        SNBHelperPurgeCacheIfNeeded(cache);
        NSString *key = SNBHelperConnectionKey(sourceAddress, sourcePort, destinationAddress, destinationPort);
        SNBHelperProcessCacheEntry *entry = [[SNBHelperProcessCacheEntry alloc] init];
        entry.processInfo = info;
        entry.lastSeen = [NSDate date].timeIntervalSince1970;
        entry.startTime = SNBProcessStartTimeForPID(info.pid);
        cache[key] = entry;
    });
    reply([info toDictionary], nil);
}

@end

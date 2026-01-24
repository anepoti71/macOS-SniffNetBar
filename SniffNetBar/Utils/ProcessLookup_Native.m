//
//  ProcessLookup_Native.m
//  SniffNetBar
//
//  Native macOS API-based process lookup using libproc
//  More reliable than lsof, doesn't require parsing text output
//
//  PERF-1 FIX: Uses SNBSocketPIDMap for O(1) lookups instead of
//  scanning all PIDs/FDs on every request (was O(n*m)).
//

#import "ProcessLookup.h"
#import "SNBSocketPIDMap.h"
#import "Logger.h"
#import <libproc.h>
#import <sys/proc_info.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>

static const NSTimeInterval kSocketMapRefreshInterval = 2.0;

static const struct in_sockinfo *SNBInSockInfoForSocket(const struct socket_fdinfo *socketInfo) {
    if (socketInfo->psi.soi_kind == SOCKINFO_TCP) {
        return &socketInfo->psi.soi_proto.pri_tcp.tcpsi_ini;
    }
    if (socketInfo->psi.soi_kind == SOCKINFO_IN) {
        return &socketInfo->psi.soi_proto.pri_in;
    }
    return NULL;
}

static NSString *SNBConnectionKeyForSockinfo(const struct in_sockinfo *info) {
    char localBuffer[INET6_ADDRSTRLEN] = {0};
    char remoteBuffer[INET6_ADDRSTRLEN] = {0};
    NSString *local = @"";
    NSString *remote = @"";

    if (info->insi_vflag & INI_IPV4) {
        inet_ntop(AF_INET, &info->insi_laddr.ina_46.i46a_addr4, localBuffer, sizeof(localBuffer));
        inet_ntop(AF_INET, &info->insi_faddr.ina_46.i46a_addr4, remoteBuffer, sizeof(remoteBuffer));
    } else if (info->insi_vflag & INI_IPV6) {
        inet_ntop(AF_INET6, &info->insi_laddr.ina_6, localBuffer, sizeof(localBuffer));
        inet_ntop(AF_INET6, &info->insi_faddr.ina_6, remoteBuffer, sizeof(remoteBuffer));
    }
    if (localBuffer[0] != '\0') {
        local = [NSString stringWithUTF8String:localBuffer];
    }
    if (remoteBuffer[0] != '\0') {
        remote = [NSString stringWithUTF8String:remoteBuffer];
    }

    uint16_t localPort = ntohs(info->insi_lport);
    uint16_t remotePort = ntohs(info->insi_fport);
    return [NSString stringWithFormat:@"%@:%u->%@:%u", local, localPort, remote, remotePort];
}

static NSDictionary<NSString *, ProcessInfo *> *SNBRefreshSocketMapIfNeeded(void) {
    static NSMutableDictionary<NSString *, ProcessInfo *> *socketMap = nil;
    static NSTimeInterval lastRefresh = 0;
    static dispatch_queue_t socketMapQueue;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        socketMapQueue = dispatch_queue_create("com.sniffnetbar.processlookup.socketmap", DISPATCH_QUEUE_SERIAL);
        socketMap = [NSMutableDictionary dictionary];
    });

    __block NSDictionary<NSString *, ProcessInfo *> *snapshot = nil;
    dispatch_sync(socketMapQueue, ^{
        NSTimeInterval now = [NSDate date].timeIntervalSince1970;
        if (socketMap.count > 0 && (now - lastRefresh) < kSocketMapRefreshInterval) {
            snapshot = [socketMap copy];
            return;
        }

        [socketMap removeAllObjects];

        int numberOfPids = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
        if (numberOfPids <= 0) {
            snapshot = [socketMap copy];
            return;
        }

        pid_t *pids = malloc(sizeof(pid_t) * numberOfPids);
        if (!pids) {
            snapshot = [socketMap copy];
            return;
        }

        numberOfPids = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pid_t) * numberOfPids);
        if (numberOfPids <= 0) {
            free(pids);
            snapshot = [socketMap copy];
            return;
        }

        NSMutableDictionary<NSNumber *, ProcessInfo *> *pidCache = [NSMutableDictionary dictionary];

        for (int i = 0; i < numberOfPids; i++) {
            pid_t pid = pids[i];
            if (pid == 0) {
                continue;
            }

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
            for (int j = 0; j < numFds; j++) {
                if (fdInfo[j].proc_fdtype != PROX_FDTYPE_SOCKET) {
                    continue;
                }

                struct socket_fdinfo socketInfo;
                int socketInfoSize = proc_pidfdinfo(pid, fdInfo[j].proc_fd, PROC_PIDFDSOCKETINFO,
                                                   &socketInfo, sizeof(socketInfo));
                if (socketInfoSize <= 0) {
                    continue;
                }

                const struct in_sockinfo *inInfo = SNBInSockInfoForSocket(&socketInfo);
                if (!inInfo) {
                    continue;
                }

                NSString *key = SNBConnectionKeyForSockinfo(inInfo);
                if (key.length == 0) {
                    continue;
                }

                ProcessInfo *info = pidCache[@(pid)];
                if (!info) {
                    info = [[ProcessInfo alloc] init];
                    info.pid = pid;
                    char pathBuffer[PROC_PIDPATHINFO_MAXSIZE] = {0};
                    int pathLen = proc_pidpath(pid, pathBuffer, sizeof(pathBuffer));
                    if (pathLen > 0) {
                        NSString *fullPath = [NSString stringWithUTF8String:pathBuffer];
                        info.executablePath = fullPath;
                        info.processName = [fullPath lastPathComponent];
                    } else {
                        char nameBuffer[PROC_PIDPATHINFO_MAXSIZE] = {0};
                        if (proc_name(pid, nameBuffer, sizeof(nameBuffer)) > 0) {
                            info.processName = [NSString stringWithUTF8String:nameBuffer];
                        } else {
                            info.processName = [NSString stringWithFormat:@"PID %d", pid];
                        }
                    }
                    pidCache[@(pid)] = info;
                }

                socketMap[key] = info;
            }

            free(fdInfo);
        }

        free(pids);
        lastRefresh = now;
        snapshot = [socketMap copy];
    });

    return snapshot ?: @{};
}

// Category for native API-based lookups
@implementation ProcessLookup (Native)

+ (nullable ProcessInfo *)lookupUsingNativeAPIForSource:(NSString *)sourceAddress
                                             sourcePort:(NSInteger)sourcePort
                                            destination:(NSString *)destinationAddress
                                        destinationPort:(NSInteger)destinationPort {

    // PERF-1 FIX: Try O(1) lookup from global socket-to-PID map first
    ProcessInfo *fastResult = [[SNBSocketPIDMap sharedMap] processForSource:sourceAddress
                                                                 sourcePort:sourcePort
                                                                destination:destinationAddress
                                                            destinationPort:destinationPort];
    if (fastResult) {
        SNBLogInfo("ProcessLookup(native): O(1) map hit for %{public}@:%ld -> %{public}@:%ld = %{public}@ (PID %d)",
                   sourceAddress, (long)sourcePort, destinationAddress, (long)destinationPort,
                   fastResult.processName, fastResult.pid);
        return fastResult;
    }

    // Fallback to full scan for connections not in map (e.g., very short-lived)
    SNBLogInfo("ProcessLookup(native): Map miss, falling back to full scan for %{public}@:%ld -> %{public}@:%ld",
               sourceAddress, (long)sourcePort, destinationAddress, (long)destinationPort);

    NSDictionary<NSString *, ProcessInfo *> *socketMap = SNBRefreshSocketMapIfNeeded();
    NSString *key = [NSString stringWithFormat:@"%@:%ld->%@:%ld",
                     sourceAddress, (long)sourcePort, destinationAddress, (long)destinationPort];
    ProcessInfo *result = socketMap[key];
    if (result) {
        SNBLogInfo("ProcessLookup(native): ✓ Found %{public}@ (PID %d)", result.processName, result.pid);
    } else {
        SNBLogInfo("ProcessLookup(native): ✗ No matching process found");
    }
    return result;
}

+ (nullable ProcessInfo *)lookupListeningProcessOnPort:(NSInteger)port {
    if (port <= 0 || port > 65535) {
        return nil;
    }

    // PERF-1 FIX: Try O(1) lookup from global socket-to-PID map first
    ProcessInfo *fastResult = [[SNBSocketPIDMap sharedMap] processListeningOnPort:port];
    if (fastResult) {
        SNBLogDebug("ProcessLookup(native): O(1) map hit for listener on port %ld = %{public}@ (PID %d)",
                   (long)port, fastResult.processName, fastResult.pid);
        return fastResult;
    }

    // Fallback to full scan
    SNBLogDebug("ProcessLookup(native): Map miss for listener on port %ld, falling back to full scan", (long)port);

    // Get list of all PIDs
    int numberOfPids = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
    if (numberOfPids <= 0) {
        return nil;
    }

    pid_t *pids = malloc(sizeof(pid_t) * numberOfPids);
    if (!pids) {
        return nil;
    }

    numberOfPids = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pid_t) * numberOfPids);
    if (numberOfPids <= 0) {
        free(pids);
        return nil;
    }

    ProcessInfo *result = nil;

    for (int i = 0; i < numberOfPids; i++) {
        pid_t pid = pids[i];
        if (pid == 0) {
            continue;
        }

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

        for (int j = 0; j < numFds; j++) {
            if (fdInfo[j].proc_fdtype != PROX_FDTYPE_SOCKET) {
                continue;
            }

            struct socket_fdinfo socketInfo;
            int socketInfoSize = proc_pidfdinfo(pid, fdInfo[j].proc_fd, PROC_PIDFDSOCKETINFO,
                                               &socketInfo, sizeof(socketInfo));
            if (socketInfoSize <= 0) {
                continue;
            }

            const struct in_sockinfo *inInfo = SNBInSockInfoForSocket(&socketInfo);
            if (!inInfo) {
                continue;
            }

            // Check if this socket is listening on the specified port
            uint16_t localPort = ntohs(inInfo->insi_lport);
            BOOL isTcpListening = (socketInfo.psi.soi_kind == SOCKINFO_TCP &&
                                   socketInfo.psi.soi_proto.pri_tcp.tcpsi_state == TSI_S_LISTEN);
            if (localPort == port && (isTcpListening || socketInfo.psi.soi_kind == SOCKINFO_IN)) {
                // Found a listening socket on this port
                char pathBuffer[PROC_PIDPATHINFO_MAXSIZE] = {0};
                int pathLen = proc_pidpath(pid, pathBuffer, sizeof(pathBuffer));

                result = [[ProcessInfo alloc] init];
                result.pid = pid;

                if (pathLen > 0) {
                    NSString *fullPath = [NSString stringWithUTF8String:pathBuffer];
                    result.executablePath = fullPath;
                    result.processName = [fullPath lastPathComponent];
                } else {
                    char nameBuffer[PROC_PIDPATHINFO_MAXSIZE] = {0};
                    if (proc_name(pid, nameBuffer, sizeof(nameBuffer)) > 0) {
                        result.processName = [NSString stringWithUTF8String:nameBuffer];
                    } else {
                        result.processName = [NSString stringWithFormat:@"PID %d", pid];
                    }
                }

                SNBLogDebug("ProcessLookup(native): ✓ Found listener %{public}@ (PID %d) on port %ld",
                           result.processName, result.pid, (long)port);
                free(fdInfo);
                goto found;
            }
        }

        free(fdInfo);
    }

found:
    free(pids);
    return result;
}

@end

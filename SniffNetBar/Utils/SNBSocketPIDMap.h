//
//  SNBSocketPIDMap.h
//  SniffNetBar
//
//  Global socket-to-PID mapping with periodic refresh for O(1) lookups.
//  Solves PERF-1: O(n*m) process lookup scanning all PIDs and FDs.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@class ProcessInfo;

/// Socket key for fast lookup combining addresses and ports
@interface SNBSocketKey : NSObject <NSCopying>
@property (nonatomic, copy, readonly) NSString *localAddress;
@property (nonatomic, copy, readonly) NSString *remoteAddress;
@property (nonatomic, assign, readonly) uint16_t localPort;
@property (nonatomic, assign, readonly) uint16_t remotePort;
@property (nonatomic, assign, readonly) BOOL isIPv6;

- (instancetype)initWithLocalAddress:(NSString *)localAddr
                           localPort:(uint16_t)localPort
                       remoteAddress:(NSString *)remoteAddr
                          remotePort:(uint16_t)remotePort
                              isIPv6:(BOOL)isIPv6;

/// Create a key for listening sockets (remote = 0.0.0.0:0)
+ (instancetype)listeningKeyWithLocalPort:(uint16_t)port isIPv6:(BOOL)isIPv6;
@end


/// Global socket-to-PID map with periodic refresh.
/// Instead of scanning all PIDs/FDs on every lookup (O(n*m)),
/// this builds a complete map periodically and provides O(1) lookups.
@interface SNBSocketPIDMap : NSObject

/// Shared singleton instance
+ (instancetype)sharedMap;

/// Refresh interval in seconds (default: 2.0)
@property (nonatomic, assign) NSTimeInterval refreshInterval;

/// Start periodic refresh timer
- (void)startPeriodicRefresh;

/// Stop periodic refresh timer
- (void)stopPeriodicRefresh;

/// Force an immediate refresh of the socket map
- (void)refreshNow;

/// O(1) lookup for a connection
/// @param sourceAddress Local source IP address
/// @param sourcePort Local source port
/// @param destinationAddress Remote destination IP address
/// @param destinationPort Remote destination port
/// @return ProcessInfo if found, nil otherwise
- (nullable ProcessInfo *)processForSource:(NSString *)sourceAddress
                                sourcePort:(NSInteger)sourcePort
                               destination:(NSString *)destinationAddress
                           destinationPort:(NSInteger)destinationPort;

/// O(1) lookup for a listening port
/// @param port Local port number
/// @return ProcessInfo if found, nil otherwise
- (nullable ProcessInfo *)processListeningOnPort:(NSInteger)port;

/// Statistics for monitoring
@property (nonatomic, assign, readonly) NSUInteger totalSocketCount;
@property (nonatomic, assign, readonly) NSUInteger totalProcessCount;
@property (nonatomic, strong, readonly, nullable) NSDate *lastRefreshTime;
@property (nonatomic, assign, readonly) NSTimeInterval lastRefreshDuration;

@end

NS_ASSUME_NONNULL_END

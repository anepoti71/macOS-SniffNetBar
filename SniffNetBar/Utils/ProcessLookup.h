//
//  ProcessLookup.h
//  SniffNetBar
//
//  Utility for looking up process information for network connections
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface ProcessInfo : NSObject

@property (nonatomic, assign) pid_t pid;
@property (nonatomic, copy) NSString *processName;
@property (nonatomic, copy, nullable) NSString *executablePath;

@end

@interface ProcessLookup : NSObject

/// Lookup process information for a connection
/// @param sourceAddress Source IP address
/// @param sourcePort Source port
/// @param destinationAddress Destination IP address
/// @param destinationPort Destination port
/// @param completion Completion handler with process info (nil if not found)
+ (void)lookupProcessForConnectionWithSource:(NSString *)sourceAddress
                                  sourcePort:(NSInteger)sourcePort
                                 destination:(NSString *)destinationAddress
                             destinationPort:(NSInteger)destinationPort
                                  completion:(void (^)(ProcessInfo * _Nullable processInfo))completion;

/// Synchronous version (use sparingly, may block)
+ (nullable ProcessInfo *)lookupProcessForConnectionWithSource:(NSString *)sourceAddress
                                                    sourcePort:(NSInteger)sourcePort
                                                   destination:(NSString *)destinationAddress
                                               destinationPort:(NSInteger)destinationPort;

@end

NS_ASSUME_NONNULL_END

@interface ProcessLookup (Lsof)

/// Alternative synchronous lookup using lsof output.
+ (nullable ProcessInfo *)lookupUsingLsofForSource:(NSString *)sourceAddress
                                        sourcePort:(NSInteger)sourcePort
                                       destination:(NSString *)destinationAddress
                                   destinationPort:(NSInteger)destinationPort;

@end

@interface ProcessLookup (Native)

/// Native macOS API-based lookup using libproc (most reliable).
/// Uses proc_listpids() and proc_pidfdinfo() to enumerate all process sockets
/// and match connection details directly without text parsing.
+ (nullable ProcessInfo *)lookupUsingNativeAPIForSource:(NSString *)sourceAddress
                                             sourcePort:(NSInteger)sourcePort
                                            destination:(NSString *)destinationAddress
                                        destinationPort:(NSInteger)destinationPort;

/// Look up the process listening on a specific local port.
/// Used for incoming connections where we need to find the server process.
+ (nullable ProcessInfo *)lookupListeningProcessOnPort:(NSInteger)port;

@end

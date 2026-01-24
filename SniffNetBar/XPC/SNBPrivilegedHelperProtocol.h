//
//  SNBPrivilegedHelperProtocol.h
//  SniffNetBar
//
//  XPC protocol shared between app and helper
//

#import <Foundation/Foundation.h>

#define kSNBPrivilegedHelperMachServiceName @"com.sniffnetbar.helper"

@protocol SNBPrivilegedHelperProtocol

// Helper version
- (void)getVersionWithReply:(void (^)(NSString *version))reply;

// Device enumeration
- (void)enumerateNetworkDevicesWithReply:(void (^)(NSArray<NSDictionary *> *devices, NSError *error))reply;

// Packet capture
- (void)startCaptureOnDevice:(NSString *)deviceName
                   withReply:(void (^)(NSString *sessionID, NSError *error))reply;

- (void)stopCaptureForSession:(NSString *)sessionID
                     withReply:(void (^)(NSError *error))reply;

- (void)getNextPacketForSession:(NSString *)sessionID
                      withReply:(void (^)(NSDictionary *packetInfo, NSError *error))reply;

// Process lookup
- (void)lookupProcessWithSourceAddress:(NSString *)sourceAddress
                            sourcePort:(NSInteger)sourcePort
                    destinationAddress:(NSString *)destinationAddress
                       destinationPort:(NSInteger)destinationPort
                             withReply:(void (^)(NSDictionary *processInfo, NSError *error))reply;

@end

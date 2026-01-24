//
//  SNBPrivilegedHelperClient.h
//  SniffNetBar
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@class NetworkDevice;
@class ProcessInfo;
@class PacketInfo;

@interface SNBPrivilegedHelperClient : NSObject

+ (instancetype)sharedClient;

- (void)connectToHelper;
- (void)disconnect;
- (BOOL)isConnected;

- (void)getVersionWithCompletion:(void (^)(NSString * _Nullable version, NSError * _Nullable error))completion;

- (void)enumerateDevicesWithCompletion:(void (^)(NSArray<NetworkDevice *> * _Nullable devices, NSError * _Nullable error))completion;

- (void)startCaptureOnDevice:(NSString *)deviceName
                  completion:(void (^)(NSString * _Nullable sessionID, NSError * _Nullable error))completion;

- (void)stopCaptureForSession:(NSString *)sessionID
                   completion:(void (^)(NSError * _Nullable error))completion;

- (void)getNextPacketForSession:(NSString *)sessionID
                     completion:(void (^)(PacketInfo * _Nullable packet, NSError * _Nullable error))completion;

- (void)lookupProcessWithSourceAddress:(NSString *)sourceAddress
                            sourcePort:(NSInteger)sourcePort
                       destinationAddr:(NSString *)destinationAddr
                       destinationPort:(NSInteger)destinationPort
                            completion:(void (^)(ProcessInfo * _Nullable processInfo, NSError * _Nullable error))completion;

@end

NS_ASSUME_NONNULL_END

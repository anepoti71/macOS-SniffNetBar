//
//  PacketCaptureManager.h
//  SniffNetBar
//
//  Packet capture manager using privileged helper via XPC
//

#import <Foundation/Foundation.h>

@class PacketInfo;

@interface PacketCaptureManager : NSObject

@property (nonatomic, copy) void (^onPacketReceived)(PacketInfo *packetInfo);
@property (nonatomic, copy) void (^onCaptureError)(NSError *error);
@property (nonatomic, strong, readonly) NSString *currentDeviceName;
@property (nonatomic, strong, readonly) NSDate *captureStartDate;

- (BOOL)startCaptureWithDeviceName:(NSString *)deviceName error:(NSError **)error;
- (BOOL)startCaptureWithError:(NSError **)error; // Uses default device
- (void)stopCapture;

@end

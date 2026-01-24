//
//  SNBHelperPacketCapture.h
//  SniffNetBarHelper
//

#import <Foundation/Foundation.h>

@interface SNBHelperPacketCapture : NSObject

- (void)startCaptureOnDevice:(NSString *)deviceName
                   withReply:(void (^)(NSString *sessionID, NSError *error))reply;

- (void)stopCaptureForSession:(NSString *)sessionID
                     withReply:(void (^)(NSError *error))reply;

- (void)getNextPacketForSession:(NSString *)sessionID
                      withReply:(void (^)(NSDictionary *packetInfo, NSError *error))reply;

- (void)stopAllSessionsWithReply:(void (^)(void))reply;

@end

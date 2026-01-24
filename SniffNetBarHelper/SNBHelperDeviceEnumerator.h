//
//  SNBHelperDeviceEnumerator.h
//  SniffNetBarHelper
//

#import <Foundation/Foundation.h>

@interface SNBHelperDeviceEnumerator : NSObject

- (void)enumerateDevicesWithReply:(void (^)(NSArray<NSDictionary *> *devices, NSError *error))reply;

@end

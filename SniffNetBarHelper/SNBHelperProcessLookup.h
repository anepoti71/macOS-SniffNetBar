//
//  SNBHelperProcessLookup.h
//  SniffNetBarHelper
//

#import <Foundation/Foundation.h>

@interface SNBHelperProcessLookup : NSObject

- (void)lookupProcessWithSourceAddress:(NSString *)sourceAddress
                            sourcePort:(NSInteger)sourcePort
                    destinationAddress:(NSString *)destinationAddress
                       destinationPort:(NSInteger)destinationPort
                             withReply:(void (^)(NSDictionary *processInfo, NSError *error))reply;

@end

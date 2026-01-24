//
//  SNBModelingXPCService.h
//  SniffNetBar
//

#import <Foundation/Foundation.h>
#import "SNBModelingXPCProtocol.h"

NS_ASSUME_NONNULL_BEGIN

@interface SNBModelingXPCService : NSObject <SNBModelingXPCProtocol>
- (instancetype)init;
@end

NS_ASSUME_NONNULL_END

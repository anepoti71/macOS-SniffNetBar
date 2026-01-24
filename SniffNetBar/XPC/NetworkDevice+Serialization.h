//
//  NetworkDevice+Serialization.h
//  SniffNetBar
//

#import <Foundation/Foundation.h>
#import "NetworkDevice.h"

NS_ASSUME_NONNULL_BEGIN

@interface NetworkDevice (Serialization)

- (NSDictionary *)toDictionary;
+ (nullable NetworkDevice *)fromDictionary:(NSDictionary *)dictionary;

@end

NS_ASSUME_NONNULL_END

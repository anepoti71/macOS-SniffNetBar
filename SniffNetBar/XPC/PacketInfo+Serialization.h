//
//  PacketInfo+Serialization.h
//  SniffNetBar
//

#import <Foundation/Foundation.h>
#import "PacketInfo.h"

NS_ASSUME_NONNULL_BEGIN

@interface PacketInfo (Serialization)

- (NSDictionary *)toDictionary;
+ (nullable PacketInfo *)fromDictionary:(NSDictionary *)dictionary;

@end

NS_ASSUME_NONNULL_END

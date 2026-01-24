//
//  ProcessInfo+Serialization.h
//  SniffNetBar
//

#import <Foundation/Foundation.h>
#import "ProcessLookup.h"

NS_ASSUME_NONNULL_BEGIN

@interface ProcessInfo (Serialization)

- (NSDictionary *)toDictionary;
+ (nullable ProcessInfo *)fromDictionary:(NSDictionary *)dictionary;

@end

NS_ASSUME_NONNULL_END

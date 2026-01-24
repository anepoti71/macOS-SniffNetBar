//
//  NetworkDevice+Serialization.m
//  SniffNetBar
//

#import "NetworkDevice+Serialization.h"

@implementation NetworkDevice (Serialization)

- (NSDictionary *)toDictionary {
    return @{
        @"name": self.name ?: @"",
        @"description": self.deviceDescription ?: @"",
        @"addresses": self.addresses ?: @[]
    };
}

+ (NetworkDevice *)fromDictionary:(NSDictionary *)dictionary {
    if (!dictionary) {
        return nil;
    }

    NSString *name = dictionary[@"name"] ?: @"";
    NSString *desc = dictionary[@"description"] ?: @"";
    NSArray<NSString *> *addresses = dictionary[@"addresses"];
    if (![addresses isKindOfClass:[NSArray class]]) {
        addresses = @[];
    }

    return [[NetworkDevice alloc] initWithName:name
                                   description:desc
                                     addresses:addresses];
}

@end

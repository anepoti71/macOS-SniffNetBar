//
//  PacketInfo+Serialization.m
//  SniffNetBar
//

#import "PacketInfo+Serialization.h"

@implementation PacketInfo (Serialization)

- (NSDictionary *)toDictionary {
    return @{
        @"sourceAddress": self.sourceAddress ?: @"",
        @"destinationAddress": self.destinationAddress ?: @"",
        @"sourcePort": @(self.sourcePort),
        @"destinationPort": @(self.destinationPort),
        @"protocol": @(self.protocol),
        @"totalBytes": @(self.totalBytes)
    };
}

+ (PacketInfo *)fromDictionary:(NSDictionary *)dictionary {
    if (!dictionary) {
        return nil;
    }

    PacketInfo *info = [[PacketInfo alloc] init];
    info.sourceAddress = dictionary[@"sourceAddress"] ?: @"";
    info.destinationAddress = dictionary[@"destinationAddress"] ?: @"";
    info.sourcePort = [dictionary[@"sourcePort"] integerValue];
    info.destinationPort = [dictionary[@"destinationPort"] integerValue];
    info.protocol = (PacketProtocol)[dictionary[@"protocol"] integerValue];
    info.totalBytes = [dictionary[@"totalBytes"] unsignedLongLongValue];
    return info;
}

@end

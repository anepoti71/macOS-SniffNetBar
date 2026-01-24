//
//  PacketInfo.m
//  SniffNetBar
//
//  Packet information structure
//

#import "PacketInfo.h"

@implementation PacketInfo

- (instancetype)init {
    self = [super init];
    if (self) {
        _sourcePort = -1;
        _destinationPort = -1;
        _protocol = PacketProtocolUnknown;
        _totalBytes = 0;
    }
    return self;
}

@end


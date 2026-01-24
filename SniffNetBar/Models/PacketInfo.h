//
//  PacketInfo.h
//  SniffNetBar
//
//  Packet information structure
//

#import <Foundation/Foundation.h>

typedef NS_ENUM(NSInteger, PacketProtocol) {
    PacketProtocolTCP,
    PacketProtocolUDP,
    PacketProtocolICMP,
    PacketProtocolARP,
    PacketProtocolUnknown
};

@interface PacketInfo : NSObject

@property (nonatomic, strong) NSString *sourceAddress;
@property (nonatomic, strong) NSString *destinationAddress;
@property (nonatomic, assign) NSInteger sourcePort;
@property (nonatomic, assign) NSInteger destinationPort;
@property (nonatomic, assign) PacketProtocol protocol;
@property (nonatomic, assign) uint64_t totalBytes;

@end


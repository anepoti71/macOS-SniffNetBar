//
//  SNBHelperPacketCapture.m
//  SniffNetBarHelper
//

#import "SNBHelperPacketCapture.h"
#import "../SniffNetBar/Models/PacketInfo.h"
#import "../SniffNetBar/XPC/PacketInfo+Serialization.h"
#import <pcap/pcap.h>
#import <net/ethernet.h>
#import <netinet/ip.h>
#import <netinet/tcp.h>
#import <netinet/udp.h>
#import <arpa/inet.h>

static const int kPcapSnaplen = 65536;
static const int kPcapPromiscuousMode = 0;
static const int kPcapTimeoutMs = 500;
static const NSUInteger kSNBMaxActiveCaptureSessions = 4;

@interface SNBHelperCaptureSession : NSObject

@property (nonatomic, assign) pcap_t *pcapHandle;
@property (nonatomic, strong) dispatch_queue_t queue;
@property (nonatomic, copy) NSString *deviceName;

@end

@implementation SNBHelperCaptureSession
@end

@interface SNBHelperPacketCapture ()

@property (nonatomic, strong) NSMutableDictionary<NSString *, SNBHelperCaptureSession *> *sessions;
@property (nonatomic, strong) dispatch_queue_t managementQueue;

@end

@implementation SNBHelperPacketCapture

- (instancetype)init {
    self = [super init];
    if (self) {
        _sessions = [[NSMutableDictionary alloc] init];
        _managementQueue = dispatch_queue_create("com.sniffnetbar.helper.capture.management", DISPATCH_QUEUE_SERIAL);
    }
    return self;
}

- (void)startCaptureOnDevice:(NSString *)deviceName
                   withReply:(void (^)(NSString *sessionID, NSError *error))reply {
    if (deviceName.length == 0) {
        NSError *error = [NSError errorWithDomain:@"SNBHelperPacketCapture"
                                             code:1
                                         userInfo:@{NSLocalizedDescriptionKey: @"Invalid device name"}];
        reply(nil, error);
        return;
    }

    dispatch_async(self.managementQueue, ^{
        if (self.sessions.count >= kSNBMaxActiveCaptureSessions) {
            NSError *error = [NSError errorWithDomain:@"SNBHelperPacketCapture"
                                                 code:7
                                             userInfo:@{NSLocalizedDescriptionKey:
                                                            @"Too many active capture sessions"}];
            reply(nil, error);
            return;
        }

        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t *handle = pcap_open_live(deviceName.UTF8String,
                                        kPcapSnaplen,
                                        kPcapPromiscuousMode,
                                        kPcapTimeoutMs,
                                        errbuf);
        if (!handle) {
            NSError *error = [NSError errorWithDomain:@"SNBHelperPacketCapture"
                                                 code:2
                                             userInfo:@{NSLocalizedDescriptionKey:
                                                            [NSString stringWithUTF8String:errbuf]}];
            reply(nil, error);
            return;
        }

        if (pcap_setnonblock(handle, 1, errbuf) == -1) {
            NSLog(@"Helper: Failed to set non-blocking mode: %s", errbuf);
        }

        SNBHelperCaptureSession *session = [[SNBHelperCaptureSession alloc] init];
        session.pcapHandle = handle;
        session.deviceName = deviceName;
        session.queue = dispatch_queue_create("com.sniffnetbar.helper.capture.session", DISPATCH_QUEUE_SERIAL);

        NSString *sessionID = [NSUUID UUID].UUIDString;
        self.sessions[sessionID] = session;
        reply(sessionID, nil);
    });
}

- (void)stopCaptureForSession:(NSString *)sessionID
                     withReply:(void (^)(NSError *error))reply {
    if (sessionID.length == 0) {
        reply([NSError errorWithDomain:@"SNBHelperPacketCapture"
                                  code:3
                              userInfo:@{NSLocalizedDescriptionKey: @"Invalid session ID"}]);
        return;
    }

    dispatch_async(self.managementQueue, ^{
        SNBHelperCaptureSession *session = self.sessions[sessionID];
        if (!session) {
            reply(nil);
            return;
        }

        dispatch_sync(session.queue, ^{
            if (session.pcapHandle) {
                pcap_close(session.pcapHandle);
                session.pcapHandle = NULL;
            }
        });

        [self.sessions removeObjectForKey:sessionID];
        reply(nil);
    });
}

- (void)getNextPacketForSession:(NSString *)sessionID
                      withReply:(void (^)(NSDictionary *packetInfo, NSError *error))reply {
    if (sessionID.length == 0) {
        reply(nil, [NSError errorWithDomain:@"SNBHelperPacketCapture"
                                       code:4
                                   userInfo:@{NSLocalizedDescriptionKey: @"Invalid session ID"}]);
        return;
    }

    dispatch_async(self.managementQueue, ^{
        SNBHelperCaptureSession *session = self.sessions[sessionID];
        if (!session) {
            reply(nil, [NSError errorWithDomain:@"SNBHelperPacketCapture"
                                           code:5
                                       userInfo:@{NSLocalizedDescriptionKey: @"Session not found"}]);
            return;
        }

        dispatch_async(session.queue, ^{
            if (!session.pcapHandle) {
                reply(nil, [NSError errorWithDomain:@"SNBHelperPacketCapture"
                                               code:8
                                           userInfo:@{NSLocalizedDescriptionKey: @"Session closed"}]);
                return;
            }

            struct pcap_pkthdr *header = NULL;
            const u_char *packet = NULL;
            int result = pcap_next_ex(session.pcapHandle, &header, &packet);

            if (result == 1) {
                PacketInfo *info = [self parsePacket:packet
                                       capturedLength:header->caplen
                                         actualLength:header->len];
                reply(info ? [info toDictionary] : nil, nil);
                return;
            }

            if (result == 0) {
                reply(nil, nil);
                return;
            }

            if (result == -1) {
                const char *errorMsg = pcap_geterr(session.pcapHandle);
                NSError *error = [NSError errorWithDomain:@"SNBHelperPacketCapture"
                                                     code:6
                                                 userInfo:@{NSLocalizedDescriptionKey:
                                                                [NSString stringWithUTF8String:errorMsg]}];
                reply(nil, error);
                return;
            }

            reply(nil, nil);
        });
    });
}

- (PacketInfo *)parsePacket:(const u_char *)packet
             capturedLength:(int)capturedLength
               actualLength:(int)actualLength {
    if (capturedLength < (int)sizeof(struct ether_header)) {
        return nil;
    }

    PacketInfo *info = [[PacketInfo alloc] init];
    info.totalBytes = actualLength;

    struct ether_header *ethHeader = (struct ether_header *)packet;
    uint16_t etherType = ntohs(ethHeader->ether_type);

    const u_char *ipPacket = packet + sizeof(struct ether_header);
    int ipLength = capturedLength - (int)sizeof(struct ether_header);
    if (ipLength <= 0) {
        return nil;
    }

    if (etherType == ETHERTYPE_IP) {
        if (ipLength < (int)sizeof(struct ip)) {
            return nil;
        }

        struct ip *ipHeader = (struct ip *)ipPacket;
        int ipHeaderLen = ipHeader->ip_hl * 4;
        if (ipLength < ipHeaderLen) {
            return nil;
        }

        char srcAddr[INET_ADDRSTRLEN];
        char dstAddr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ipHeader->ip_src, srcAddr, sizeof(srcAddr));
        inet_ntop(AF_INET, &ipHeader->ip_dst, dstAddr, sizeof(dstAddr));
        info.sourceAddress = [NSString stringWithUTF8String:srcAddr];
        info.destinationAddress = [NSString stringWithUTF8String:dstAddr];

        const u_char *transport = ipPacket + ipHeaderLen;
        int transportLength = ipLength - ipHeaderLen;

        if (ipHeader->ip_p == IPPROTO_TCP && transportLength >= (int)sizeof(struct tcphdr)) {
            struct tcphdr *tcpHeader = (struct tcphdr *)transport;
            info.sourcePort = ntohs(tcpHeader->th_sport);
            info.destinationPort = ntohs(tcpHeader->th_dport);
            info.protocol = PacketProtocolTCP;
        } else if (ipHeader->ip_p == IPPROTO_UDP && transportLength >= (int)sizeof(struct udphdr)) {
            struct udphdr *udpHeader = (struct udphdr *)transport;
            info.sourcePort = ntohs(udpHeader->uh_sport);
            info.destinationPort = ntohs(udpHeader->uh_dport);
            info.protocol = PacketProtocolUDP;
        } else if (ipHeader->ip_p == IPPROTO_ICMP) {
            info.protocol = PacketProtocolICMP;
        } else {
            info.protocol = PacketProtocolUnknown;
        }
    } else {
        info.protocol = PacketProtocolUnknown;
    }

    return info;
}

- (void)stopAllSessionsWithReply:(void (^)(void))reply {
    dispatch_async(self.managementQueue, ^{
        NSArray<SNBHelperCaptureSession *> *activeSessions = self.sessions.allValues;
        [self.sessions removeAllObjects];

        for (SNBHelperCaptureSession *session in activeSessions) {
            dispatch_sync(session.queue, ^{
                if (session.pcapHandle) {
                    pcap_close(session.pcapHandle);
                    session.pcapHandle = NULL;
                }
            });
        }

        if (reply) {
            reply();
        }
    });
}

@end

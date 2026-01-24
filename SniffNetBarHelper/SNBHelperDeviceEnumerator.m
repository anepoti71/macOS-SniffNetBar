//
//  SNBHelperDeviceEnumerator.m
//  SniffNetBarHelper
//

#import "SNBHelperDeviceEnumerator.h"
#import <pcap/pcap.h>
#import <ifaddrs.h>
#import <arpa/inet.h>

@implementation SNBHelperDeviceEnumerator

- (void)enumerateDevicesWithReply:(void (^)(NSArray<NSDictionary *> *devices, NSError *error))reply {
    NSMutableArray<NSDictionary *> *deviceDicts = [NSMutableArray array];
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_if_t *allDevs = NULL;
    if (pcap_findalldevs(&allDevs, errbuf) == -1) {
        NSError *error = [NSError errorWithDomain:@"SNBHelperDeviceEnumerator"
                                             code:1
                                         userInfo:@{NSLocalizedDescriptionKey:
                                                        [NSString stringWithUTF8String:errbuf]}];
        reply(@[], error);
        return;
    }

    NSMutableDictionary<NSString *, NSMutableArray<NSString *> *> *interfaceAddresses = [NSMutableDictionary dictionary];
    struct ifaddrs *interfaces;
    if (getifaddrs(&interfaces) == 0) {
        for (struct ifaddrs *interface = interfaces; interface != NULL; interface = interface->ifa_next) {
            if (!interface->ifa_addr) {
                continue;
            }

            NSString *ifName = [NSString stringWithUTF8String:interface->ifa_name];
            if (!ifName) {
                continue;
            }

            NSMutableArray<NSString *> *addresses = interfaceAddresses[ifName];
            if (!addresses) {
                addresses = [NSMutableArray array];
                interfaceAddresses[ifName] = addresses;
            }

            if (interface->ifa_addr->sa_family == AF_INET) {
                struct sockaddr_in *sin = (struct sockaddr_in *)interface->ifa_addr;
                char addr[INET_ADDRSTRLEN];
                if (inet_ntop(AF_INET, &sin->sin_addr, addr, INET_ADDRSTRLEN)) {
                    [addresses addObject:[NSString stringWithUTF8String:addr]];
                }
            } else if (interface->ifa_addr->sa_family == AF_INET6) {
                struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)interface->ifa_addr;
                char addr[INET6_ADDRSTRLEN];
                if (inet_ntop(AF_INET6, &sin6->sin6_addr, addr, INET6_ADDRSTRLEN)) {
                    [addresses addObject:[NSString stringWithUTF8String:addr]];
                }
            }
        }
        freeifaddrs(interfaces);
    }

    for (pcap_if_t *dev = allDevs; dev != NULL; dev = dev->next) {
        NSString *devName = [NSString stringWithUTF8String:dev->name];
        if (!devName) {
            continue;
        }

        NSString *devDesc = dev->description ? [NSString stringWithUTF8String:dev->description] : @"";
        NSArray<NSString *> *addresses = interfaceAddresses[devName] ?: @[];

        NSDictionary *deviceDict = @{
            @"name": devName,
            @"description": devDesc ?: @"",
            @"addresses": addresses ?: @[]
        };
        [deviceDicts addObject:deviceDict];
    }

    pcap_freealldevs(allDevs);
    reply([deviceDicts copy], nil);
}

@end

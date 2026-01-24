//
//  list_devices.m
//  Debug tool to list network devices
//

#import <Foundation/Foundation.h>
#import <ifaddrs.h>
#import <arpa/inet.h>

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        struct ifaddrs *interfaces = NULL;
        struct ifaddrs *temp_addr = NULL;

        if (getifaddrs(&interfaces) == 0) {
            temp_addr = interfaces;
            NSMutableDictionary *deviceMap = [NSMutableDictionary dictionary];

            while (temp_addr != NULL) {
                if (temp_addr->ifa_addr && temp_addr->ifa_addr->sa_family == AF_INET) {
                    NSString *name = [NSString stringWithUTF8String:temp_addr->ifa_name];
                    char addressBuffer[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &((struct sockaddr_in *)temp_addr->ifa_addr)->sin_addr, addressBuffer, INET_ADDRSTRLEN);
                    NSString *address = [NSString stringWithUTF8String:addressBuffer];

                    if (!deviceMap[name]) {
                        deviceMap[name] = [NSMutableArray array];
                    }
                    [deviceMap[name] addObject:address];
                }
                temp_addr = temp_addr->ifa_next;
            }
            freeifaddrs(interfaces);

            NSLog(@"Network Devices:");
            for (NSString *name in [deviceMap.allKeys sortedArrayUsingSelector:@selector(compare:)]) {
                NSLog(@"  %@ -> %@", name, [deviceMap[name] componentsJoinedByString:@", "]);
            }
        }

        // Check saved device
        NSArray *paths = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, YES);
        if (paths.count > 0) {
            NSString *plistPath = [[paths[0] stringByAppendingPathComponent:@"SniffNetBar"] stringByAppendingPathComponent:@"SelectedNetworkDevice.plist"];
            NSDictionary *saved = [NSDictionary dictionaryWithContentsOfFile:plistPath];
            if (saved) {
                NSLog(@"\nSaved device:");
                NSLog(@"  name: %@", saved[@"name"]);
                NSLog(@"  addresses: %@", [saved[@"addresses"] componentsJoinedByString:@", "]);
            } else {
                NSLog(@"\nNo saved device found");
            }
        }
    }
    return 0;
}

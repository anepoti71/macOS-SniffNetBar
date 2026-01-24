//
//  NetworkDevice.m
//  SniffNetBar
//
//  Represents a network interface/device
//

#import "NetworkDevice.h"
#import "SNBPrivilegedHelperClient.h"
#import "Logger.h"

@implementation NetworkDevice

- (instancetype)initWithName:(NSString *)name description:(NSString *)description addresses:(NSArray<NSString *> *)addresses {
    self = [super init];
    if (self) {
        _name = [name copy];
        _deviceDescription = description ? [description copy] : @"";
        _addresses = addresses ? [addresses copy] : @[];
    }
    return self;
}

+ (NSArray<NetworkDevice *> *)listAllDevices {
    __block NSArray<NetworkDevice *> *devices = @[];
    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);

    [[SNBPrivilegedHelperClient sharedClient] enumerateDevicesWithCompletion:^(NSArray<NetworkDevice *> *devs, NSError *error) {
        if (error) {
            SNBLogNetworkError("Error enumerating devices: %{public}s", error.localizedDescription.UTF8String);
        } else if (devs) {
            devices = devs;
        }
        dispatch_semaphore_signal(semaphore);
    }];

    dispatch_time_t timeout = dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC);
    long waitResult = dispatch_semaphore_wait(semaphore, timeout);
    if (waitResult != 0) {
        SNBLogNetworkWarn("Timeout waiting for device enumeration");
        return @[];
    }

    return devices;
}

+ (NetworkDevice *)defaultDevice {
    NSArray<NetworkDevice *> *allDevices = [self listAllDevices];
    if (allDevices.count > 0) {
        return allDevices.firstObject;
    }

    SNBLogNetworkWarn("No network devices available, returning placeholder");
    return [[NetworkDevice alloc] initWithName:@"(no device)"
                                   description:@"No network devices found"
                                     addresses:@[]];
}

- (NSString *)displayName {
    if (self.deviceDescription.length > 0) {
        return [NSString stringWithFormat:@"%@ (%@)", self.deviceDescription, self.name];
    }
    return self.name;
}

@end

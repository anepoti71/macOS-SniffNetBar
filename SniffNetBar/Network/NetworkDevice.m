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
    // The privileged helper may be restarting (e.g. after an app update replaced
    // its binary), which makes the first XPC call fail with "Couldn't communicate
    // with a helper application". Retry a few times before giving up.
    static const NSInteger kMaxAttempts = 3;
    for (NSInteger attempt = 1; attempt <= kMaxAttempts; attempt++) {
        __block NSArray<NetworkDevice *> *devices = @[];
        __block BOOL failed = NO;
        dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);

        [[SNBPrivilegedHelperClient sharedClient] enumerateDevicesWithCompletion:^(NSArray<NetworkDevice *> *devs, NSError *error) {
            if (error) {
                SNBLogNetworkError("Error enumerating devices (attempt %ld): %{public}s",
                                   (long)attempt, error.localizedDescription.UTF8String);
                failed = YES;
            } else if (devs) {
                devices = devs;
            }
            dispatch_semaphore_signal(semaphore);
        }];

        dispatch_time_t timeout = dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC);
        if (dispatch_semaphore_wait(semaphore, timeout) != 0) {
            SNBLogNetworkWarn("Timeout waiting for device enumeration");
            return @[];
        }
        if (!failed) {
            return devices;
        }
        if (attempt < kMaxAttempts) {
            [NSThread sleepForTimeInterval:1.0];
        }
    }
    return @[];
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

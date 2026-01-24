//
//  DeviceManager.m
//  SniffNetBar
//

#import "DeviceManager.h"
#import "ConfigurationManager.h"
#import "NetworkDevice.h"
#import "PacketCaptureManager.h"
#import "UserDefaultsKeys.h"
#import "Logger.h"
#import <math.h>

static NSString *SNBSelectedDeviceStorageDirectory(void) {
    NSArray<NSString *> *paths = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory,
                                                                      NSUserDomainMask,
                                                                      YES);
    if (paths.count == 0) {
        return nil;
    }
    NSString *directory = [paths.firstObject stringByAppendingPathComponent:@"SniffNetBar"];
    return directory;
}

static NSString *SNBSelectedDeviceStoragePath(void) {
    NSString *directory = SNBSelectedDeviceStorageDirectory();
    if (directory.length == 0) {
        return nil;
    }
    return [directory stringByAppendingPathComponent:@"SelectedNetworkDevice.plist"];
}

static void SNBSynchronizeSelectedDeviceStorageDirectory(void) {
    NSString *directory = SNBSelectedDeviceStorageDirectory();
    if (directory.length == 0) {
        return;
    }
    [[NSFileManager defaultManager] createDirectoryAtPath:directory
                              withIntermediateDirectories:YES
                                               attributes:nil
                                                    error:nil];
}

static NSDictionary<NSString *, id> *SNBLoadSavedDeviceInfo(void) {
    NSString *path = SNBSelectedDeviceStoragePath();
    NSDictionary<NSString *, id> *stored = nil;
    if (path.length > 0) {
        stored = [NSDictionary dictionaryWithContentsOfFile:path];
    }

    NSString *savedName = stored[@"name"];
    NSArray<NSString *> *addresses = stored[@"addresses"];
    if (savedName.length == 0 && (!addresses || addresses.count == 0)) {
        NSString *defaultsName = [[NSUserDefaults standardUserDefaults] stringForKey:SNBUserDefaultsKeySelectedNetworkDevice];
        if (defaultsName.length > 0) {
            return @{@"name": defaultsName};
        }
        return nil;
    }

    NSMutableDictionary<NSString *, id> *info = [NSMutableDictionary dictionary];
    if (savedName.length > 0) {
        info[@"name"] = savedName;
        [[NSUserDefaults standardUserDefaults] setObject:savedName forKey:SNBUserDefaultsKeySelectedNetworkDevice];
    }
    if (addresses) {
        info[@"addresses"] = [addresses copy];
    }
    return [info copy];
}

static BOOL SNBSaveSelectedDeviceInfo(NetworkDevice *device) {
    if (!device || device.name.length == 0) {
        return NO;
    }

    NSString *name = device.name;
    NSArray<NSString *> *addresses = device.addresses ?: @[];
    SNBSynchronizeSelectedDeviceStorageDirectory();
    NSString *path = SNBSelectedDeviceStoragePath();
    if (path.length == 0) {
        return NO;
    }

    NSDictionary *info = @{@"name": name,
                           @"addresses": addresses};
    BOOL success = [info writeToFile:path atomically:YES];
    if (success) {
        [[NSUserDefaults standardUserDefaults] setObject:name forKey:SNBUserDefaultsKeySelectedNetworkDevice];
    }
    return success;
}

@interface DeviceManager ()
@property (nonatomic, strong) ConfigurationManager *configuration;
@property (nonatomic, strong, readwrite) PacketCaptureManager *packetManager;
@property (nonatomic, strong, readwrite) NSArray<NetworkDevice *> *availableDevices;
@property (nonatomic, assign) NSUInteger reconnectAttempts;
@end

@implementation DeviceManager

- (instancetype)initWithPacketManager:(PacketCaptureManager *)packetManager
                        configuration:(ConfigurationManager *)configuration {
    self = [super init];
    if (self) {
        _packetManager = packetManager;
        _configuration = configuration;
        _availableDevices = @[];
    }
    return self;
}

- (void)loadAvailableDevices {
    self.availableDevices = [NetworkDevice listAllDevices];
    if (self.availableDevices.count == 0) {
        SNBLogNetworkWarn("No network devices found");
    }
}

- (void)restoreSelectedDevice {
    NSDictionary<NSString *, id> *savedInfo = SNBLoadSavedDeviceInfo();
    NSString *savedDeviceName = savedInfo[@"name"];
    NSSet<NSString *> *savedAddresses = savedInfo[@"addresses"] ? [NSSet setWithArray:savedInfo[@"addresses"]] : nil;

    // Log all available devices for debugging
    SNBLogNetworkInfo("Available devices: %lu", (unsigned long)self.availableDevices.count);
    for (NetworkDevice *d in self.availableDevices) {
        SNBLogNetworkInfo("  - %{public}@ (addresses: %{public}@)", d.name, [d.addresses componentsJoinedByString:@", "]);
    }

    if (savedDeviceName.length > 0 || savedAddresses.count > 0) {
        SNBLogNetworkInfo("Attempting to restore saved device: %{public}@ (addresses: %{public}@)",
                          savedDeviceName ?: @"<unknown>",
                          savedAddresses.count > 0 ? [[savedAddresses allObjects] componentsJoinedByString:@", "] : @"none");

        // First try: exact name match (most reliable)
        if (savedDeviceName.length > 0) {
            for (NetworkDevice *device in self.availableDevices) {
                if ([device.name isEqualToString:savedDeviceName]) {
                    self.selectedDevice = device;
                    SNBLogNetworkInfo("Successfully restored device: %{public}@ (matched by name)", device.name);
                    return;
                }
            }
        }

        // Second try: address match (for devices that changed names but kept IPs)
        if (savedAddresses.count > 0) {
            for (NetworkDevice *device in self.availableDevices) {
                if (device.addresses.count > 0) {
                    NSSet<NSString *> *deviceAddresses = [NSSet setWithArray:device.addresses];
                    if ([savedAddresses intersectsSet:deviceAddresses]) {
                        self.selectedDevice = device;
                        SNBLogNetworkInfo("Successfully restored device: %{public}@ (matched by address, was: %{public}@)",
                                          device.name, savedDeviceName ?: @"<unknown>");
                        // Update saved name to new name
                        [self saveSelectedDevice];
                        return;
                    }
                }
            }
        }

        SNBLogNetworkWarn("Saved device '%{public}@' not found in available devices, falling back to default",
                          savedDeviceName ?: @"<unknown>");
    } else {
        SNBLogNetworkInfo("No saved device found, using default device");
    }

    self.selectedDevice = [NetworkDevice defaultDevice];

    // Save the default device so next launch uses the same device
    if (self.selectedDevice) {
        SNBLogNetworkInfo("Saving default device: %{public}@", self.selectedDevice.name);
        [self saveSelectedDevice];
    }
}

- (void)saveSelectedDevice {
    if (self.selectedDevice) {
        NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
        [defaults setObject:self.selectedDevice.name forKey:SNBUserDefaultsKeySelectedNetworkDevice];
        [defaults synchronize];
        SNBLogNetworkInfo("Saved selected device to UserDefaults: %{public}@", self.selectedDevice.name);
        if (SNBSaveSelectedDeviceInfo(self.selectedDevice)) {
            SNBLogNetworkInfo("Persisted selected device to Application Support storage");
        } else {
            SNBLogNetworkWarn("Failed to persist selected device to storage");
        }
    }
}

- (BOOL)startCaptureWithError:(NSError **)error {
    if (!self.selectedDevice || [self.selectedDevice.name isEqualToString:@"(no device)"]) {
        [self loadAvailableDevices];
        self.selectedDevice = [NetworkDevice defaultDevice];
    }

    if (!self.selectedDevice || [self.selectedDevice.name isEqualToString:@"(no device)"]) {
        SNBLogNetworkError("No valid network device available for capture");
        if (error) {
            *error = [NSError errorWithDomain:@"DeviceManager"
                                         code:1
                                     userInfo:@{NSLocalizedDescriptionKey: @"No valid network device available"}];
        }
        return NO;
    }

    NSError *startError = nil;
    if (![self.packetManager startCaptureWithDeviceName:self.selectedDevice.name error:&startError]) {
        SNBLogNetworkError("Failed to start packet capture: %{public}@", startError.localizedDescription);
        if (error) {
            *error = startError;
        }
        [self scheduleReconnection];
        return NO;
    }

    self.reconnectAttempts = 0;

    // Set up error callback to handle capture failures
    __weak typeof(self) weakSelf = self;
    self.packetManager.onCaptureError = ^(NSError *captureError) {
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (strongSelf) {
            SNBLogNetworkWarn("Capture error occurred: %{public}@", captureError.localizedDescription);
            [strongSelf handleCaptureFailure:captureError];
        }
    };

    return YES;
}

- (void)handleCaptureFailure:(NSError *)error {
    SNBLogNetworkWarn("Handling capture failure, will attempt reconnection");
    [self scheduleReconnection];
}

- (void)attemptReconnection {
    SNBLogNetworkInfo("Attempting to reconnect to device: %{public}@", self.selectedDevice.name);
    [self refreshDeviceList];
    [self startCaptureWithError:nil];
}

- (void)scheduleReconnection {
    ConfigurationManager *config = self.configuration;
    if (self.reconnectAttempts < config.maxReconnectAttempts) {
        self.reconnectAttempts++;

        // Calculate exponential backoff delay: baseDelay * 2^(attempt-1)
        // Capped at 60 seconds maximum
        NSTimeInterval exponentialDelay = config.reconnectDelay * pow(2, self.reconnectAttempts - 1);
        exponentialDelay = MIN(exponentialDelay, 60.0);

        SNBLogNetworkWarn("Scheduling reconnection attempt %lu of %lu in %.1f seconds (exponential backoff)",
                          (unsigned long)self.reconnectAttempts,
                          (unsigned long)config.maxReconnectAttempts,
                          exponentialDelay);

        __weak typeof(self) weakSelf = self;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(exponentialDelay * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            [weakSelf attemptReconnection];
        });
    } else {
        SNBLogNetworkError("Maximum reconnection attempts reached. Manual intervention required.");
    }
}

- (void)refreshDeviceList {
    NSArray<NetworkDevice *> *previousDevices = self.availableDevices;
    [self loadAvailableDevices];

    if (previousDevices.count != self.availableDevices.count) {
        SNBLogNetworkInfo("Device list changed: %lu -> %lu devices",
                          (unsigned long)previousDevices.count,
                          (unsigned long)self.availableDevices.count);
    }

    BOOL deviceStillAvailable = NO;
    for (NetworkDevice *device in self.availableDevices) {
        if ([device.name isEqualToString:self.selectedDevice.name]) {
            deviceStillAvailable = YES;
            break;
        }
    }

    if (!deviceStillAvailable && self.selectedDevice) {
        SNBLogNetworkWarn("Currently selected device '%{public}@' is no longer available", self.selectedDevice.name);
    }
}

- (BOOL)selectDevice:(NetworkDevice *)device error:(NSError **)error {
    if (!device || [device.name isEqualToString:self.selectedDevice.name]) {
        return NO;
    }

    SNBLogNetworkInfo("User selected device: %{public}@ (previous: %{public}@)",
                      device.name, self.selectedDevice.name ?: @"none");
    self.selectedDevice = device;
    [self saveSelectedDevice];
    [self startCaptureWithError:error];
    return YES;
}

@end

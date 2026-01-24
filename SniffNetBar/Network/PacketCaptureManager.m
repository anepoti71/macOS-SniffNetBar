//
//  PacketCaptureManager.m
//  SniffNetBar
//
//  Packet capture manager using privileged helper via XPC
//

#import "PacketCaptureManager.h"
#import "PacketInfo.h"
#import "NetworkDevice.h"
#import "SNBPrivilegedHelperClient.h"
#import "Logger.h"
#import "ConfigurationManager.h"

@interface PacketCaptureManager ()
@property (nonatomic, assign) BOOL isCapturing;
@property (nonatomic, strong) dispatch_queue_t captureQueue;
@property (nonatomic, strong, readwrite) NSString *currentDeviceName;
@property (nonatomic, strong, readwrite) NSDate *captureStartDate;
@property (nonatomic, strong) NSString *sessionID;
@property (nonatomic, strong) dispatch_source_t pollingTimer;  // Use dispatch_source for background polling
@property (nonatomic, strong) ConfigurationManager *configuration;
@end

@implementation PacketCaptureManager

static const NSTimeInterval kCaptureStartTimeoutSeconds = 5.0;

- (instancetype)init {
    self = [super init];
    if (self) {
        _captureQueue = dispatch_queue_create("com.sniffnetbar.capture", DISPATCH_QUEUE_SERIAL);
        _isCapturing = NO;
        _configuration = [ConfigurationManager sharedManager];
    }
    return self;
}

- (void)dealloc {
    [self stopCapture];
}

- (BOOL)startCaptureWithError:(NSError **)error {
    __block NSString *defaultDevice = nil;
    __block NSError *deviceError = nil;
    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);

    [[SNBPrivilegedHelperClient sharedClient] enumerateDevicesWithCompletion:^(NSArray<NetworkDevice *> *devices, NSError *err) {
        if (err || devices.count == 0) {
            deviceError = err ?: [NSError errorWithDomain:@"PacketCaptureError"
                                                     code:1
                                                 userInfo:@{NSLocalizedDescriptionKey: @"No devices available"}];
        } else {
            defaultDevice = devices.firstObject.name;
        }
        dispatch_semaphore_signal(semaphore);
    }];

    dispatch_time_t timeout = dispatch_time(DISPATCH_TIME_NOW,
                                            (int64_t)(kCaptureStartTimeoutSeconds * NSEC_PER_SEC));
    if (dispatch_semaphore_wait(semaphore, timeout) != 0) {
        if (error) {
            *error = [NSError errorWithDomain:@"PacketCaptureError"
                                         code:1
                                     userInfo:@{NSLocalizedDescriptionKey: @"Timeout while enumerating devices"}];
        }
        return NO;
    }

    if (deviceError) {
        if (error) {
            *error = deviceError;
        }
        return NO;
    }

    return [self startCaptureWithDeviceName:defaultDevice error:error];
}

- (BOOL)startCaptureWithDeviceName:(NSString *)deviceName error:(NSError **)error {
    if (self.isCapturing) {
        [self stopCapture];
    }

    if (!deviceName || deviceName.length == 0) {
        if (error) {
            *error = [NSError errorWithDomain:@"PacketCaptureError"
                                         code:1
                                     userInfo:@{NSLocalizedDescriptionKey: @"Invalid device name"}];
        }
        return NO;
    }

    __block BOOL success = NO;
    __block NSError *startError = nil;
    __block NSString *newSessionID = nil;
    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);

    [[SNBPrivilegedHelperClient sharedClient] startCaptureOnDevice:deviceName
                                                        completion:^(NSString *sessionID, NSError *err) {
        if (err) {
            startError = err;
        } else if (sessionID) {
            newSessionID = sessionID;
            success = YES;
        } else {
            startError = [NSError errorWithDomain:@"PacketCaptureError"
                                             code:2
                                         userInfo:@{NSLocalizedDescriptionKey: @"Failed to start capture"}];
        }
        dispatch_semaphore_signal(semaphore);
    }];

    dispatch_time_t timeout = dispatch_time(DISPATCH_TIME_NOW,
                                            (int64_t)(kCaptureStartTimeoutSeconds * NSEC_PER_SEC));
    if (dispatch_semaphore_wait(semaphore, timeout) != 0) {
        if (error) {
            *error = [NSError errorWithDomain:@"PacketCaptureError"
                                         code:2
                                     userInfo:@{NSLocalizedDescriptionKey: @"Timeout while starting capture"}];
        }
        return NO;
    }

    if (!success) {
        if (error) {
            *error = startError;
        }
        return NO;
    }

    self.sessionID = newSessionID;
    self.currentDeviceName = deviceName;
    self.isCapturing = YES;
    self.captureStartDate = [NSDate date];

    SNBLogInfo("Capture started with session ID: %{public}@", self.sessionID);
    [self startPollingForPackets];
    return YES;
}

- (void)stopCapture {
    if (!self.isCapturing) {
        return;
    }

    self.isCapturing = NO;
    self.captureStartDate = nil;

    if (self.pollingTimer) {
        dispatch_source_cancel(self.pollingTimer);
        self.pollingTimer = nil;
    }

    if (self.sessionID) {
        [[SNBPrivilegedHelperClient sharedClient] stopCaptureForSession:self.sessionID
                                                             completion:^(NSError *error) {
            if (error) {
                SNBLogWarn("Error stopping capture: %{public}@", error.localizedDescription);
            }
        }];
        self.sessionID = nil;
    }
}

- (void)startPollingForPackets {
    // Cancel any existing timer
    if (self.pollingTimer) {
        dispatch_source_cancel(self.pollingTimer);
        self.pollingTimer = nil;
    }

    __weak typeof(self) weakSelf = self;
    NSTimeInterval pollingInterval = self.configuration.packetPollingInterval;

    // Performance: Use dispatch_source on background queue instead of main thread NSTimer
    // This prevents UI blocking during high packet rates
    dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, self.captureQueue);
    uint64_t intervalNanos = (uint64_t)(pollingInterval * NSEC_PER_SEC);
    uint64_t leewayNanos = (uint64_t)(pollingInterval * 0.1 * NSEC_PER_SEC);  // 10% leeway for power efficiency

    dispatch_source_set_timer(timer,
                              dispatch_time(DISPATCH_TIME_NOW, intervalNanos),
                              intervalNanos,
                              leewayNanos);

    dispatch_source_set_event_handler(timer, ^{
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (strongSelf && strongSelf.isCapturing) {
            [strongSelf pollNextPacket];
        }
    });

    self.pollingTimer = timer;
    dispatch_resume(timer);
}

- (void)pollNextPacket {
    if (!self.isCapturing || !self.sessionID) {
        return;
    }

    [[SNBPrivilegedHelperClient sharedClient] getNextPacketForSession:self.sessionID
                                                           completion:^(PacketInfo *packet, NSError *error) {
        if (error) {
            SNBLogWarn("Error getting packet: %{public}@", error.localizedDescription);
            if (self.onCaptureError) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    self.onCaptureError(error);
                });
            }
            return;
        }

        if (packet && self.onPacketReceived) {
            dispatch_async(self.captureQueue, ^{
                self.onPacketReceived(packet);
            });
        }
    }];
}

@end

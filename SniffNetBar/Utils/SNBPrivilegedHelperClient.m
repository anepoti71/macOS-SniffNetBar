//
//  SNBPrivilegedHelperClient.m
//  SniffNetBar
//

#import "SNBPrivilegedHelperClient.h"
#import "../XPC/SNBPrivilegedHelperProtocol.h"
#import "NetworkDevice.h"
#import "../XPC/NetworkDevice+Serialization.h"
#import "ProcessLookup.h"
#import "../XPC/ProcessInfo+Serialization.h"
#import "PacketInfo.h"
#import "../XPC/PacketInfo+Serialization.h"
#import "Logger.h"

@interface SNBPrivilegedHelperClient ()
@property (nonatomic, strong) NSXPCConnection *connection;
@property (nonatomic, strong) dispatch_queue_t connectionQueue;
@property (nonatomic, assign) BOOL isConnecting;
@end

@implementation SNBPrivilegedHelperClient

static void SNBConfigureHelperInterface(NSXPCInterface *interface) {
    NSSet *stringClasses = [NSSet setWithObjects:[NSString class], nil];
    NSSet *sessionReplyClasses = [NSSet setWithObjects:[NSString class], [NSError class], nil];
    NSSet *errorClasses = [NSSet setWithObjects:[NSError class], nil];
    NSSet *packetDictClasses = [NSSet setWithObjects:[NSDictionary class], [NSString class], [NSNumber class], nil];
    NSSet *processDictClasses = [NSSet setWithObjects:[NSDictionary class], [NSString class], [NSNumber class], nil];
    NSSet *deviceArrayClasses = [NSSet setWithObjects:[NSArray class], [NSDictionary class], [NSString class], nil];

    [interface setClasses:stringClasses
              forSelector:@selector(getVersionWithReply:)
            argumentIndex:0
                  ofReply:YES];

    [interface setClasses:deviceArrayClasses
              forSelector:@selector(enumerateNetworkDevicesWithReply:)
            argumentIndex:0
                  ofReply:YES];
    [interface setClasses:errorClasses
              forSelector:@selector(enumerateNetworkDevicesWithReply:)
            argumentIndex:1
                  ofReply:YES];

    [interface setClasses:stringClasses
              forSelector:@selector(startCaptureOnDevice:withReply:)
            argumentIndex:0
                  ofReply:NO];
    [interface setClasses:sessionReplyClasses
              forSelector:@selector(startCaptureOnDevice:withReply:)
            argumentIndex:0
                  ofReply:YES];
    [interface setClasses:errorClasses
              forSelector:@selector(startCaptureOnDevice:withReply:)
            argumentIndex:1
                  ofReply:YES];

    [interface setClasses:stringClasses
              forSelector:@selector(stopCaptureForSession:withReply:)
            argumentIndex:0
                  ofReply:NO];
    [interface setClasses:errorClasses
              forSelector:@selector(stopCaptureForSession:withReply:)
            argumentIndex:0
                  ofReply:YES];

    [interface setClasses:stringClasses
              forSelector:@selector(getNextPacketForSession:withReply:)
            argumentIndex:0
                  ofReply:NO];
    [interface setClasses:packetDictClasses
              forSelector:@selector(getNextPacketForSession:withReply:)
            argumentIndex:0
                  ofReply:YES];
    [interface setClasses:errorClasses
              forSelector:@selector(getNextPacketForSession:withReply:)
            argumentIndex:1
                  ofReply:YES];

    [interface setClasses:stringClasses
              forSelector:@selector(lookupProcessWithSourceAddress:sourcePort:destinationAddress:destinationPort:withReply:)
            argumentIndex:0
                  ofReply:NO];
    [interface setClasses:[NSSet setWithObjects:[NSNumber class], nil]
              forSelector:@selector(lookupProcessWithSourceAddress:sourcePort:destinationAddress:destinationPort:withReply:)
            argumentIndex:1
                  ofReply:NO];
    [interface setClasses:stringClasses
              forSelector:@selector(lookupProcessWithSourceAddress:sourcePort:destinationAddress:destinationPort:withReply:)
            argumentIndex:2
                  ofReply:NO];
    [interface setClasses:[NSSet setWithObjects:[NSNumber class], nil]
              forSelector:@selector(lookupProcessWithSourceAddress:sourcePort:destinationAddress:destinationPort:withReply:)
            argumentIndex:3
                  ofReply:NO];
    [interface setClasses:processDictClasses
              forSelector:@selector(lookupProcessWithSourceAddress:sourcePort:destinationAddress:destinationPort:withReply:)
            argumentIndex:0
                  ofReply:YES];
    [interface setClasses:errorClasses
              forSelector:@selector(lookupProcessWithSourceAddress:sourcePort:destinationAddress:destinationPort:withReply:)
            argumentIndex:1
                  ofReply:YES];
}

+ (instancetype)sharedClient {
    static SNBPrivilegedHelperClient *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[self alloc] init];
    });
    return instance;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _connectionQueue = dispatch_queue_create("com.sniffnetbar.helperclient", DISPATCH_QUEUE_SERIAL);
        _isConnecting = NO;
    }
    return self;
}

- (void)dealloc {
    [self disconnect];
}

- (void)connectToHelper {
    dispatch_async(self.connectionQueue, ^{
        if (self.connection || self.isConnecting) {
            return;
        }

        self.isConnecting = YES;
        [self createConnection];
        self.isConnecting = NO;
    });
}

- (void)disconnect {
    dispatch_sync(self.connectionQueue, ^{
        if (self.connection) {
            [self.connection invalidate];
            self.connection = nil;
        }
    });
}

- (BOOL)isConnected {
    __block BOOL connected = NO;
    dispatch_sync(self.connectionQueue, ^{
        connected = self.connection != nil;
    });
    return connected;
}

- (id<SNBPrivilegedHelperProtocol>)helperProxy {
    __block id<SNBPrivilegedHelperProtocol> proxy = nil;
    dispatch_sync(self.connectionQueue, ^{
        if (!self.connection) {
            [self createConnection];
            if (!self.connection) {
                SNBLogError("No helper connection available");
                return;
            }
        }
        proxy = [self.connection remoteObjectProxyWithErrorHandler:^(NSError *error) {
            SNBLogError("Helper proxy error: %{public}s", error.localizedDescription.UTF8String);
        }];
    });
    return proxy;
}

- (id<SNBPrivilegedHelperProtocol>)helperProxyWithErrorHandler:(void (^)(NSError *error))errorHandler {
    __block id<SNBPrivilegedHelperProtocol> proxy = nil;
    dispatch_sync(self.connectionQueue, ^{
        if (!self.connection) {
            [self createConnection];
            if (!self.connection) {
                SNBLogError("No helper connection available");
                return;
            }
        }
        proxy = [self.connection remoteObjectProxyWithErrorHandler:^(NSError *error) {
            SNBLogError("Helper proxy error: %{public}s", error.localizedDescription.UTF8String);
            if (errorHandler) {
                errorHandler(error);
            }
        }];
    });
    return proxy;
}

- (void)createConnection {
    SNBLogInfo("Connecting to privileged helper...");

    self.connection = [[NSXPCConnection alloc] initWithMachServiceName:kSNBPrivilegedHelperMachServiceName
                                                                options:NSXPCConnectionPrivileged];
    NSXPCInterface *interface = [NSXPCInterface interfaceWithProtocol:@protocol(SNBPrivilegedHelperProtocol)];
    SNBConfigureHelperInterface(interface);
    self.connection.remoteObjectInterface = interface;

    __weak typeof(self) weakSelf = self;
    self.connection.invalidationHandler = ^{
        SNBLogWarn("Helper connection invalidated");
        dispatch_async(weakSelf.connectionQueue, ^{
            weakSelf.connection = nil;
            weakSelf.isConnecting = NO;
        });
    };

    self.connection.interruptionHandler = ^{
        SNBLogWarn("Helper connection interrupted");
        dispatch_async(weakSelf.connectionQueue, ^{
            [weakSelf.connection invalidate];
            weakSelf.connection = nil;
            weakSelf.isConnecting = NO;
        });
    };

    [self.connection resume];
}

- (void)getVersionWithCompletion:(void (^)(NSString * _Nullable, NSError * _Nullable))completion {
    __block BOOL completed = NO;
    id<SNBPrivilegedHelperProtocol> helper = [self helperProxyWithErrorHandler:^(NSError *error) {
        if (completed) {
            return;
        }
        completed = YES;
        if (completion) {
            completion(nil, error);
        }
    }];
    if (!helper) {
        if (completion) {
            NSError *error = [NSError errorWithDomain:@"SNBHelperClient"
                                                 code:1
                                             userInfo:@{NSLocalizedDescriptionKey: @"Helper not connected"}];
            completion(nil, error);
        }
        return;
    }

    [helper getVersionWithReply:^(NSString *version) {
        if (completed) {
            return;
        }
        completed = YES;
        if (completion) {
            completion(version, nil);
        }
    }];
}

- (void)enumerateDevicesWithCompletion:(void (^)(NSArray<NetworkDevice *> *, NSError *))completion {
    __block BOOL completed = NO;
    id<SNBPrivilegedHelperProtocol> helper = [self helperProxyWithErrorHandler:^(NSError *error) {
        if (completed) {
            return;
        }
        completed = YES;
        if (completion) {
            completion(nil, error);
        }
    }];
    if (!helper) {
        if (completion) {
            NSError *error = [NSError errorWithDomain:@"SNBHelperClient"
                                                 code:1
                                             userInfo:@{NSLocalizedDescriptionKey: @"Helper not connected"}];
            completion(nil, error);
        }
        return;
    }

    [helper enumerateNetworkDevicesWithReply:^(NSArray<NSDictionary *> *devices, NSError *error) {
        if (completed) {
            return;
        }
        completed = YES;
        if (error) {
            if (completion) {
                completion(nil, error);
            }
            return;
        }

        NSMutableArray<NetworkDevice *> *deviceObjects = [NSMutableArray array];
        for (NSDictionary *dict in devices) {
            NetworkDevice *device = [NetworkDevice fromDictionary:dict];
            if (device) {
                [deviceObjects addObject:device];
            }
        }

        if (completion) {
            completion([deviceObjects copy], nil);
        }
    }];
}

- (void)startCaptureOnDevice:(NSString *)deviceName
                  completion:(void (^)(NSString * _Nullable, NSError * _Nullable))completion {
    __block BOOL completed = NO;
    id<SNBPrivilegedHelperProtocol> helper = [self helperProxyWithErrorHandler:^(NSError *error) {
        if (completed) {
            return;
        }
        completed = YES;
        if (completion) {
            completion(nil, error);
        }
    }];
    if (!helper) {
        if (completion) {
            NSError *error = [NSError errorWithDomain:@"SNBHelperClient"
                                                 code:1
                                             userInfo:@{NSLocalizedDescriptionKey: @"Helper not connected"}];
            completion(nil, error);
        }
        return;
    }

    [helper startCaptureOnDevice:deviceName withReply:^(NSString *sessionID, NSError *error) {
        if (completed) {
            return;
        }
        completed = YES;
        if (completion) {
            completion(sessionID, error);
        }
    }];
}

- (void)stopCaptureForSession:(NSString *)sessionID
                   completion:(void (^)(NSError * _Nullable))completion {
    __block BOOL completed = NO;
    id<SNBPrivilegedHelperProtocol> helper = [self helperProxyWithErrorHandler:^(NSError *error) {
        if (completed) {
            return;
        }
        completed = YES;
        if (completion) {
            completion(error);
        }
    }];
    if (!helper) {
        if (completion) {
            NSError *error = [NSError errorWithDomain:@"SNBHelperClient"
                                                 code:1
                                             userInfo:@{NSLocalizedDescriptionKey: @"Helper not connected"}];
            completion(error);
        }
        return;
    }

    [helper stopCaptureForSession:sessionID withReply:^(NSError *error) {
        if (completed) {
            return;
        }
        completed = YES;
        if (completion) {
            completion(error);
        }
    }];
}

- (void)getNextPacketForSession:(NSString *)sessionID
                     completion:(void (^)(PacketInfo * _Nullable, NSError * _Nullable))completion {
    __block BOOL completed = NO;
    id<SNBPrivilegedHelperProtocol> helper = [self helperProxyWithErrorHandler:^(NSError *error) {
        if (completed) {
            return;
        }
        completed = YES;
        if (completion) {
            completion(nil, error);
        }
    }];
    if (!helper) {
        if (completion) {
            completion(nil, nil);
        }
        return;
    }

    [helper getNextPacketForSession:sessionID withReply:^(NSDictionary *packetInfo, NSError *error) {
        if (completed) {
            return;
        }
        completed = YES;
        if (error) {
            if (completion) {
                completion(nil, error);
            }
            return;
        }

        if (!packetInfo) {
            if (completion) {
                completion(nil, nil);
            }
            return;
        }

        PacketInfo *packet = [PacketInfo fromDictionary:packetInfo];
        if (completion) {
            completion(packet, nil);
        }
    }];
}

- (void)lookupProcessWithSourceAddress:(NSString *)sourceAddress
                            sourcePort:(NSInteger)sourcePort
                       destinationAddr:(NSString *)destinationAddr
                       destinationPort:(NSInteger)destinationPort
                            completion:(void (^)(ProcessInfo * _Nullable, NSError * _Nullable))completion {
    __block BOOL completed = NO;
    id<SNBPrivilegedHelperProtocol> helper = [self helperProxyWithErrorHandler:^(NSError *error) {
        if (completed) {
            return;
        }
        completed = YES;
        if (completion) {
            completion(nil, error);
        }
    }];
    if (!helper) {
        if (completion) {
            completion(nil, nil);
        }
        return;
    }

    [helper lookupProcessWithSourceAddress:sourceAddress
                                sourcePort:sourcePort
                        destinationAddress:destinationAddr
                           destinationPort:destinationPort
                                 withReply:^(NSDictionary *processInfo, NSError *error) {
        if (completed) {
            return;
        }
        completed = YES;
        if (error) {
            if (completion) {
                completion(nil, error);
            }
            return;
        }

        if (!processInfo) {
            if (completion) {
                completion(nil, nil);
            }
            return;
        }

        ProcessInfo *info = [ProcessInfo fromDictionary:processInfo];
        if (completion) {
            completion(info, nil);
        }
    }];
}

@end

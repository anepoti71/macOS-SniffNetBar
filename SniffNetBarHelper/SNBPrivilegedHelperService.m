//
//  SNBPrivilegedHelperService.m
//  SniffNetBarHelper
//
//  XPC service listener for privileged helper tool
//

#import "SNBPrivilegedHelperService.h"
#import <Security/Security.h>
#import "SNBHelperPacketCapture.h"
#import "SNBHelperProcessLookup.h"
#import "SNBHelperDeviceEnumerator.h"

#import "../SniffNetBar/XPC/SNBPrivilegedHelperProtocol.h"

#define kSNBPrivilegedHelperVersion @"1.0"

@interface SNBPrivilegedHelperService () <NSXPCListenerDelegate, SNBPrivilegedHelperProtocol>

@property (nonatomic, strong) NSXPCListener *listener;
@property (nonatomic, strong) SNBHelperPacketCapture *packetCapture;
@property (nonatomic, strong) SNBHelperProcessLookup *processLookup;
@property (nonatomic, strong) SNBHelperDeviceEnumerator *deviceEnumerator;
@property (nonatomic, copy) NSString *teamIdentifier;

@end

@implementation SNBPrivilegedHelperService

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

static NSString *SNBTeamIdentifierForSelf(void) {
    SecCodeRef selfCode = NULL;
    OSStatus status = SecCodeCopySelf(kSecCSDefaultFlags, &selfCode);
    if (status != errSecSuccess || !selfCode) {
        return nil;
    }

    CFDictionaryRef signingInfo = NULL;
    status = SecCodeCopySigningInformation(selfCode, kSecCSSigningInformation, &signingInfo);
    CFRelease(selfCode);
    if (status != errSecSuccess || !signingInfo) {
        if (signingInfo) {
            CFRelease(signingInfo);
        }
        return nil;
    }

    NSString *teamID = [(__bridge NSDictionary *)signingInfo objectForKey:(__bridge id)kSecCodeInfoTeamIdentifier];
    CFRelease(signingInfo);
    return teamID;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _listener = [[NSXPCListener alloc] initWithMachServiceName:kSNBPrivilegedHelperMachServiceName];
        _listener.delegate = self;
        _packetCapture = [[SNBHelperPacketCapture alloc] init];
        _processLookup = [[SNBHelperProcessLookup alloc] init];
        _deviceEnumerator = [[SNBHelperDeviceEnumerator alloc] init];
        _teamIdentifier = SNBTeamIdentifierForSelf();
    }
    return self;
}

- (void)run {
    NSLog(@"SniffNetBarHelper starting (version %@)", kSNBPrivilegedHelperVersion);
    NSLog(@"Helper running as UID: %d", getuid());

    [self.listener resume];
    [[NSRunLoop currentRunLoop] run];
}

#pragma mark - NSXPCListenerDelegate

- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
    NSLog(@"Helper: Received new XPC connection from PID %d", newConnection.processIdentifier);

    if (![self validateConnection:newConnection]) {
        NSLog(@"Helper: Connection validation failed, rejecting");
        return NO;
    }

    [self.packetCapture stopAllSessionsWithReply:^{
        NSLog(@"Helper: Cleared existing capture sessions for new connection");
    }];

    NSXPCInterface *interface = [NSXPCInterface interfaceWithProtocol:@protocol(SNBPrivilegedHelperProtocol)];
    SNBConfigureHelperInterface(interface);
    newConnection.exportedInterface = interface;
    newConnection.exportedObject = self;

    newConnection.invalidationHandler = ^{
        NSLog(@"Helper: Connection invalidated");
        [self.packetCapture stopAllSessionsWithReply:^{
            NSLog(@"Helper: Cleared capture sessions after invalidation");
        }];
    };

    newConnection.interruptionHandler = ^{
        NSLog(@"Helper: Connection interrupted");
        [self.packetCapture stopAllSessionsWithReply:^{
            NSLog(@"Helper: Cleared capture sessions after interruption");
        }];
    };

    [newConnection resume];
    NSLog(@"Helper: Connection accepted and resumed");
    return YES;
}

#pragma mark - Connection Validation

- (BOOL)validateConnection:(NSXPCConnection *)connection {
    pid_t pid = connection.processIdentifier;
    NSDictionary *attributes = @{(__bridge id)kSecGuestAttributePid: @(pid)};
    SecCodeRef code = NULL;
    OSStatus status = SecCodeCopyGuestWithAttributes(NULL,
                                                     (__bridge CFDictionaryRef)attributes,
                                                     kSecCSDefaultFlags,
                                                     &code);
    if (status != errSecSuccess) {
        NSLog(@"Helper: Failed to create SecCode from pid: %d", status);
        return NO;
    }

    status = SecCodeCheckValidity(code, kSecCSDefaultFlags, NULL);
    if (status != errSecSuccess) {
        NSLog(@"Helper: Code signature validation failed: %d", status);
        CFRelease(code);
        return NO;
    }

    CFDictionaryRef signingInfo = NULL;
    status = SecCodeCopySigningInformation(code, kSecCSSigningInformation, &signingInfo);
    if (status != errSecSuccess) {
        NSLog(@"Helper: Failed to get signing information: %d", status);
        CFRelease(code);
        return NO;
    }

    NSString *bundleID = [(__bridge NSDictionary *)signingInfo objectForKey:(__bridge id)kSecCodeInfoIdentifier];

#ifdef SNIFFNETBAR_DEV_MODE
    // Development mode: only check bundle ID, skip team ID validation
    // This allows running without an Apple Developer certificate
    BOOL isValid = [bundleID isEqualToString:@"com.sniffnetbar.app"];
    if (!isValid) {
        NSLog(@"Helper [DEV]: Invalid client bundle ID: %@", bundleID);
    } else {
        NSLog(@"Helper [DEV]: Accepted connection (team ID check disabled)");
    }
#else
    // Production mode: require matching team ID
    NSString *teamID = [(__bridge NSDictionary *)signingInfo objectForKey:(__bridge id)kSecCodeInfoTeamIdentifier];
    BOOL isValid = [bundleID isEqualToString:@"com.sniffnetbar.app"] &&
        (self.teamIdentifier.length > 0) &&
        [teamID isEqualToString:self.teamIdentifier];
    if (!isValid) {
        NSLog(@"Helper: Invalid client signature (bundleID: %@, teamID: %@)", bundleID, teamID);
    }
#endif

    CFRelease(signingInfo);
    CFRelease(code);
    return isValid;
}

#pragma mark - SNBPrivilegedHelperProtocol

- (void)getVersionWithReply:(void (^)(NSString *version))reply {
    reply(kSNBPrivilegedHelperVersion);
}

- (void)enumerateNetworkDevicesWithReply:(void (^)(NSArray<NSDictionary *> *devices, NSError *error))reply {
    [self.deviceEnumerator enumerateDevicesWithReply:reply];
}

- (void)startCaptureOnDevice:(NSString *)deviceName
                   withReply:(void (^)(NSString *sessionID, NSError *error))reply {
    // Security: Validate device name to prevent path traversal or injection
    // Valid device names are alphanumeric with length <= 16 (e.g., en0, lo0, utun0, bridge100)
    if (!deviceName || deviceName.length == 0 || deviceName.length > 16) {
        NSError *error = [NSError errorWithDomain:@"SNBHelper"
                                             code:400
                                         userInfo:@{NSLocalizedDescriptionKey: @"Invalid device name: empty or too long"}];
        reply(nil, error);
        return;
    }

    // Only allow alphanumeric characters (network interface names are always alphanumeric)
    NSCharacterSet *allowedChars = [NSCharacterSet alphanumericCharacterSet];
    NSCharacterSet *deviceChars = [NSCharacterSet characterSetWithCharactersInString:deviceName];
    if (![allowedChars isSupersetOfSet:deviceChars]) {
        NSLog(@"Helper: Rejected invalid device name: %@", deviceName);
        NSError *error = [NSError errorWithDomain:@"SNBHelper"
                                             code:400
                                         userInfo:@{NSLocalizedDescriptionKey: @"Invalid device name: contains invalid characters"}];
        reply(nil, error);
        return;
    }

    [self.packetCapture startCaptureOnDevice:deviceName withReply:reply];
}

- (void)stopCaptureForSession:(NSString *)sessionID
                     withReply:(void (^)(NSError *error))reply {
    [self.packetCapture stopCaptureForSession:sessionID withReply:reply];
}

- (void)getNextPacketForSession:(NSString *)sessionID
                      withReply:(void (^)(NSDictionary *packetInfo, NSError *error))reply {
    [self.packetCapture getNextPacketForSession:sessionID withReply:reply];
}

- (void)lookupProcessWithSourceAddress:(NSString *)sourceAddress
                            sourcePort:(NSInteger)sourcePort
                    destinationAddress:(NSString *)destinationAddress
                       destinationPort:(NSInteger)destinationPort
                             withReply:(void (^)(NSDictionary *processInfo, NSError *error))reply {
    [self.processLookup lookupProcessWithSourceAddress:sourceAddress
                                            sourcePort:sourcePort
                                    destinationAddress:destinationAddress
                                       destinationPort:destinationPort
                                             withReply:reply];
}

@end

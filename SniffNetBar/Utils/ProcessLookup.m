//
//  ProcessLookup.m
//  SniffNetBar
//
//  Proxy to privileged helper for process lookups
//

#import "ProcessLookup.h"
#import "SNBPrivilegedHelperClient.h"
#import "Logger.h"

@implementation ProcessInfo
@end

@implementation ProcessLookup

+ (void)lookupProcessForConnectionWithSource:(NSString *)sourceAddress
                                  sourcePort:(NSInteger)sourcePort
                                 destination:(NSString *)destinationAddress
                             destinationPort:(NSInteger)destinationPort
                                  completion:(void (^)(ProcessInfo * _Nullable processInfo))completion {
    if (!completion) {
        return;
    }

    [[SNBPrivilegedHelperClient sharedClient] lookupProcessWithSourceAddress:sourceAddress
                                                                  sourcePort:sourcePort
                                                             destinationAddr:destinationAddress
                                                             destinationPort:destinationPort
                                                                  completion:^(ProcessInfo *processInfo, NSError *error) {
        if (error) {
            SNBLogDebug("ProcessLookup: error: %{public}@", error.localizedDescription);
        }
        completion(processInfo);
    }];
}

+ (nullable ProcessInfo *)lookupProcessForConnectionWithSource:(NSString *)sourceAddress
                                                    sourcePort:(NSInteger)sourcePort
                                                   destination:(NSString *)destinationAddress
                                               destinationPort:(NSInteger)destinationPort {
    __block ProcessInfo *result = nil;
    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);

    [[SNBPrivilegedHelperClient sharedClient] lookupProcessWithSourceAddress:sourceAddress
                                                                  sourcePort:sourcePort
                                                             destinationAddr:destinationAddress
                                                             destinationPort:destinationPort
                                                                  completion:^(ProcessInfo *processInfo, NSError *error) {
        if (error) {
            SNBLogDebug("ProcessLookup: error: %{public}@", error.localizedDescription);
        }
        result = processInfo;
        dispatch_semaphore_signal(semaphore);
    }];

    dispatch_time_t timeout = dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5 * NSEC_PER_SEC));
    dispatch_semaphore_wait(semaphore, timeout);
    return result;
}

@end

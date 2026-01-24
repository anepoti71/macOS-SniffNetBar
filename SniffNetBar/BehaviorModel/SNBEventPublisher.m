//
//  SNBEventPublisher.m
//  SniffNetBar
//

#import "SNBEventPublisher.h"
#import "SNBEventSchema.h"
#import "SNBModelingXPCProtocol.h"
#import "PromotionAgent/SNBPromotionCandidate.h"
#import "Logger.h"

@interface SNBEventPublisher ()
@property (nonatomic, copy) NSString *serviceName;
@property (nonatomic, strong) NSXPCConnection *connection;
@property (nonatomic, strong) dispatch_queue_t queue;
@property (nonatomic, strong) id<SNBModelingXPCProtocol> localService;
@property (nonatomic, assign) BOOL loggedServiceInfo;
@end

@implementation SNBEventPublisher

- (instancetype)initWithServiceName:(NSString *)serviceName {
    self = [super init];
    if (self) {
        _serviceName = [serviceName copy];
        _queue = dispatch_queue_create("com.sniffnetbar.modeling.publisher", DISPATCH_QUEUE_SERIAL);
    }
    return self;
}

- (void)enqueueEvents:(NSArray<SNBFlowEvent *> *)events
              context:(SNBHostContext *)context
           completion:(SNBEventPublisherAck)completion {
    if (events.count == 0) {
        if (completion) {
            completion(0, 0);
        }
        return;
    }

    dispatch_async(self.queue, ^{
        if (self.localService) {
            [self.localService ingest:events context:context reply:^(NSUInteger accepted, NSUInteger dropped) {
                SNBLogBehaviorDebug("Local ingest events=%lu accepted=%lu dropped=%lu",
                                    (unsigned long)events.count,
                                    (unsigned long)accepted,
                                    (unsigned long)dropped);
                if (completion) {
                    completion(accepted, dropped);
                }
            }];
            return;
        }
        id<SNBModelingXPCProtocol> proxy = [self remoteProxy];
        if (!proxy) {
            if (completion) {
                completion(0, events.count);
            }
            return;
        }
        SNBLogBehaviorDebug("XPC ingest events=%lu", (unsigned long)events.count);
        [proxy ingest:events context:context reply:^(NSUInteger accepted, NSUInteger dropped) {
            SNBLogBehaviorDebug("XPC ingest reply accepted=%lu dropped=%lu",
                                (unsigned long)accepted,
                                (unsigned long)dropped);
            if (completion) {
                completion(accepted, dropped);
            }
        }];
    });
}

- (void)getPromotionCandidatesWithCompletion:(SNBPromotionCandidatesReply)completion {
    SNBLogAgentInfo("getPromotionCandidates: starting (localService=%p)", self.localService);
    dispatch_async(self.queue, ^{
        if (self.localService) {
            SNBLogAgentInfo("getPromotionCandidates: using LOCAL service");
            [self.localService getPromotionCandidates:^(NSArray<SNBPromotionCandidate *> *candidates) {
                SNBLogAgentInfo("Local getPromotionCandidates returned count=%lu", (unsigned long)candidates.count);
                if (completion) {
                    completion(candidates);
                }
            }];
            return;
        }
        SNBLogAgentInfo("getPromotionCandidates: using XPC service");
        id<SNBModelingXPCProtocol> proxy = [self remoteProxy];
        if (!proxy) {
            SNBLogAgentWarn("getPromotionCandidates: XPC proxy is nil, returning empty");
            if (completion) {
                completion(@[]);
            }
            return;
        }
        SNBLogAgentInfo("XPC getPromotionCandidates request sent");
        [proxy getPromotionCandidates:^(NSArray<SNBPromotionCandidate *> *candidates) {
            SNBLogAgentInfo("XPC getPromotionCandidates reply count=%lu", (unsigned long)candidates.count);
            if (completion) {
                completion(candidates);
            }
        }];
    });
}

- (void)applyPromotion:(NSString *)clusterID
                 label:(NSString *)label
                reason:(NSString *)reason
            completion:(SNBPromotionApplyReply)completion {
    dispatch_async(self.queue, ^{
        if (self.localService) {
            [self.localService applyPromotion:clusterID label:label reason:reason reply:^(BOOL success) {
                SNBLogAgentInfo("Local applyPromotion cluster=%{public}@ label=%{public}@ success=%d",
                                clusterID, label, success);
                if (completion) {
                    completion(success);
                }
            }];
            return;
        }
        id<SNBModelingXPCProtocol> proxy = [self remoteProxy];
        if (!proxy) {
            if (completion) {
                completion(NO);
            }
            return;
        }
        SNBLogAgentInfo("XPC applyPromotion cluster=%{public}@ label=%{public}@", clusterID, label);
        [proxy applyPromotion:clusterID label:label reason:reason reply:^(BOOL success) {
            SNBLogAgentInfo("XPC applyPromotion reply cluster=%{public}@ success=%d", clusterID, success);
            if (completion) {
                completion(success);
            }
        }];
    });
}

- (void)setLocalServiceFallback:(id<SNBModelingXPCProtocol>)service {
    self.localService = service;
}

- (void)pingWithCompletion:(SNBEventPublisherPing)completion {
    dispatch_async(self.queue, ^{
        id<SNBModelingXPCProtocol> proxy = [self remoteProxy];
        if (!proxy) {
            if (completion) {
                completion(NO);
            }
            return;
        }
        SNBLogBehaviorDebug("XPC ping request");
        [proxy ping:^(BOOL ok) {
            SNBLogBehaviorDebug("XPC ping reply ok=%d", ok);
            if (completion) {
                completion(ok);
            }
        }];
    });
}
- (id<SNBModelingXPCProtocol>)remoteProxy {
    if (!self.connection) {
        self.connection = [[NSXPCConnection alloc] initWithServiceName:self.serviceName];
        SNBLogBehaviorInfo("Opening modeling XPC connection to %{public}@", self.serviceName);
        if (!self.loggedServiceInfo) {
            NSBundle *bundle = [NSBundle mainBundle];
            NSString *bundleID = bundle.bundleIdentifier ?: @"unknown";
            NSString *xpcPath = [bundle.bundlePath stringByAppendingPathComponent:@"Contents/XPCServices/ModelingXPCService.xpc"];
            BOOL xpcExists = [[NSFileManager defaultManager] fileExistsAtPath:xpcPath];
            SNBLogBehaviorInfo("Modeling XPC service=%{public}@ appBundleID=%{public}@ xpcPath=%{public}@",
                               self.serviceName, bundleID, xpcExists ? xpcPath : @"missing");
            self.loggedServiceInfo = YES;
        }
        NSXPCInterface *interface = [NSXPCInterface interfaceWithProtocol:@protocol(SNBModelingXPCProtocol)];
        NSSet *eventClasses = [NSSet setWithObjects:[NSArray class], [SNBFlowEvent class], nil];
        [interface setClasses:eventClasses
                  forSelector:@selector(ingest:context:reply:)
                argumentIndex:0
                      ofReply:NO];
        [interface setClasses:[NSSet setWithObject:[SNBHostContext class]]
                  forSelector:@selector(ingest:context:reply:)
                argumentIndex:1
                      ofReply:NO];
        [interface setClasses:[NSSet setWithObjects:[NSArray class], [SNBRecommendation class], nil]
                  forSelector:@selector(getRecommendationsSince:reply:)
                argumentIndex:0
                      ofReply:YES];
        [interface setClasses:[NSSet setWithObjects:[NSArray class], [SNBPromotionCandidate class], nil]
                  forSelector:@selector(getPromotionCandidates:)
                argumentIndex:0
                      ofReply:YES];

        // Configure class whitelisting for getClusterDetails:reply:
        [interface setClasses:[NSSet setWithObject:[NSString class]]
                  forSelector:@selector(getClusterDetails:reply:)
                argumentIndex:0
                      ofReply:NO];
        [interface setClasses:[NSSet setWithObjects:[NSDictionary class], [NSString class], [NSNumber class], [NSDate class], [NSArray class], nil]
                  forSelector:@selector(getClusterDetails:reply:)
                argumentIndex:0
                      ofReply:YES];

        // Configure class whitelisting for setUserLabel:label:scope:reply:
        [interface setClasses:[NSSet setWithObject:[NSString class]]
                  forSelector:@selector(setUserLabel:label:scope:reply:)
                argumentIndex:0
                      ofReply:NO];
        [interface setClasses:[NSSet setWithObject:[NSString class]]
                  forSelector:@selector(setUserLabel:label:scope:reply:)
                argumentIndex:1
                      ofReply:NO];
        [interface setClasses:[NSSet setWithObject:[NSString class]]
                  forSelector:@selector(setUserLabel:label:scope:reply:)
                argumentIndex:2
                      ofReply:NO];

        // Configure class whitelisting for applyPromotion:label:reason:reply:
        [interface setClasses:[NSSet setWithObject:[NSString class]]
                  forSelector:@selector(applyPromotion:label:reason:reply:)
                argumentIndex:0
                      ofReply:NO];
        [interface setClasses:[NSSet setWithObject:[NSString class]]
                  forSelector:@selector(applyPromotion:label:reason:reply:)
                argumentIndex:1
                      ofReply:NO];
        [interface setClasses:[NSSet setWithObject:[NSString class]]
                  forSelector:@selector(applyPromotion:label:reason:reply:)
                argumentIndex:2
                      ofReply:NO];

        self.connection.remoteObjectInterface = interface;

        // Use weak self to avoid retain cycle - clear connection on invalidation
        __weak typeof(self) weakSelf = self;
        self.connection.interruptionHandler = ^{
            SNBLogBehaviorWarn("Modeling XPC connection interrupted");
        };
        self.connection.invalidationHandler = ^{
            SNBLogBehaviorWarn("Modeling XPC connection invalidated");
            // Clear connection so next call creates a new one
            dispatch_async(weakSelf.queue, ^{
                weakSelf.connection = nil;
            });
        };
        [self.connection resume];
    }
    return [self.connection remoteObjectProxyWithErrorHandler:^(NSError *error) {
        SNBLogBehaviorWarn("Modeling XPC proxy error: %{public}@", error.localizedDescription);
    }];
}

@end

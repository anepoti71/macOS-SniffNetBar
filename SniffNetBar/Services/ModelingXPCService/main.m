//
//  main.m
//  ModelingXPCService
//

#import <Foundation/Foundation.h>
#import "SNBModelingXPCProtocol.h"
#import "SNBModelingXPCService.h"
#import "SNBEventSchema.h"
#import "SNBPromotionCandidate.h"
#import "Logger.h"

@interface SNBModelingXPCDelegate : NSObject <NSXPCListenerDelegate>
@end

@implementation SNBModelingXPCDelegate

- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
    NSXPCInterface *interface = [NSXPCInterface interfaceWithProtocol:@protocol(SNBModelingXPCProtocol)];
    SNBLogBehaviorInfo("Modeling XPC accepted connection pid=%d", newConnection.processIdentifier);

    // Configure class whitelisting for ingest:context:reply:
    NSSet *eventClasses = [NSSet setWithObjects:[NSArray class], [SNBFlowEvent class], nil];
    [interface setClasses:eventClasses
              forSelector:@selector(ingest:context:reply:)
            argumentIndex:0
                  ofReply:NO];
    [interface setClasses:[NSSet setWithObject:[SNBHostContext class]]
              forSelector:@selector(ingest:context:reply:)
            argumentIndex:1
                  ofReply:NO];

    // Configure class whitelisting for getRecommendationsSince:reply:
    [interface setClasses:[NSSet setWithObjects:[NSArray class], [SNBRecommendation class], nil]
              forSelector:@selector(getRecommendationsSince:reply:)
            argumentIndex:0
                  ofReply:YES];

    // Configure class whitelisting for getPromotionCandidates:
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

    newConnection.exportedInterface = interface;
    SNBModelingXPCService *service = [[SNBModelingXPCService alloc] init];
    newConnection.exportedObject = service;
    [newConnection resume];
    return YES;
}

@end

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        SNBLogBehaviorInfo("ModelingXPCService starting");
        NSXPCListener *listener = [NSXPCListener serviceListener];
        SNBModelingXPCDelegate *delegate = [[SNBModelingXPCDelegate alloc] init];
        listener.delegate = delegate;
        [listener resume];

        // Run forever - XPC service must not exit
        dispatch_main();
    }
    return 0;
}

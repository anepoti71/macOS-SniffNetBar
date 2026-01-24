//
//  SNBEventPublisher.h
//  SniffNetBar
//

#import <Foundation/Foundation.h>
#import "SNBModelingXPCProtocol.h"

NS_ASSUME_NONNULL_BEGIN

@class SNBHostContext;
@class SNBFlowEvent;
@class SNBPromotionCandidate;

typedef void (^SNBEventPublisherAck)(NSUInteger accepted, NSUInteger dropped);
typedef void (^SNBEventPublisherPing)(BOOL ok);
typedef void (^SNBPromotionCandidatesReply)(NSArray<SNBPromotionCandidate *> *candidates);
typedef void (^SNBPromotionApplyReply)(BOOL success);

@interface SNBEventPublisher : NSObject

- (instancetype)initWithServiceName:(NSString *)serviceName;

- (void)setLocalServiceFallback:(id<SNBModelingXPCProtocol>)service;
- (void)pingWithCompletion:(nullable SNBEventPublisherPing)completion;

- (void)enqueueEvents:(NSArray<SNBFlowEvent *> *)events
              context:(SNBHostContext *)context
           completion:(nullable SNBEventPublisherAck)completion;

- (void)getPromotionCandidatesWithCompletion:(nullable SNBPromotionCandidatesReply)completion;
- (void)applyPromotion:(NSString *)clusterID
                 label:(NSString *)label
                reason:(NSString *)reason
            completion:(nullable SNBPromotionApplyReply)completion;

@end

NS_ASSUME_NONNULL_END

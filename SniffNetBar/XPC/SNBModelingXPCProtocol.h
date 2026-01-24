//
//  SNBModelingXPCProtocol.h
//  SniffNetBar
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@class SNBHostContext;
@class SNBFlowEvent;
@class SNBRecommendation;
@class SNBPromotionCandidate;

@protocol SNBModelingXPCProtocol
- (void)ping:(void (^)(BOOL ok))reply;

- (void)ingest:(NSArray<SNBFlowEvent *> *)events
      context:(SNBHostContext *)context
        reply:(void (^)(NSUInteger accepted, NSUInteger dropped))reply;

- (void)getRecommendationsSince:(NSDate *)since
                          reply:(void (^)(NSArray<SNBRecommendation *> *results))reply;

- (void)getClusterDetails:(NSString *)clusterID
                    reply:(void (^)(NSDictionary *detail))reply;

- (void)setUserLabel:(NSString *)clusterID
               label:(NSString *)label
               scope:(NSString *)scope
               reply:(void (^)(BOOL success))reply;

// Promotion agent methods
- (void)getPromotionCandidates:(void (^)(NSArray<SNBPromotionCandidate *> *candidates))reply;

- (void)applyPromotion:(NSString *)clusterID
                 label:(NSString *)label
                reason:(NSString *)reason
                 reply:(void (^)(BOOL success))reply;
@end

NS_ASSUME_NONNULL_END

//
//  SNBPromotionAgent.h
//  SniffNetBar
//
//  Main orchestrator for the hybrid promotion agent with timer-based evaluation.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@class SNBPromotionPolicy;
@class SNBPromotionDecision;
@class SNBEventPublisher;
@class SNBPromotionAgent;

@protocol SNBPromotionAgentDelegate <NSObject>
@optional
- (void)promotionAgent:(SNBPromotionAgent *)agent didAutoPromote:(SNBPromotionDecision *)decision;
- (void)promotionAgent:(SNBPromotionAgent *)agent didAutoBlock:(SNBPromotionDecision *)decision;
- (void)promotionAgent:(SNBPromotionAgent *)agent hasSuggestion:(SNBPromotionDecision *)decision;
- (void)promotionAgent:(SNBPromotionAgent *)agent needsReview:(SNBPromotionDecision *)decision;
- (void)promotionAgent:(SNBPromotionAgent *)agent didEncounterError:(NSError *)error;
- (void)promotionAgentDidCompleteEvaluation:(SNBPromotionAgent *)agent;
@end

@interface SNBPromotionAgent : NSObject

@property (nonatomic, strong, readonly) SNBPromotionPolicy *policy;
@property (nonatomic, assign, readonly) BOOL isRunning;
@property (nonatomic, assign, readonly) BOOL aiAvailable;
@property (nonatomic, assign) NSTimeInterval evaluationInterval;

@property (nonatomic, weak, nullable) id<SNBPromotionAgentDelegate> delegate;

- (instancetype)initWithEventPublisher:(SNBEventPublisher *)publisher
                                policy:(SNBPromotionPolicy *)policy;

// Control
- (void)start;
- (void)stop;

// Manual trigger
- (void)evaluateNow;

// Check Ollama availability
- (void)checkAIAvailability:(void (^)(BOOL available))completion;

// Pending suggestions (for UI)
- (NSArray<SNBPromotionDecision *> *)pendingSuggestions;
- (void)approveSuggestion:(SNBPromotionDecision *)decision;
- (void)rejectSuggestion:(SNBPromotionDecision *)decision;
- (void)clearSuggestion:(SNBPromotionDecision *)decision;

// Statistics
- (NSDictionary<NSString *, NSNumber *> *)statistics;

@end

NS_ASSUME_NONNULL_END

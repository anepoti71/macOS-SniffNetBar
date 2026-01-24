//
//  SNBPromotionEvaluator.h
//  SniffNetBar
//
//  Hybrid evaluation logic with fast path rules and AI routing.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@class SNBPromotionPolicy;
@class SNBPromotionCandidate;
@class SNBPromotionDecision;
@class SNBOllamaClient;

typedef NS_ENUM(NSInteger, SNBEvaluationPath) {
    SNBEvaluationPathFast = 0,    // Rule-based, no AI
    SNBEvaluationPathSlow,        // AI-assisted
    SNBEvaluationPathSkipped      // Candidate excluded
};

@interface SNBEvaluationResult : NSObject
@property (nonatomic, strong) SNBPromotionDecision *decision;
@property (nonatomic, assign) SNBEvaluationPath path;
@property (nonatomic, assign) BOOL aiAssisted;
@property (nonatomic, copy, nullable) NSString *aiReasoning;
@end

@interface SNBPromotionEvaluator : NSObject

@property (nonatomic, strong, readonly) SNBPromotionPolicy *policy;
@property (nonatomic, strong, readonly, nullable) SNBOllamaClient *ollamaClient;
@property (nonatomic, assign) BOOL aiEnabled;

- (instancetype)initWithPolicy:(SNBPromotionPolicy *)policy;
- (instancetype)initWithPolicy:(SNBPromotionPolicy *)policy
                  ollamaClient:(nullable SNBOllamaClient *)ollamaClient;

// Evaluate candidate - routes to fast or slow path
- (void)evaluateCandidate:(SNBPromotionCandidate *)candidate
               completion:(void (^)(SNBEvaluationResult *result))completion;

// Fast path only (synchronous)
- (SNBPromotionDecision *)evaluateFastPath:(SNBPromotionCandidate *)candidate;

// Determine if AI routing is needed
- (BOOL)needsAIEvaluation:(SNBPromotionCandidate *)candidate;

@end

NS_ASSUME_NONNULL_END

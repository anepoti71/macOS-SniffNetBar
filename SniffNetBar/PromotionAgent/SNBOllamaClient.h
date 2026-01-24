//
//  SNBOllamaClient.h
//  SniffNetBar
//
//  HTTP client for Ollama API integration with local LLM.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@class SNBPromotionCandidate;
@class SNBPromotionDecision;

@interface SNBOllamaClient : NSObject

@property (nonatomic, copy) NSString *baseURL;
@property (nonatomic, copy) NSString *model;
@property (nonatomic, assign) NSTimeInterval timeout;

- (instancetype)init;
- (instancetype)initWithBaseURL:(NSString *)baseURL model:(NSString *)model;

// Check if Ollama is available
- (void)pingWithCompletion:(void (^)(BOOL available))completion;

// Check available models
- (void)listModelsWithCompletion:(void (^)(NSArray<NSString *> * _Nullable models, NSError * _Nullable error))completion;

// Evaluate a promotion candidate using the LLM
- (void)evaluateCandidate:(SNBPromotionCandidate *)candidate
               completion:(void (^)(SNBPromotionDecision * _Nullable decision, NSError * _Nullable error))completion;

// Raw generate endpoint for testing
- (void)generateWithPrompt:(NSString *)prompt
                completion:(void (^)(NSString * _Nullable response, NSError * _Nullable error))completion;

@end

NS_ASSUME_NONNULL_END

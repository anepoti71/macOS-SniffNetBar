//
//  AnomalyExplanationService.h
//  SniffNetBar
//
//  Local LLM explainability for anomaly windows
//

#import <Foundation/Foundation.h>

@class ConfigurationManager;
@class SNBAnomalyWindowRecord;
@class TIEnrichmentResponse;

NS_ASSUME_NONNULL_BEGIN

@interface SNBAnomalyExplanation : NSObject

@property (nonatomic, copy) NSString *summary;
@property (nonatomic, copy) NSString *riskBand;
@property (nonatomic, copy) NSArray<NSString *> *evidenceTags;
@property (nonatomic, copy) NSString *tone;

@end

@interface SNBAnomalyExplanationService : NSObject

@property (nonatomic, readonly, getter=isEnabled) BOOL enabled;
@property (nonatomic, copy, readonly) NSString *promptVersion;

- (instancetype)initWithConfiguration:(ConfigurationManager *)configuration;

- (NSDictionary *)inputForWindow:(SNBAnomalyWindowRecord *)window
                   windowSeconds:(NSTimeInterval)windowSeconds
                    threatIntel:(TIEnrichmentResponse * _Nullable)threatIntel;

- (void)generateExplanationWithInput:(NSDictionary *)input
                          completion:(void (^)(SNBAnomalyExplanation * _Nullable explanation,
                                               NSError * _Nullable error))completion;

@end

NS_ASSUME_NONNULL_END

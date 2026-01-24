//
//  AnomalyCoreMLScorer.h
//  SniffNetBar
//
//  Core ML scorer for anomaly detection
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface SNBAnomalyCoreMLScorer : NSObject

- (instancetype)initWithModelPath:(nullable NSString *)modelPath;

- (nullable NSNumber *)scoreFeaturePayload:(NSDictionary<NSString *, NSNumber *> *)payload
                                     error:(NSError **)error;

@end

NS_ASSUME_NONNULL_END

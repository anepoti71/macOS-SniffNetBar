//
//  AnomalyPythonScorer.h
//  SniffNetBar
//
//  Python helper for Isolation Forest scoring
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface SNBAnomalyPythonScorer : NSObject

- (instancetype)initWithScriptPath:(nullable NSString *)scriptPath
                         modelPath:(nullable NSString *)modelPath;

- (nullable NSNumber *)scoreFeaturePayload:(NSDictionary<NSString *, NSNumber *> *)payload
                                     error:(NSError **)error;

@end

NS_ASSUME_NONNULL_END

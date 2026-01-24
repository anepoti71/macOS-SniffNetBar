//
//  AnomalyCoreMLScorer.m
//  SniffNetBar
//
//  Core ML scorer for anomaly detection
//

#import "AnomalyCoreMLScorer.h"
#import <CoreML/CoreML.h>

@interface SNBAnomalyCoreMLScorer ()
@property (nonatomic, strong) MLModel *model;
@end

@implementation SNBAnomalyCoreMLScorer

- (instancetype)initWithModelPath:(NSString *)modelPath {
    self = [super init];
    if (self) {
        if (modelPath.length > 0) {
            NSURL *url = [NSURL fileURLWithPath:modelPath];
            NSError *error = nil;
            _model = [MLModel modelWithContentsOfURL:url error:&error];
        }
    }
    return self;
}

- (NSNumber *)scoreFeaturePayload:(NSDictionary<NSString *, NSNumber *> *)payload
                            error:(NSError **)error {
    if (!self.model) {
        return nil;
    }
    NSMutableDictionary<NSString *, MLFeatureValue *> *features = [NSMutableDictionary dictionary];
    [payload enumerateKeysAndObjectsUsingBlock:^(NSString *key, NSNumber *value, BOOL *stop) {
        features[key] = [MLFeatureValue featureValueWithDouble:value.doubleValue];
    }];

    MLDictionaryFeatureProvider *provider =
        [[MLDictionaryFeatureProvider alloc] initWithDictionary:features error:error];
    if (!provider) {
        return nil;
    }

    id<MLFeatureProvider> output = [self.model predictionFromFeatures:provider error:error];
    if (!output) {
        return nil;
    }

    MLFeatureValue *scoreValue = [output featureValueForName:@"score"];
    if (!scoreValue || scoreValue.type != MLFeatureTypeDouble) {
        return nil;
    }
    return @(scoreValue.doubleValue);
}

@end

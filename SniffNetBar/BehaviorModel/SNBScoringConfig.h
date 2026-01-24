//
//  SNBScoringConfig.h
//  SniffNetBar
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface SNBScoringConfig : NSObject

@property (nonatomic, assign) NSInteger repeatThresholdHigh;
@property (nonatomic, assign) NSInteger repeatThresholdLow;
@property (nonatomic, assign) double beaconThreshold;
@property (nonatomic, assign) double timeNoveltyThreshold;
@property (nonatomic, assign) NSInteger repeatScoreBonus;
@property (nonatomic, assign) NSInteger repeatScorePenalty;
@property (nonatomic, assign) NSInteger timeNoveltyPenalty;
@property (nonatomic, assign) NSInteger beaconPenalty;
@property (nonatomic, assign) NSInteger commonPortBonus;
@property (nonatomic, assign) NSInteger attributionBonus;
@property (nonatomic, assign) NSInteger missingAttributionPenalty;
@property (nonatomic, assign) NSInteger stableWindowBonus;
@property (nonatomic, assign) NSInteger sparseWindowPenalty;
@property (nonatomic, assign) NSInteger inboundPenalty;
@property (nonatomic, assign) double volumeAnomalyRatio;
@property (nonatomic, assign) NSInteger volumeAnomalyPenalty;
@property (nonatomic, assign) NSInteger vpnRelayPenalty;
@property (nonatomic, assign) NSInteger threatPenalty;
@property (nonatomic, assign) double threatScoreThreshold;
@property (nonatomic, assign) NSInteger bundleIDBonus;
@property (nonatomic, assign) NSInteger parentProcessBonus;
@property (nonatomic, assign) NSInteger tlsFingerprintBonus;
@property (nonatomic, assign) NSInteger asnAnomalyPenalty;
@property (nonatomic, assign) NSTimeInterval longDurationThreshold;
@property (nonatomic, assign) NSInteger longDurationPenalty;
@property (nonatomic, assign) NSInteger failurePenalty;

+ (instancetype)defaultConfig;

@end

NS_ASSUME_NONNULL_END

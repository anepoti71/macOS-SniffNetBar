//
//  SNBScoringConfig.m
//  SniffNetBar
//

#import "SNBScoringConfig.h"

@implementation SNBScoringConfig

+ (instancetype)defaultConfig {
    SNBScoringConfig *config = [[SNBScoringConfig alloc] init];
    config.repeatThresholdHigh = 20;
    config.repeatThresholdLow = 2;
    config.beaconThreshold = 0.7;
    config.timeNoveltyThreshold = 0.05;
    config.repeatScoreBonus = 15;
    config.repeatScorePenalty = 10;
    config.timeNoveltyPenalty = 8;
    config.beaconPenalty = 12;
    config.commonPortBonus = 5;
    config.attributionBonus = 10;
    config.missingAttributionPenalty = 15;
    config.stableWindowBonus = 6;
    config.sparseWindowPenalty = 6;
    config.inboundPenalty = 6;
    config.volumeAnomalyRatio = 10.0;
    config.volumeAnomalyPenalty = 8;
    config.vpnRelayPenalty = 5;
    config.threatPenalty = 20;
    config.threatScoreThreshold = 50.0;
    config.bundleIDBonus = 4;
    config.parentProcessBonus = 3;
    config.tlsFingerprintBonus = 2;
    config.asnAnomalyPenalty = 4;
    config.longDurationThreshold = 300.0;
    config.longDurationPenalty = 4;
    config.failurePenalty = 4;
    return config;
}

@end

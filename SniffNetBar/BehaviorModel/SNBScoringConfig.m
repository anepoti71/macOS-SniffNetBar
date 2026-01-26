//
//  SNBScoringConfig.m
//  SniffNetBar
//

#import "SNBScoringConfig.h"
#import "SNBSystemProcessWhitelist.h"

@implementation SNBScoringConfig

+ (instancetype)defaultConfig {
    SNBScoringConfig *config = [[SNBScoringConfig alloc] init];

    // Repeat/history thresholds
    config.repeatThresholdHigh = 20;
    config.repeatThresholdLow = 2;
    config.beaconThreshold = 0.7;
    config.timeNoveltyThreshold = 0.05;

    // Score adjustments
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

    // Attribution bonus cap
    config.maxAttributionBonus = 20;

    // System process whitelist configuration
    config.processWhitelist = [SNBSystemProcessWhitelist sharedWhitelist];
    config.whitelistedProcessBonus = 8;
    config.whitelistedPenaltyMultiplier = 0.3;  // 30% of normal penalty
    config.whitelistMinSeenCount = 5;
    config.skipAttributionPenaltyForHighTrust = YES;
    config.highTrustThreshold = 0.9;

    return config;
}

@end

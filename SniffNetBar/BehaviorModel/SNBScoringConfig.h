//
//  SNBScoringConfig.h
//  SniffNetBar
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@class SNBSystemProcessWhitelist;

@interface SNBScoringConfig : NSObject

// Repeat/history thresholds
@property (nonatomic, assign) NSInteger repeatThresholdHigh;
@property (nonatomic, assign) NSInteger repeatThresholdLow;
@property (nonatomic, assign) double beaconThreshold;
@property (nonatomic, assign) double timeNoveltyThreshold;

// Score adjustments
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

// Attribution bonus cap (prevents score inflation)
@property (nonatomic, assign) NSInteger maxAttributionBonus;

// System process whitelist configuration
@property (nonatomic, strong, nullable) SNBSystemProcessWhitelist *processWhitelist;

/// Bonus for whitelisted system processes (added to score)
@property (nonatomic, assign) NSInteger whitelistedProcessBonus;

/// Reduced penalty multiplier for whitelisted processes (0.0-1.0)
/// Example: 0.3 means only 30% of normal penalty applied
@property (nonatomic, assign) double whitelistedPenaltyMultiplier;

/// Minimum seen count before applying reduced penalty for whitelisted processes
/// Helps prevent abuse of whitelist for truly new/suspicious traffic
@property (nonatomic, assign) NSInteger whitelistMinSeenCount;

/// Whether to skip missing attribution penalty entirely for high-trust system processes
@property (nonatomic, assign) BOOL skipAttributionPenaltyForHighTrust;

/// Trust level threshold above which to skip attribution penalty (0.0-1.0)
@property (nonatomic, assign) double highTrustThreshold;

+ (instancetype)defaultConfig;

@end

NS_ASSUME_NONNULL_END

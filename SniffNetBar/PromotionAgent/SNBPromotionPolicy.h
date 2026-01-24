//
//  SNBPromotionPolicy.h
//  SniffNetBar
//
//  Configurable thresholds for the promotion agent.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, SNBAutomationLevel) {
    SNBAutomationLevelOff = 0,           // No auto-promotion
    SNBAutomationLevelSuggestOnly,       // Suggest, user approves
    SNBAutomationLevelConservative,      // Very strict auto-promotion
    SNBAutomationLevelModerate,          // Balanced
    SNBAutomationLevelAggressive         // Trust more readily
};

@interface SNBPromotionPolicy : NSObject <NSSecureCoding>

@property (nonatomic, assign) SNBAutomationLevel level;

// Score thresholds
@property (nonatomic, assign) NSInteger minScoreForPromotion;
@property (nonatomic, assign) NSInteger minConfidenceForPromotion;

// History requirements
@property (nonatomic, assign) uint64_t minSeenCount;
@property (nonatomic, assign) NSTimeInterval minObservationPeriod;
@property (nonatomic, assign) uint64_t minSeen7d;

// Safety requirements
@property (nonatomic, assign) BOOL requireSignedProcess;
@property (nonatomic, assign) BOOL requireDomainInfo;
@property (nonatomic, assign) BOOL requireNoThreatIntel;
@property (nonatomic, assign) BOOL requireNoASNAnomaly;
@property (nonatomic, assign) BOOL requireNoBeaconBehavior;
@property (nonatomic, assign) double maxBeaconScore;

// Exclusion lists
@property (nonatomic, copy) NSSet<NSString *> *neverAutoTrustProcesses;
@property (nonatomic, copy) NSSet<NSNumber *> *neverAutoTrustPorts;

// Threshold adjustment
- (void)increaseThresholds;
- (void)decreaseThresholds;

+ (instancetype)policyForLevel:(SNBAutomationLevel)level;
+ (instancetype)defaultPolicy;

@end

NS_ASSUME_NONNULL_END

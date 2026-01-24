//
//  SNBPromotionPolicy.m
//  SniffNetBar
//

#import "SNBPromotionPolicy.h"

@implementation SNBPromotionPolicy

+ (BOOL)supportsSecureCoding {
    return YES;
}

- (instancetype)initWithCoder:(NSCoder *)coder {
    self = [super init];
    if (self) {
        _level = [coder decodeIntegerForKey:@"level"];
        _minScoreForPromotion = [coder decodeIntegerForKey:@"minScoreForPromotion"];
        _minConfidenceForPromotion = [coder decodeIntegerForKey:@"minConfidenceForPromotion"];
        _minSeenCount = (uint64_t)[coder decodeInt64ForKey:@"minSeenCount"];
        _minObservationPeriod = [coder decodeDoubleForKey:@"minObservationPeriod"];
        _minSeen7d = (uint64_t)[coder decodeInt64ForKey:@"minSeen7d"];
        _requireSignedProcess = [coder decodeBoolForKey:@"requireSignedProcess"];
        _requireDomainInfo = [coder decodeBoolForKey:@"requireDomainInfo"];
        _requireNoThreatIntel = [coder decodeBoolForKey:@"requireNoThreatIntel"];
        _requireNoASNAnomaly = [coder decodeBoolForKey:@"requireNoASNAnomaly"];
        _requireNoBeaconBehavior = [coder decodeBoolForKey:@"requireNoBeaconBehavior"];
        _maxBeaconScore = [coder decodeDoubleForKey:@"maxBeaconScore"];
        _neverAutoTrustProcesses = [coder decodeObjectOfClasses:[NSSet setWithObjects:[NSSet class], [NSString class], nil]
                                                         forKey:@"neverAutoTrustProcesses"];
        _neverAutoTrustPorts = [coder decodeObjectOfClasses:[NSSet setWithObjects:[NSSet class], [NSNumber class], nil]
                                                     forKey:@"neverAutoTrustPorts"];
    }
    return self;
}

- (void)encodeWithCoder:(NSCoder *)coder {
    [coder encodeInteger:_level forKey:@"level"];
    [coder encodeInteger:_minScoreForPromotion forKey:@"minScoreForPromotion"];
    [coder encodeInteger:_minConfidenceForPromotion forKey:@"minConfidenceForPromotion"];
    [coder encodeInt64:(int64_t)_minSeenCount forKey:@"minSeenCount"];
    [coder encodeDouble:_minObservationPeriod forKey:@"minObservationPeriod"];
    [coder encodeInt64:(int64_t)_minSeen7d forKey:@"minSeen7d"];
    [coder encodeBool:_requireSignedProcess forKey:@"requireSignedProcess"];
    [coder encodeBool:_requireDomainInfo forKey:@"requireDomainInfo"];
    [coder encodeBool:_requireNoThreatIntel forKey:@"requireNoThreatIntel"];
    [coder encodeBool:_requireNoASNAnomaly forKey:@"requireNoASNAnomaly"];
    [coder encodeBool:_requireNoBeaconBehavior forKey:@"requireNoBeaconBehavior"];
    [coder encodeDouble:_maxBeaconScore forKey:@"maxBeaconScore"];
    [coder encodeObject:_neverAutoTrustProcesses forKey:@"neverAutoTrustProcesses"];
    [coder encodeObject:_neverAutoTrustPorts forKey:@"neverAutoTrustPorts"];
}

+ (instancetype)defaultPolicy {
    return [self policyForLevel:SNBAutomationLevelConservative];
}

+ (instancetype)policyForLevel:(SNBAutomationLevel)level {
    SNBPromotionPolicy *policy = [[SNBPromotionPolicy alloc] init];
    policy.level = level;

    // Common exclusions for all levels
    policy.neverAutoTrustProcesses = [NSSet setWithObjects:
        @"curl", @"wget", @"nc", @"ncat", @"netcat",
        @"python", @"python3", @"ruby", @"perl",
        @"bash", @"sh", @"zsh", @"fish",
        @"telnet", @"ssh", @"scp", @"sftp",
        @"nmap", @"masscan", nil];

    policy.neverAutoTrustPorts = [NSSet setWithObjects:
        @4444, @5555, @6666, @7777,  // Common C2 ports
        @1337, @31337,               // "Elite" ports
        @8888, @9999,                // Common backdoor ports
        @23, @21,                    // Telnet, FTP
        nil];

    switch (level) {
        case SNBAutomationLevelOff:
            // All thresholds set to impossible values
            policy.minScoreForPromotion = 101;
            policy.minConfidenceForPromotion = 101;
            policy.minSeenCount = UINT64_MAX;
            policy.minObservationPeriod = DBL_MAX;
            policy.minSeen7d = UINT64_MAX;
            policy.requireSignedProcess = YES;
            policy.requireDomainInfo = YES;
            policy.requireNoThreatIntel = YES;
            policy.requireNoASNAnomaly = YES;
            policy.requireNoBeaconBehavior = YES;
            policy.maxBeaconScore = 0.0;
            break;

        case SNBAutomationLevelSuggestOnly:
            // Same as conservative but only suggests
            policy.minScoreForPromotion = 80;
            policy.minConfidenceForPromotion = 75;
            policy.minSeenCount = 30;
            policy.minObservationPeriod = 3 * 86400;  // 3 days
            policy.minSeen7d = 15;
            policy.requireSignedProcess = YES;
            policy.requireDomainInfo = YES;
            policy.requireNoThreatIntel = YES;
            policy.requireNoASNAnomaly = YES;
            policy.requireNoBeaconBehavior = YES;
            policy.maxBeaconScore = 0.5;
            break;

        case SNBAutomationLevelConservative:
            policy.minScoreForPromotion = 85;
            policy.minConfidenceForPromotion = 80;
            policy.minSeenCount = 50;
            policy.minObservationPeriod = 7 * 86400;  // 7 days
            policy.minSeen7d = 20;
            policy.requireSignedProcess = YES;
            policy.requireDomainInfo = YES;
            policy.requireNoThreatIntel = YES;
            policy.requireNoASNAnomaly = YES;
            policy.requireNoBeaconBehavior = YES;
            policy.maxBeaconScore = 0.5;
            break;

        case SNBAutomationLevelModerate:
            policy.minScoreForPromotion = 75;
            policy.minConfidenceForPromotion = 70;
            policy.minSeenCount = 30;
            policy.minObservationPeriod = 3 * 86400;  // 3 days
            policy.minSeen7d = 10;
            policy.requireSignedProcess = YES;
            policy.requireDomainInfo = YES;
            policy.requireNoThreatIntel = YES;
            policy.requireNoASNAnomaly = NO;  // Allow some ASN variance
            policy.requireNoBeaconBehavior = YES;
            policy.maxBeaconScore = 0.6;
            break;

        case SNBAutomationLevelAggressive:
            policy.minScoreForPromotion = 70;
            policy.minConfidenceForPromotion = 60;
            policy.minSeenCount = 20;
            policy.minObservationPeriod = 1 * 86400;  // 1 day
            policy.minSeen7d = 5;
            policy.requireSignedProcess = NO;  // Allow unsigned
            policy.requireDomainInfo = YES;
            policy.requireNoThreatIntel = YES;
            policy.requireNoASNAnomaly = NO;
            policy.requireNoBeaconBehavior = NO;
            policy.maxBeaconScore = 0.8;
            break;
    }

    return policy;
}

- (void)increaseThresholds {
    self.minScoreForPromotion = MIN(95, self.minScoreForPromotion + 5);
    self.minConfidenceForPromotion = MIN(95, self.minConfidenceForPromotion + 5);
    self.minSeenCount = (uint64_t)(self.minSeenCount * 1.2);
    self.maxBeaconScore = MAX(0.3, self.maxBeaconScore - 0.1);
}

- (void)decreaseThresholds {
    self.minScoreForPromotion = MAX(60, self.minScoreForPromotion - 5);
    self.minConfidenceForPromotion = MAX(50, self.minConfidenceForPromotion - 5);
    self.minSeenCount = (uint64_t)(self.minSeenCount * 0.8);
    self.maxBeaconScore = MIN(0.8, self.maxBeaconScore + 0.1);
}

@end

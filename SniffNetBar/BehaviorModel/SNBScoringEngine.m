//
//  SNBScoringEngine.m
//  SniffNetBar
//

#import "SNBScoringEngine.h"
#import "SNBEventSchema.h"
#import "SNBAggregateEngine.h"
#import "SNBModelingUtilities.h"
#import "SNBScoringConfig.h"
#import "SNBSystemProcessWhitelist.h"

@interface SNBScoringEngine ()
@property (nonatomic, strong) SNBScoringConfig *config;
@end

@implementation SNBScoringEngine

- (instancetype)initWithConfig:(SNBScoringConfig *)config {
    self = [super init];
    if (self) {
        _config = config ?: [SNBScoringConfig defaultConfig];
    }
    return self;
}

- (SNBRecommendation *)recommendationForEvent:(SNBFlowEvent *)event
                                     snapshot:(SNBAggregateSnapshot *)snapshot {
    NSInteger score = 50;
    NSMutableArray<NSDictionary *> *evidence = [NSMutableArray array];
    NSMutableArray<NSString *> *actions = [NSMutableArray array];
    uint64_t seenCount = snapshot ? snapshot.seenCount : 0;
    SNBScoringConfig *config = self.config ?: [SNBScoringConfig defaultConfig];

    // Track attribution bonuses to enforce cap
    NSInteger totalAttributionBonus = 0;

    // Check if process is whitelisted
    BOOL isWhitelisted = NO;
    double trustLevel = 0.0;
    if (config.processWhitelist && event.processName.length > 0) {
        isWhitelisted = [config.processWhitelist isProcessWhitelisted:event.processName];
        if (isWhitelisted) {
            trustLevel = [config.processWhitelist trustLevelForProcess:event.processName];
        }
    }

    // Process attribution scoring
    BOOL hasProcess = event.processName.length > 0;
    if (hasProcess) {
        NSInteger bonus = config.attributionBonus;
        totalAttributionBonus += bonus;
        score += bonus;
        [evidence addObject:@{@"type": @"attribution", @"detail": @"Process attribution available"}];

        // Add bonus for whitelisted system processes
        if (isWhitelisted) {
            NSInteger whitelistBonus = config.whitelistedProcessBonus;
            totalAttributionBonus += whitelistBonus;
            score += whitelistBonus;
            NSString *detail = [NSString stringWithFormat:@"Known system process (trust: %.0f%%)", trustLevel * 100];
            [evidence addObject:@{@"type": @"attribution", @"detail": detail}];
        }
    } else {
        // Missing attribution penalty - check if we should reduce/skip for whitelisted processes
        // Note: If process name is missing, we can't check whitelist, so full penalty applies
        score -= config.missingAttributionPenalty;
        [evidence addObject:@{@"type": @"attribution", @"detail": @"Missing process attribution"}];
    }

    // Signing status
    if ([event.signingStatus isEqualToString:@"signed"]) {
        NSInteger bonus = config.attributionBonus;
        totalAttributionBonus += bonus;
        score += bonus;
        [evidence addObject:@{@"type": @"attribution", @"detail": @"Signed binary"}];
    }

    // Bundle ID
    if (event.bundleID.length > 0) {
        NSInteger bonus = config.bundleIDBonus;
        totalAttributionBonus += bonus;
        score += bonus;
        [evidence addObject:@{@"type": @"attribution", @"detail": @"Bundle ID available"}];
    }

    // Parent process
    if (event.parentProcess.length > 0) {
        NSInteger bonus = config.parentProcessBonus;
        totalAttributionBonus += bonus;
        score += bonus;
        [evidence addObject:@{@"type": @"attribution", @"detail": @"Parent process available"}];
    }

    // Enforce attribution bonus cap
    if (totalAttributionBonus > config.maxAttributionBonus) {
        NSInteger excess = totalAttributionBonus - config.maxAttributionBonus;
        score -= excess;
    }

    // Repeat/history scoring
    if (seenCount > (uint64_t)config.repeatThresholdHigh) {
        score += config.repeatScoreBonus;
        [evidence addObject:@{@"type": @"behavior", @"detail": @"Repeated destination over time"}];
    } else if (seenCount <= (uint64_t)config.repeatThresholdLow) {
        // Reduce penalty for whitelisted processes with some history
        NSInteger penalty = config.repeatScorePenalty;
        if (isWhitelisted && seenCount >= (uint64_t)config.whitelistMinSeenCount) {
            penalty = (NSInteger)(penalty * config.whitelistedPenaltyMultiplier);
            [evidence addObject:@{@"type": @"behavior", @"detail": @"New destination (reduced penalty for system process)"}];
        } else {
            [evidence addObject:@{@"type": @"behavior", @"detail": @"New destination, limited history"}];
        }
        score -= penalty;
    }

    // Time-based novelty scoring
    if (snapshot) {
        NSString *hourKey = [NSString stringWithFormat:@"%ld",
                             (long)[[NSCalendar currentCalendar] component:NSCalendarUnitHour fromDate:event.end]];
        NSString *dowKey = [NSString stringWithFormat:@"%ld",
                            (long)[[NSCalendar currentCalendar] component:NSCalendarUnitWeekday fromDate:event.end]];
        double hourCount = [snapshot.hourHistogram[hourKey] doubleValue];
        double dowCount = [snapshot.dowHistogram[dowKey] doubleValue];

        if (seenCount > 0 && (hourCount / (double)seenCount) < config.timeNoveltyThreshold) {
            NSInteger penalty = config.timeNoveltyPenalty;
            // Reduce penalty for whitelisted system processes
            if (isWhitelisted && trustLevel >= config.highTrustThreshold) {
                penalty = (NSInteger)(penalty * config.whitelistedPenaltyMultiplier);
            }
            score -= penalty;
            [evidence addObject:@{@"type": @"behavior", @"detail": @"Unusual time-of-day for this destination"}];
        }

        if (seenCount > 0 && (dowCount / (double)seenCount) < config.timeNoveltyThreshold) {
            NSInteger penalty = config.timeNoveltyPenalty - 2;
            if (isWhitelisted && trustLevel >= config.highTrustThreshold) {
                penalty = (NSInteger)(penalty * config.whitelistedPenaltyMultiplier);
            }
            score -= penalty;
            [evidence addObject:@{@"type": @"behavior", @"detail": @"Unusual day-of-week for this destination"}];
        }

        // Beacon detection - still apply to whitelisted processes but note in evidence
        if (snapshot.beaconScore > config.beaconThreshold) {
            NSInteger penalty = config.beaconPenalty;
            // High-trust system processes may legitimately beacon (telemetry, updates, etc.)
            if (isWhitelisted && trustLevel >= config.highTrustThreshold) {
                penalty = (NSInteger)(penalty * config.whitelistedPenaltyMultiplier);
                [evidence addObject:@{@"type": @"behavior", @"detail": @"Regular interval pattern (expected for system service)"}];
            } else {
                [evidence addObject:@{@"type": @"behavior", @"detail": @"Regular interval pattern (possible beaconing)"}];
            }
            score -= penalty;
        }

        // Rolling window stability
        if (snapshot.seen1h > 10 || snapshot.seen24h > 50 || snapshot.seen7d > 200) {
            score += config.stableWindowBonus;
            [evidence addObject:@{@"type": @"behavior", @"detail": @"Stable activity across rolling windows"}];
        } else if (snapshot.seen1h <= 1 && snapshot.seen24h <= 3) {
            NSInteger penalty = config.sparseWindowPenalty;
            if (isWhitelisted && seenCount >= (uint64_t)config.whitelistMinSeenCount) {
                penalty = (NSInteger)(penalty * config.whitelistedPenaltyMultiplier);
            }
            score -= penalty;
            [evidence addObject:@{@"type": @"behavior", @"detail": @"Sparse history in rolling windows"}];
        }
    }

    // Direction penalty
    if ([event.direction isEqualToString:@"in"]) {
        score -= config.inboundPenalty;
        [evidence addObject:@{@"type": @"network", @"detail": @"Inbound connection"}];
    }

    // Volume anomaly
    if (snapshot && snapshot.bytesEwma > 0.0) {
        double currentBytes = (double)(event.bytesIn + event.bytesOut);
        double ratio = currentBytes / snapshot.bytesEwma;
        if (ratio > config.volumeAnomalyRatio) {
            score -= config.volumeAnomalyPenalty;
            [evidence addObject:@{@"type": @"behavior", @"detail": @"Unusually high data volume"}];
        }
    }

    // VPN/relay/hosting penalty
    if (event.vpn || event.relay || event.hosting) {
        score -= config.vpnRelayPenalty;
        [evidence addObject:@{@"type": @"network", @"detail": @"Connection via VPN/relay/hosting"}];
    }

    // Threat intel
    double intelScore = MAX(event.vtScore.doubleValue, event.abuseScore.doubleValue);
    if (intelScore >= config.threatScoreThreshold ||
        [event.greyNoiseClass isEqualToString:@"malicious"]) {
        // Always apply full threat penalty regardless of whitelist
        score -= config.threatPenalty;
        [evidence addObject:@{@"type": @"threat", @"detail": @"High-confidence threat intel signal"}];
    }

    // TLS fingerprint
    if (event.ja3.length > 0 || event.ja4.length > 0) {
        score += config.tlsFingerprintBonus;
        [evidence addObject:@{@"type": @"network", @"detail": @"TLS fingerprint observed"}];
    }

    // Long duration penalty
    if (event.duration >= config.longDurationThreshold) {
        NSInteger penalty = config.longDurationPenalty;
        // Long-lived connections are common for system services
        if (isWhitelisted && trustLevel >= 0.8) {
            penalty = (NSInteger)(penalty * config.whitelistedPenaltyMultiplier);
        }
        score -= penalty;
        [evidence addObject:@{@"type": @"network", @"detail": @"Long-lived connection"}];
    }

    // Connection failure penalty
    if ([event.outcome isEqualToString:@"fail"] || [event.outcome isEqualToString:@"reset"]) {
        score -= config.failurePenalty;
        [evidence addObject:@{@"type": @"network", @"detail": @"Failed connection attempts"}];
    }

    // Common ports bonus
    if (event.dstPort == 80 || event.dstPort == 443) {
        score += config.commonPortBonus;
        [evidence addObject:@{@"type": @"network", @"detail": @"Common web port"}];
    }

    // ASN/Org/Geo anomaly detection
    BOOL asnAnomaly = NO;
    if (snapshot) {
        if (snapshot.baselineASN.length > 0 && event.asn.length > 0 &&
            ![snapshot.baselineASN isEqualToString:event.asn]) {
            asnAnomaly = YES;
        }
        if (snapshot.baselineOrg.length > 0 && event.org.length > 0 &&
            ![snapshot.baselineOrg isEqualToString:event.org]) {
            asnAnomaly = YES;
        }
        NSString *currentGeo = @"";
        if (event.country.length > 0 || event.region.length > 0) {
            currentGeo = [NSString stringWithFormat:@"%@-%@", event.country ?: @"", event.region ?: @""];
        }
        if (snapshot.baselineGeo.length > 0 && currentGeo.length > 0 &&
            ![snapshot.baselineGeo isEqualToString:currentGeo]) {
            asnAnomaly = YES;
        }
        if (asnAnomaly) {
            NSInteger penalty = config.asnAnomalyPenalty;
            // CDN-based services (like Apple) may have legitimate ASN variance
            if (isWhitelisted && trustLevel >= config.highTrustThreshold) {
                penalty = (NSInteger)(penalty * config.whitelistedPenaltyMultiplier);
            }
            score -= penalty;
            [evidence addObject:@{@"type": @"network", @"detail": @"ASN/org/geo deviates from baseline"}];
        }
    }

    // Clamp score to valid range
    score = MAX(0, MIN(100, score));

    // Determine label based on score
    NSString *label = @"Unclear";
    if (score >= 70) {
        label = @"Likely Legitimate";
        [actions addObject:@"Recommend: Mark as Trusted (app + destination)"];
    } else if (score <= 30) {
        label = @"Likely Suspicious";
        [actions addObject:@"Recommend: Observe longer or restrict by app"];
    } else {
        [actions addObject:@"Recommend: Observe longer"];
    }

    // Calculate confidence based on available data points
    NSInteger dataPoints = 0;
    if (hasProcess) {
        dataPoints += 1;
    }
    if (isWhitelisted) {
        dataPoints += 1; // Extra confidence for known processes
    }
    if (snapshot && snapshot.seenCount > 5) {
        dataPoints += 1;
    }
    if (event.sni.length > 0) {
        dataPoints += 1;
    }
    if (event.parentProcess.length > 0) {
        dataPoints += 1;
    }
    if (event.ja3.length > 0 || event.ja4.length > 0) {
        dataPoints += 1;
    }
    if (event.asn.length > 0 || event.org.length > 0) {
        dataPoints += 1;
    }
    NSInteger baseConfidence = MIN(95, 40 + (dataPoints * 15));
    NSInteger confidence = baseConfidence;
    NSString *summary = [NSString stringWithFormat:@"Score %ld with %llu sightings",
                         (long)score, (unsigned long long)seenCount];

    // Build recommendation
    SNBRecommendation *recommendation = [[SNBRecommendation alloc] init];
    recommendation.clusterID = SNBClusterIDForEvent(event);
    recommendation.extendedContext = SNBExtendedContextJSONForEvent(event);
    recommendation.asnAnomaly = asnAnomaly;
    recommendation.baseConfidence = baseConfidence;
    recommendation.score = score;
    recommendation.label = label;
    recommendation.confidence = confidence;
    recommendation.summary = summary;
    recommendation.evidence = evidence;
    recommendation.actions = actions;
    recommendation.generatedAt = [NSDate date];

    // Handle IP-only connections (no domain info)
    if (SNBEventIsIPOnly(event)) {
        recommendation.ipOnly = YES;
        recommendation.confidence = MIN(30, recommendation.baseConfidence);
        if ([recommendation.label isEqualToString:@"Likely Legitimate"]) {
            recommendation.label = @"Unclear";
            [actions addObject:@"Recommend: Confirm legitimacy before trusting"];
        }
        [evidence addObject:@{@"type": @"network", @"detail": @"No domain info (IP-only)"}];
    }

    return recommendation;
}

- (SNBRecommendation *)applyUserLabel:(NSString *)label
                       toRecommendation:(SNBRecommendation *)recommendation {
    if (!recommendation || label.length == 0) {
        return recommendation;
    }
    if ([label isEqualToString:@"Trusted"]) {
        recommendation.label = @"Likely Legitimate";
        recommendation.confidence = 95;
        recommendation.summary = @"User trusted this cluster";
        return recommendation;
    }
    if ([label isEqualToString:@"Blocked"]) {
        recommendation.label = @"Likely Suspicious";
        recommendation.confidence = 95;
        recommendation.summary = @"User blocked this cluster";
        return recommendation;
    }
    return recommendation;
}

@end

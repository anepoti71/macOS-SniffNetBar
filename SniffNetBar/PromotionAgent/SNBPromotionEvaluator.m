//
//  SNBPromotionEvaluator.m
//  SniffNetBar
//

#import "SNBPromotionEvaluator.h"
#import "SNBPromotionPolicy.h"
#import "SNBPromotionCandidate.h"
#import "SNBPromotionDecision.h"
#import "SNBOllamaClient.h"
#import "Logger.h"

// Thresholds for fast path decisions
static const NSInteger kAutoPromoteMinScore = 90;
static const NSInteger kAutoBlockVTScore = 5;
static const double kAutoBlockAbuseScore = 80.0;
static const NSInteger kAmbiguousMinScore = 60;
static const NSInteger kAmbiguousMaxScore = 89;

@implementation SNBEvaluationResult
@end

@interface SNBPromotionEvaluator ()
@property (nonatomic, strong, readwrite) SNBPromotionPolicy *policy;
@property (nonatomic, strong, readwrite) SNBOllamaClient *ollamaClient;
@end

@implementation SNBPromotionEvaluator

- (instancetype)initWithPolicy:(SNBPromotionPolicy *)policy {
    return [self initWithPolicy:policy ollamaClient:nil];
}

- (instancetype)initWithPolicy:(SNBPromotionPolicy *)policy
                  ollamaClient:(SNBOllamaClient *)ollamaClient {
    self = [super init];
    if (self) {
        _policy = policy;
        _ollamaClient = ollamaClient;
        _aiEnabled = (ollamaClient != nil);
    }
    return self;
}

#pragma mark - Public Methods

- (void)evaluateCandidate:(SNBPromotionCandidate *)candidate
               completion:(void (^)(SNBEvaluationResult *))completion {
    NSString *actionNames[] = {@"None", @"Suggest", @"AutoPromote", @"AutoBlock", @"NeedsReview"};

    // Check if candidate should be skipped
    SNBPromotionDecision *skipDecision = [self checkSkipConditions:candidate];
    if (skipDecision) {
        SNBLogAgentDebug("Eval %{public}@: SKIPPED - %{public}@",
                        candidate.clusterID, skipDecision.reason);
        SNBEvaluationResult *result = [[SNBEvaluationResult alloc] init];
        result.decision = skipDecision;
        result.path = SNBEvaluationPathSkipped;
        result.aiAssisted = NO;
        completion(result);
        return;
    }

    // Try fast path first
    SNBPromotionDecision *fastDecision = [self evaluateFastPath:candidate];
    if (fastDecision.action != SNBPromotionActionNone ||
        ![self needsAIEvaluation:candidate]) {
        SNBLogAgentInfo("Eval %{public}@: FAST -> %{public}@ (score=%ld, blockers=%lu) reason=%{public}@",
                       candidate.clusterID,
                       actionNames[fastDecision.action],
                       (long)candidate.score,
                       (unsigned long)fastDecision.blockers.count,
                       fastDecision.reason);
        SNBEvaluationResult *result = [[SNBEvaluationResult alloc] init];
        result.decision = fastDecision;
        result.path = SNBEvaluationPathFast;
        result.aiAssisted = NO;
        completion(result);
        return;
    }

    // Route to AI for ambiguous cases
    if (self.aiEnabled && self.ollamaClient) {
        SNBLogAgentInfo("Eval %{public}@: routing to AI (score=%ld, ambiguous)",
                       candidate.clusterID, (long)candidate.score);
        [self evaluateSlowPath:candidate completion:completion];
    } else {
        // No AI available, return fast path result
        SNBLogAgentInfo("Eval %{public}@: FAST (no AI) -> %{public}@ reason=%{public}@",
                       candidate.clusterID,
                       actionNames[fastDecision.action],
                       fastDecision.reason);
        SNBEvaluationResult *result = [[SNBEvaluationResult alloc] init];
        result.decision = fastDecision;
        result.path = SNBEvaluationPathFast;
        result.aiAssisted = NO;
        completion(result);
    }
}

- (SNBPromotionDecision *)evaluateFastPath:(SNBPromotionCandidate *)candidate {
    SNBPromotionDecision *decision = [[SNBPromotionDecision alloc] init];
    decision.clusterID = candidate.clusterID;
    decision.score = candidate.score;
    decision.seenCount = candidate.seenCount;
    decision.processName = candidate.processName;
    decision.destinationFamily = candidate.dstDomain;
    decision.destinationIP = candidate.dstIP;
    decision.extendedContext = candidate.extendedContext;

    NSMutableArray<NSString *> *factors = [NSMutableArray array];
    NSMutableArray<NSString *> *blockers = [NSMutableArray array];

    // Check for auto-block conditions (threat intel)
    if (candidate.vtScore > kAutoBlockVTScore) {
        decision.action = SNBPromotionActionAutoBlock;
        decision.reason = [NSString stringWithFormat:@"High VirusTotal score (%.1f)", candidate.vtScore];
        decision.confidence = 95;
        [factors addObject:@"vtScore > threshold"];
        decision.factors = factors;
        return decision;
    }

    if (candidate.abuseScore > kAutoBlockAbuseScore) {
        decision.action = SNBPromotionActionAutoBlock;
        decision.reason = [NSString stringWithFormat:@"High AbuseIPDB score (%.1f)", candidate.abuseScore];
        decision.confidence = 95;
        [factors addObject:@"abuseScore > threshold"];
        decision.factors = factors;
        return decision;
    }

    if ([candidate.greyNoiseClass.lowercaseString isEqualToString:@"malicious"]) {
        decision.action = SNBPromotionActionAutoBlock;
        decision.reason = @"GreyNoise classified as malicious";
        decision.confidence = 90;
        [factors addObject:@"greyNoise = malicious"];
        decision.factors = factors;
        return decision;
    }

    // Gather factors and blockers for promotion decision
    BOOL isSigned = [candidate.signingStatus isEqualToString:@"signed"] ||
                    [candidate.signingStatus isEqualToString:@"apple"];
    BOOL hasDomainInfo = candidate.dstDomain.length > 0;
    BOOL hasThreatIntel = candidate.vtScore > 0 || candidate.abuseScore > 0;
    BOOL isExcludedProcess = [self.policy.neverAutoTrustProcesses containsObject:candidate.processName];
    BOOL isExcludedPort = [self.policy.neverAutoTrustPorts containsObject:@(candidate.dstPort)];
    NSTimeInterval observationPeriod = candidate.firstSeen ? [[NSDate date] timeIntervalSinceDate:candidate.firstSeen] : 0;

    // Add factors
    if (candidate.score >= kAutoPromoteMinScore) {
        [factors addObject:@"highScore"];
    }
    if (isSigned) {
        [factors addObject:@"signedProcess"];
    }
    if (hasDomainInfo) {
        [factors addObject:@"hasDomain"];
    }
    if (candidate.seenCount >= self.policy.minSeenCount) {
        [factors addObject:@"sufficientHistory"];
    }
    if (candidate.beaconScore < self.policy.maxBeaconScore) {
        [factors addObject:@"lowBeaconScore"];
    }
    if (candidate.seen7d >= self.policy.minSeen7d) {
        [factors addObject:@"consistentActivity"];
    }

    // Add blockers
    if (self.policy.requireSignedProcess && !isSigned) {
        [blockers addObject:@"unsignedProcess"];
    }
    if (self.policy.requireDomainInfo && !hasDomainInfo) {
        [blockers addObject:@"noDomainInfo"];
    }
    if (self.policy.requireNoThreatIntel && hasThreatIntel) {
        [blockers addObject:@"hasThreatIntel"];
    }
    if (self.policy.requireNoASNAnomaly && candidate.asnAnomaly) {
        [blockers addObject:@"asnAnomaly"];
    }
    if (self.policy.requireNoBeaconBehavior && candidate.beaconScore > self.policy.maxBeaconScore) {
        [blockers addObject:@"beaconBehavior"];
    }
    if (isExcludedProcess) {
        [blockers addObject:@"excludedProcess"];
    }
    if (isExcludedPort) {
        [blockers addObject:@"excludedPort"];
    }
    if (candidate.seenCount < self.policy.minSeenCount) {
        [blockers addObject:@"insufficientHistory"];
    }
    if (observationPeriod < self.policy.minObservationPeriod) {
        [blockers addObject:@"observationTooShort"];
    }
    if (candidate.ipOnly) {
        [blockers addObject:@"ipOnly"];
    }

    decision.factors = factors;
    decision.blockers = blockers;

    // AUTO-PROMOTE: High score with no blockers
    if (candidate.score >= kAutoPromoteMinScore &&
        blockers.count == 0 &&
        self.policy.level >= SNBAutomationLevelConservative) {
        decision.action = SNBPromotionActionAutoPromote;
        decision.reason = @"High behavioral score with no red flags";
        decision.confidence = MIN(95, candidate.score);
        return decision;
    }

    // SUGGEST: Good score but automation level requires user approval (SuggestOnly mode)
    if (candidate.score >= self.policy.minScoreForPromotion &&
        candidate.confidence >= self.policy.minConfidenceForPromotion &&
        blockers.count == 0 &&
        self.policy.level == SNBAutomationLevelSuggestOnly) {
        decision.action = SNBPromotionActionSuggest;
        decision.reason = @"Good behavioral score, suggest for user approval";
        decision.confidence = candidate.confidence;
        return decision;
    }

    // SUGGEST: Ambiguous score range (60-89) with sufficient history for Conservative+ levels
    // These are candidates that score well but not perfectly - suggest to user for review
    if (candidate.score >= kAmbiguousMinScore &&
        candidate.score < kAutoPromoteMinScore &&
        candidate.seenCount >= 10 &&  // Minimum history requirement
        self.policy.level >= SNBAutomationLevelConservative) {

        // Check for critical blockers that should prevent suggestion
        BOOL hasCriticalBlockers = [blockers containsObject:@"excludedProcess"] ||
                                   [blockers containsObject:@"excludedPort"] ||
                                   [blockers containsObject:@"hasThreatIntel"];

        if (!hasCriticalBlockers) {
            decision.action = SNBPromotionActionSuggest;
            if (blockers.count > 0) {
                decision.reason = [NSString stringWithFormat:@"Good score (%ld), minor concerns: %@",
                                   (long)candidate.score, [blockers componentsJoinedByString:@", "]];
            } else {
                decision.reason = [NSString stringWithFormat:@"Moderate score (%ld), needs more observation or user decision",
                                   (long)candidate.score];
            }
            decision.confidence = candidate.confidence;
            return decision;
        }
    }

    // NEEDS REVIEW: Score below threshold but has positive signals
    if (candidate.score >= 50 &&
        candidate.seenCount >= 20 &&
        factors.count >= 2 &&
        self.policy.level >= SNBAutomationLevelModerate) {

        BOOL hasCriticalBlockers = [blockers containsObject:@"excludedProcess"] ||
                                   [blockers containsObject:@"excludedPort"] ||
                                   [blockers containsObject:@"hasThreatIntel"];

        if (!hasCriticalBlockers) {
            decision.action = SNBPromotionActionNeedsReview;
            decision.reason = [NSString stringWithFormat:@"Mixed signals - score %ld with %lu positive factors",
                               (long)candidate.score, (unsigned long)factors.count];
            decision.confidence = candidate.confidence;
            return decision;
        }
    }

    // Default: Keep observing
    decision.action = SNBPromotionActionNone;
    if (blockers.count > 0) {
        decision.reason = [NSString stringWithFormat:@"Blocked by: %@", [blockers componentsJoinedByString:@", "]];
    } else {
        decision.reason = @"Score below threshold";
    }
    decision.confidence = candidate.confidence;

    return decision;
}

- (BOOL)needsAIEvaluation:(SNBPromotionCandidate *)candidate {
    // Already has user label - no evaluation needed
    if (candidate.userLabel.length > 0) {
        return NO;
    }

    // Too new for evaluation
    if (candidate.seenCount < 5) {
        return NO;
    }

    // Clear-cut high score - no AI needed
    if (candidate.score >= kAutoPromoteMinScore && !candidate.ipOnly && !candidate.asnAnomaly) {
        return NO;
    }

    // Clear-cut threat intel - no AI needed
    if (candidate.vtScore > kAutoBlockVTScore || candidate.abuseScore > kAutoBlockAbuseScore) {
        return NO;
    }

    // Ambiguous score range - AI can help
    if (candidate.score >= kAmbiguousMinScore && candidate.score <= kAmbiguousMaxScore) {
        return YES;
    }

    // Mixed signals that could benefit from AI reasoning
    BOOL hasPositiveSignals = candidate.score >= 50 || candidate.seenCount > 100;
    BOOL hasNegativeSignals = candidate.ipOnly || candidate.asnAnomaly ||
                              candidate.beaconScore > 0.5 || candidate.hosting;

    if (hasPositiveSignals && hasNegativeSignals) {
        return YES;
    }

    return NO;
}

#pragma mark - Private Methods

- (SNBPromotionDecision *)checkSkipConditions:(SNBPromotionCandidate *)candidate {
    // Already has user label - skip
    if (candidate.userLabel.length > 0) {
        SNBPromotionDecision *decision = [[SNBPromotionDecision alloc] init];
        decision.clusterID = candidate.clusterID;
        decision.action = SNBPromotionActionNone;
        decision.reason = @"User label exists";
        decision.confidence = 100;
        return decision;
    }

    // Automation disabled - skip
    if (self.policy.level == SNBAutomationLevelOff) {
        SNBPromotionDecision *decision = [[SNBPromotionDecision alloc] init];
        decision.clusterID = candidate.clusterID;
        decision.action = SNBPromotionActionNone;
        decision.reason = @"Automation disabled";
        decision.confidence = 100;
        return decision;
    }

    // Excluded process - skip
    if ([self.policy.neverAutoTrustProcesses containsObject:candidate.processName]) {
        SNBPromotionDecision *decision = [[SNBPromotionDecision alloc] init];
        decision.clusterID = candidate.clusterID;
        decision.action = SNBPromotionActionNone;
        decision.reason = [NSString stringWithFormat:@"Excluded process: %@", candidate.processName];
        decision.confidence = 100;
        decision.blockers = @[@"excludedProcess"];
        return decision;
    }

    return nil;
}

- (void)evaluateSlowPath:(SNBPromotionCandidate *)candidate
              completion:(void (^)(SNBEvaluationResult *))completion {
    SNBLogAgentInfo("Routing to AI evaluation for cluster: %{public}@", candidate.clusterID);

    [self.ollamaClient evaluateCandidate:candidate completion:^(SNBPromotionDecision *aiDecision, NSError *error) {
        SNBEvaluationResult *result = [[SNBEvaluationResult alloc] init];
        result.path = SNBEvaluationPathSlow;
        result.aiAssisted = YES;

        if (error || !aiDecision) {
            SNBLogAgentWarn("AI evaluation failed, falling back to fast path: %{public}@", error.localizedDescription);
            // Fall back to fast path on error
            result.decision = [self evaluateFastPath:candidate];
            result.aiAssisted = NO;
            result.aiReasoning = error.localizedDescription;
        } else {
            result.decision = aiDecision;
            result.aiReasoning = aiDecision.reason;

            // Apply policy constraints to AI decision
            result.decision = [self applyPolicyConstraints:aiDecision candidate:candidate];
        }

        completion(result);
    }];
}

- (SNBPromotionDecision *)applyPolicyConstraints:(SNBPromotionDecision *)aiDecision
                                       candidate:(SNBPromotionCandidate *)candidate {
    // Prevent AI from auto-promoting if policy is suggest-only
    if (aiDecision.action == SNBPromotionActionAutoPromote &&
        self.policy.level == SNBAutomationLevelSuggestOnly) {
        SNBPromotionDecision *constrained = [[SNBPromotionDecision alloc] init];
        constrained.clusterID = aiDecision.clusterID;
        constrained.action = SNBPromotionActionSuggest;
        constrained.reason = [NSString stringWithFormat:@"AI recommends trust: %@", aiDecision.reason];
        constrained.confidence = aiDecision.confidence;
        constrained.factors = aiDecision.factors;
        constrained.blockers = @[@"policyRequiresApproval"];
        constrained.score = aiDecision.score;
        constrained.seenCount = aiDecision.seenCount;
        constrained.processName = aiDecision.processName;
        constrained.destinationFamily = aiDecision.destinationFamily;
        constrained.destinationIP = aiDecision.destinationIP;
        constrained.extendedContext = aiDecision.extendedContext;
        return constrained;
    }

    // Prevent AI from auto-blocking without high confidence
    if (aiDecision.action == SNBPromotionActionAutoBlock && aiDecision.confidence < 80) {
        SNBPromotionDecision *constrained = [[SNBPromotionDecision alloc] init];
        constrained.clusterID = aiDecision.clusterID;
        constrained.action = SNBPromotionActionNeedsReview;
        constrained.reason = [NSString stringWithFormat:@"AI suggests block (low confidence): %@", aiDecision.reason];
        constrained.confidence = aiDecision.confidence;
        constrained.factors = aiDecision.factors;
        constrained.blockers = @[@"lowConfidenceBlock"];
        constrained.score = aiDecision.score;
        constrained.seenCount = aiDecision.seenCount;
        constrained.processName = aiDecision.processName;
        constrained.destinationFamily = aiDecision.destinationFamily;
        constrained.destinationIP = aiDecision.destinationIP;
        constrained.extendedContext = aiDecision.extendedContext;
        return constrained;
    }

    return aiDecision;
}

@end

//
//  SNBPromotionAgent.m
//  SniffNetBar
//

#import "SNBPromotionAgent.h"
#import "SNBPromotionPolicy.h"
#import "SNBPromotionDecision.h"
#import "SNBPromotionCandidate.h"
#import "SNBPromotionEvaluator.h"
#import "SNBPromotionLog.h"
#import "SNBOllamaClient.h"
#import "SNBEventPublisher.h"
#import "SNBTimerCoordinator.h"
#import "ConfigurationManager.h"
#import "TrustedIPStore.h"
#import "Logger.h"

static const NSTimeInterval kDefaultEvaluationInterval = 900.0;  // 15 minutes
@interface SNBPromotionAgent ()
@property (nonatomic, strong, readwrite) SNBPromotionPolicy *policy;
@property (nonatomic, assign, readwrite) BOOL isRunning;
@property (nonatomic, assign, readwrite) BOOL aiAvailable;
@property (nonatomic, strong) SNBEventPublisher *eventPublisher;
@property (nonatomic, strong) SNBOllamaClient *ollamaClient;
@property (nonatomic, strong) SNBPromotionEvaluator *evaluator;
@property (nonatomic, strong) SNBPromotionLog *promotionLog;
@property (nonatomic, copy, nullable) SNBTimerID evaluationTimerID;
@property (nonatomic, copy, nullable) SNBTimerID idleTimerID;
@property (nonatomic, strong) NSMutableArray<SNBPromotionDecision *> *pendingSuggestionsArray;
@property (nonatomic, strong) dispatch_queue_t evaluationQueue;
@property (nonatomic, assign) BOOL evaluationInProgress;

// Statistics
@property (nonatomic, assign) NSUInteger totalEvaluations;
@property (nonatomic, assign) NSUInteger fastPathDecisions;
@property (nonatomic, assign) NSUInteger slowPathDecisions;
@property (nonatomic, assign) NSUInteger autoPromotions;
@property (nonatomic, assign) NSUInteger autoBlocks;
@property (nonatomic, assign) NSUInteger suggestions;
@end

@implementation SNBPromotionAgent

- (instancetype)initWithEventPublisher:(SNBEventPublisher *)publisher
                                policy:(SNBPromotionPolicy *)policy {
    self = [super init];
    if (self) {
        _eventPublisher = publisher;
        _policy = policy;
        _evaluationInterval = kDefaultEvaluationInterval;
        _isRunning = NO;
        _aiAvailable = NO;
        _evaluationInProgress = NO;
        _pendingSuggestionsArray = [NSMutableArray array];
        _evaluationQueue = dispatch_queue_create("com.sniffnetbar.promotionagent", DISPATCH_QUEUE_SERIAL);

        // Initialize Ollama client using configuration defaults
        ConfigurationManager *config = [ConfigurationManager sharedManager];
        _ollamaClient = [[SNBOllamaClient alloc] initWithBaseURL:config.promotionOllamaBaseURL
                                                          model:config.promotionOllamaModel];
        _ollamaClient.timeout = config.promotionOllamaTimeout;

        // Initialize promotion log
        NSString *logPath = [[self applicationSupportDirectory] stringByAppendingPathComponent:@"promotion_log.sqlite"];
        _promotionLog = [[SNBPromotionLog alloc] initWithDatabasePath:logPath];

        _evaluator = nil;
    }
    return self;
}

#pragma mark - Control

- (void)start {
    if (self.isRunning) {
        SNBLogAgentInfo("Promotion agent already running, ignoring start");
        return;
    }

    SNBLogAgentInfo("=== PROMOTION AGENT STARTING === interval=%.0fs", self.evaluationInterval);
    SNBLogAgentInfo("Policy level=%ld minScore=%ld minConf=%ld minSeen=%llu",
                   (long)self.policy.level,
                   (long)self.policy.minScoreForPromotion,
                   (long)self.policy.minConfidenceForPromotion,
                   (unsigned long long)self.policy.minSeenCount);
    self.isRunning = YES;

    if (!self.evaluator) {
        self.evaluator = [[SNBPromotionEvaluator alloc] initWithPolicy:self.policy ollamaClient:nil];
    }
    if (self.idleTimerID) {
        [[SNBTimerCoordinator sharedCoordinator] cancelTimer:self.idleTimerID];
        self.idleTimerID = nil;
    }

    // Check AI availability
    [self checkAIAvailability:^(BOOL available) {
        if (available) {
            SNBLogAgentInfo("Ollama AI available, enabling hybrid evaluation");
            self.aiAvailable = YES;
            self.evaluator = [[SNBPromotionEvaluator alloc] initWithPolicy:self.policy
                                                              ollamaClient:self.ollamaClient];
            self.evaluator.aiEnabled = YES;
        } else {
            SNBLogAgentInfo("Ollama AI not available, using rule-based evaluation only");
            self.aiAvailable = NO;
            self.evaluator.aiEnabled = NO;
        }
    }];

    // Schedule periodic evaluation
    [self scheduleEvaluationTimerIfNeeded];

    // Run initial evaluation after a short delay
    __weak typeof(self) weakSelf = self;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        [weakSelf evaluateNow];
    });
}

- (void)stop {
    if (!self.isRunning) {
        return;
    }

    SNBLogAgentInfo("Stopping promotion agent");
    self.isRunning = NO;

    if (self.evaluationTimerID) {
        SNBTimerCoordinator *coordinator = [SNBTimerCoordinator sharedCoordinator];
        [coordinator cancelTimer:self.evaluationTimerID];
        self.evaluationTimerID = nil;
    }
    if (self.idleTimerID) {
        SNBTimerCoordinator *coordinator = [SNBTimerCoordinator sharedCoordinator];
        [coordinator cancelTimer:self.idleTimerID];
        self.idleTimerID = nil;
    }
}

- (void)evaluateNow {
    SNBLogAgentInfo("evaluateNow called (inProgress=%d, isRunning=%d)",
                   self.evaluationInProgress, self.isRunning);

    if (self.evaluationInProgress) {
        SNBLogAgentInfo("Evaluation already in progress, skipping");
        return;
    }

    self.evaluationInProgress = YES;
    SNBLogAgentInfo("=== STARTING PROMOTION EVALUATION CYCLE ===");

    [self fetchPromotionCandidates:^(NSArray<SNBPromotionCandidate *> *candidates) {
        if (candidates.count == 0) {
            SNBLogAgentInfo("No promotion candidates found");
            self.evaluationInProgress = NO;
            if (self.evaluationTimerID) {
                SNBTimerCoordinator *coordinator = [SNBTimerCoordinator sharedCoordinator];
                [coordinator cancelTimer:self.evaluationTimerID];
                self.evaluationTimerID = nil;
                [self scheduleIdleCheck];
            }
            dispatch_async(dispatch_get_main_queue(), ^{
                if ([self.delegate respondsToSelector:@selector(promotionAgentDidCompleteEvaluation:)]) {
                    [self.delegate promotionAgentDidCompleteEvaluation:self];
                }
            });
            return;
        }

        SNBLogAgentInfo("Evaluating %lu promotion candidates", (unsigned long)candidates.count);
        // Log candidate summary for debugging
        for (SNBPromotionCandidate *c in candidates) {
            SNBLogAgentDebug("Candidate: cluster=%{public}@ score=%ld conf=%ld seen=%llu userLabel=%{public}@ label=%{public}@",
                            c.clusterID, (long)c.score, (long)c.confidence,
                            (unsigned long long)c.seenCount, c.userLabel ?: @"(none)", c.label ?: @"(none)");
        }
        [self scheduleEvaluationTimerIfNeeded];
        [self evaluateCandidates:candidates];
    }];
}

- (void)scheduleEvaluationTimerIfNeeded {
    if (self.evaluationTimerID) {
        return;
    }
    __weak typeof(self) weakSelf = self;
    SNBTimerCoordinator *coordinator = [SNBTimerCoordinator sharedCoordinator];
    self.evaluationTimerID = [coordinator scheduleRepeatingTimerWithInterval:self.evaluationInterval
                                                                       queue:dispatch_get_main_queue()
                                                                     handler:^{
        [weakSelf evaluateNow];
    }];
}

- (void)scheduleIdleCheck {
    if (self.idleTimerID) {
        return;
    }
    NSTimeInterval delay = MAX(self.evaluationInterval * 2.0, 60.0);
    __weak typeof(self) weakSelf = self;
    SNBTimerCoordinator *coordinator = [SNBTimerCoordinator sharedCoordinator];
    self.idleTimerID = [coordinator scheduleOneShotTimerWithDelay:delay
                                                           queue:dispatch_get_main_queue()
                                                         handler:^{
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) {
            return;
        }
        strongSelf.idleTimerID = nil;
        if (strongSelf.isRunning) {
            [strongSelf scheduleEvaluationTimerIfNeeded];
            [strongSelf evaluateNow];
        }
    }];
}

- (void)checkAIAvailability:(void (^)(BOOL))completion {
    [self.ollamaClient pingWithCompletion:^(BOOL available) {
        self.aiAvailable = available;
        if (completion) {
            completion(available);
        }
    }];
}

#pragma mark - Pending Suggestions

- (NSArray<SNBPromotionDecision *> *)pendingSuggestions {
    @synchronized (self.pendingSuggestionsArray) {
        return [self.pendingSuggestionsArray copy];
    }
}

- (void)approveSuggestion:(SNBPromotionDecision *)decision {
    @synchronized (self.pendingSuggestionsArray) {
        [self.pendingSuggestionsArray removeObject:decision];
    }

    // Apply the promotion via XPC
    [self applyPromotion:decision.clusterID label:@"Trusted" reason:decision.reason];
    [self.promotionLog markDecisionApplied:decision.clusterID];

    SNBLogAgentInfo("User approved suggestion for cluster: %{public}@", decision.clusterID);
}

- (void)rejectSuggestion:(SNBPromotionDecision *)decision {
    @synchronized (self.pendingSuggestionsArray) {
        [self.pendingSuggestionsArray removeObject:decision];
    }

    // Log the user override
    [self.promotionLog logUserOverride:decision.clusterID
                            fromAction:decision.action
                             toLabel:@"untrusted"];

    SNBLogAgentInfo("User rejected suggestion for cluster: %{public}@", decision.clusterID);
}

- (void)clearSuggestion:(SNBPromotionDecision *)decision {
    @synchronized (self.pendingSuggestionsArray) {
        [self.pendingSuggestionsArray removeObject:decision];
    }
}

#pragma mark - Statistics

- (NSDictionary<NSString *, NSNumber *> *)statistics {
    return @{
        @"totalEvaluations": @(self.totalEvaluations),
        @"fastPathDecisions": @(self.fastPathDecisions),
        @"slowPathDecisions": @(self.slowPathDecisions),
        @"autoPromotions": @(self.autoPromotions),
        @"autoBlocks": @(self.autoBlocks),
        @"suggestions": @(self.suggestions),
        @"aiAvailable": @(self.aiAvailable),
        @"aiAccuracyRate": @([self.promotionLog aiAccuracyRate]),
        @"userOverrideRate": @([self.promotionLog userOverrideRate])
    };
}

#pragma mark - Private Methods

- (void)fetchPromotionCandidates:(void (^)(NSArray<SNBPromotionCandidate *> *))completion {
    SNBLogAgentInfo("Fetching promotion candidates via XPC...");

    [self.eventPublisher getPromotionCandidatesWithCompletion:^(NSArray<SNBPromotionCandidate *> *candidates) {
        SNBLogAgentInfo("XPC returned %lu candidates", (unsigned long)(candidates ? candidates.count : 0));
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(candidates ?: @[]);
        });
    }];
}

- (void)evaluateCandidates:(NSArray<SNBPromotionCandidate *> *)candidates {
    dispatch_async(self.evaluationQueue, ^{
        dispatch_group_t group = dispatch_group_create();

        for (SNBPromotionCandidate *candidate in candidates) {
            dispatch_group_enter(group);

            [self.evaluator evaluateCandidate:candidate completion:^(SNBEvaluationResult *result) {
                self.totalEvaluations++;

                if (result.path == SNBEvaluationPathFast) {
                    self.fastPathDecisions++;
                } else if (result.path == SNBEvaluationPathSlow) {
                    self.slowPathDecisions++;
                }

                // Log the decision
                [self.promotionLog logDecision:result.decision
                                    aiAssisted:result.aiAssisted
                                   aiReasoning:result.aiReasoning];

                // Handle the decision
                [self handleDecision:result.decision aiAssisted:result.aiAssisted];

                dispatch_group_leave(group);
            }];
        }

        // Wait with timeout to prevent deadlock if evaluator hangs
        static const NSTimeInterval kEvaluationTimeoutSeconds = 120.0;
        dispatch_time_t timeout = dispatch_time(DISPATCH_TIME_NOW,
                                                (int64_t)(kEvaluationTimeoutSeconds * NSEC_PER_SEC));
        long result = dispatch_group_wait(group, timeout);
        if (result != 0) {
            SNBLogAgentWarn("Promotion evaluation timed out after %.0fs, some candidates incomplete",
                           kEvaluationTimeoutSeconds);
        }

        dispatch_async(dispatch_get_main_queue(), ^{
            self.evaluationInProgress = NO;
            SNBLogAgentInfo("Promotion evaluation cycle complete: %lu evaluated", (unsigned long)candidates.count);

            if ([self.delegate respondsToSelector:@selector(promotionAgentDidCompleteEvaluation:)]) {
                [self.delegate promotionAgentDidCompleteEvaluation:self];
            }
        });
    });
}

- (void)handleDecision:(SNBPromotionDecision *)decision aiAssisted:(BOOL)aiAssisted {
    dispatch_async(dispatch_get_main_queue(), ^{
        switch (decision.action) {
            case SNBPromotionActionAutoPromote:
                self.autoPromotions++;
                [self applyPromotion:decision.clusterID label:@"Trusted" reason:decision.reason];
                [self trustDecisionDestination:decision];
                [self.promotionLog markDecisionApplied:decision.clusterID];
                if ([self.delegate respondsToSelector:@selector(promotionAgent:didAutoPromote:)]) {
                    [self.delegate promotionAgent:self didAutoPromote:decision];
                }
                SNBLogAgentInfo("Auto-promoted cluster: %{public}@ (AI=%d)", decision.clusterID, aiAssisted);
                break;

            case SNBPromotionActionAutoBlock:
                self.autoBlocks++;
                [self applyPromotion:decision.clusterID label:@"Blocked" reason:decision.reason];
                [self.promotionLog markDecisionApplied:decision.clusterID];
                if ([self.delegate respondsToSelector:@selector(promotionAgent:didAutoBlock:)]) {
                    [self.delegate promotionAgent:self didAutoBlock:decision];
                }
                SNBLogAgentInfo("Auto-blocked cluster: %{public}@ (AI=%d)", decision.clusterID, aiAssisted);
                break;

            case SNBPromotionActionSuggest:
                self.autoPromotions++;
                [self applyPromotion:decision.clusterID label:@"Trusted" reason:decision.reason];
                [self trustDecisionDestination:decision];
                [self.promotionLog markDecisionApplied:decision.clusterID];
                if ([self.delegate respondsToSelector:@selector(promotionAgent:didAutoPromote:)]) {
                    [self.delegate promotionAgent:self didAutoPromote:decision];
                }
                SNBLogAgentInfo("Auto-trusted suggestion for cluster: %{public}@ (AI=%d)",
                               decision.clusterID, aiAssisted);
                break;

            case SNBPromotionActionNeedsReview:
                if ([self.delegate respondsToSelector:@selector(promotionAgent:needsReview:)]) {
                    [self.delegate promotionAgent:self needsReview:decision];
                }
                SNBLogAgentInfo("Review needed for cluster: %{public}@ (AI=%d)", decision.clusterID, aiAssisted);
                break;

            case SNBPromotionActionNone:
            default:
                // No action needed
                break;
        }
    });
}

- (void)applyPromotion:(NSString *)clusterID label:(NSString *)label reason:(NSString *)reason {
    [self.eventPublisher applyPromotion:clusterID label:label reason:reason completion:^(BOOL success) {
        if (!success) {
            SNBLogAgentWarn("Failed to apply promotion for %{public}@", clusterID);
        }
    }];
}

- (void)trustDecisionDestination:(SNBPromotionDecision *)decision {
    NSString *destinationIP = decision.destinationIP;
    if (destinationIP.length == 0) {
        SNBLogAgentWarn("Skipping trust: missing destination IP for cluster %{public}@", decision.clusterID);
        return;
    }

    SNBTrustContext *context = [[SNBTrustContext alloc] init];
    context.ipAddress = destinationIP;
    context.reason = SNBTrustReasonAgent;
    context.processName = decision.processName;
    context.hostname = decision.destinationFamily;
    [[SNBTrustedIPStore sharedStore] setTrusted:YES forIP:destinationIP withContext:context];
}

- (NSString *)applicationSupportDirectory {
    NSArray<NSString *> *paths = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory,
                                                                     NSUserDomainMask,
                                                                     YES);
    NSString *baseDir = paths.firstObject ?: NSTemporaryDirectory();
    NSString *appDir = [baseDir stringByAppendingPathComponent:@"SniffNetBar"];
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:appDir]) {
        [fm createDirectoryAtPath:appDir withIntermediateDirectories:YES attributes:nil error:nil];
    }
    return appDir;
}

@end

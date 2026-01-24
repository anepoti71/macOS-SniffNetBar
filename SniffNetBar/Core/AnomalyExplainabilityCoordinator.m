//
//  AnomalyExplainabilityCoordinator.m
//  SniffNetBar
//
//  Orchestrates local LLM explainability for anomaly windows
//

#import "AnomalyExplainabilityCoordinator.h"
#import "AnomalyExplanationService.h"
#import "AnomalyStore.h"
#import "ConfigurationManager.h"
#import "ThreatIntelCoordinator.h"
#import "ThreatIntelModels.h"
#import "Logger.h"

static const NSTimeInterval SNBExplainabilityMinInterval = 3.0;
static const NSTimeInterval SNBExplainabilityWindowSeconds = 60.0;
static const NSInteger SNBExplainabilityBatchLimit = 1;

@interface SNBAnomalyExplainabilityCoordinator ()
@property (nonatomic, strong) ConfigurationManager *configuration;
@property (nonatomic, strong) ThreatIntelCoordinator *threatIntelCoordinator;
@property (nonatomic, strong) SNBAnomalyStore *store;
@property (nonatomic, strong) SNBAnomalyExplanationService *service;
@property (nonatomic, strong) dispatch_queue_t workQueue;
@property (nonatomic, assign) BOOL inFlight;
@property (nonatomic, assign) NSTimeInterval lastRun;
@property (nonatomic, assign) double minScore;
@end

@implementation SNBAnomalyExplainabilityCoordinator

- (instancetype)initWithConfiguration:(ConfigurationManager *)configuration
              threatIntelCoordinator:(ThreatIntelCoordinator *)threatIntelCoordinator {
    self = [super init];
    if (self) {
        _configuration = configuration;
        _threatIntelCoordinator = threatIntelCoordinator;
        _store = [SNBAnomalyStore sharedStore];
        _service = [[SNBAnomalyExplanationService alloc] initWithConfiguration:configuration];
        _workQueue = dispatch_queue_create("com.sniffnetbar.explainability", DISPATCH_QUEUE_SERIAL);
        _minScore = configuration.explainabilityMinScore;
    }
    return self;
}

- (void)processPendingExplanations {
    if (!self.service.isEnabled) {
        return;
    }
    dispatch_async(self.workQueue, ^{
        NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
        if (self.inFlight) {
            return;
        }
        if (self.lastRun > 0 && now - self.lastRun < SNBExplainabilityMinInterval) {
            return;
        }
        self.lastRun = now;

        NSArray<SNBAnomalyWindowRecord *> *windows =
            [self.store windowsNeedingExplanationWithMinimumScore:self.minScore
                                                           limit:SNBExplainabilityBatchLimit];
        if (windows.count == 0) {
            return;
        }

        SNBAnomalyWindowRecord *window = windows.firstObject;
        TIEnrichmentResponse *ti = [self threatIntelForIP:window.dstIP];

        NSDictionary *input = [self.service inputForWindow:window
                                             windowSeconds:SNBExplainabilityWindowSeconds
                                              threatIntel:ti];
        self.inFlight = YES;

        __weak typeof(self) weakSelf = self;
        [self.service generateExplanationWithInput:input completion:^(SNBAnomalyExplanation *explanation, NSError *error) {
            __strong typeof(weakSelf) strongSelf = weakSelf;
            if (!strongSelf) {
                return;
            }
            strongSelf.inFlight = NO;
            if (!explanation) {
                SNBLogWarn("Explainability failed for %{" SNB_IP_PRIVACY "}@: %{public}@",
                           window.dstIP, error.localizedDescription);
                return;
            }
            [strongSelf.store storeExplanationForIP:window.dstIP
                                        windowStart:window.windowStart
                                           riskBand:explanation.riskBand
                                            summary:explanation.summary
                                       evidenceTags:explanation.evidenceTags
                                       promptVersion:strongSelf.service.promptVersion];
        }];
    });
}

- (TIEnrichmentResponse *)threatIntelForIP:(NSString *)ipAddress {
    if (!self.threatIntelCoordinator.isEnabled) {
        return nil;
    }
    NSDictionary<NSString *, TIEnrichmentResponse *> *results = [self.threatIntelCoordinator resultsSnapshot];
    return results[ipAddress];
}

@end

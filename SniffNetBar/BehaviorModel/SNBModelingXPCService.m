//
//  SNBModelingXPCService.m
//  SniffNetBar
//

#import "SNBModelingXPCService.h"
#import "SNBBehaviorDatabase.h"
#import "SNBEventSchema.h"
#import "SNBEventStore.h"
#import "SNBAggregateEngine.h"
#import "SNBRecommendationStore.h"
#import "SNBScoringEngine.h"
#import "SNBModelingUtilities.h"
#import "PromotionAgent/SNBPromotionCandidate.h"
#import "Logger.h"

@interface SNBModelingXPCService ()
@property (nonatomic, strong) dispatch_queue_t ingestQueue;
@property (nonatomic, strong) NSMutableArray<SNBFlowEvent *> *buffer;
@property (nonatomic, strong) SNBEventStore *eventStore;
@property (nonatomic, strong) SNBAggregateEngine *aggregateEngine;
@property (nonatomic, strong) SNBRecommendationStore *recommendationStore;
@property (nonatomic, strong) SNBScoringEngine *scoringEngine;
@end

@implementation SNBModelingXPCService

- (instancetype)init {
    self = [super init];
    if (self) {
        _ingestQueue = dispatch_queue_create("com.sniffnetbar.modeling.ingest", DISPATCH_QUEUE_SERIAL);
        _buffer = [NSMutableArray array];
        NSString *supportDir = [self applicationSupportDirectory];
        NSString *dbPath = [supportDir stringByAppendingPathComponent:@"behavioral.sqlite"];
        SNBBehaviorDatabase *database = [[SNBBehaviorDatabase alloc] initWithPath:dbPath];
        _eventStore = [[SNBEventStore alloc] initWithDatabase:database];
        _aggregateEngine = [[SNBAggregateEngine alloc] initWithDatabase:database];
        _recommendationStore = [[SNBRecommendationStore alloc] initWithDatabase:database];
        _scoringEngine = [[SNBScoringEngine alloc] initWithConfig:nil];
    }
    return self;
}

- (void)ingest:(NSArray<SNBFlowEvent *> *)events
      context:(SNBHostContext *)context
        reply:(void (^)(NSUInteger accepted, NSUInteger dropped))reply {
    if (events.count == 0) {
        reply(0, 0);
        return;
    }

    dispatch_async(self.ingestQueue, ^{
        SNBLogBehaviorDebug("Modeling ingest received events=%lu", (unsigned long)events.count);
        [self.buffer addObjectsFromArray:events];
        [self.eventStore appendEvents:events];
        [self.aggregateEngine processEvents:events];
        NSMutableDictionary<NSString *, SNBFlowEvent *> *latestEventByCluster = [NSMutableDictionary dictionary];
        for (SNBFlowEvent *event in events) {
            NSString *clusterID = SNBClusterIDForEvent(event);
            latestEventByCluster[clusterID] = event;
        }
        NSMutableArray<SNBRecommendation *> *recs = [NSMutableArray arrayWithCapacity:latestEventByCluster.count];
        [latestEventByCluster enumerateKeysAndObjectsUsingBlock:^(NSString *clusterID, SNBFlowEvent *event, BOOL *stop) {
            SNBAggregateSnapshot *snapshot = [self.aggregateEngine snapshotForClusterID:clusterID];
            SNBRecommendation *rec = [self.scoringEngine recommendationForEvent:event snapshot:snapshot];
            NSString *userLabel = [self.recommendationStore userLabelForClusterID:clusterID];
            rec = [self.scoringEngine applyUserLabel:userLabel toRecommendation:rec];
        [recs addObject:rec];
    }];
        [self.recommendationStore upsertRecommendations:recs];
        reply(events.count, 0);
    });
}

- (void)ping:(void (^)(BOOL ok))reply {
    SNBLogBehaviorDebug("Modeling XPC ping");
    reply(YES);
}

- (void)getRecommendationsSince:(NSDate *)since
                          reply:(void (^)(NSArray<SNBRecommendation *> *results))reply {
    NSArray<SNBRecommendation *> *results = [self.recommendationStore recommendationsSince:since];
    reply(results);
}

- (void)getClusterDetails:(NSString *)clusterID
                    reply:(void (^)(NSDictionary *detail))reply {
    uint64_t seenCount = [self.aggregateEngine seenCountForClusterID:clusterID];
    reply(@{@"clusterID": clusterID, @"seenCount": @(seenCount)});
}

- (void)setUserLabel:(NSString *)clusterID
               label:(NSString *)label
               scope:(NSString *)scope
               reply:(void (^)(BOOL success))reply {
    BOOL success = [self.recommendationStore setUserLabel:label forClusterID:clusterID scope:scope];
    if (success) {
        [self.recommendationStore updateRecommendationLabel:label forClusterID:clusterID];
    }
    reply(success);
}

- (void)getPromotionCandidates:(void (^)(NSArray<SNBPromotionCandidate *> *candidates))reply {
    SNBLogBehaviorInfo("getPromotionCandidates: fetching recommendations from last 7 days");
    NSDate *since = [NSDate dateWithTimeIntervalSinceNow:-(7 * 24 * 3600)];
    NSArray<SNBRecommendation *> *recommendations = [self.recommendationStore recommendationsSince:since];
    SNBLogBehaviorInfo("getPromotionCandidates: found %lu recommendations", (unsigned long)recommendations.count);
    NSMutableArray<SNBPromotionCandidate *> *candidates = [NSMutableArray array];

    for (SNBRecommendation *rec in recommendations) {
        NSString *clusterID = rec.clusterID;
        if (clusterID.length == 0) {
            continue;
        }
        NSDate *firstSeen = nil;
        SNBFlowEvent *event = [self.eventStore latestEventForClusterID:clusterID firstSeen:&firstSeen];
        if (!event) {
            continue;
        }
        SNBAggregateSnapshot *snapshot = [self.aggregateEngine snapshotForClusterID:clusterID];
        SNBPromotionCandidate *candidate = [[SNBPromotionCandidate alloc] init];
        candidate.clusterID = clusterID;
        candidate.extendedContext = rec.extendedContext;
        candidate.label = rec.label;
        candidate.score = rec.score;
        candidate.confidence = rec.confidence;
        candidate.ipOnly = rec.ipOnly;
        candidate.asnAnomaly = rec.asnAnomaly;
        candidate.seenCount = snapshot.seenCount;
        candidate.seen1h = snapshot.seen1h;
        candidate.seen24h = snapshot.seen24h;
        candidate.seen7d = snapshot.seen7d;
        candidate.beaconScore = snapshot.beaconScore;
        candidate.firstSeen = firstSeen;
        candidate.processName = event.processName;
        candidate.signingStatus = event.signingStatus;
        candidate.dstPort = event.dstPort;
        candidate.hosting = event.hosting;
        candidate.vpn = event.vpn;
        candidate.relay = event.relay;
        candidate.vtScore = event.vtScore.doubleValue;
        candidate.abuseScore = event.abuseScore.doubleValue;
        candidate.greyNoiseClass = event.greyNoiseClass;
        candidate.userLabel = [self.recommendationStore userLabelForClusterID:clusterID];
        candidate.asn = event.asn;
        candidate.org = event.org;
        candidate.country = event.country;
        candidate.dstIP = event.dstIP;
        NSString *host = event.sni.length > 0 ? event.sni : (event.httpHost.length > 0 ? event.httpHost : event.dnsQuery);
        candidate.dstDomain = host;
        [candidates addObject:candidate];
    }

    SNBLogBehaviorInfo("Modeling promotion candidates count=%lu", (unsigned long)candidates.count);
    reply(candidates);
}

- (void)applyPromotion:(NSString *)clusterID
                 label:(NSString *)label
                reason:(NSString *)reason
                 reply:(void (^)(BOOL success))reply {
    // Input validation - reject empty or nil values
    if (clusterID.length == 0 || label.length == 0) {
        SNBLogBehaviorWarn("applyPromotion rejected: empty clusterID or label");
        reply(NO);
        return;
    }

    // Validate clusterID format - alphanumeric, colon, dot, dash only (max 256 chars)
    static NSCharacterSet *invalidChars = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSMutableCharacterSet *allowed = [NSMutableCharacterSet alphanumericCharacterSet];
        [allowed addCharactersInString:@":.-_"];
        invalidChars = [allowed invertedSet];
    });
    if (clusterID.length > 256 || [clusterID rangeOfCharacterFromSet:invalidChars].location != NSNotFound) {
        SNBLogBehaviorWarn("applyPromotion rejected: invalid clusterID format");
        reply(NO);
        return;
    }

    // Whitelist valid labels - security: prevent arbitrary label injection
    static NSSet *validLabels = nil;
    static dispatch_once_t labelOnceToken;
    dispatch_once(&labelOnceToken, ^{
        validLabels = [NSSet setWithObjects:@"trusted", @"blocked", @"suspicious", @"safe", nil];
    });
    NSString *lowercaseLabel = [label lowercaseString];
    if (![validLabels containsObject:lowercaseLabel]) {
        SNBLogBehaviorWarn("applyPromotion rejected: invalid label '%{public}@'", label);
        reply(NO);
        return;
    }

    // Normalize label to canonical form
    NSString *normalized = label;
    if ([lowercaseLabel isEqualToString:@"trusted"] || [lowercaseLabel isEqualToString:@"safe"]) {
        normalized = @"Trusted";
    } else if ([lowercaseLabel isEqualToString:@"blocked"]) {
        normalized = @"Blocked";
    } else if ([lowercaseLabel isEqualToString:@"suspicious"]) {
        normalized = @"Suspicious";
    }

    BOOL success = [self.recommendationStore setUserLabel:normalized forClusterID:clusterID scope:@"promotion"];
    if (success) {
        [self.recommendationStore updateRecommendationLabel:normalized forClusterID:clusterID];
    }
    SNBLogBehaviorInfo("Modeling applyPromotion cluster=%{public}@ label=%{public}@ success=%d",
                       clusterID, normalized, success);
    reply(success);
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

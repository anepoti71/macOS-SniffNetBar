//
//  SNBTimerCoordinator.m
//  SniffNetBar
//
//  Centralized timer management for reduced wake-ups and better battery efficiency.
//

#import "SNBTimerCoordinator.h"
#import "Logger.h"

/// Internal timer entry storing timer state
@interface SNBTimerEntry : NSObject
@property (nonatomic, strong) dispatch_source_t source;
@property (nonatomic, assign) NSTimeInterval interval;
@property (nonatomic, assign) NSTimeInterval leeway;
@property (nonatomic, assign) SNBTimerGroup group;
@property (nonatomic, strong) dispatch_queue_t queue;
@property (nonatomic, copy) SNBTimerBlock handler;
@property (nonatomic, assign) BOOL repeating;
@property (nonatomic, assign) BOOL suspended;
@property (nonatomic, assign) NSUInteger fireCount;
@property (nonatomic, strong) NSDate *createdAt;
@property (nonatomic, strong) NSDate *lastFiredAt;
@end

@implementation SNBTimerEntry
@end

@interface SNBTimerCoordinator ()
@property (nonatomic, strong) NSMutableDictionary<SNBTimerID, SNBTimerEntry *> *timers;
@property (nonatomic, strong) dispatch_queue_t coordinatorQueue;
@property (nonatomic, assign) NSUInteger nextTimerID;
@end

@implementation SNBTimerCoordinator

+ (instancetype)sharedCoordinator {
    static SNBTimerCoordinator *shared = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        shared = [[SNBTimerCoordinator alloc] init];
    });
    return shared;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _timers = [NSMutableDictionary dictionary];
        _coordinatorQueue = dispatch_queue_create("com.sniffnetbar.timercoordinator", DISPATCH_QUEUE_SERIAL);
        _nextTimerID = 1;
    }
    return self;
}

- (void)dealloc {
    [self cancelAllTimers];
}

#pragma mark - Public API

- (SNBTimerID)scheduleRepeatingTimerWithInterval:(NSTimeInterval)interval
                                           queue:(dispatch_queue_t)queue
                                         handler:(SNBTimerBlock)handler {
    SNBTimerGroup group = [self groupForInterval:interval];
    NSTimeInterval leeway = [self defaultLeewayForGroup:group];
    return [self scheduleRepeatingTimerWithInterval:interval
                                             leeway:leeway
                                              group:group
                                              queue:queue
                                            handler:handler];
}

- (SNBTimerID)scheduleRepeatingTimerWithInterval:(NSTimeInterval)interval
                                          leeway:(NSTimeInterval)leeway
                                           group:(SNBTimerGroup)group
                                           queue:(dispatch_queue_t)queue
                                         handler:(SNBTimerBlock)handler {
    if (!handler || interval <= 0) {
        return nil;
    }

    dispatch_queue_t targetQueue = queue ?: dispatch_get_main_queue();

    __block SNBTimerID timerID = nil;
    dispatch_sync(self.coordinatorQueue, ^{
        timerID = [self generateTimerID];

        SNBTimerEntry *entry = [[SNBTimerEntry alloc] init];
        entry.interval = interval;
        entry.leeway = leeway;
        entry.group = group;
        entry.queue = targetQueue;
        entry.handler = handler;
        entry.repeating = YES;
        entry.suspended = NO;
        entry.fireCount = 0;
        entry.createdAt = [NSDate date];

        // Create dispatch_source timer
        dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, targetQueue);

        uint64_t intervalNS = (uint64_t)(interval * NSEC_PER_SEC);
        uint64_t leewayNS = (uint64_t)(leeway * NSEC_PER_SEC);

        dispatch_source_set_timer(timer,
                                  dispatch_time(DISPATCH_TIME_NOW, intervalNS),
                                  intervalNS,
                                  leewayNS);

        __weak SNBTimerCoordinator *weakSelf = self;
        __weak SNBTimerEntry *weakEntry = entry;
        dispatch_source_set_event_handler(timer, ^{
            SNBTimerEntry *strongEntry = weakEntry;
            if (strongEntry && strongEntry.handler) {
                strongEntry.fireCount++;
                strongEntry.lastFiredAt = [NSDate date];
                strongEntry.handler();
            }
            // Log occasional stats for debugging
            if (strongEntry && strongEntry.fireCount % 100 == 0) {
                [weakSelf logTimerStats:timerID entry:strongEntry];
            }
        });

        entry.source = timer;
        self.timers[timerID] = entry;

        dispatch_resume(timer);

        SNBLogDebug("TimerCoordinator: Scheduled repeating timer %{public}@ (interval=%.1fs, leeway=%.1fs, group=%lu)",
                    timerID, interval, leeway, (unsigned long)group);
    });

    return timerID;
}

- (SNBTimerID)scheduleOneShotTimerWithDelay:(NSTimeInterval)delay
                                      queue:(dispatch_queue_t)queue
                                    handler:(SNBTimerBlock)handler {
    if (!handler || delay < 0) {
        return nil;
    }

    dispatch_queue_t targetQueue = queue ?: dispatch_get_main_queue();

    __block SNBTimerID timerID = nil;
    dispatch_sync(self.coordinatorQueue, ^{
        timerID = [self generateTimerID];

        SNBTimerEntry *entry = [[SNBTimerEntry alloc] init];
        entry.interval = delay;
        entry.leeway = delay * 0.1; // 10% leeway for one-shot timers
        entry.group = SNBTimerGroupCustom;
        entry.queue = targetQueue;
        entry.handler = handler;
        entry.repeating = NO;
        entry.suspended = NO;
        entry.fireCount = 0;
        entry.createdAt = [NSDate date];

        dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, targetQueue);

        uint64_t delayNS = (uint64_t)(delay * NSEC_PER_SEC);
        uint64_t leewayNS = (uint64_t)(entry.leeway * NSEC_PER_SEC);

        // One-shot: fire once after delay, with DISPATCH_TIME_FOREVER as repeat interval
        dispatch_source_set_timer(timer,
                                  dispatch_time(DISPATCH_TIME_NOW, delayNS),
                                  DISPATCH_TIME_FOREVER,
                                  leewayNS);

        __weak SNBTimerCoordinator *weakSelf = self;
        SNBTimerID capturedID = timerID;
        dispatch_source_set_event_handler(timer, ^{
            SNBTimerCoordinator *strongSelf = weakSelf;
            SNBTimerEntry *capturedEntry = strongSelf.timers[capturedID];
            if (capturedEntry && capturedEntry.handler) {
                capturedEntry.fireCount++;
                capturedEntry.lastFiredAt = [NSDate date];
                capturedEntry.handler();
            }
            // Auto-cleanup one-shot timer after firing
            [strongSelf cancelTimer:capturedID];
        });

        entry.source = timer;
        self.timers[timerID] = entry;

        dispatch_resume(timer);

        SNBLogDebug("TimerCoordinator: Scheduled one-shot timer %{public}@ (delay=%.2fs)",
                    timerID, delay);
    });

    return timerID;
}

- (void)cancelTimer:(SNBTimerID)timerID {
    if (!timerID) {
        return;
    }

    dispatch_sync(self.coordinatorQueue, ^{
        SNBTimerEntry *entry = self.timers[timerID];
        if (entry) {
            if (entry.source) {
                if (entry.suspended) {
                    // Must resume before cancelling a suspended source
                    dispatch_resume(entry.source);
                }
                dispatch_source_cancel(entry.source);
            }
            [self.timers removeObjectForKey:timerID];
            SNBLogDebug("TimerCoordinator: Cancelled timer %{public}@ (fired %lu times)",
                        timerID, (unsigned long)entry.fireCount);
        }
    });
}

- (void)cancelAllTimers {
    dispatch_sync(self.coordinatorQueue, ^{
        for (SNBTimerID timerID in self.timers.allKeys) {
            SNBTimerEntry *entry = self.timers[timerID];
            if (entry && entry.source) {
                if (entry.suspended) {
                    dispatch_resume(entry.source);
                }
                dispatch_source_cancel(entry.source);
            }
        }
        NSUInteger count = self.timers.count;
        [self.timers removeAllObjects];
        SNBLogInfo("TimerCoordinator: Cancelled all %lu timers", (unsigned long)count);
    });
}

- (void)pauseTimer:(SNBTimerID)timerID {
    if (!timerID) {
        return;
    }

    dispatch_sync(self.coordinatorQueue, ^{
        SNBTimerEntry *entry = self.timers[timerID];
        if (entry && entry.source && !entry.suspended) {
            dispatch_suspend(entry.source);
            entry.suspended = YES;
            SNBLogDebug("TimerCoordinator: Paused timer %{public}@", timerID);
        }
    });
}

- (void)resumeTimer:(SNBTimerID)timerID {
    if (!timerID) {
        return;
    }

    dispatch_sync(self.coordinatorQueue, ^{
        SNBTimerEntry *entry = self.timers[timerID];
        if (entry && entry.source && entry.suspended) {
            dispatch_resume(entry.source);
            entry.suspended = NO;
            SNBLogDebug("TimerCoordinator: Resumed timer %{public}@", timerID);
        }
    });
}

- (NSUInteger)activeTimerCount {
    __block NSUInteger count = 0;
    dispatch_sync(self.coordinatorQueue, ^{
        count = self.timers.count;
    });
    return count;
}

- (NSDictionary<NSString *, id> *)statisticsSnapshot {
    __block NSDictionary *stats = nil;
    dispatch_sync(self.coordinatorQueue, ^{
        NSMutableArray *timerInfos = [NSMutableArray array];
        for (SNBTimerID timerID in self.timers) {
            SNBTimerEntry *entry = self.timers[timerID];
            [timerInfos addObject:@{
                @"id": timerID,
                @"interval": @(entry.interval),
                @"leeway": @(entry.leeway),
                @"group": @(entry.group),
                @"repeating": @(entry.repeating),
                @"suspended": @(entry.suspended),
                @"fireCount": @(entry.fireCount),
                @"createdAt": entry.createdAt ?: [NSNull null],
                @"lastFiredAt": entry.lastFiredAt ?: [NSNull null]
            }];
        }

        NSUInteger byGroup[5] = {0, 0, 0, 0, 0};
        for (SNBTimerEntry *entry in self.timers.allValues) {
            if (entry.group < 5) {
                byGroup[entry.group]++;
            }
        }

        stats = @{
            @"totalTimers": @(self.timers.count),
            @"byGroup": @{
                @"fast": @(byGroup[SNBTimerGroupFast]),
                @"medium": @(byGroup[SNBTimerGroupMedium]),
                @"slow": @(byGroup[SNBTimerGroupSlow]),
                @"infrequent": @(byGroup[SNBTimerGroupInfrequent]),
                @"custom": @(byGroup[SNBTimerGroupCustom])
            },
            @"timers": timerInfos
        };
    });
    return stats;
}

#pragma mark - Private Helpers

- (SNBTimerID)generateTimerID {
    NSUInteger timerNum = self.nextTimerID++;
    return [NSString stringWithFormat:@"timer_%lu", (unsigned long)timerNum];
}

- (SNBTimerGroup)groupForInterval:(NSTimeInterval)interval {
    if (interval <= 2.0) {
        return SNBTimerGroupFast;
    } else if (interval <= 10.0) {
        return SNBTimerGroupMedium;
    } else if (interval <= 60.0) {
        return SNBTimerGroupSlow;
    } else {
        return SNBTimerGroupInfrequent;
    }
}

- (NSTimeInterval)defaultLeewayForGroup:(SNBTimerGroup)group {
    switch (group) {
        case SNBTimerGroupFast:
            return 0.1;  // 100ms leeway for 1-second timers
        case SNBTimerGroupMedium:
            return 0.5;  // 500ms leeway for 5-second timers
        case SNBTimerGroupSlow:
            return 2.0;  // 2s leeway for 30-second timers
        case SNBTimerGroupInfrequent:
            return 10.0; // 10s leeway for 5-minute timers
        case SNBTimerGroupCustom:
        default:
            return 1.0;  // Default 1s leeway
    }
}

- (void)logTimerStats:(SNBTimerID)timerID entry:(SNBTimerEntry *)entry {
    SNBLogDebug("TimerCoordinator: Timer %{public}@ stats - fireCount=%lu, interval=%.1fs",
                timerID, (unsigned long)entry.fireCount, entry.interval);
}

@end

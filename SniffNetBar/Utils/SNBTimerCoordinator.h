//
//  SNBTimerCoordinator.h
//  SniffNetBar
//
//  Centralized timer management for reduced wake-ups and better battery efficiency.
//  Uses dispatch_source_t timers with leeway for OS-level timer coalescing.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Timer identifier returned when scheduling a timer
typedef NSString *SNBTimerID;

/// Timer execution block
typedef void (^SNBTimerBlock)(void);

/// Predefined timer groups for common intervals (enables timer coalescing)
typedef NS_ENUM(NSUInteger, SNBTimerGroup) {
    SNBTimerGroupFast,       // ~1 second interval (sampling, UI updates)
    SNBTimerGroupMedium,     // ~5 seconds interval (batch flushes)
    SNBTimerGroupSlow,       // ~30 seconds interval (asset monitoring)
    SNBTimerGroupInfrequent, // ~5 minutes interval (cleanup, stats flush)
    SNBTimerGroupCustom      // Custom interval (no grouping)
};

@interface SNBTimerCoordinator : NSObject

/// Shared coordinator instance
+ (instancetype)sharedCoordinator;

/// Schedule a repeating timer with automatic group assignment based on interval
/// @param interval Timer interval in seconds
/// @param queue Queue to execute handler on (nil = main queue)
/// @param handler Block to execute on each timer fire
/// @return Timer identifier for later cancellation
- (SNBTimerID)scheduleRepeatingTimerWithInterval:(NSTimeInterval)interval
                                           queue:(nullable dispatch_queue_t)queue
                                         handler:(SNBTimerBlock)handler;

/// Schedule a repeating timer with explicit group and leeway
/// @param interval Timer interval in seconds
/// @param leeway Acceptable delay for timer coalescing (improves battery)
/// @param group Timer group for potential coalescing
/// @param queue Queue to execute handler on (nil = main queue)
/// @param handler Block to execute on each timer fire
/// @return Timer identifier for later cancellation
- (SNBTimerID)scheduleRepeatingTimerWithInterval:(NSTimeInterval)interval
                                          leeway:(NSTimeInterval)leeway
                                           group:(SNBTimerGroup)group
                                           queue:(nullable dispatch_queue_t)queue
                                         handler:(SNBTimerBlock)handler;

/// Schedule a one-shot timer (fires once after delay)
/// @param delay Delay in seconds before firing
/// @param queue Queue to execute handler on (nil = main queue)
/// @param handler Block to execute when timer fires
/// @return Timer identifier for cancellation (if needed before firing)
- (SNBTimerID)scheduleOneShotTimerWithDelay:(NSTimeInterval)delay
                                      queue:(nullable dispatch_queue_t)queue
                                    handler:(SNBTimerBlock)handler;

/// Cancel a scheduled timer
/// @param timerID Timer identifier returned from schedule methods
- (void)cancelTimer:(SNBTimerID)timerID;

/// Cancel all timers (call on app termination)
- (void)cancelAllTimers;

/// Pause a timer temporarily (can be resumed)
- (void)pauseTimer:(SNBTimerID)timerID;

/// Resume a paused timer
- (void)resumeTimer:(SNBTimerID)timerID;

/// Get count of active timers (for debugging/monitoring)
@property (nonatomic, readonly) NSUInteger activeTimerCount;

/// Get timer statistics snapshot
- (NSDictionary<NSString *, id> *)statisticsSnapshot;

@end

NS_ASSUME_NONNULL_END

#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#import <sys/types.h>

NS_ASSUME_NONNULL_BEGIN

@interface SNBBadgeRegistry : NSObject

/// Shared registry used to keep badge colors consistent across UI sections.
+ (instancetype)sharedRegistry;

/// Returns a color associated with a process name and PID.
/// Provides a default color when the process is unknown.
- (NSColor *)colorForProcessName:(NSString *)processName
                              pid:(pid_t)pid
             createIfMissing:(BOOL)create;

/// Returns a color derived from a label (e.g. host or location) using the shared palette.
- (NSColor *)colorForLabel:(NSString *)label
            createIfMissing:(BOOL)create;

/// Returns an icon string (initial or fallback token) for the process or label.
- (NSString *)badgeIconForProcessName:(NSString *)processName
                                   pid:(pid_t)pid
                        fallbackLabel:(NSString *)fallback;

/// Returns a simple badge icon derived from a label or fallback string.
- (NSString *)badgeIconForLabel:(NSString *)label fallback:(NSString *)fallback;

@end

NS_ASSUME_NONNULL_END

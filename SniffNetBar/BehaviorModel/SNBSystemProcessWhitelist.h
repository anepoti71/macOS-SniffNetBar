//
//  SNBSystemProcessWhitelist.h
//  SniffNetBar
//
//  Configurable whitelist of known system processes to reduce false positives

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Manages a whitelist of known system processes that should not be penalized
/// for missing attribution or other typical "suspicious" patterns.
///
/// The whitelist includes:
/// - macOS system daemons (mDNSResponder, trustd, etc.)
/// - Apple services (nsurlsessiond, apsd, etc.)
/// - Common system utilities
///
/// Custom entries can be added via configuration file or programmatically.
@interface SNBSystemProcessWhitelist : NSObject

/// Shared singleton instance with default system processes
+ (instancetype)sharedWhitelist;

/// Initialize with custom whitelist entries (merged with defaults)
- (instancetype)initWithCustomEntries:(nullable NSArray<NSString *> *)customEntries;

/// Initialize from a configuration file (JSON array of process names)
/// Falls back to defaults if file doesn't exist or is invalid
- (instancetype)initWithConfigFile:(nullable NSString *)configPath;

/// Check if a process name is whitelisted (case-insensitive)
- (BOOL)isProcessWhitelisted:(nullable NSString *)processName;

/// Check if a process matches a whitelisted pattern (supports wildcards)
- (BOOL)processMatchesWhitelist:(nullable NSString *)processName;

/// Get the trust level for a process (0.0 = not whitelisted, 1.0 = fully trusted system process)
- (double)trustLevelForProcess:(nullable NSString *)processName;

/// Add a custom process to the whitelist at runtime
- (void)addProcess:(NSString *)processName;

/// Remove a process from the whitelist at runtime
- (void)removeProcess:(NSString *)processName;

/// Save current whitelist to configuration file
- (BOOL)saveToConfigFile:(NSString *)configPath error:(NSError **)error;

/// Reload whitelist from configuration file
- (BOOL)reloadFromConfigFile:(NSString *)configPath error:(NSError **)error;

/// All currently whitelisted process names (read-only)
@property (nonatomic, readonly) NSArray<NSString *> *allWhitelistedProcesses;

/// Path to the configuration file (if loaded from file)
@property (nonatomic, readonly, nullable) NSString *configFilePath;

/// Whether to include default system processes (default: YES)
@property (nonatomic, assign) BOOL includeDefaults;

@end

NS_ASSUME_NONNULL_END

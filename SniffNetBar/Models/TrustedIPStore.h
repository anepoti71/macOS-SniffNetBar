//
//  TrustedIPStore.h
//  SniffNetBar
//
//  Persistence for user-trusted IPs with learning context
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

extern NSString *const SNBTrustedIPStoreDidChangeNotification;

// Trust reasons for UI selection
typedef NS_ENUM(NSInteger, SNBTrustReason) {
    SNBTrustReasonUnspecified = 0,
    SNBTrustReasonKnownService,      // "Known service (e.g., CDN, cloud provider)"
    SNBTrustReasonOwnInfrastructure, // "My infrastructure (server, VPN, etc.)"
    SNBTrustReasonFalsePositive,     // "False positive detection"
    SNBTrustReasonTestingDev,        // "Testing/development"
    SNBTrustReasonOther,             // "Other reason"
    SNBTrustReasonAgent              // "Agent decision"
};

// Trust decision context for learning
@interface SNBTrustContext : NSObject <NSCopying>

@property (nonatomic, copy, nullable) NSString *ipAddress;
@property (nonatomic, assign) SNBTrustReason reason;
@property (nonatomic, copy, nullable) NSString *customReasonNote;
@property (nonatomic, assign) NSInteger threatScoreAtDecision;
@property (nonatomic, copy, nullable) NSString *verdictAtDecision;
@property (nonatomic, copy, nullable) NSString *processName;
@property (nonatomic, assign) pid_t processPID;
@property (nonatomic, assign) NSInteger destinationPort;
@property (nonatomic, copy, nullable) NSString *hostname;
@property (nonatomic, strong, nullable) NSDate *trustedAt;
@property (nonatomic, strong, nullable) NSDate *untrustedAt;
@property (nonatomic, assign) BOOL autoUntrusted;  // Was this auto-untrusted due to high threat?

+ (NSString *)displayStringForReason:(SNBTrustReason)reason;
+ (NSArray<NSNumber *> *)allReasons;

@end

// Trust history entry for audit trail
@interface SNBTrustHistoryEntry : NSObject

@property (nonatomic, copy) NSString *ipAddress;
@property (nonatomic, assign) BOOL trusted;
@property (nonatomic, assign) SNBTrustReason reason;
@property (nonatomic, copy, nullable) NSString *customReasonNote;
@property (nonatomic, assign) NSInteger threatScoreAtDecision;
@property (nonatomic, copy, nullable) NSString *verdictAtDecision;
@property (nonatomic, strong) NSDate *timestamp;
@property (nonatomic, assign) BOOL autoAction;  // Was this an automatic action?

@end

@interface SNBTrustedIPStore : NSObject

+ (instancetype)sharedStore;

// Returns YES if the IP is currently trusted.
- (BOOL)isTrustedIP:(NSString *)ipAddress;

// Get full trust context for an IP
- (nullable SNBTrustContext *)trustContextForIP:(NSString *)ipAddress;

// Mark or unmark an IP as trusted (simple interface).
- (void)setTrusted:(BOOL)trusted forIP:(NSString *)ipAddress;

// Mark an IP as trusted with full context for learning.
- (void)setTrusted:(BOOL)trusted
             forIP:(NSString *)ipAddress
       withContext:(nullable SNBTrustContext *)context;

// Remove the trusted flag (soft delete).
- (void)removeTrustedIP:(NSString *)ipAddress;

// Auto-untrust: Called when a trusted IP later scores very high threat.
// Returns YES if the IP was auto-untrusted.
- (BOOL)autoUntrustIPIfNeeded:(NSString *)ipAddress
               withThreatScore:(NSInteger)threatScore
                       verdict:(NSString *)verdict;

// Get trust history for an IP (for display and learning).
- (NSArray<SNBTrustHistoryEntry *> *)trustHistoryForIP:(NSString *)ipAddress;

// Get all currently trusted IPs with their contexts.
- (NSArray<SNBTrustContext *> *)allTrustedIPContexts;

// Configuration
@property (nonatomic, assign) NSInteger autoUntrustThreshold;  // Default: 85

@end

NS_ASSUME_NONNULL_END

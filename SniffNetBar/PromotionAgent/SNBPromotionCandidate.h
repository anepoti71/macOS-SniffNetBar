//
//  SNBPromotionCandidate.h
//  SniffNetBar
//
//  Data transfer object for promotion candidates via XPC.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface SNBPromotionCandidate : NSObject <NSSecureCoding>

// Cluster identification
@property (nonatomic, copy) NSString *clusterID;
@property (nonatomic, copy, nullable) NSString *extendedContext;

// Recommendation data
@property (nonatomic, copy, nullable) NSString *label;
@property (nonatomic, assign) NSInteger score;
@property (nonatomic, assign) NSInteger confidence;
@property (nonatomic, assign) BOOL ipOnly;
@property (nonatomic, assign) BOOL asnAnomaly;

// Aggregate data
@property (nonatomic, assign) uint64_t seenCount;
@property (nonatomic, assign) uint64_t seen1h;
@property (nonatomic, assign) uint64_t seen24h;
@property (nonatomic, assign) uint64_t seen7d;
@property (nonatomic, assign) double beaconScore;
@property (nonatomic, strong, nullable) NSDate *firstSeen;

// Event data for safety checks
@property (nonatomic, copy, nullable) NSString *processName;
@property (nonatomic, copy, nullable) NSString *signingStatus;
@property (nonatomic, assign) NSInteger dstPort;
@property (nonatomic, assign) BOOL hosting;
@property (nonatomic, assign) BOOL vpn;
@property (nonatomic, assign) BOOL relay;
@property (nonatomic, assign) double vtScore;
@property (nonatomic, assign) double abuseScore;
@property (nonatomic, copy, nullable) NSString *greyNoiseClass;

// User label (if exists)
@property (nonatomic, copy, nullable) NSString *userLabel;

// ASN/Geo info
@property (nonatomic, copy, nullable) NSString *asn;
@property (nonatomic, copy, nullable) NSString *org;
@property (nonatomic, copy, nullable) NSString *country;

// Destination info
@property (nonatomic, copy, nullable) NSString *dstIP;
@property (nonatomic, copy, nullable) NSString *dstDomain;

@end

NS_ASSUME_NONNULL_END

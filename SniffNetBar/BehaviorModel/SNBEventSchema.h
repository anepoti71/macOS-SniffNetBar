//
//  SNBEventSchema.h
//  SniffNetBar
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface SNBHostContext : NSObject <NSSecureCoding>
@property (nonatomic, copy) NSString *deviceID;
@property (nonatomic, copy) NSString *hostname;
@property (nonatomic, copy) NSString *osVersion;
@property (nonatomic, copy) NSString *timezone;
@property (nonatomic, copy) NSString *networkType;
@property (nonatomic, assign) BOOL vpnActive;
@property (nonatomic, assign) BOOL proxyActive;
@end

@interface SNBFlowEvent : NSObject <NSSecureCoding>
@property (nonatomic, strong) NSDate *start;
@property (nonatomic, strong) NSDate *end;
@property (nonatomic, copy) NSString *direction;
@property (nonatomic, copy) NSString *protocolName;
@property (nonatomic, copy) NSString *srcIP;
@property (nonatomic, copy) NSString *dstIP;
@property (nonatomic, assign) NSInteger srcPort;
@property (nonatomic, assign) NSInteger dstPort;
@property (nonatomic, assign) uint64_t bytesIn;
@property (nonatomic, assign) uint64_t bytesOut;
@property (nonatomic, assign) uint64_t packets;
@property (nonatomic, assign) NSTimeInterval duration;
@property (nonatomic, copy) NSString *dnsQuery;
@property (nonatomic, copy) NSString *sni;
@property (nonatomic, copy) NSString *ja3;
@property (nonatomic, copy) NSString *ja4;
@property (nonatomic, copy) NSString *httpHost;
@property (nonatomic, copy) NSString *processName;
@property (nonatomic, copy) NSString *bundleID;
@property (nonatomic, copy) NSString *parentProcess;
@property (nonatomic, copy) NSString *signingStatus;
@property (nonatomic, copy) NSString *codeHash;
@property (nonatomic, copy) NSString *outcome;
@property (nonatomic, copy) NSString *asn;
@property (nonatomic, copy) NSString *org;
@property (nonatomic, copy) NSString *country;
@property (nonatomic, copy) NSString *region;
@property (nonatomic, assign) BOOL hosting;
@property (nonatomic, assign) BOOL vpn;
@property (nonatomic, assign) BOOL relay;
@property (nonatomic, strong, nullable) NSNumber *vtScore;
@property (nonatomic, strong, nullable) NSNumber *abuseScore;
@property (nonatomic, copy) NSString *greyNoiseClass;
@end

@interface SNBEnrichment : NSObject <NSSecureCoding>
@property (nonatomic, copy) NSString *ip;
@property (nonatomic, copy) NSString *asn;
@property (nonatomic, copy) NSString *org;
@property (nonatomic, copy) NSString *country;
@property (nonatomic, copy) NSString *region;
@property (nonatomic, copy) NSString *city;
@property (nonatomic, assign) BOOL hosting;
@property (nonatomic, assign) BOOL vpn;
@property (nonatomic, assign) BOOL relay;

@property (nonatomic, strong, nullable) NSNumber *vtScore;
@property (nonatomic, copy, nullable) NSDictionary *vtStats;
@property (nonatomic, copy, nullable) NSArray<NSString *> *vtCategories;

@property (nonatomic, strong, nullable) NSNumber *abuseScore;
@property (nonatomic, strong, nullable) NSNumber *abuseReports;
@property (nonatomic, strong, nullable) NSDate *abuseLastReported;

@property (nonatomic, copy, nullable) NSString *greyNoiseClass;
@property (nonatomic, copy, nullable) NSArray<NSString *> *greyNoiseTags;
@property (nonatomic, strong, nullable) NSDate *greyNoiseLastSeen;
@end

@interface SNBAggregates : NSObject <NSSecureCoding>
@property (nonatomic, copy) NSString *clusterID;
@property (nonatomic, copy) NSString *appKey;
@property (nonatomic, copy) NSString *asn;
@property (nonatomic, copy) NSString *org;
@property (nonatomic, copy) NSString *domainFamily;
@property (nonatomic, copy) NSString *protocolName;
@property (nonatomic, assign) NSInteger port;
@property (nonatomic, copy) NSDictionary<NSString *, NSNumber *> *hourHistogram;
@property (nonatomic, copy) NSDictionary<NSString *, NSNumber *> *dowHistogram;
@property (nonatomic, assign) double ewmaBytes;
@property (nonatomic, assign) double ewmaFreq;
@property (nonatomic, assign) double zScoreBytes;
@property (nonatomic, assign) double zScoreFreq;
@property (nonatomic, assign) uint64_t seenCount;
@property (nonatomic, strong) NSDate *lastSeen;
@end

@interface SNBRecommendation : NSObject <NSSecureCoding>
@property (nonatomic, copy) NSString *clusterID;
@property (nonatomic, copy) NSString *extendedContext;
@property (nonatomic, assign) BOOL asnAnomaly;
@property (nonatomic, assign) BOOL ipOnly;
@property (nonatomic, assign) NSInteger baseConfidence;
@property (nonatomic, assign) NSInteger score;
@property (nonatomic, copy) NSString *label;
@property (nonatomic, assign) NSInteger confidence;
@property (nonatomic, copy) NSString *summary;
@property (nonatomic, copy) NSArray<NSDictionary *> *evidence;
@property (nonatomic, copy) NSArray<NSString *> *actions;
@property (nonatomic, strong) NSDate *generatedAt;
@end

NS_ASSUME_NONNULL_END

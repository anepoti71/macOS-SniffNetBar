//
//  NetworkAssetMonitor.h
//  SniffNetBar
//
//  Passive network asset monitor using ARP table snapshots
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface SNBNetworkAsset : NSObject
@property (nonatomic, copy) NSString *ipAddress;
@property (nonatomic, copy) NSString *macAddress;
@property (nonatomic, copy) NSString *hostname;
@property (nonatomic, copy) NSString *vendor;
@property (nonatomic, copy, nullable) NSString *bonjourName;
@property (nonatomic, copy, nullable) NSString *deviceInfo;
@property (nonatomic, strong) NSDate *lastSeen;
@property (nonatomic, assign) BOOL isNew;
@end

@interface SNBNetworkAssetMonitor : NSObject

@property (nonatomic, assign, getter=isEnabled) BOOL enabled;
@property (nonatomic, copy) void (^onAssetsUpdated)(NSArray<SNBNetworkAsset *> *assets,
                                                    NSArray<SNBNetworkAsset *> *newAssets);
@property (nonatomic, copy, nullable) NSString *interfaceName;

- (void)start;
- (void)stop;
- (void)refresh;
- (NSArray<SNBNetworkAsset *> *)assetsSnapshot;
- (NSArray<SNBNetworkAsset *> *)recentNewAssetsSnapshot;

@end

NS_ASSUME_NONNULL_END

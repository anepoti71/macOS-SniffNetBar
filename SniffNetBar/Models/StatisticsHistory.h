//
//  StatisticsHistory.h
//  SniffNetBar
//
//  Daily/weekly statistics persistence and reporting
//

#import <Foundation/Foundation.h>

@class PacketInfo;
@class TrafficStats;

NS_ASSUME_NONNULL_BEGIN

@interface SNBStatisticsHistory : NSObject

@property (nonatomic, assign, getter=isEnabled) BOOL enabled;

- (instancetype)init;
- (void)processPacket:(PacketInfo *)packetInfo;
- (void)updateConnectionProcessInfoWithStats:(TrafficStats *)stats;
- (void)flush;
- (void)generateReport;
- (NSString *)reportPath;
- (BOOL)reportExists;

@end

NS_ASSUME_NONNULL_END

//
//  AnomalyDetector.h
//  SniffNetBar
//
//  Windowed feature aggregation and anomaly scoring
//

#import <Foundation/Foundation.h>

@class PacketInfo;

NS_ASSUME_NONNULL_BEGIN

@interface SNBAnomalyDetector : NSObject

- (instancetype)initWithWindowSeconds:(NSTimeInterval)windowSeconds;

- (void)processPacket:(PacketInfo *)packetInfo;
- (void)flushIfNeeded;
- (void)reloadModels;

@end

NS_ASSUME_NONNULL_END

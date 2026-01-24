//
//  ProcessRiskEvaluator.h
//  SniffNetBar
//

#import <Foundation/Foundation.h>

@class ThreatInfo;
@class ConnectionTraffic;
@class SNBProcessRiskReport;

NS_ASSUME_NONNULL_BEGIN

@interface SNBProcessRiskEvaluator : NSObject

+ (instancetype)sharedEvaluator;

- (nullable SNBProcessRiskReport *)evaluatePID:(pid_t)pid
                                   processName:(nullable NSString *)processName
                                    connection:(nullable ConnectionTraffic *)connection
                                        threat:(nullable ThreatInfo *)threat;

@end

NS_ASSUME_NONNULL_END

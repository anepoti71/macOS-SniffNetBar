//
//  ProcessRiskModels.h
//  SniffNetBar
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, SNBRiskLevel) {
    SNBRiskLevelLow = 0,
    SNBRiskLevelMedium,
    SNBRiskLevelHigh,
    SNBRiskLevelCritical
};

@interface SNBRiskSignal : NSObject

@property (nonatomic, copy) NSString *title;
@property (nonatomic, assign) NSInteger score;
@property (nonatomic, copy) NSString *category;

@end

@interface SNBProcessRiskReport : NSObject

@property (nonatomic, assign) NSInteger score;
@property (nonatomic, assign) SNBRiskLevel level;
@property (nonatomic, copy) NSString *summary;
@property (nonatomic, strong) NSArray<SNBRiskSignal *> *signals;
@property (nonatomic, strong) NSArray<NSString *> *infoLines;
@property (nonatomic, copy, nullable) NSString *teamID;
@property (nonatomic, copy, nullable) NSString *bundleID;
@property (nonatomic, copy, nullable) NSString *signingID;
@property (nonatomic, copy, nullable) NSString *executablePath;
@property (nonatomic, assign) pid_t pid;

@end

NS_ASSUME_NONNULL_END

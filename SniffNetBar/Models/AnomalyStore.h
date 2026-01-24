//
//  AnomalyStore.h
//  SniffNetBar
//
//  Local persistence for anomaly detection features and scores
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface SNBAnomalyWindowRecord : NSObject

@property (nonatomic, copy) NSString *dstIP;
@property (nonatomic, assign) NSTimeInterval windowStart;
@property (nonatomic, assign) NSInteger dstPort;
@property (nonatomic, assign) NSInteger proto;
@property (nonatomic, assign) BOOL isNew;
@property (nonatomic, assign) BOOL isRare;
@property (nonatomic, assign) NSInteger seenCount;
@property (nonatomic, assign) double score;

@end

@interface SNBAnomalyStore : NSObject

+ (instancetype)sharedStore;

+ (NSString *)defaultDatabasePath;
+ (NSString *)defaultModelPath;
+ (NSString *)defaultCoreMLModelPath;
+ (NSString *)applicationSupportDirectoryPath;

- (instancetype)init;

- (NSInteger)seenCountForIP:(NSString *)ipAddress;

- (void)recordWindowForIP:(NSString *)ipAddress
              windowStart:(NSTimeInterval)windowStart
                  dstPort:(NSInteger)dstPort
                    proto:(NSInteger)proto
               totalBytes:(double)totalBytes
             totalPackets:(double)totalPackets
          uniqueSrcPorts:(double)uniqueSrcPorts
                flowCount:(double)flowCount
             avgPktSize:(double)avgPktSize
          bytesPerFlow:(double)bytesPerFlow
            pktsPerFlow:(double)pktsPerFlow
              burstiness:(double)burstiness
                 isNewDst:(BOOL)isNewDst
                isRareDst:(BOOL)isRareDst
                   score:(double)score;

- (NSArray<SNBAnomalyWindowRecord *> *)windowsNeedingExplanationWithMinimumScore:(double)minimumScore
                                                                          limit:(NSInteger)limit;

- (void)storeExplanationForIP:(NSString *)ipAddress
                  windowStart:(NSTimeInterval)windowStart
                     riskBand:(NSString *)riskBand
                      summary:(NSString *)summary
                 evidenceTags:(NSArray<NSString *> *)evidenceTags
                 promptVersion:(NSString *)promptVersion;

// Performance: Flush any buffered writes immediately
- (void)flush;

@end

NS_ASSUME_NONNULL_END

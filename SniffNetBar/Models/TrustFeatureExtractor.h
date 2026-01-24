//
//  TrustFeatureExtractor.h
//  SniffNetBar
//

#import <Foundation/Foundation.h>

@class TIEnrichmentResponse, ConnectionTraffic;
@class SNBTrustFeatureVector;

NS_ASSUME_NONNULL_BEGIN

@interface SNBTrustFeatureExtractor : NSObject

- (SNBTrustFeatureVector *)featureVectorForIP:(NSString *)ipAddress
                                     response:(nullable TIEnrichmentResponse *)response
                                   connection:(nullable ConnectionTraffic *)connection
                                   totalBytes:(uint64_t)totalBytes
                              connectionCount:(NSInteger)connectionCount;

@end

NS_ASSUME_NONNULL_END

//
//  SNBMapRenderer.h
//  SniffNetBar
//

#import <Foundation/Foundation.h>
#import <CoreLocation/CoreLocation.h>

@class ConnectionTraffic;

NS_ASSUME_NONNULL_BEGIN

@interface SNBMapRenderResult : NSObject
@property (nonatomic, copy) NSString *pointsJSON;
@property (nonatomic, copy) NSString *linesJSON;
@property (nonatomic, assign) NSUInteger drawnConnectionCount;
@end

@interface SNBMapRenderer : NSObject

- (nullable SNBMapRenderResult *)renderWithTargetIPs:(NSArray<NSString *> *)targetIPs
                                         connections:(NSArray<ConnectionTraffic *> *)connections
                                        locationByIP:(NSDictionary<NSString *, NSDictionary *> *)locationByIP
                                       badgeInfoByIP:(NSDictionary<NSString *, NSDictionary *> *)badgeInfoByIP
                                      processesByIP:(NSDictionary<NSString *, NSSet<NSString *> *> *)processesByIP
                               connectionCountsByIP:(NSDictionary<NSString *, NSNumber *> *)connectionCountsByIP
                                 firstSeenByIP:(NSDictionary<NSString *, NSDate *> *)firstSeenByIP
                                  lastSeenByIP:(NSDictionary<NSString *, NSDate *> *)lastSeenByIP
                                           publicIP:(NSString *)publicIP
                                         publicCoord:(CLLocationCoordinate2D)publicCoord
                                     riskStateForIP:(NSString * (^)(NSString *ip))riskStateForIP
                                            maxLines:(NSInteger)maxLines;

@end

NS_ASSUME_NONNULL_END

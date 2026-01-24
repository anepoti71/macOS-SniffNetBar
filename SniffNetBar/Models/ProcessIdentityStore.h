//
//  ProcessIdentityStore.h
//  SniffNetBar
//

#import <Foundation/Foundation.h>

@class SNBProcessIdentityRecord;

NS_ASSUME_NONNULL_BEGIN

@interface SNBProcessIdentityStore : NSObject

+ (instancetype)sharedStore;

- (nullable SNBProcessIdentityRecord *)resolveIdentityWithCDHash:(nullable NSString *)cdhash
                                                          teamID:(nullable NSString *)teamID
                                                       signingID:(nullable NSString *)signingID
                                                          sha256:(nullable NSString *)sha256;

- (nullable SNBProcessIdentityRecord *)upsertIdentity:(SNBProcessIdentityRecord *)record;

- (void)recordObservationForIdentityID:(NSInteger)identityID
                                   pid:(pid_t)pid
                                  ppid:(pid_t)ppid
                                   uid:(uid_t)uid
                                  path:(nullable NSString *)path
                              riskScore:(NSInteger)riskScore
                                verdict:(nullable NSString *)verdict
                            telemetryJSON:(nullable NSString *)telemetryJSON;

@end

NS_ASSUME_NONNULL_END

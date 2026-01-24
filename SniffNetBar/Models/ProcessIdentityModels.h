//
//  ProcessIdentityModels.h
//  SniffNetBar
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface SNBProcessIdentityRecord : NSObject

@property (nonatomic, assign) NSInteger identityID;
@property (nonatomic, copy, nullable) NSString *cdhash;
@property (nonatomic, copy, nullable) NSString *teamID;
@property (nonatomic, copy, nullable) NSString *bundleID;
@property (nonatomic, copy, nullable) NSString *signingID;
@property (nonatomic, assign) BOOL signatureValid;
@property (nonatomic, copy, nullable) NSString *signatureKind;
@property (nonatomic, copy, nullable) NSString *entitlementsHash;
@property (nonatomic, copy, nullable) NSString *sha256;
@property (nonatomic, copy, nullable) NSString *pathHint;
@property (nonatomic, assign) NSTimeInterval firstSeen;
@property (nonatomic, assign) NSTimeInterval lastSeen;
@property (nonatomic, assign) NSInteger seenCount;
@property (nonatomic, assign) NSInteger riskScore;
@property (nonatomic, copy, nullable) NSString *verdict;
@property (nonatomic, assign) double confidence;
@property (nonatomic, copy, nullable) NSString *notes;

@end

NS_ASSUME_NONNULL_END

//
//  AuthorizationHelper.h
//  SniffNetBar
//
//  Authorization helper for requesting root privileges
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, SNBAuthorizationStatus) {
    SNBAuthorizationStatusAuthorized,
    SNBAuthorizationStatusDenied,
    SNBAuthorizationStatusCanceled,
    SNBAuthorizationStatusAlreadyRoot
};

@interface AuthorizationHelper : NSObject

+ (BOOL)isRunningAsRoot;

+ (SNBAuthorizationStatus)requestAuthorizationWithMessage:(NSString *)message
                                            informativeText:(NSString *)informativeText;

+ (BOOL)relaunchAsRoot;

@end

NS_ASSUME_NONNULL_END

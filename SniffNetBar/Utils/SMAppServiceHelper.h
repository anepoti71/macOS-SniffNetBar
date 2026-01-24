//
//  SMAppServiceHelper.h
//  SniffNetBar
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface SMAppServiceHelper : NSObject

+ (BOOL)isHelperInstalled;
+ (BOOL)installHelperWithError:(NSError **)error;
+ (BOOL)uninstallHelperWithError:(NSError **)error;
+ (NSString *)helperStatus;
+ (BOOL)helperBinaryExists;
+ (BOOL)helperPlistProgramArgumentsMatch;

// Helpers for inspecting non-bundled installations (e.g., status_helper CLI)
+ (NSString *)helperBinaryPathForBundlePath:(NSString *)bundlePath;
+ (NSString *)helperPlistPathForBundlePath:(NSString *)bundlePath;
+ (BOOL)helperBinaryExistsAtBundlePath:(NSString *)bundlePath;
+ (BOOL)helperPlistProgramArgumentsMatchForBundlePath:(NSString *)bundlePath;

+ (NSString *)helperStatusForLegacyPlistPath:(NSString *)plistPath;

@end

NS_ASSUME_NONNULL_END

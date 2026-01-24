//
//  SMAppServiceHelper.m
//  SniffNetBar
//

#import "SMAppServiceHelper.h"
#import <ServiceManagement/ServiceManagement.h>
#import <Security/Security.h>
#import "Logger.h"

@implementation SMAppServiceHelper

static BOOL SNBSetError(NSError **error, NSInteger code, NSString *message) {
    if (error && *error == nil) {
        *error = [NSError errorWithDomain:@"SMAppServiceHelper"
                                     code:code
                                 userInfo:@{NSLocalizedDescriptionKey: message ?: @"Unknown error"}];
    }
    return NO;
}

static NSString *SNBHelperLaunchDaemonPlistPath(NSString *bundlePath) {
    if (bundlePath.length == 0) {
        return nil;
    }
    return [bundlePath stringByAppendingPathComponent:
            @"Contents/Library/LaunchDaemons/com.sniffnetbar.helper.plist"];
}

static NSString *SNBHelperBinaryPath(NSString *bundlePath) {
    if (bundlePath.length == 0) {
        return nil;
    }
    return [bundlePath stringByAppendingPathComponent:
            @"Contents/Library/LaunchDaemons/com.sniffnetbar.helper.app/Contents/MacOS/com.sniffnetbar.helper"];
}

API_AVAILABLE(macos(13.0))
static SMAppService * _Nullable SNBCurrentHelperService(void) {
    return [SMAppService daemonServiceWithPlistName:@"com.sniffnetbar.helper.plist"];
}

static BOOL SNBIsHelperServiceAvailable(void) {
    if (@available(macOS 13.0, *)) {
        return SNBCurrentHelperService() != nil;
    }
    return NO;
}

+ (NSString *)helperPlistPath {
    return SNBHelperLaunchDaemonPlistPath([NSBundle mainBundle].bundlePath);
}

+ (NSString *)helperBinaryPath {
    return SNBHelperBinaryPath([NSBundle mainBundle].bundlePath);
}

+ (BOOL)helperPlistProgramArgumentsMatch {
    NSString *plistPath = [self helperPlistPath];
    NSMutableDictionary *plist = [NSMutableDictionary dictionaryWithContentsOfFile:plistPath];
    if (!plist) {
        SNBLogWarn("Helper plist not found or unreadable at %@", plistPath);
        return NO;
    }

    NSString *binaryPath = [self helperBinaryPath];
    NSArray *arguments = plist[@"ProgramArguments"];
    if (arguments.count == 0) {
        SNBLogWarn("Helper plist ProgramArguments missing at %@", plistPath);
        return NO;
    }

    NSString *currentPath = arguments.firstObject;
    if (![currentPath isEqualToString:binaryPath]) {
        SNBLogWarn("Helper plist ProgramArguments mismatch. Expected %@, found %@",
                   binaryPath, currentPath);
        return NO;
    }

    return YES;
}

+ (BOOL)isBundleCodeSigned {
    NSString *bundlePath = [NSBundle mainBundle].bundlePath;
    if (bundlePath.length == 0) {
        return NO;
    }

    SecStaticCodeRef codeRef = NULL;
    NSURL *bundleURL = [NSURL fileURLWithPath:bundlePath];
    OSStatus status = SecStaticCodeCreateWithPath((__bridge CFURLRef)bundleURL,
                                                  kSecCSDefaultFlags,
                                                  &codeRef);
    if (status != errSecSuccess || !codeRef) {
        return NO;
    }

    status = SecStaticCodeCheckValidity(codeRef, kSecCSDefaultFlags, NULL);
    CFRelease(codeRef);
    return status == errSecSuccess;
}

+ (BOOL)ensureHelperPlistProgramArgumentsWithError:(NSError **)error {
    NSString *plistPath = [self helperPlistPath];
    NSMutableDictionary *plist = [NSMutableDictionary dictionaryWithContentsOfFile:plistPath];
    if (!plist) {
        return SNBSetError(error, 4, @"Helper plist not found or unreadable in app bundle.");
    }

    NSString *binaryPath = [self helperBinaryPath];
    NSArray *arguments = plist[@"ProgramArguments"];
    NSString *currentPath = arguments.firstObject;
    if ([currentPath isEqualToString:binaryPath]) {
        return YES;
    }

    if ([self isBundleCodeSigned]) {
        return SNBSetError(error, 5,
                           @"Helper plist ProgramArguments do not match the current app location. "
                           @"App bundle is code signed, so it cannot be modified. Rebuild and reinstall.");
    }

    plist[@"ProgramArguments"] = @[binaryPath];
    if (![plist writeToFile:plistPath atomically:YES]) {
        return SNBSetError(error, 6, @"Failed to update helper plist ProgramArguments.");
    }

    SNBLogInfo("Updated helper plist ProgramArguments to %@", binaryPath);
    return YES;
}

+ (NSString *)helperBinaryPathForBundlePath:(NSString *)bundlePath {
    return SNBHelperBinaryPath(bundlePath);
}

+ (NSString *)helperPlistPathForBundlePath:(NSString *)bundlePath {
    return SNBHelperLaunchDaemonPlistPath(bundlePath);
}

+ (BOOL)helperBinaryExistsAtBundlePath:(NSString *)bundlePath {
    NSString *binaryPath = [self helperBinaryPathForBundlePath:bundlePath];
    if (binaryPath.length == 0) {
        return NO;
    }
    return [[NSFileManager defaultManager] fileExistsAtPath:binaryPath];
}

+ (BOOL)helperPlistProgramArgumentsMatchForBundlePath:(NSString *)bundlePath {
    NSString *plistPath = [self helperPlistPathForBundlePath:bundlePath];
    NSMutableDictionary *plist = [NSMutableDictionary dictionaryWithContentsOfFile:plistPath];
    if (!plist) {
        return NO;
    }

    NSArray *arguments = plist[@"ProgramArguments"];
    if (arguments.count == 0) {
        return NO;
    }

    NSString *currentPath = arguments.firstObject;
    NSString *expectedPath = [self helperBinaryPathForBundlePath:bundlePath];
    return [currentPath isEqualToString:expectedPath];
}

+ (BOOL)helperBinaryExists {
    return [self helperBinaryExistsAtBundlePath:[NSBundle mainBundle].bundlePath];
}

+ (SMAppService *)helperService API_AVAILABLE(macos(13.0)) {
    return SNBCurrentHelperService();
}

+ (BOOL)isHelperInstalled {
    if (![self helperBinaryExists] || ![self helperPlistProgramArgumentsMatch]) {
        return NO;
    }

    if (!SNBIsHelperServiceAvailable()) {
        return NO;
    }

    if (@available(macOS 13.0, *)) {
        SMAppService *service = [self helperService];
        SMAppServiceStatus status = service.status;
        return status == SMAppServiceStatusEnabled;
    }
    return NO;
}

+ (BOOL)installHelperWithError:(NSError **)error {
    if (![self helperBinaryExists]) {
        return SNBSetError(error, 2,
                           @"Helper binary missing from app bundle. Rebuild and reinstall the app.");
    }

    if (![self ensureHelperPlistProgramArgumentsWithError:error]) {
        return NO;
    }

    if (@available(macOS 13.0, *)) {
        SMAppService *service = [self helperService];
        if (!service) {
            return SNBSetError(error, 7, @"SMAppService is unavailable on this OS version.");
        }

        SMAppServiceStatus status = service.status;
        SNBLogInfo("Helper daemon status before registration: %ld", (long)status);
        if (status == SMAppServiceStatusEnabled) {
            SNBLogInfo("Helper already enabled, skipping registration");
            return YES;
        }

        BOOL success = [service registerAndReturnError:error];
        if (!success) {
            SNBLogError("Helper registration failed: %s", error ? (*error).localizedDescription.UTF8String : "unknown error");
            return NO;
        }

        SMAppServiceStatus newStatus = service.status;
        SNBLogInfo("Helper daemon status after registration: %ld", (long)newStatus);
        if (newStatus == SMAppServiceStatusNotFound || newStatus == SMAppServiceStatusNotRegistered) {
            return SNBSetError(error, 1,
                               @"Helper registration failed. Verify helper plist and bundle are embedded in the app.");
        }
        return YES;
    }

    return SNBSetError(error, 7, @"SMAppService is unavailable on this OS version.");
}

+ (BOOL)uninstallHelperWithError:(NSError **)error {
    if (@available(macOS 13.0, *)) {
        SMAppService *service = [self helperService];
        if (!service) {
            return SNBSetError(error, 8, @"SMAppService is unavailable on this OS version.");
        }
        return [service unregisterAndReturnError:error];
    }
    return SNBSetError(error, 8, @"SMAppService is unavailable on this OS version.");
}

+ (NSString *)helperStatus {
    if (@available(macOS 13.0, *)) {
        SMAppService *service = [self helperService];
        if (!service) {
            return @"Unsupported";
        }
        SMAppServiceStatus status = service.status;
        switch (status) {
            case SMAppServiceStatusNotRegistered:
                return @"Not Registered";
            case SMAppServiceStatusEnabled:
                return @"Enabled";
            case SMAppServiceStatusRequiresApproval:
                return @"Requires Approval";
            case SMAppServiceStatusNotFound:
                return @"Not Found";
            default:
                return @"Unknown";
        }
    }
    return @"Unsupported";
}

+ (NSString *)helperStatusForLegacyPlistPath:(NSString *)plistPath {
    if (@available(macOS 13.0, *)) {
        NSURL *plistURL = [NSURL fileURLWithPath:plistPath];
        if (!plistURL) {
            return @"Unknown";
        }
        SMAppServiceStatus status = [SMAppService statusForLegacyURL:plistURL];
        switch (status) {
            case SMAppServiceStatusNotRegistered: return @"Not Registered";
            case SMAppServiceStatusEnabled: return @"Enabled";
            case SMAppServiceStatusRequiresApproval: return @"Requires Approval";
            case SMAppServiceStatusNotFound: return @"Not Found";
            default: return @"Unknown";
        }
    }
    return @"Unsupported";
}

@end

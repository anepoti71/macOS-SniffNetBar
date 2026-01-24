//
//  AuthorizationHelper.m
//  SniffNetBar
//
//  Authorization helper for requesting root privileges
//

#import "AuthorizationHelper.h"
#import "Logger.h"
#import <Cocoa/Cocoa.h>
#import <Security/Security.h>
#import <unistd.h>

@implementation AuthorizationHelper

+ (BOOL)isRunningAsRoot {
    return geteuid() == 0;
}

+ (SNBAuthorizationStatus)requestAuthorizationWithMessage:(NSString *)message
                                            informativeText:(NSString *)informativeText {
    if ([self isRunningAsRoot]) {
        return SNBAuthorizationStatusAlreadyRoot;
    }

    __block SNBAuthorizationStatus status = SNBAuthorizationStatusDenied;
    __block BOOL dialogCompleted = NO;

    dispatch_async(dispatch_get_main_queue(), ^{
        NSAlert *alert = [[NSAlert alloc] init];
        alert.messageText = message;
        alert.informativeText = informativeText;
        alert.alertStyle = NSAlertStyleInformational;
        [alert addButtonWithTitle:@"Grant Access"];
        [alert addButtonWithTitle:@"Quit"];
        alert.icon = [NSImage imageNamed:NSImageNameCaution];

        NSModalResponse response = [alert runModal];

        if (response == NSAlertFirstButtonReturn) {
            status = SNBAuthorizationStatusAuthorized;
        } else {
            status = SNBAuthorizationStatusDenied;
        }

        dialogCompleted = YES;
    });

    while (!dialogCompleted) {
        [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode
                                 beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.1]];
    }

    return status;
}

+ (BOOL)relaunchAsRoot {
    // SECURITY: This method previously used AuthorizationExecuteWithPrivileges which is
    // deprecated and has TOCTOU (time-of-check-time-of-use) vulnerabilities.
    // The modern approach is to use SMAppService with a privileged helper tool,
    // which SniffNetBar now implements via SMAppServiceHelper.
    //
    // This method is kept for API compatibility but now returns NO with a warning.
    // Callers should use the privileged helper pattern instead.

    if ([self isRunningAsRoot]) {
        SNBLogInfo("Already running as root");
        return YES;
    }

    SNBLogError("relaunchAsRoot is deprecated due to security vulnerabilities. "
                "Use SMAppService with a privileged helper tool instead. "
                "See SMAppServiceHelper for the modern implementation.");

    // Show user-facing alert explaining the situation
    dispatch_async(dispatch_get_main_queue(), ^{
        NSAlert *alert = [[NSAlert alloc] init];
        alert.messageText = @"Privilege Elevation Not Available";
        alert.informativeText = @"This method of obtaining root privileges is no longer supported "
                                @"for security reasons. SniffNetBar uses a privileged helper tool "
                                @"that should be installed via System Settings > Login Items.\n\n"
                                @"Please ensure the SniffNetBar helper is approved in System Settings.";
        alert.alertStyle = NSAlertStyleWarning;
        [alert addButtonWithTitle:@"Open System Settings"];
        [alert addButtonWithTitle:@"OK"];

        NSModalResponse response = [alert runModal];
        if (response == NSAlertFirstButtonReturn) {
            // Open System Settings to Login Items (macOS 13+) or Security pane
            NSURL *url = [NSURL URLWithString:@"x-apple.systempreferences:com.apple.LoginItems-Settings.extension"];
            if (![[NSWorkspace sharedWorkspace] openURL:url]) {
                // Fallback for older macOS
                [[NSWorkspace sharedWorkspace] openURL:[NSURL URLWithString:@"x-apple.systempreferences:com.apple.preference.security"]];
            }
        }
    });

    return NO;
}

@end

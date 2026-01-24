//
//  status_helper.m
//  SniffNetBar
//

#import <Foundation/Foundation.h>
#import "SMAppServiceHelper.h"

static const char *statusString(NSString *status) {
    return status.length > 0 ? status.UTF8String : "Unknown";
}

static NSString *defaultInstallPath(void) {
    return [NSHomeDirectory() stringByAppendingPathComponent:@"Applications/SniffNetBar.app"];
}

static NSString *sniffNetBarAppBundleNearPath(NSString *path) {
    if (path.length == 0) {
        return nil;
    }

    if ([[path lastPathComponent] isEqual:@"SniffNetBar.app"]) {
        return path;
    }

    NSString *parent = path;
    while (parent.length > 0) {
        NSString *candidate = [parent stringByAppendingPathComponent:@"SniffNetBar.app"];
        if ([[NSFileManager defaultManager] fileExistsAtPath:candidate]) {
            return candidate;
        }
        NSString *next = [parent stringByDeletingLastPathComponent];
        if ([next isEqualToString:parent]) {
            break;
        }
        parent = next;
    }

    NSString *current = path;
    while (current.length > 0) {
        if ([[current lastPathComponent] isEqual:@"SniffNetBar.app"]) {
            return current;
        }
        NSString *next = [current stringByDeletingLastPathComponent];
        if ([next isEqualToString:current]) {
            break;
        }
        current = next;
    }

    return nil;
}

static NSString *resolveAppBundlePath(int argc, const char *argv[]) {
    if (argc > 1) {
        return [NSString stringWithUTF8String:argv[1]];
    }

    NSString *defaultPath = defaultInstallPath();
    if ([[NSFileManager defaultManager] fileExistsAtPath:defaultPath]) {
        return defaultPath;
    }

    NSString *bundlePath = [[NSBundle mainBundle] bundlePath];
    NSString *found = sniffNetBarAppBundleNearPath(bundlePath);
    if (found) {
        return found;
    }

    return bundlePath;
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        NSString *bundlePath = resolveAppBundlePath(argc, argv);
        if (bundlePath.length == 0 || ![[NSFileManager defaultManager] fileExistsAtPath:bundlePath]) {
            fprintf(stderr, "App bundle not found at %s\n", bundlePath.UTF8String ?: "Unknown");
            return 1;
        }

        BOOL binaryExists = [SMAppServiceHelper helperBinaryExistsAtBundlePath:bundlePath];
        BOOL plistMatch = [SMAppServiceHelper helperPlistProgramArgumentsMatchForBundlePath:bundlePath];
        NSString *plistPath = [SMAppServiceHelper helperPlistPathForBundlePath:bundlePath];
        NSString *status = [SMAppServiceHelper helperStatusForLegacyPlistPath:plistPath];

        printf("=== SniffNetBar Helper Status ===\n\n");
        printf("Inspecting app bundle at: %s\n", bundlePath.UTF8String);
        printf("Helper binary exists: %s\n", binaryExists ? "YES" : "NO");
        printf("Plist ProgramArguments match: %s\n", plistMatch ? "YES" : "NO");
        printf("Service status: %s\n", statusString(status));

        if (!binaryExists) {
            printf("Hint: rebuild and reinstall the app bundle.\n");
        } else if (!plistMatch) {
            printf("Hint: run make install to fix ProgramArguments path.\n");
        } else if ([status isEqualToString:@"Requires Approval"]) {
            printf("Hint: enable SniffNetBar Helper in System Settings > Login Items.\n");
        }

        BOOL helperReady = binaryExists && plistMatch &&
                           ([status isEqualToString:@"Enabled"] || [status isEqualToString:@"Requires Approval"]);
        return helperReady ? 0 : 1;
    }
}

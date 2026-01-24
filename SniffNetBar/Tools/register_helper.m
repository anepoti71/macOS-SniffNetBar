//
//  register_helper.m
//  SniffNetBar
//

#import <Foundation/Foundation.h>
#import <string.h>
#import "SMAppServiceHelper.h"

static const char *statusString(NSString *status) {
    return status.length > 0 ? status.UTF8String : "Unknown";
}

static BOOL helperReady(void) {
    NSString *status = [SMAppServiceHelper helperStatus];
    return [status isEqualToString:@"Enabled"] || [status isEqualToString:@"Requires Approval"];
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc > 1 && strcmp(argv[1], "--status") == 0) {
            NSString *status = [SMAppServiceHelper helperStatus];
            printf("Helper status: %s\n", statusString(status));
            return helperReady() ? 0 : 1;
        }

        if ([SMAppServiceHelper isHelperInstalled]) {
            printf("Helper already registered. Status: %s\n", statusString([SMAppServiceHelper helperStatus]));
            return 0;
        }

        NSError *error = nil;
        BOOL success = [SMAppServiceHelper installHelperWithError:&error];
        if (!success) {
            const char *message = error.localizedDescription.UTF8String ?: "Unknown error";
            fprintf(stderr, "Failed to register helper: %s\n", message);
            return 1;
        }

        printf("Helper registered. Status: %s\n", statusString([SMAppServiceHelper helperStatus]));
        return 0;
    }
}

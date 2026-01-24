//
//  unregister_helper.m
//  SniffNetBar
//

#import <Foundation/Foundation.h>
#import <ServiceManagement/ServiceManagement.h>
#import <Security/Security.h>
#import "SMAppServiceHelper.h"

static BOOL removeHelperWithAuthorization(NSError **error) {
    AuthorizationRef authRef = NULL;
    OSStatus status = AuthorizationCreate(NULL,
                                          kAuthorizationEmptyEnvironment,
                                          kAuthorizationFlagDefaults,
                                          &authRef);
    if (status != errAuthorizationSuccess || !authRef) {
        if (error) {
            *error = [NSError errorWithDomain:NSOSStatusErrorDomain
                                         code:status
                                     userInfo:@{NSLocalizedDescriptionKey: @"Failed to create authorization reference"}];
        }
        return NO;
    }

    AuthorizationItem authItem = {kSMRightModifySystemDaemons, 0, NULL, 0};
    AuthorizationRights rights = {1, &authItem};
    AuthorizationFlags flags = kAuthorizationFlagInteractionAllowed |
                               kAuthorizationFlagPreAuthorize |
                               kAuthorizationFlagExtendRights;
    status = AuthorizationCopyRights(authRef, &rights, NULL, flags, NULL);
    if (status != errAuthorizationSuccess) {
        AuthorizationFree(authRef, kAuthorizationFlagDestroyRights);
        if (error) {
            *error = [NSError errorWithDomain:NSOSStatusErrorDomain
                                         code:status
                                     userInfo:@{NSLocalizedDescriptionKey: @"Authorization denied for modifying system daemons"}];
        }
        return NO;
    }

    CFErrorRef cfError = NULL;
    Boolean removed = SMJobRemove(kSMDomainSystemLaunchd,
                                  CFSTR("com.sniffnetbar.helper"),
                                  authRef,
                                  true,
                                  &cfError);
    AuthorizationFree(authRef, kAuthorizationFlagDestroyRights);

    if (!removed) {
        if (error) {
            if (cfError) {
                *error = CFBridgingRelease(cfError);
            } else {
                *error = [NSError errorWithDomain:@"SMJobRemove"
                                             code:1
                                         userInfo:@{NSLocalizedDescriptionKey: @"Failed to remove helper job"}];
            }
        } else if (cfError) {
            CFRelease(cfError);
        }
        return NO;
    }

    if (cfError) {
        CFRelease(cfError);
    }
    return YES;
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        NSError *error = nil;
        BOOL success = [SMAppServiceHelper uninstallHelperWithError:&error];
        if (!success) {
            NSError *fallbackError = nil;
            if (removeHelperWithAuthorization(&fallbackError)) {
                printf("Helper unregistered using SMJobRemove.\n");
                return 0;
            }

            const char *message = (fallbackError ?: error).localizedDescription.UTF8String ?: "Unknown error";
            fprintf(stderr, "Failed to unregister helper: %s\n", message);
            return 1;
        }

        printf("Helper unregistered.\n");
        return 0;
    }
}

//
//  KeychainManager.m
//  SniffNetBar
//
//  Secure keychain management for API keys
//

#import "KeychainManager.h"
#import "Logger.h"
#import <Security/Security.h>

// Service identifier for keychain items
static NSString * const kKeychainServiceName = @"com.sniffnetbar.api-keys";

// Error domain for KeychainManager errors
static NSString * const kKeychainManagerErrorDomain = @"com.sniffnetbar.keychain";

// In-memory cache to avoid repeated keychain prompts.
static NSMutableDictionary<NSString *, NSString *> *s_cachedAPIKeys = nil;
static NSMutableSet<NSString *> *s_missingAPIKeys = nil;
static BOOL s_cacheLoaded = NO;
static BOOL s_keychainAccessEnabled = NO;

// Class-level lock for synchronizing access to static variables
static NSObject *s_lock = nil;

// Error codes
typedef NS_ENUM(NSInteger, KeychainManagerErrorCode) {
    KeychainManagerErrorItemNotFound = 1001,
    KeychainManagerErrorAccessDenied = 1002,
    KeychainManagerErrorInvalidParameter = 1003,
    KeychainManagerErrorUnknown = 1004
};

@implementation KeychainManager

+ (void)initialize {
    if (self == [KeychainManager class]) {
        s_lock = [[NSObject alloc] init];
    }
}

#pragma mark - Cache Helpers

+ (NSMutableDictionary<NSString *, NSString *> *)loadAPIKeyCacheWithError:(NSError *_Nullable *_Nullable)error {
    // Don't actually load anything - let individual key accesses handle their own queries
    // This prevents multiple prompts
    @synchronized(s_lock) {
        if (!s_cachedAPIKeys) {
            s_cachedAPIKeys = [[NSMutableDictionary alloc] init];
        }
        s_cacheLoaded = YES;
        return s_cachedAPIKeys;
    }
}

- (void)invalidateCache {
    @synchronized(s_lock) {
        s_cachedAPIKeys = nil;
        s_cacheLoaded = NO;
    }
}

#pragma mark - Public Methods

+ (BOOL)saveAPIKey:(nullable NSString *)apiKey
     forIdentifier:(NSString *)identifier
             error:(NSError *_Nullable *_Nullable)error {

    if (!identifier || identifier.length == 0) {
        if (error) {
            *error = [self errorWithCode:KeychainManagerErrorInvalidParameter
                             description:@"Identifier cannot be nil or empty"];
        }
        return NO;
    }

    // If apiKey is nil or empty, delete the item
    if (!apiKey || apiKey.length == 0) {
        return [self deleteAPIKeyForIdentifier:identifier error:error];
    }

    NSData *passwordData = [apiKey dataUsingEncoding:NSUTF8StringEncoding];

    // Try to add new item first
    NSDictionary *attributes = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kKeychainServiceName,
        (__bridge id)kSecAttrAccount: identifier,
        (__bridge id)kSecValueData: passwordData,
        (__bridge id)kSecAttrAccessible: (__bridge id)kSecAttrAccessibleAfterFirstUnlock
    };

    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)attributes, NULL);

    if (status == errSecDuplicateItem) {
        // Item exists, update it instead
        NSDictionary *query = @{
            (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
            (__bridge id)kSecAttrService: kKeychainServiceName,
            (__bridge id)kSecAttrAccount: identifier
        };

        NSDictionary *attributesToUpdate = @{
            (__bridge id)kSecValueData: passwordData
        };

        status = SecItemUpdate((__bridge CFDictionaryRef)query,
                              (__bridge CFDictionaryRef)attributesToUpdate);
    }

    if (status != errSecSuccess) {
        if (error) {
            *error = [self errorFromOSStatus:status];
        }
        return NO;
    }

    // Update cache
    @synchronized(s_lock) {
        if (!s_cachedAPIKeys) {
            s_cachedAPIKeys = [[NSMutableDictionary alloc] init];
        }
        s_cachedAPIKeys[identifier] = apiKey;
        if (s_missingAPIKeys) {
            [s_missingAPIKeys removeObject:identifier];
        }
        s_cacheLoaded = YES;
    }

    return YES;
}

+ (nullable NSString *)getAPIKeyForIdentifier:(NSString *)identifier
                                        error:(NSError *_Nullable *_Nullable)error {

    // Block keychain access until explicitly enabled (after root privileges obtained)
    @synchronized(s_lock) {
        if (!s_keychainAccessEnabled) {
            SNBLogConfigInfo("Keychain access blocked - not yet enabled (waiting for root privileges)");
            return nil;
        }
    }

    if (!identifier || identifier.length == 0) {
        if (error) {
            *error = [self errorWithCode:KeychainManagerErrorInvalidParameter
                             description:@"Identifier cannot be nil or empty"];
        }
        return nil;
    }

    // Check cache first
    @synchronized(s_lock) {
        if (s_cacheLoaded && s_cachedAPIKeys && s_cachedAPIKeys[identifier]) {
            SNBLogConfigDebug("Keychain cache hit for: %{public}@", identifier);
            return s_cachedAPIKeys[identifier];
        }
        if (s_missingAPIKeys && [s_missingAPIKeys containsObject:identifier]) {
            return nil;
        }
    }

    SNBLogConfigDebug("Keychain lookup for: %{public}@", identifier);

    // Query keychain directly
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kKeychainServiceName,
        (__bridge id)kSecAttrAccount: identifier,
        (__bridge id)kSecReturnData: @YES
    };

    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);

    if (status == errSecItemNotFound) {
        @synchronized(s_lock) {
            if (!s_missingAPIKeys) {
                s_missingAPIKeys = [[NSMutableSet alloc] init];
            }
            [s_missingAPIKeys addObject:identifier];
        }
        return nil;
    }

    if (status != errSecSuccess) {
        if (error) {
            *error = [self errorFromOSStatus:status];
        }
        return nil;
    }

    NSData *passwordData = (__bridge_transfer NSData *)result;
    NSString *apiKey = [[NSString alloc] initWithData:passwordData encoding:NSUTF8StringEncoding];

    // Update cache
    @synchronized(s_lock) {
        if (!s_cachedAPIKeys) {
            s_cachedAPIKeys = [[NSMutableDictionary alloc] init];
        }
        if (apiKey) {
            s_cachedAPIKeys[identifier] = apiKey;
            if (s_missingAPIKeys) {
                [s_missingAPIKeys removeObject:identifier];
            }
        }
    }

    return apiKey;
}

+ (BOOL)deleteAPIKeyForIdentifier:(NSString *)identifier
                            error:(NSError *_Nullable *_Nullable)error {

    if (!identifier || identifier.length == 0) {
        if (error) {
            *error = [self errorWithCode:KeychainManagerErrorInvalidParameter
                             description:@"Identifier cannot be nil or empty"];
        }
        return NO;
    }

    NSMutableDictionary<NSString *, NSString *> *cache = [self loadAPIKeyCacheWithError:error];
    if (!cache) {
        return NO;
    }

    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kKeychainServiceName,
        (__bridge id)kSecAttrAccount: identifier
    };

    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);

    // Consider errSecItemNotFound as success (item doesn't exist = successfully deleted)
    if (status == errSecSuccess || status == errSecItemNotFound) {
        [cache removeObjectForKey:identifier];
        @synchronized(s_lock) {
            if (!s_missingAPIKeys) {
                s_missingAPIKeys = [[NSMutableSet alloc] init];
            }
            [s_missingAPIKeys addObject:identifier];
        }
        return YES;
    }

    if (error) {
        *error = [self errorFromOSStatus:status];
    }

    return NO;
}

+ (BOOL)hasAPIKeyForIdentifier:(NSString *)identifier {
    if (!identifier || identifier.length == 0) {
        return NO;
    }

    NSError *error = nil;
    NSMutableDictionary<NSString *, NSString *> *cache = [self loadAPIKeyCacheWithError:&error];
    if (!cache) {
        return NO;
    }

    return (cache[identifier] != nil);
}

+ (BOOL)preloadAPIKeysWithError:(NSError *_Nullable *_Nullable)error {
    NSMutableDictionary<NSString *, NSString *> *cache = [self loadAPIKeyCacheWithError:error];
    return cache != nil;
}

+ (BOOL)requestKeychainAccessWithError:(NSError *_Nullable *_Nullable)error {
    BOOL alreadyEnabled = NO;
    @synchronized(s_lock) {
        alreadyEnabled = s_keychainAccessEnabled;
        s_keychainAccessEnabled = YES;
    }
    if (!alreadyEnabled) {
        SNBLogConfigInfo("Keychain access enabled");
    }

    // Success - keychain is now accessible
    return YES;
}

#pragma mark - Error Handling

+ (NSError *)errorFromOSStatus:(OSStatus)status {
    KeychainManagerErrorCode code;
    NSString *description;

    switch (status) {
        case errSecItemNotFound:
            code = KeychainManagerErrorItemNotFound;
            description = @"Keychain item not found";
            break;

        case errSecAuthFailed:
        case errSecInteractionNotAllowed:
            code = KeychainManagerErrorAccessDenied;
            description = @"Access to keychain denied";
            break;

        case errSecParam:
            code = KeychainManagerErrorInvalidParameter;
            description = @"Invalid parameter";
            break;

        default:
            code = KeychainManagerErrorUnknown;
            description = [NSString stringWithFormat:@"Keychain error: %d", (int)status];
            break;
    }

    return [self errorWithCode:code description:description];
}

+ (NSError *)errorWithCode:(KeychainManagerErrorCode)code description:(NSString *)description {
    NSDictionary *userInfo = @{NSLocalizedDescriptionKey: description};
    return [NSError errorWithDomain:kKeychainManagerErrorDomain
                               code:code
                           userInfo:userInfo];
}

@end

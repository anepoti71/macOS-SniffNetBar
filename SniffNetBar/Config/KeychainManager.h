//
//  KeychainManager.h
//  SniffNetBar
//
//  Secure keychain management for API keys
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/**
 * Manages secure storage and retrieval of API keys using macOS Keychain Services.
 * This class provides a simple interface to store sensitive credentials securely
 * instead of storing them in plaintext configuration files.
 */
@interface KeychainManager : NSObject

/**
 * Save an API key to the keychain
 * @param apiKey The API key value to store (if nil or empty, removes the keychain item)
 * @param identifier The unique identifier for this key (e.g., "VirusTotalAPIKey")
 * @param error Output parameter for error information
 * @return YES if successful, NO if an error occurred
 */
+ (BOOL)saveAPIKey:(nullable NSString *)apiKey
     forIdentifier:(NSString *)identifier
             error:(NSError *_Nullable *_Nullable)error;

/**
 * Retrieve an API key from the keychain
 * @param identifier The unique identifier for this key (e.g., "VirusTotalAPIKey")
 * @param error Output parameter for error information
 * @return The API key string, or nil if not found or error occurred
 */
+ (nullable NSString *)getAPIKeyForIdentifier:(NSString *)identifier
                                        error:(NSError *_Nullable *_Nullable)error;

/**
 * Delete an API key from the keychain
 * @param identifier The unique identifier for this key
 * @param error Output parameter for error information
 * @return YES if successful or item doesn't exist, NO if an error occurred
 */
+ (BOOL)deleteAPIKeyForIdentifier:(NSString *)identifier
                            error:(NSError *_Nullable *_Nullable)error;

/**
 * Check if an API key exists in the keychain
 * @param identifier The unique identifier for this key
 * @return YES if the key exists and is accessible
 */
+ (BOOL)hasAPIKeyForIdentifier:(NSString *)identifier;

/**
 * Preload API keys from the keychain to trigger a single permission prompt.
 * @param error Output parameter for error information
 * @return YES if the cache was loaded, NO if an error occurred
 */
+ (BOOL)preloadAPIKeysWithError:(NSError *_Nullable *_Nullable)error;

/**
 * Request keychain access permission by attempting a keychain operation.
 * This triggers the system keychain access prompt on first launch.
 * @param error Output parameter for error information
 * @return YES if access was granted or already available, NO if denied
 */
+ (BOOL)requestKeychainAccessWithError:(NSError *_Nullable *_Nullable)error;

@end

NS_ASSUME_NONNULL_END

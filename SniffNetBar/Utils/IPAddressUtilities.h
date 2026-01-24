//
//  IPAddressUtilities.h
//  SniffNetBar
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/**
 * Centralized IP address validation utilities
 * Provides comprehensive validation for IPv4 and IPv6 addresses
 */
@interface IPAddressUtilities : NSObject

// Basic validation
+ (BOOL)isValidIPv4:(NSString *)ipAddress;
+ (BOOL)isValidIPv6:(NSString *)ipAddress;

// Private/local address detection
+ (BOOL)isPrivateIPv4Address:(NSString *)ipAddress;
+ (BOOL)isPrivateIPv6Address:(NSString *)ipAddress;
+ (BOOL)isPrivateIPAddress:(NSString *)ipAddress;  // IPv4 or IPv6

// Public address detection (suitable for threat intelligence)
+ (BOOL)isPublicIPAddress:(NSString *)ipAddress;

// Special address ranges
+ (BOOL)isLoopbackAddress:(NSString *)ipAddress;
+ (BOOL)isMulticastAddress:(NSString *)ipAddress;
+ (BOOL)isLinkLocalAddress:(NSString *)ipAddress;

@end

NS_ASSUME_NONNULL_END

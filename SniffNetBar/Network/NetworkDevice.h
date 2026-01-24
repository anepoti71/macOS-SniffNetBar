//
//  NetworkDevice.h
//  SniffNetBar
//
//  Represents a network interface/device
//

#import <Foundation/Foundation.h>

@interface NetworkDevice : NSObject

@property (nonatomic, strong, readonly) NSString *name;
@property (nonatomic, strong, readonly) NSString *deviceDescription;
@property (nonatomic, strong, readonly) NSArray<NSString *> *addresses;

- (instancetype)initWithName:(NSString *)name description:(NSString *)description addresses:(NSArray<NSString *> *)addresses;

- (NSString *)displayName;

+ (NSArray<NetworkDevice *> *)listAllDevices;
+ (NetworkDevice *)defaultDevice;

@end


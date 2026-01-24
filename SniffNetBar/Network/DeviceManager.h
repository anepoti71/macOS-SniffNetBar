//
//  DeviceManager.h
//  SniffNetBar
//

#import <Foundation/Foundation.h>

@class ConfigurationManager;
@class NetworkDevice;
@class PacketCaptureManager;

@interface DeviceManager : NSObject

@property (nonatomic, strong, readonly) PacketCaptureManager *packetManager;
@property (nonatomic, strong, readonly) NSArray<NetworkDevice *> *availableDevices;
@property (nonatomic, strong) NetworkDevice *selectedDevice;

- (instancetype)initWithPacketManager:(PacketCaptureManager *)packetManager
                        configuration:(ConfigurationManager *)configuration;
- (void)loadAvailableDevices;
- (void)restoreSelectedDevice;
- (void)refreshDeviceList;
- (BOOL)startCaptureWithError:(NSError **)error;
- (BOOL)selectDevice:(NetworkDevice *)device error:(NSError **)error;

@end

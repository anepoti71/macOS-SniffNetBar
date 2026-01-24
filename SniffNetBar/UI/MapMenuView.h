//
//  MapMenuView.h
//  SniffNetBar
//
//  Map visualization embedded in the menu
//

#import <Cocoa/Cocoa.h>
#import "TrafficStatistics.h"

@class MapMenuView;
@class TIEnrichmentResponse;

@protocol MapMenuViewDelegate <NSObject>
@optional
- (void)mapMenuView:(MapMenuView *)mapView didSelectConnectionWithSource:(NSString *)sourceIP destination:(NSString *)destinationIP;
- (void)mapMenuViewDidClearSelection:(MapMenuView *)mapView;
- (void)mapMenuView:(MapMenuView *)mapView didRequestAction:(NSString *)action forIP:(NSString *)ipAddress;
@end

/// Map layer type for visualization options
typedef NS_ENUM(NSInteger, SNBMapLayerType) {
    SNBMapLayerTypeStandard = 0,   // CARTO Voyager (default)
    SNBMapLayerTypeSatellite = 1   // Esri World Imagery
};

@interface MapMenuView : NSView

@property (nonatomic, weak) id<MapMenuViewDelegate> delegate;

@property (nonatomic, copy) NSString *providerName;
@property (nonatomic, assign, readonly) NSUInteger drawnConnectionCount;

/// Current base layer type (standard or satellite)
@property (nonatomic, assign) SNBMapLayerType baseLayerType;

/// Whether heat map overlay is enabled
@property (nonatomic, assign) BOOL heatMapEnabled;

/// Whether legend panel is visible
@property (nonatomic, assign) BOOL legendVisible;

- (void)updateWithConnections:(NSArray<ConnectionTraffic *> *)connections;
- (void)updateWithConnections:(NSArray<ConnectionTraffic *> *)connections
           threatIntelResults:(NSDictionary<NSString *, TIEnrichmentResponse *> *)threatIntelResults
                    blockedIPs:(NSSet<NSString *> *)blockedIPs;

/// Toggle between standard and satellite base layers
- (void)toggleSatelliteLayer;

/// Toggle heat map overlay on/off
- (void)toggleHeatMap;

/// Toggle legend panel visibility
- (void)toggleLegend;

@end

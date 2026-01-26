//
//  SNBMenuThreatsSectionBuilder.h
//  SniffNetBar
//

#import <Cocoa/Cocoa.h>

@class MenuBuilder;
@class TrafficStats;
@class TIEnrichmentResponse;
@class ThreatInfo;

NS_ASSUME_NONNULL_BEGIN

@interface SNBMenuThreatsSectionBuilder : NSObject

@property (nonatomic, strong, readonly, nullable) NSMenuItem *cleanConnectionsHeader;
@property (nonatomic, strong, readonly, nullable) NSMenuItem *cleanConnectionsSeparator;

- (void)appendToMenu:(NSMenu *)menu
               stats:(TrafficStats *)stats
   threatIntelEnabled:(BOOL)threatIntelEnabled
threatIntelStatusMessage:(nullable NSString *)threatIntelStatusMessage
   threatIntelResults:(NSDictionary<NSString *, TIEnrichmentResponse *> *)threatIntelResults
          cacheStats:(NSDictionary * _Nullable)cacheStats
  selectedThreatInfo:(nullable ThreatInfo *)selectedThreatInfo
         menuBuilder:(MenuBuilder *)menuBuilder;

- (void)refreshCleanConnectionsWithStats:(TrafficStats *)stats
                     threatIntelResults:(NSDictionary<NSString *, TIEnrichmentResponse *> *)threatIntelResults
                                 inMenu:(NSMenu *)menu
                            menuBuilder:(MenuBuilder *)menuBuilder;

- (void)reset;

@end

NS_ASSUME_NONNULL_END

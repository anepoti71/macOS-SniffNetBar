//
//  SNBMenuTopHostsSectionBuilder.h
//  SniffNetBar
//

#import <Cocoa/Cocoa.h>

@class TrafficStats;
@class MenuBuilder;

NS_ASSUME_NONNULL_BEGIN

@interface SNBMenuTopHostsSectionBuilder : NSObject

@property (nonatomic, strong, readonly, nullable) NSMenuItem *headerItem;
@property (nonatomic, strong, readonly, nullable) NSMenuItem *separatorItem;

- (void)appendToDetailsMenu:(NSMenu *)detailsMenu
                      stats:(TrafficStats *)stats
                menuBuilder:(MenuBuilder *)menuBuilder;
- (void)refreshWithStats:(TrafficStats *)stats
            detailsMenu:(NSMenu *)detailsMenu
             menuBuilder:(MenuBuilder *)menuBuilder;
- (void)reset;

@end

NS_ASSUME_NONNULL_END

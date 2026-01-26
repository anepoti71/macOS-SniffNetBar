//
//  SNBMenuAssetsSectionBuilder.h
//  SniffNetBar
//

#import <Cocoa/Cocoa.h>

@class MenuBuilder;
@class SNBNetworkAsset;

NS_ASSUME_NONNULL_BEGIN

@interface SNBMenuAssetsSectionBuilder : NSObject

@property (nonatomic, strong, readonly, nullable) NSMenuItem *headerItem;
@property (nonatomic, strong, readonly, nullable) NSMenuItem *separatorItem;
@property (nonatomic, copy, readonly) NSArray<NSMenuItem *> *sectionItems;

- (void)appendToMenu:(NSMenu *)menu
  assetMonitorEnabled:(BOOL)assetMonitorEnabled
       networkAssets:(NSArray<SNBNetworkAsset *> *)networkAssets
     recentNewAssets:(NSArray<SNBNetworkAsset *> *)recentNewAssets
         menuBuilder:(MenuBuilder *)menuBuilder;
- (void)refreshWithAssets:(NSArray<SNBNetworkAsset *> *)networkAssets
          recentNewAssets:(NSArray<SNBNetworkAsset *> *)recentNewAssets
      assetMonitorEnabled:(BOOL)assetMonitorEnabled
                   inMenu:(NSMenu *)menu
              menuBuilder:(MenuBuilder *)menuBuilder;
- (void)reset;

@end

NS_ASSUME_NONNULL_END

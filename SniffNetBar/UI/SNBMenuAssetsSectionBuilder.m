//
//  SNBMenuAssetsSectionBuilder.m
//  SniffNetBar
//

#import "SNBMenuAssetsSectionBuilder.h"
#import "MenuBuilder+SectionSupport.h"
#import "MenuBuilderConstants.h"
#import "NetworkAssetMonitor.h"

@interface SNBMenuAssetsSectionBuilder ()
@property (nonatomic, strong) NSMenuItem *headerItem;
@property (nonatomic, strong) NSMenuItem *separatorItem;
@property (nonatomic, copy) NSArray<NSMenuItem *> *sectionItems;
@end

@implementation SNBMenuAssetsSectionBuilder

- (void)appendToMenu:(NSMenu *)menu
  assetMonitorEnabled:(BOOL)assetMonitorEnabled
       networkAssets:(NSArray<SNBNetworkAsset *> *)networkAssets
     recentNewAssets:(NSArray<SNBNetworkAsset *> *)recentNewAssets
         menuBuilder:(MenuBuilder *)menuBuilder {
    if (!menu || !assetMonitorEnabled) {
        [self reset];
        return;
    }

    NSMenuItem *networkDevicesHeader = [menuBuilder collapsibleSectionHeaderWithTitle:@"NETWORK DEVICES"
                                                                             expanded:menuBuilder.sectionNetworkDevicesExpanded
                                                                               action:@selector(toggleSectionNetworkDevices)
                                                                               target:menuBuilder];
    self.headerItem = networkDevicesHeader;
    [menu addItem:networkDevicesHeader];

    NSMutableArray<NSMenuItem *> *items = [NSMutableArray array];
    if (menuBuilder.sectionNetworkDevicesExpanded) {
        if (networkAssets.count == 0) {
            NSMenuItem *emptyItem = [[NSMenuItem alloc] initWithTitle:@"⟳ Scanning network..."
                                                              action:nil
                                                       keyEquivalent:@""];
            emptyItem.enabled = NO;
            [menu addItem:emptyItem];
            [items addObject:emptyItem];
        } else {
            NSString *newBadge = recentNewAssets.count > 0
                ? [NSString stringWithFormat:@" (%lu new)", (unsigned long)recentNewAssets.count]
                : @"";
            NSString *summaryStr = [NSString stringWithFormat:@"%lu Device%@%@",
                                   (unsigned long)networkAssets.count,
                                   networkAssets.count == 1 ? @"" : @"s",
                                   newBadge];
            NSMenuItem *devicesTotalItem = [menuBuilder styledStatItemWithLabel:@"Total"
                                                                         value:summaryStr
                                                                         color:[NSColor labelColor]];
            [menuBuilder cacheStatItem:devicesTotalItem
                                 label:@"Total"
                                 color:[NSColor labelColor]
                                forKey:SNBMenuItemKeyNetworkDevicesTotal];
            [menu addItem:devicesTotalItem];
            [items addObject:devicesTotalItem];

            if (recentNewAssets.count > 0) {
                NSMenuItem *newDevicesHeader = [menuBuilder styledMenuItemWithTitle:@"New Devices" style:@"subheader"];
                [menu addItem:newDevicesHeader];
                [items addObject:newDevicesHeader];
                NSUInteger limit = MIN(3, recentNewAssets.count);
                for (NSUInteger i = 0; i < limit; i++) {
                    SNBNetworkAsset *asset = recentNewAssets[i];

                    NSString *line;
                    if (asset.hostname.length > 0 && asset.vendor.length > 0) {
                        line = [NSString stringWithFormat:@"  🆕 %@ (%@)", asset.hostname, asset.vendor];
                    } else if (asset.hostname.length > 0) {
                        line = [NSString stringWithFormat:@"  🆕 %@", asset.hostname];
                    } else if (asset.vendor.length > 0) {
                        line = [NSString stringWithFormat:@"  🆕 %@ - %@", asset.vendor, asset.ipAddress];
                    } else {
                        line = [NSString stringWithFormat:@"  🆕 %@", asset.ipAddress];
                    }

                    NSMenuItem *item = [[NSMenuItem alloc] initWithTitle:line action:nil keyEquivalent:@""];
                    item.enabled = NO;
                    [menu addItem:item];
                    [items addObject:item];
                }
                if (recentNewAssets.count > limit) {
                    NSMenuItem *moreNewItem = [[NSMenuItem alloc] initWithTitle:[NSString stringWithFormat:@"  ... and %lu more new",
                                                                                (unsigned long)(recentNewAssets.count - limit)]
                                                                        action:nil
                                                                 keyEquivalent:@""];
                    moreNewItem.enabled = NO;
                    [menu addItem:moreNewItem];
                    [items addObject:moreNewItem];
                }
            }
        }
    }
    self.sectionItems = items;

    NSMenuItem *networkDevicesSeparator = [NSMenuItem separatorItem];
    self.separatorItem = networkDevicesSeparator;
    [menu addItem:networkDevicesSeparator];
}

- (NSArray<NSMenuItem *> *)menuItemsForNetworkDevicesSectionWithAssets:(NSArray<SNBNetworkAsset *> *)networkAssets
                                                       recentNewAssets:(NSArray<SNBNetworkAsset *> *)recentNewAssets
                                                  assetMonitorEnabled:(BOOL)assetMonitorEnabled
                                                           menuBuilder:(MenuBuilder *)menuBuilder {
    NSMutableArray<NSMenuItem *> *items = [NSMutableArray array];
    if (!menuBuilder.sectionNetworkDevicesExpanded || !assetMonitorEnabled || networkAssets.count == 0) {
        return items;
    }

    NSString *newBadge = recentNewAssets.count > 0
        ? [NSString stringWithFormat:@" (%lu new)", (unsigned long)recentNewAssets.count]
        : @"";
    NSString *summaryStr = [NSString stringWithFormat:@"%lu Device%@%@",
                           (unsigned long)networkAssets.count,
                           networkAssets.count == 1 ? @"" : @"s",
                           newBadge];
    NSMenuItem *devicesTotalItem = [menuBuilder styledStatItemWithLabel:@"Total"
                                                                 value:summaryStr
                                                                 color:[NSColor labelColor]];
    [items addObject:devicesTotalItem];

    NSSet<NSString *> *localIPs = [menuBuilder localIPAddresses];
    if (recentNewAssets.count > 0) {
        [items addObject:[menuBuilder styledMenuItemWithTitle:@"New Devices" style:@"subheader"]];
        NSUInteger limit = MIN(3, recentNewAssets.count);
        for (NSUInteger i = 0; i < limit; i++) {
            SNBNetworkAsset *asset = recentNewAssets[i];

            NSString *line;
            BOOL isLocal = [localIPs containsObject:asset.ipAddress];
            NSString *suffix = isLocal ? @" (This Mac)" : @"";

            if (asset.hostname.length > 0 && asset.vendor.length > 0) {
                line = [NSString stringWithFormat:@"  🆕 %@ (%@) - %@%@",
                       asset.hostname, asset.vendor, asset.ipAddress, suffix];
            } else if (asset.hostname.length > 0) {
                line = [NSString stringWithFormat:@"  🆕 %@ - %@%@", asset.hostname, asset.ipAddress, suffix];
            } else if (asset.vendor.length > 0) {
                line = [NSString stringWithFormat:@"  🆕 %@ - %@%@", asset.vendor, asset.ipAddress, suffix];
            } else {
                line = [NSString stringWithFormat:@"  🆕 %@%@", asset.ipAddress, suffix];
            }
            NSMenuItem *item = [menuBuilder styledListItemWithText:line
                                                             color:[NSColor secondaryLabelColor]];
            [items addObject:item];
        }
        if (recentNewAssets.count > limit) {
            NSString *moreText = [NSString stringWithFormat:@"  ... and %lu more new",
                                  (unsigned long)(recentNewAssets.count - limit)];
            NSMenuItem *moreNewItem = [menuBuilder styledListItemWithText:moreText
                                                                    color:[NSColor secondaryLabelColor]];
            [items addObject:moreNewItem];
        }
    }

    return items;
}

- (void)refreshWithAssets:(NSArray<SNBNetworkAsset *> *)networkAssets
          recentNewAssets:(NSArray<SNBNetworkAsset *> *)recentNewAssets
      assetMonitorEnabled:(BOOL)assetMonitorEnabled
                   inMenu:(NSMenu *)menu
              menuBuilder:(MenuBuilder *)menuBuilder {
    if (!self.headerItem || !menu) {
        return;
    }
    NSArray<NSMenuItem *> *newItems = [self menuItemsForNetworkDevicesSectionWithAssets:networkAssets
                                                                       recentNewAssets:recentNewAssets
                                                                  assetMonitorEnabled:assetMonitorEnabled
                                                                            menuBuilder:menuBuilder];
    [menuBuilder replaceMenuItemsAfterHeader:self.headerItem
                                  beforeItem:self.separatorItem
                                       inMenu:menu
                                    withItems:newItems];
    self.sectionItems = newItems;
}

- (void)reset {
    self.headerItem = nil;
    self.separatorItem = nil;
    self.sectionItems = @[];
}

@end

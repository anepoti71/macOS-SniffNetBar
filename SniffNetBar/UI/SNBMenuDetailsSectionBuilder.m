//
//  SNBMenuDetailsSectionBuilder.m
//  SniffNetBar
//

#import "SNBMenuDetailsSectionBuilder.h"
#import "MenuBuilder+SectionSupport.h"
#import "MenuBuilderConstants.h"
#import "SNBMenuTopHostsSectionBuilder.h"
#import "ByteFormatter.h"
#import "ConfigurationManager.h"
#import "NetworkAssetMonitor.h"
#import "ThreatIntelModels.h"
#import "TrafficStatistics.h"

@interface SNBMenuDetailsSectionBuilder ()
@property (nonatomic, strong) SNBMenuTopHostsSectionBuilder *topHostsBuilder;
@end

@implementation SNBMenuDetailsSectionBuilder

- (instancetype)initWithTopHostsBuilder:(SNBMenuTopHostsSectionBuilder *)topHostsBuilder {
    self = [super init];
    if (self) {
        _topHostsBuilder = topHostsBuilder;
    }
    return self;
}

- (NSMenuItem *)buildDetailsMenuItemWithStats:(TrafficStats *)stats
                          threatIntelEnabled:(BOOL)threatIntelEnabled
                     threatIntelStatusMessage:(NSString *)threatIntelStatusMessage
                           threatIntelResults:(NSDictionary<NSString *, TIEnrichmentResponse *> *)threatIntelResults
                                    cacheStats:(NSDictionary *)cacheStats
                          assetMonitorEnabled:(BOOL)assetMonitorEnabled
                               networkAssets:(NSArray<SNBNetworkAsset *> *)networkAssets
                             recentNewAssets:(NSArray<SNBNetworkAsset *> *)recentNewAssets
                                  menuBuilder:(MenuBuilder *)menuBuilder {
    (void)recentNewAssets;
    NSMenu *detailsSubmenu = [[NSMenu alloc] init];
    NSMenuItem *detailsItem = [[NSMenuItem alloc] initWithTitle:@"Details" action:nil keyEquivalent:@""];
    detailsItem.submenu = detailsSubmenu;
    menuBuilder.detailsSubmenu = detailsSubmenu;

    if (menuBuilder.showMap && menuBuilder.menuIsOpen && !menuBuilder.mapMenuView.detachedWindowVisible) {
        if (menuBuilder.mapMenuItem.menu && menuBuilder.mapMenuItem.menu != detailsSubmenu) {
            [menuBuilder.mapMenuItem.menu removeItem:menuBuilder.mapMenuItem];
        }
        NSMenuItem *mapItem = [menuBuilder mapMenuItemIfNeeded];
        if (mapItem) {
            [detailsSubmenu addItem:mapItem];
            [detailsSubmenu addItem:[NSMenuItem separatorItem]];
        }
    } else {
        if (menuBuilder.mapMenuItem.menu) {
            [menuBuilder.mapMenuItem.menu removeItem:menuBuilder.mapMenuItem];
        }
        if (!menuBuilder.mapMenuView.detachedWindowVisible) {
            [menuBuilder tearDownMapMenuItem];
        }
    }

    NSString *captureValue = [menuBuilder captureStartDisplayValue];
    NSMenuItem *captureItem = [menuBuilder styledStatItemWithLabel:@"Capture started:"
                                                             value:captureValue
                                                             color:[NSColor labelColor]];
    [menuBuilder cacheDetailItem:captureItem
                           label:@"Capture started:"
                           color:[NSColor labelColor]
                          forKey:SNBMenuItemKeyCaptureStart];
    [detailsSubmenu addItem:captureItem];

    NSString *incomingStr = [SNBByteFormatter stringFromBytes:stats.incomingBytes];
    NSMenuItem *incomingItem = [menuBuilder styledStatItemWithLabel:@"↓ Incoming:"
                                                              value:incomingStr
                                                              color:[NSColor labelColor]];
    [menuBuilder cacheDetailItem:incomingItem
                           label:@"↓ Incoming:"
                           color:[NSColor labelColor]
                          forKey:SNBMenuItemKeyDetailIncoming];
    [detailsSubmenu addItem:incomingItem];

    NSString *outgoingStr = [SNBByteFormatter stringFromBytes:stats.outgoingBytes];
    NSMenuItem *outgoingItem = [menuBuilder styledStatItemWithLabel:@"↑ Outgoing:"
                                                              value:outgoingStr
                                                              color:[NSColor labelColor]];
    [menuBuilder cacheDetailItem:outgoingItem
                           label:@"↑ Outgoing:"
                           color:[NSColor labelColor]
                          forKey:SNBMenuItemKeyDetailOutgoing];
    [detailsSubmenu addItem:outgoingItem];

    NSString *totalBytesStr = [SNBByteFormatter stringFromBytes:stats.totalBytes];
    NSMenuItem *bytesItem = [menuBuilder styledStatItemWithLabel:@"Total:"
                                                          value:totalBytesStr
                                                          color:[NSColor labelColor]];
    [menuBuilder cacheDetailItem:bytesItem
                           label:@"Total:"
                           color:[NSColor labelColor]
                          forKey:SNBMenuItemKeyDetailTotal];
    [detailsSubmenu addItem:bytesItem];

    NSString *packetsStr = [NSString stringWithFormat:@"%llu", stats.totalPackets];
    NSMenuItem *packetsItem = [menuBuilder styledStatItemWithLabel:@"Packets:"
                                                            value:packetsStr
                                                            color:[NSColor labelColor]];
    [menuBuilder cacheDetailItem:packetsItem
                           label:@"Packets:"
                           color:[NSColor labelColor]
                          forKey:SNBMenuItemKeyDetailPackets];
    [detailsSubmenu addItem:packetsItem];

    if (menuBuilder.showTopHosts) {
        [detailsSubmenu addItem:[NSMenuItem separatorItem]];
        [self.topHostsBuilder appendToDetailsMenu:detailsSubmenu
                                            stats:stats
                                      menuBuilder:menuBuilder];
    } else {
        [self.topHostsBuilder reset];
    }

    if (menuBuilder.showTopConnections) {
        if (!self.topHostsBuilder.headerItem) {
            [detailsSubmenu addItem:[NSMenuItem separatorItem]];
        }
        NSString *topConnectionsTitle = [NSString stringWithFormat:@"TOP %lu CONNECTIONS by Traffic",
                                         (unsigned long)menuBuilder.configuration.maxTopConnectionsToShow];
        NSMenuItem *topConnectionsHeader = [menuBuilder collapsibleSectionHeaderWithTitle:topConnectionsTitle
                                                                                expanded:menuBuilder.sectionTopConnectionsExpanded
                                                                                  action:@selector(toggleSectionTopConnections)
                                                                                  target:menuBuilder];
        [detailsSubmenu addItem:topConnectionsHeader];
        menuBuilder.topConnectionsSectionHeader = topConnectionsHeader;

        if (menuBuilder.sectionTopConnectionsExpanded) {
            NSArray<NSMenuItem *> *items = [menuBuilder menuItemsForTopConnectionsSectionWithConnections:stats.topConnections];
            for (NSMenuItem *item in items) {
                [detailsSubmenu addItem:item];
            }
        }

        NSMenuItem *connectionsTerminator = [NSMenuItem separatorItem];
        menuBuilder.topConnectionsSectionSeparator = connectionsTerminator;
        [detailsSubmenu addItem:connectionsTerminator];
    } else {
        menuBuilder.topConnectionsSectionHeader = nil;
        menuBuilder.topConnectionsSectionSeparator = nil;
    }

    if (menuBuilder.showProcessActivity) {
        [menuBuilder appendProcessActivitySectionWithSummaries:stats.processSummaries detailsMenu:detailsSubmenu];
    } else {
        menuBuilder.processActivityHeader = nil;
        menuBuilder.processActivitySeparator = nil;
        menuBuilder.processActivityItems = [NSMutableArray array];
    }

    if (assetMonitorEnabled && networkAssets.count > 0) {
        if (!menuBuilder.topConnectionsSectionSeparator) {
            [detailsSubmenu addItem:[NSMenuItem separatorItem]];
        }
        NSString *networkDevicesTitle = @"NETWORK DEVICES";
        if (menuBuilder.selectedDeviceDisplayName.length > 0) {
            networkDevicesTitle = [NSString stringWithFormat:@"NETWORK DEVICES (%@)", menuBuilder.selectedDeviceDisplayName];
        }
        [detailsSubmenu addItem:[menuBuilder collapsibleSectionHeaderWithTitle:networkDevicesTitle
                                                                      expanded:menuBuilder.sectionNetworkAssetsExpanded
                                                                        action:@selector(toggleSectionNetworkAssets)
                                                                        target:menuBuilder]];

        if (menuBuilder.sectionNetworkAssetsExpanded) {
            NSSet<NSString *> *localIPs = [menuBuilder localIPAddresses];
            NSUInteger limit = MIN(10, networkAssets.count);
            for (NSUInteger i = 0; i < limit; i++) {
                SNBNetworkAsset *asset = networkAssets[i];

                NSString *line;
                BOOL isLocal = [localIPs containsObject:asset.ipAddress];
                NSString *suffix = isLocal ? @" (This Mac)" : @"";

                if (asset.hostname.length > 0 && asset.vendor.length > 0) {
                    line = [NSString stringWithFormat:@"  %@ (%@) - %@%@",
                           asset.hostname, asset.vendor, asset.ipAddress, suffix];
                } else if (asset.hostname.length > 0) {
                    line = [NSString stringWithFormat:@"  %@ - %@%@",
                           asset.hostname, asset.ipAddress, suffix];
                } else if (asset.vendor.length > 0) {
                    line = [NSString stringWithFormat:@"  %@ - %@%@",
                           asset.vendor, asset.ipAddress, suffix];
                } else {
                    line = [NSString stringWithFormat:@"  %@%@", asset.ipAddress, suffix];
                }
                NSMenuItem *assetItem = [[NSMenuItem alloc] initWithTitle:line action:nil keyEquivalent:@""];
                assetItem.enabled = NO;
                [detailsSubmenu addItem:assetItem];
            }
        }
    }

    if (threatIntelEnabled && threatIntelStatusMessage.length > 0 &&
        (threatIntelResults == nil || threatIntelResults.count == 0)) {
        [detailsSubmenu addItem:[NSMenuItem separatorItem]];
        NSMenuItem *threatTitle = [[NSMenuItem alloc] initWithTitle:@"THREAT INTELLIGENCE"
                                                             action:nil
                                                      keyEquivalent:@""];
        threatTitle.enabled = NO;
        [detailsSubmenu addItem:threatTitle];

        NSMenuItem *statusItem = [[NSMenuItem alloc] initWithTitle:[NSString stringWithFormat:@"  %@", threatIntelStatusMessage]
                                                            action:nil
                                                     keyEquivalent:@""];
        statusItem.enabled = NO;
        [detailsSubmenu addItem:statusItem];
    } else if (threatIntelEnabled && threatIntelResults.count > 0) {
        NSArray<NSDictionary *> *maliciousConnections = [menuBuilder maliciousConnectionsFromStats:stats
                                                                               threatIntelResults:threatIntelResults];
        if (maliciousConnections.count > 0) {
            [detailsSubmenu addItem:[NSMenuItem separatorItem]];
            NSMenuItem *maliciousTitle = [[NSMenuItem alloc] initWithTitle:@"SUSPICIOUS NETWORK ACTIVITY (UNCONFIRMED)"
                                                                    action:nil
                                                             keyEquivalent:@""];
            maliciousTitle.enabled = NO;
            menuBuilder.maliciousConnectionsHeader = maliciousTitle;
            [detailsSubmenu addItem:maliciousTitle];

            NSArray<NSMenuItem *> *maliciousItems = [menuBuilder menuItemsForMaliciousConnectionsSectionWithEntries:maliciousConnections];
            for (NSMenuItem *item in maliciousItems) {
                [detailsSubmenu addItem:item];
            }

            NSMenuItem *maliciousSeparator = [NSMenuItem separatorItem];
            menuBuilder.maliciousConnectionsSeparator = maliciousSeparator;
            [detailsSubmenu addItem:maliciousSeparator];
        } else {
            menuBuilder.maliciousConnectionsHeader = nil;
            menuBuilder.maliciousConnectionsSeparator = nil;
        }

        if (cacheStats && menuBuilder.debugEnabled) {
            [detailsSubmenu addItem:[NSMenuItem separatorItem]];
            NSString *sizeStr = [NSString stringWithFormat:@"%@", cacheStats[@"size"]];
            NSString *hitRateStr = [NSString stringWithFormat:@"%.1f%%", [cacheStats[@"hitRate"] doubleValue] * 100];
            NSString *statsStr = [NSString stringWithFormat:@"Cache: %@ entries - %@ hit rate", sizeStr, hitRateStr];

            NSMenuItem *statsItem = [[NSMenuItem alloc] initWithTitle:statsStr
                                                               action:nil
                                                        keyEquivalent:@""];
            statsItem.enabled = NO;
            [detailsSubmenu addItem:statsItem];
        }
    }

    [menuBuilder appendServiceHealthSectionToDetailsMenu:detailsSubmenu];
    return detailsItem;
}

- (void)refreshDetailStatsWithStats:(TrafficStats *)stats
                        menuBuilder:(MenuBuilder *)menuBuilder {
    NSString *captureValue = [menuBuilder captureStartDisplayValue];
    [menuBuilder updateDetailItemForKey:SNBMenuItemKeyCaptureStart value:captureValue];

    [menuBuilder updateDetailItemForKey:SNBMenuItemKeyDetailIncoming
                                  value:[SNBByteFormatter stringFromBytes:stats.incomingBytes]];
    [menuBuilder updateDetailItemForKey:SNBMenuItemKeyDetailOutgoing
                                  value:[SNBByteFormatter stringFromBytes:stats.outgoingBytes]];
    [menuBuilder updateDetailItemForKey:SNBMenuItemKeyDetailTotal
                                  value:[SNBByteFormatter stringFromBytes:stats.totalBytes]];
    [menuBuilder updateDetailItemForKey:SNBMenuItemKeyDetailPackets
                                  value:[NSString stringWithFormat:@"%llu", stats.totalPackets]];
}

- (void)reset {
    [self.topHostsBuilder reset];
}

@end

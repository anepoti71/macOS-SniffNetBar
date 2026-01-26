//
//  SNBMenuTopHostsSectionBuilder.m
//  SniffNetBar
//

#import "SNBMenuTopHostsSectionBuilder.h"
#import "MenuBuilder+SectionSupport.h"
#import "ByteFormatter.h"
#import "ConfigurationManager.h"
#import "TrafficStatistics.h"

@interface SNBMenuTopHostsSectionBuilder ()
@property (nonatomic, strong) NSMenuItem *headerItem;
@property (nonatomic, strong) NSMenuItem *separatorItem;
@end

@implementation SNBMenuTopHostsSectionBuilder

- (void)appendToDetailsMenu:(NSMenu *)detailsMenu
                      stats:(TrafficStats *)stats
                menuBuilder:(MenuBuilder *)menuBuilder {
    if (!detailsMenu || !menuBuilder.showTopHosts) {
        [self reset];
        return;
    }

    NSString *topHostsTitle = [NSString stringWithFormat:@"TOP %lu HOSTS by Traffic",
                               (unsigned long)menuBuilder.configuration.maxTopHostsToShow];
    NSMenuItem *topHostsHeader = [menuBuilder collapsibleSectionHeaderWithTitle:topHostsTitle
                                                                       expanded:menuBuilder.sectionTopHostsExpanded
                                                                         action:@selector(toggleSectionTopHosts)
                                                                         target:menuBuilder];
    self.headerItem = topHostsHeader;
    [detailsMenu addItem:topHostsHeader];

    if (menuBuilder.sectionTopHostsExpanded) {
        NSArray<NSMenuItem *> *items = [self menuItemsForTopHostsSectionWithHosts:stats.topHosts
                                                                     menuBuilder:menuBuilder];
        for (NSMenuItem *item in items) {
            [detailsMenu addItem:item];
        }
    }

    NSMenuItem *separator = [NSMenuItem separatorItem];
    self.separatorItem = separator;
    [detailsMenu addItem:separator];
}

- (NSArray<NSMenuItem *> *)menuItemsForTopHostsSectionWithHosts:(NSArray<HostTraffic *> *)hosts
                                                  menuBuilder:(MenuBuilder *)menuBuilder {
    if (!menuBuilder.sectionTopHostsExpanded) {
        return @[];
    }
    if (hosts.count == 0) {
        NSMenuItem *emptyItem = [menuBuilder styledStatItemWithLabel:@"No hosts captured yet"
                                                               value:@""
                                                               color:[NSColor secondaryLabelColor]];
        return @[emptyItem];
    }
    NSInteger limit = MIN(menuBuilder.configuration.maxTopHostsToShow, hosts.count);
    if (limit == 0) {
        return @[];
    }

    NSMutableArray<NSMenuItem *> *items = [NSMutableArray arrayWithCapacity:limit];
    for (NSInteger i = 0; i < limit; i++) {
        HostTraffic *host = hosts[i];
        NSString *hostName = host.hostname.length > 0 ? host.hostname : @"";
        NSString *hostDisplay = hostName.length > 0 ? [NSString stringWithFormat:@"%@ (%@)", hostName, host.address] : host.address;
        NSString *bytesStr = [SNBByteFormatter stringFromBytes:host.bytes];
        NSColor *hostColor = [menuBuilder highlightColorForHostAddress:host.address];
        NSString *icon = [menuBuilder badgeIconForHost:host];
        NSMenuItem *hostItem = [menuBuilder styledStatItemWithLabel:hostDisplay
                                                             value:bytesStr
                                                             color:hostColor
                                                              icon:icon];
        if ([menuBuilder isHostAddressSelected:host.address]) {
            hostItem.state = NSControlStateValueOn;
        }
        [items addObject:hostItem];
    }
    return items;
}

- (void)refreshWithStats:(TrafficStats *)stats
            detailsMenu:(NSMenu *)detailsMenu
             menuBuilder:(MenuBuilder *)menuBuilder {
    if (!detailsMenu || !self.headerItem) {
        return;
    }
    NSArray<NSMenuItem *> *items = [self menuItemsForTopHostsSectionWithHosts:stats.topHosts
                                                                 menuBuilder:menuBuilder];
    [menuBuilder replaceMenuItemsAfterHeader:self.headerItem
                                  beforeItem:self.separatorItem
                                       inMenu:detailsMenu
                                    withItems:items];
}

- (void)reset {
    self.headerItem = nil;
    self.separatorItem = nil;
}

@end

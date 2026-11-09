//
//  MenuBuilder+SectionSupport.h
//  SniffNetBar
//

#import "MenuBuilder.h"
#import "MenuBuilder+ThreatDisplay.h"

@class ConfigurationManager;
@class MapMenuView;
@class ProcessTrafficSummary;
@class HostTraffic;
@class ConnectionTraffic;
@class TrafficStats;
@class TIEnrichmentResponse;
@class SNBTrustedIPStore;

@interface MenuBuilder (SectionSupport)

@property (nonatomic, strong) ConfigurationManager *configuration;
@property (nonatomic, strong) MapMenuView *mapMenuView;
@property (nonatomic, strong) NSMenuItem *mapMenuItem;
@property (nonatomic, strong) NSMenu *detailsSubmenu;
@property (nonatomic, copy) NSString *selectedDeviceDisplayName;
@property (nonatomic, strong) SNBTrustedIPStore *trustedStore;
@property (nonatomic, assign) NSUInteger activeMaliciousCount;
@property (nonatomic, assign) NSUInteger activeSuspiciousCount;
@property (nonatomic, strong) NSMenuItem *topConnectionsSectionHeader;
@property (nonatomic, strong) NSMenuItem *topConnectionsSectionSeparator;
@property (nonatomic, strong) NSMenuItem *maliciousConnectionsHeader;
@property (nonatomic, strong) NSMenuItem *maliciousConnectionsSeparator;
@property (nonatomic, strong) NSMenuItem *processActivityHeader;
@property (nonatomic, strong) NSMenuItem *processActivitySeparator;
@property (nonatomic, strong) NSMutableArray<NSMenuItem *> *processActivityItems;

- (NSMenuItem *)collapsibleSectionHeaderWithTitle:(NSString *)title
                                        expanded:(BOOL)expanded
                                          action:(SEL)action
                                          target:(id)target;
- (NSMenuItem *)styledMenuItemWithTitle:(NSString *)title style:(NSString *)style;
- (NSMenuItem *)styledStatItemWithLabel:(NSString *)label value:(NSString *)value color:(NSColor *)color;
- (NSMenuItem *)styledStatItemWithLabel:(NSString *)label
                                  value:(NSString *)value
                                  color:(NSColor *)color
                                   icon:(NSString *)icon;
- (NSMenuItem *)styledStatItemWithLabel:(NSString *)label
                                  value:(NSString *)value
                                  color:(NSColor *)color
                                   icon:(NSString *)icon
                              showBadge:(BOOL)showBadge;
- (NSMenuItem *)styledListItemWithText:(NSString *)text color:(NSColor *)color;
- (NSMenuItem *)networkActivityGraphMenuItemWithWidth:(CGFloat)width;
- (NSString *)captureStartDisplayValue;
- (void)cacheDetailItem:(NSMenuItem *)item label:(NSString *)label color:(NSColor *)color forKey:(NSString *)key;
- (void)cacheStatItem:(NSMenuItem *)item label:(NSString *)label color:(NSColor *)color forKey:(NSString *)key;
- (void)updateDetailItemForKey:(NSString *)key value:(NSString *)value;
- (void)replaceMenuItemsAfterHeader:(NSMenuItem *)header
                          beforeItem:(NSMenuItem *)stopItem
                               inMenu:(NSMenu *)menu
                            withItems:(NSArray<NSMenuItem *> *)newItems;
- (NSSet<NSString *> *)localIPAddresses;

- (NSMenuItem *)mapMenuItemIfNeeded;
- (void)tearDownMapMenuItem;
- (void)openMapWindow:(id)sender;

- (NSArray<NSDictionary *> *)maliciousConnectionsFromStats:(TrafficStats *)stats
                                        threatIntelResults:(NSDictionary<NSString *, TIEnrichmentResponse *> *)threatIntelResults;
- (NSArray<NSMenuItem *> *)menuItemsForMaliciousConnectionsSectionWithEntries:(NSArray<NSDictionary *> *)entries;
- (NSArray<NSMenuItem *> *)menuItemsForCleanConnectionsSectionWithStats:(TrafficStats *)stats
                                                     threatIntelResults:(NSDictionary<NSString *, TIEnrichmentResponse *> *)threatIntelResults;
- (NSArray<NSString *> *)activeCleanConnectionsFromStats:(TrafficStats *)stats
                                      threatIntelResults:(NSDictionary<NSString *, TIEnrichmentResponse *> *)threatIntelResults;
- (NSArray<NSMenuItem *> *)menuItemsForSelectedThreatDetails:(ThreatInfo *)threat;

- (void)appendProcessActivitySectionWithSummaries:(NSArray<ProcessTrafficSummary *> *)summaries
                                      detailsMenu:(NSMenu *)detailsMenu;
- (NSArray<NSMenuItem *> *)menuItemsForTopConnectionsSectionWithConnections:(NSArray<ConnectionTraffic *> *)connections;

- (NSColor *)highlightColorForHostAddress:(NSString *)address;
- (NSString *)badgeIconForHost:(HostTraffic *)host;
- (BOOL)isHostAddressSelected:(NSString *)address;

- (NSColor *)processHighlightColorForConnection:(ConnectionTraffic *)connection;
- (NSString *)badgeIconForConnection:(ConnectionTraffic *)connection;
- (BOOL)isConnectionSelected:(ConnectionTraffic *)connection;
- (NSString *)sourceLabelForConnection:(ConnectionTraffic *)connection;

- (void)appendPromotionAgentSectionToMenu:(NSMenu *)visualizationSubmenu;
- (void)appendServiceHealthSectionToDetailsMenu:(NSMenu *)detailsSubmenu;

@end

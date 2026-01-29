//
//  SNBMenuThreatsSectionBuilder.m
//  SniffNetBar
//

#import "SNBMenuThreatsSectionBuilder.h"
#import "MenuBuilder+SectionSupport.h"
#import "MenuBuilder+ThreatDisplay.h"
#import "ThreatIntelModels.h"
#import "TrustLearningModels.h"

@interface SNBMenuThreatsSectionBuilder ()
@property (nonatomic, strong) NSMenuItem *cleanConnectionsHeader;
@property (nonatomic, strong) NSMenuItem *cleanConnectionsSeparator;
@end

@implementation SNBMenuThreatsSectionBuilder

- (void)appendToMenu:(NSMenu *)menu
               stats:(TrafficStats *)stats
   threatIntelEnabled:(BOOL)threatIntelEnabled
threatIntelStatusMessage:(NSString *)threatIntelStatusMessage
   threatIntelResults:(NSDictionary<NSString *, TIEnrichmentResponse *> *)threatIntelResults
          cacheStats:(NSDictionary *)cacheStats
  selectedThreatInfo:(ThreatInfo *)selectedThreatInfo
         menuBuilder:(MenuBuilder *)menuBuilder {
    if (!menu || !stats) {
        [self reset];
        return;
    }

    [menu addItem:[menuBuilder collapsibleSectionHeaderWithTitle:@"ACTIVE UNCLASSIFIED"
                                                        expanded:menuBuilder.sectionThreatsExpanded
                                                          action:@selector(toggleSectionThreats)
                                                          target:menuBuilder]];

    menuBuilder.activeMaliciousCount = 0;
    menuBuilder.activeSuspiciousCount = 0;
    self.cleanConnectionsHeader = nil;
    self.cleanConnectionsSeparator = nil;

    if (menuBuilder.sectionThreatsExpanded) {
        if (!threatIntelEnabled) {
            NSMenuItem *disabledItem = [[NSMenuItem alloc] initWithTitle:@"✓ Threat Intel: Off"
                                                                 action:nil
                                                          keyEquivalent:@""];
            disabledItem.enabled = NO;
            [menu addItem:disabledItem];
            return;
        }

        if (threatIntelStatusMessage.length > 0 && (threatIntelResults == nil || threatIntelResults.count == 0)) {
            NSMenuItem *unavailableItem = [[NSMenuItem alloc] initWithTitle:threatIntelStatusMessage
                                                                     action:nil
                                                              keyEquivalent:@""];
            unavailableItem.enabled = NO;
            [menu addItem:unavailableItem];
            return;
        }

        if (threatIntelResults == nil || threatIntelResults.count == 0) {
            NSMenuItem *scanningItem = [[NSMenuItem alloc] initWithTitle:@"⟳ Scanning connections..."
                                                                  action:nil
                                                           keyEquivalent:@""];
            scanningItem.enabled = NO;
            [menu addItem:scanningItem];
            return;
        }

        NSSet<NSString *> *activeDestIPs = stats.allActiveDestinationIPs ?: [NSSet set];
        NSDictionary<NSNumber *, NSArray<ThreatInfo *> *> *categorizedThreats =
            [menuBuilder categorizeThreats:threatIntelResults activeIPs:activeDestIPs stats:stats];

        NSArray<ThreatInfo *> *highThreats = categorizedThreats[@(ThreatSeverityHigh)] ?: @[];
        NSArray<ThreatInfo *> *mediumThreats = categorizedThreats[@(ThreatSeverityMedium)] ?: @[];
        NSArray<ThreatInfo *> *lowThreats = categorizedThreats[@(ThreatSeverityLow)] ?: @[];

        NSMutableArray<ThreatInfo *> *activeHighThreats = [NSMutableArray array];
        NSMutableArray<ThreatInfo *> *historicalThreats = [NSMutableArray array];
        for (ThreatInfo *threat in highThreats) {
            if (threat.isActive) {
                [activeHighThreats addObject:threat];
            } else {
                [historicalThreats addObject:threat];
            }
        }

        NSMutableArray<ThreatInfo *> *activeMediumThreats = [NSMutableArray array];
        for (ThreatInfo *threat in mediumThreats) {
            if (threat.isActive) {
                [activeMediumThreats addObject:threat];
            } else {
                [historicalThreats addObject:threat];
            }
        }

        NSMutableArray<ThreatInfo *> *activeLowThreats = [NSMutableArray array];
        for (ThreatInfo *threat in lowThreats) {
            if (threat.isActive) {
                [activeLowThreats addObject:threat];
            } else {
                [historicalThreats addObject:threat];
            }
        }

        NSUInteger totalActiveThreats = activeHighThreats.count + activeMediumThreats.count + activeLowThreats.count;
        menuBuilder.activeMaliciousCount = activeHighThreats.count;
        menuBuilder.activeSuspiciousCount = activeMediumThreats.count;

        if (totalActiveThreats > 0) {
            NSString *summaryTitle;
            if (activeHighThreats.count > 0 && activeMediumThreats.count > 0) {
                summaryTitle = [NSString stringWithFormat:@"%lu Active Unclassified (%lu High, %lu Med)",
                               (unsigned long)totalActiveThreats,
                               (unsigned long)activeHighThreats.count,
                               (unsigned long)activeMediumThreats.count];
            } else if (activeHighThreats.count > 0) {
                summaryTitle = [NSString stringWithFormat:@"%lu High Severity Unclassified",
                               (unsigned long)activeHighThreats.count];
            } else {
                summaryTitle = [NSString stringWithFormat:@"%lu Active Unclassified",
                               (unsigned long)totalActiveThreats];
            }

            NSMenuItem *alertItem = [[NSMenuItem alloc] initWithTitle:summaryTitle
                                                              action:nil
                                                       keyEquivalent:@""];
            alertItem.enabled = NO;
            NSImage *alertIcon = [NSImage imageWithSystemSymbolName:@"exclamationmark.triangle"
                                            accessibilityDescription:nil];
            if (alertIcon) {
                NSImageSymbolConfiguration *config =
                    [NSImageSymbolConfiguration configurationWithPointSize:12.0 weight:NSFontWeightSemibold];
                alertIcon = [alertIcon imageWithSymbolConfiguration:config] ?: alertIcon;
                alertIcon.template = YES;
                alertItem.image = alertIcon;
            }
            NSFont *boldFont = [NSFont boldSystemFontOfSize:13.0];
            NSDictionary *attributes = @{NSFontAttributeName: boldFont,
                                         NSForegroundColorAttributeName: [NSColor systemRedColor]};
            alertItem.attributedTitle = [[NSAttributedString alloc] initWithString:summaryTitle
                                                                        attributes:attributes];
            [menu addItem:alertItem];

            if (activeHighThreats.count > 0) {
                [menu addItem:[menuBuilder severityHeaderForLevel:ThreatSeverityHigh count:activeHighThreats.count]];
                for (ThreatInfo *threat in activeHighThreats) {
                    [menu addItem:[menuBuilder enhancedThreatItemForThreat:threat]];
                    [menu addItem:[menuBuilder threatDetailItemForThreat:threat]];
                    NSArray<NSMenuItem *> *connItems = [menuBuilder selectableThreatConnectionItemsForThreat:threat
                                                                                                     stats:stats];
                    for (NSMenuItem *item in connItems) {
                        [menu addItem:item];
                    }
                }
            }

            if (activeMediumThreats.count > 0) {
                [menu addItem:[menuBuilder severityHeaderForLevel:ThreatSeverityMedium count:activeMediumThreats.count]];
                for (ThreatInfo *threat in activeMediumThreats) {
                    [menu addItem:[menuBuilder enhancedThreatItemForThreat:threat]];
                    [menu addItem:[menuBuilder threatDetailItemForThreat:threat]];
                    NSArray<NSMenuItem *> *connItems = [menuBuilder selectableThreatConnectionItemsForThreat:threat
                                                                                                     stats:stats];
                    for (NSMenuItem *item in connItems) {
                        [menu addItem:item];
                    }
                }
            }

            if (activeLowThreats.count > 0) {
                NSString *expandIndicator = menuBuilder.showLowSeverityThreats ? @"▼" : @"▶";
                NSString *lowTitle = [NSString stringWithFormat:@"%@ LOW SEVERITY (%lu)",
                                     expandIndicator, (unsigned long)activeLowThreats.count];
                NSMenuItem *lowToggle = [[NSMenuItem alloc] initWithTitle:lowTitle
                                                                  action:@selector(toggleShowLowSeverityThreats)
                                                           keyEquivalent:@""];
                lowToggle.target = menuBuilder;
                [menu addItem:lowToggle];

                if (menuBuilder.showLowSeverityThreats) {
                    for (ThreatInfo *threat in activeLowThreats) {
                        [menu addItem:[menuBuilder enhancedThreatItemForThreat:threat]];
                        [menu addItem:[menuBuilder threatDetailItemForThreat:threat]];
                        NSArray<NSMenuItem *> *connItems = [menuBuilder selectableThreatConnectionItemsForThreat:threat
                                                                                                         stats:stats];
                        for (NSMenuItem *item in connItems) {
                            [menu addItem:item];
                        }
                    }
                }
            }
        } else {
            NSMenuItem *cleanItem = [[NSMenuItem alloc] initWithTitle:@"No Active Unclassified"
                                                              action:nil
                                                       keyEquivalent:@""];
            cleanItem.enabled = NO;
            NSImage *cleanIcon = [NSImage imageWithSystemSymbolName:@"checkmark.circle"
                                            accessibilityDescription:nil];
            if (cleanIcon) {
                NSImageSymbolConfiguration *config =
                    [NSImageSymbolConfiguration configurationWithPointSize:12.0 weight:NSFontWeightSemibold];
                cleanIcon = [cleanIcon imageWithSymbolConfiguration:config] ?: cleanIcon;
                cleanIcon.template = YES;
                cleanItem.image = cleanIcon;
            }
            NSFont *systemFont = [NSFont systemFontOfSize:[NSFont systemFontSize]];
            NSDictionary *attributes = @{NSFontAttributeName: systemFont,
                                         NSForegroundColorAttributeName: [NSColor labelColor]};
            cleanItem.attributedTitle = [[NSAttributedString alloc] initWithString:cleanItem.title
                                                                        attributes:attributes];
            [menu addItem:cleanItem];
        }

        if (historicalThreats.count > 0) {
            NSString *expandIndicator = menuBuilder.showHistoricalThreats ? @"▼" : @"▶";
            NSString *histTitle = [NSString stringWithFormat:@"%@ Closed Unclassified (%lu closed)",
                                  expandIndicator, (unsigned long)historicalThreats.count];
            NSMenuItem *histToggle = [[NSMenuItem alloc] initWithTitle:histTitle
                                                                action:@selector(toggleShowHistoricalThreats)
                                                         keyEquivalent:@""];
            histToggle.target = menuBuilder;
            [menu addItem:histToggle];

            if (menuBuilder.showHistoricalThreats) {
                for (ThreatInfo *threat in historicalThreats) {
                    [menu addItem:[menuBuilder enhancedThreatItemForThreat:threat]];
                    [menu addItem:[menuBuilder threatDetailItemForThreat:threat]];
                    NSArray<NSMenuItem *> *connItems = [menuBuilder selectableThreatConnectionItemsForThreat:threat
                                                                                                     stats:stats];
                    for (NSMenuItem *item in connItems) {
                        [menu addItem:item];
                    }
                }
            }
        }

        if (selectedThreatInfo) {
            NSArray<NSMenuItem *> *detailItems = [menuBuilder menuItemsForSelectedThreatDetails:selectedThreatInfo];
            if (detailItems.count > 0) {
                NSMenuItem *detailsItem = [[NSMenuItem alloc] initWithTitle:@"Selected Unclassified Details"
                                                                     action:nil
                                                              keyEquivalent:@""];
                detailsItem.enabled = YES;
                NSMenu *detailsMenu = [[NSMenu alloc] initWithTitle:@"Selected Unclassified Details"];
                [detailsMenu addItem:[menuBuilder styledMenuItemWithTitle:@"Selected Unclassified Details" style:@"header"]];
                for (NSMenuItem *item in detailItems) {
                    [detailsMenu addItem:item];
                }
                detailsItem.submenu = detailsMenu;
                [menu addItem:[NSMenuItem separatorItem]];
                [menu addItem:detailsItem];
            }
        }

        NSMutableArray<NSString *> *activeCleanIPs = [NSMutableArray array];
        for (NSString *ip in threatIntelResults) {
            TIEnrichmentResponse *response = threatIntelResults[ip];
            TIScoringResult *scoring = response.scoringResult;
            if (scoring && scoring.verdict == TIThreatVerdictClean && [activeDestIPs containsObject:ip]) {
                [activeCleanIPs addObject:ip];
            }
        }

        if (activeCleanIPs.count > 0) {
            NSString *expandIndicator = menuBuilder.showCleanConnections ? @"▼" : @"▶";
            NSString *cleanTitle = [NSString stringWithFormat:@"%@ Observed Connections (%lu)",
                                   expandIndicator, (unsigned long)activeCleanIPs.count];
            NSMenuItem *cleanToggle = [[NSMenuItem alloc] initWithTitle:cleanTitle
                                                                action:@selector(toggleShowCleanConnections)
                                                         keyEquivalent:@""];
            cleanToggle.target = menuBuilder;
            [menu addItem:cleanToggle];
            self.cleanConnectionsHeader = cleanToggle;

            if (menuBuilder.showCleanConnections) {
                NSArray<NSMenuItem *> *cleanItems = [menuBuilder menuItemsForCleanConnectionsSectionWithStats:stats
                                                                                        threatIntelResults:threatIntelResults];
                for (NSMenuItem *item in cleanItems) {
                    [menu addItem:item];
                }
            }
            NSMenuItem *cleanSeparator = [NSMenuItem separatorItem];
            self.cleanConnectionsSeparator = cleanSeparator;
            [menu addItem:cleanSeparator];
        } else {
            self.cleanConnectionsHeader = nil;
            self.cleanConnectionsSeparator = nil;
        }

        if (menuBuilder.promotionAgentEnabled) {
            [menuBuilder appendPromotionAgentSectionToMenu:menu];
            [menu addItem:[NSMenuItem separatorItem]];
        }

        NSArray<SNBTrustContext *> *trustedContexts = [menuBuilder.trustedStore allTrustedIPContexts];
        if (trustedContexts.count > 0) {
            NSString *expandIndicator = menuBuilder.showTrustedIPs ? @"▼" : @"▶";
            NSString *trustedTitle = [NSString stringWithFormat:@"%@ Legitimate Connections (%lu)",
                                     expandIndicator, (unsigned long)trustedContexts.count];
            NSMenuItem *trustedToggle = [[NSMenuItem alloc] initWithTitle:trustedTitle
                                                                  action:@selector(toggleShowTrustedIPs)
                                                           keyEquivalent:@""];
            trustedToggle.target = menuBuilder;

            NSMutableAttributedString *trustedAttr = [[NSMutableAttributedString alloc] initWithString:trustedTitle];
            [trustedAttr addAttribute:NSForegroundColorAttributeName
                                value:[NSColor labelColor]
                                range:NSMakeRange(0, trustedTitle.length)];
            trustedToggle.attributedTitle = trustedAttr;
            [menu addItem:trustedToggle];

            if (menuBuilder.showTrustedIPs) {
                for (SNBTrustContext *ctx in trustedContexts) {
                    NSString *reasonStr = [SNBTrustContext displayStringForReason:ctx.reason];
                    NSString *itemTitle = [NSString stringWithFormat:@"  %@ (%@)", ctx.ipAddress, reasonStr];

                    NSMenuItem *ipItem = [[NSMenuItem alloc] initWithTitle:itemTitle
                                                                    action:nil
                                                             keyEquivalent:@""];
                    ipItem.state = NSControlStateValueOn;

                    NSMutableAttributedString *ipAttr = [[NSMutableAttributedString alloc] initWithString:itemTitle];
                    [ipAttr addAttribute:NSForegroundColorAttributeName
                                   value:[NSColor secondaryLabelColor]
                                   range:NSMakeRange(0, itemTitle.length)];
                    [ipAttr addAttribute:NSFontAttributeName
                                   value:[NSFont systemFontOfSize:11.0]
                                   range:NSMakeRange(0, itemTitle.length)];
                    ipItem.attributedTitle = ipAttr;

                    ipItem.submenu = [menuBuilder trustedIPDetailsSubmenuForContext:ctx stats:stats];

                    [menu addItem:ipItem];
                }
            }
            [menu addItem:[NSMenuItem separatorItem]];
        }

        if (menuBuilder.showProviderDetails) {
            [menu addItem:[NSMenuItem separatorItem]];
            [menu addItem:[menuBuilder styledMenuItemWithTitle:@"Provider Details" style:@"subheader"]];
            if (cacheStats) {
                NSString *sizeStr = [NSString stringWithFormat:@"%@", cacheStats[@"size"]];
                NSString *hitRateStr = [NSString stringWithFormat:@"%.1f%%", [cacheStats[@"hitRate"] doubleValue] * 100];
                NSString *statsStr = [NSString stringWithFormat:@"  Cache: %@ entries, %@ hit rate", sizeStr, hitRateStr];
                NSMenuItem *statsItem = [[NSMenuItem alloc] initWithTitle:statsStr action:nil keyEquivalent:@""];
                statsItem.enabled = NO;
                [menu addItem:statsItem];
            }
        }
    }
}

- (void)refreshCleanConnectionsWithStats:(TrafficStats *)stats
                     threatIntelResults:(NSDictionary<NSString *, TIEnrichmentResponse *> *)threatIntelResults
                                 inMenu:(NSMenu *)menu
                            menuBuilder:(MenuBuilder *)menuBuilder {
    if (!menu || !self.cleanConnectionsHeader) {
        return;
    }
    NSArray<NSString *> *activeCleanIPs = [menuBuilder activeCleanConnectionsFromStats:stats
                                                                    threatIntelResults:threatIntelResults];
    NSString *expandIndicator = menuBuilder.showCleanConnections ? @"▼" : @"▶";
    NSString *cleanTitle = [NSString stringWithFormat:@"%@ Observed Connections (%lu)",
                            expandIndicator, (unsigned long)activeCleanIPs.count];
    self.cleanConnectionsHeader.title = cleanTitle;
    NSArray<NSMenuItem *> *items = [menuBuilder menuItemsForCleanConnectionsSectionWithStats:stats
                                                                           threatIntelResults:threatIntelResults];
    [menuBuilder replaceMenuItemsAfterHeader:self.cleanConnectionsHeader
                                  beforeItem:self.cleanConnectionsSeparator
                                       inMenu:menu
                                    withItems:items];
}

- (void)reset {
    self.cleanConnectionsHeader = nil;
    self.cleanConnectionsSeparator = nil;
}

@end

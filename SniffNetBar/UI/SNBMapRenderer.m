//
//  SNBMapRenderer.m
//  SniffNetBar
//

#import "SNBMapRenderer.h"
#import "SNBBadgeRegistry.h"
#import "TrafficStatistics.h"
#import "ByteFormatter.h"
#import <AppKit/AppKit.h>

@implementation SNBMapRenderResult
@end

@implementation SNBMapRenderer

- (NSString *)hexStringForColor:(NSColor *)color {
    NSColor *rgb = [color colorUsingColorSpace:[NSColorSpace sRGBColorSpace]];
    if (!rgb) {
        return @"#94a3b8";
    }
    NSInteger r = (NSInteger)round(rgb.redComponent * 255.0);
    NSInteger g = (NSInteger)round(rgb.greenComponent * 255.0);
    NSInteger b = (NSInteger)round(rgb.blueComponent * 255.0);
    return [NSString stringWithFormat:@"#%02lx%02lx%02lx", (long)r, (long)g, (long)b];
}

- (nullable SNBMapRenderResult *)renderWithTargetIPs:(NSArray<NSString *> *)targetIPs
                                         connections:(NSArray<ConnectionTraffic *> *)connections
                                        locationByIP:(NSDictionary<NSString *, NSDictionary *> *)locationByIP
                                       badgeInfoByIP:(NSDictionary<NSString *, NSDictionary *> *)badgeInfoByIP
                                      processesByIP:(NSDictionary<NSString *, NSSet<NSString *> *> *)processesByIP
                               connectionCountsByIP:(NSDictionary<NSString *, NSNumber *> *)connectionCountsByIP
                                  firstSeenByIP:(NSDictionary<NSString *, NSDate *> *)firstSeenByIP
                                   lastSeenByIP:(NSDictionary<NSString *, NSDate *> *)lastSeenByIP
                                           publicIP:(NSString *)publicIP
                                         publicCoord:(CLLocationCoordinate2D)publicCoord
                                     riskStateForIP:(NSString * (^)(NSString *ip))riskStateForIP
                                            maxLines:(NSInteger)maxLines {
    NSCalendar *calendar = [NSCalendar currentCalendar];
    NSDate *startOfDay = [calendar startOfDayForDate:[NSDate date]];
    NSMutableDictionary<NSString *, NSMutableArray<NSDictionary *> *> *pointsByCoord = [NSMutableDictionary dictionary];

    for (NSString *ip in targetIPs) {
        NSDictionary *value = locationByIP[ip];
        if (!value) {
            continue;
        }
        CLLocationCoordinate2D coord;
        coord.latitude = [value[@"lat"] doubleValue];
        coord.longitude = [value[@"lon"] doubleValue];
        if (!CLLocationCoordinate2DIsValid(coord)) {
            continue;
        }
        NSString *name = value[@"name"];
        NSString *isp = value[@"isp"];
        NSString *locationPart = name.length > 0 ? [NSString stringWithFormat:@"%@ — %@", ip, name] : ip;
        NSMutableDictionary *payload = [NSMutableDictionary dictionary];
        payload[@"lat"] = @(coord.latitude);
        payload[@"lon"] = @(coord.longitude);
        payload[@"ip"] = ip;
        payload[@"title"] = isp.length > 0 ? [NSString stringWithFormat:@"%@\nISP: %@", locationPart, isp] : locationPart;
        payload[@"name"] = name ?: @"";
        payload[@"isp"] = isp ?: @"";
        payload[@"country"] = value[@"country"] ?: @"";
        payload[@"asn"] = value[@"asn"] ?: @"";
        NSSet<NSString *> *processSet = processesByIP[ip] ?: [NSSet set];
        NSArray<NSString *> *processes = [[processSet allObjects] sortedArrayUsingSelector:@selector(localizedCaseInsensitiveCompare:)];
        payload[@"processes"] = processes ?: @[];
        payload[@"connectionCount"] = connectionCountsByIP[ip] ?: @0;
        NSDate *firstSeen = firstSeenByIP[ip];
        NSDate *lastSeen = lastSeenByIP[ip];
        payload[@"firstSeen"] = firstSeen ? @([firstSeen timeIntervalSince1970]) : @0;
        payload[@"lastSeen"] = lastSeen ? @([lastSeen timeIntervalSince1970]) : @0;
        payload[@"riskState"] = riskStateForIP ? (riskStateForIP(ip) ?: @"Observed") : @"Observed";
        BOOL isNewToday = firstSeen && ([firstSeen compare:startOfDay] != NSOrderedAscending);
        payload[@"isNewToday"] = @(isNewToday);

        NSString *coordKey = [NSString stringWithFormat:@"%.3f,%.3f", coord.latitude, coord.longitude];
        NSMutableArray<NSDictionary *> *group = pointsByCoord[coordKey];
        if (!group) {
            group = [NSMutableArray array];
            pointsByCoord[coordKey] = group;
        }
        [group addObject:payload];
    }

    NSMutableArray<NSDictionary *> *points = [NSMutableArray array];
    [pointsByCoord enumerateKeysAndObjectsUsingBlock:^(NSString *key, NSArray<NSDictionary *> *group, BOOL *stop) {
        NSDictionary *firstPoint = group.firstObject;
        NSMutableDictionary *pointData = [NSMutableDictionary dictionary];
        pointData[@"lat"] = firstPoint[@"lat"];
        pointData[@"lon"] = firstPoint[@"lon"];
        pointData[@"ips"] = [group valueForKey:@"ip"];
        pointData[@"names"] = [group valueForKey:@"name"];
        pointData[@"isps"] = [group valueForKey:@"isp"];
        pointData[@"locationName"] = firstPoint[@"name"] ?: @"";
        NSMutableArray<NSDictionary *> *badges = [NSMutableArray array];
        NSMutableArray<NSDictionary *> *details = [NSMutableArray array];
        for (NSDictionary *payload in group) {
            NSString *ip = payload[@"ip"];
            NSDictionary *badge = badgeInfoByIP[ip];
            if (!badge) {
                NSString *label = payload[@"name"] ?: ip;
                NSString *icon = [[SNBBadgeRegistry sharedRegistry] badgeIconForLabel:label fallback:ip];
                NSColor *badgeColor = [[SNBBadgeRegistry sharedRegistry] colorForLabel:label
                                                                       createIfMissing:YES];
                NSString *colorHex = [self hexStringForColor:badgeColor];
                badge = @{@"icon": icon ?: @"", @"color": colorHex};
            }
            [badges addObject:badge];
            NSMutableDictionary *detail = [payload mutableCopy];
            detail[@"badge"] = badge;
            [details addObject:detail];
        }
        pointData[@"badgeInfos"] = badges;
        pointData[@"ipDetails"] = details;
        if (group.count > 1) {
            pointData[@"isDuplicate"] = @YES;
            pointData[@"color"] = @"#ffad60";
        } else {
            pointData[@"isDuplicate"] = @NO;
        }
        [points addObject:pointData];
    }];

    if (publicIP.length > 0 && CLLocationCoordinate2DIsValid(publicCoord)) {
        NSString *riskState = riskStateForIP ? (riskStateForIP(publicIP) ?: @"Observed") : @"Observed";
        NSDictionary *publicDetail = @{
            @"ip": publicIP,
            @"lat": @(publicCoord.latitude),
            @"lon": @(publicCoord.longitude),
            @"name": @"",
            @"isp": @"",
            @"country": @"",
            @"asn": @"",
            @"processes": @[],
            @"connectionCount": @0,
            @"firstSeen": @0,
            @"lastSeen": @0,
            @"riskState": riskState,
            @"isNewToday": @NO,
            @"badge": @{@"icon": @"", @"color": @"#94a3b8"}
        };
        [points addObject:@{@"lat": @(publicCoord.latitude),
                            @"lon": @(publicCoord.longitude),
                            @"title": [NSString stringWithFormat:@"Public IP: %@", publicIP],
                            @"ips": @[publicIP],
                            @"ipDetails": @[publicDetail],
                            @"locationName": @"",
                            @"isDuplicate": @NO}];
    }

    NSError *jsonError = nil;
    NSData *data = [NSJSONSerialization dataWithJSONObject:points options:0 error:&jsonError];
    if (!data) {
        return nil;
    }
    NSString *json = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];

    NSMutableArray<NSDictionary *> *lines = [NSMutableArray array];
    for (NSInteger i = 0; i < maxLines; i++) {
        ConnectionTraffic *connection = connections[i];
        NSDictionary *src = locationByIP[connection.sourceAddress];
        NSDictionary *dst = locationByIP[connection.destinationAddress];

        if (!src || !dst) {
            continue;
        }

        CLLocationCoordinate2D srcCoord = CLLocationCoordinate2DMake([src[@"lat"] doubleValue], [src[@"lon"] doubleValue]);
        CLLocationCoordinate2D dstCoord = CLLocationCoordinate2DMake([dst[@"lat"] doubleValue], [dst[@"lon"] doubleValue]);
        if (!CLLocationCoordinate2DIsValid(srcCoord) || !CLLocationCoordinate2DIsValid(dstCoord)) {
            continue;
        }

        NSString *lineTitle = [NSString stringWithFormat:@"%@ → %@ (%@)",
                               connection.sourceAddress,
                               connection.destinationAddress,
                               [SNBByteFormatter stringFromBytes:connection.bytes]];
        [lines addObject:@{@"srcLat": @(srcCoord.latitude),
                           @"srcLon": @(srcCoord.longitude),
                           @"dstLat": @(dstCoord.latitude),
                           @"dstLon": @(dstCoord.longitude),
                           @"title": lineTitle,
                           @"srcIP": connection.sourceAddress,
                           @"dstIP": connection.destinationAddress}];
    }

    NSData *lineData = [NSJSONSerialization dataWithJSONObject:lines options:0 error:&jsonError];
    if (!lineData) {
        return nil;
    }
    NSString *lineJson = [[NSString alloc] initWithData:lineData encoding:NSUTF8StringEncoding];

    SNBMapRenderResult *result = [[SNBMapRenderResult alloc] init];
    result.pointsJSON = json;
    result.linesJSON = lineJson;
    result.drawnConnectionCount = lines.count;
    return result;
}

@end

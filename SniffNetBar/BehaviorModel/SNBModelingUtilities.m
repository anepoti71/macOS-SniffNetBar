//
//  SNBModelingUtilities.m
//  SniffNetBar
//

#import "SNBModelingUtilities.h"
#import "SNBEventSchema.h"

NSString *SNBClusterIDForEvent(SNBFlowEvent *event) {
    NSString *process = event.processName.length > 0 ? event.processName : @"unknown";
    NSString *proto = event.protocolName.length > 0 ? event.protocolName : @"unknown";
    NSInteger port = event.dstPort;

    NSString *host = event.sni.length > 0 ? event.sni : (event.httpHost.length > 0 ? event.httpHost : event.dnsQuery);
    NSString *family = SNBDomainFamilyFromHost(host);
    NSString *destKey = family.length > 0 ? family : (event.dstIP.length > 0 ? event.dstIP : @"unknown");

    return [NSString stringWithFormat:@"app:%@|dst:%@|%@:%ld", process, destKey, proto, (long)port];
}

NSString *SNBExtendedContextJSONForEvent(SNBFlowEvent *event) {
    NSMutableDictionary<NSString *, NSString *> *context = [NSMutableDictionary dictionary];
    if (event.asn.length > 0) {
        context[@"asn"] = event.asn;
    }
    if (event.org.length > 0) {
        context[@"org"] = event.org;
    }
    if (event.country.length > 0 || event.region.length > 0) {
        NSString *geo = [NSString stringWithFormat:@"%@-%@", event.country ?: @"", event.region ?: @""];
        if (geo.length > 1) {
            context[@"geo"] = geo;
        }
    }
    if (context.count == 0) {
        return @"{}";
    }
    NSData *data = [NSJSONSerialization dataWithJSONObject:context options:0 error:nil];
    if (!data) {
        return @"{}";
    }
    NSString *json = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    return json.length > 0 ? json : @"{}";
}

BOOL SNBEventIsIPOnly(SNBFlowEvent *event) {
    return (event.sni.length == 0 && event.httpHost.length == 0 && event.dnsQuery.length == 0);
}

static void SNBLoadPublicSuffixRules(NSSet<NSString *> **exactRules,
                                     NSSet<NSString *> **wildcardRules,
                                     NSSet<NSString *> **exceptionRules) {
    static NSSet<NSString *> *s_exact = nil;
    static NSSet<NSString *> *s_wildcards = nil;
    static NSSet<NSString *> *s_exceptions = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSMutableSet<NSString *> *exact = [NSMutableSet set];
        NSMutableSet<NSString *> *wildcards = [NSMutableSet set];
        NSMutableSet<NSString *> *exceptions = [NSMutableSet set];

        NSString *path = [[NSBundle mainBundle] pathForResource:@"public_suffix_list" ofType:@"dat"];
        NSString *contents = path.length > 0 ? [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:nil] : nil;
        if (contents.length == 0) {
            // Minimal fallback when the list isn't bundled.
            [exact addObjectsFromArray:@[@"com", @"org", @"net", @"edu", @"gov",
                                         @"co.uk", @"org.uk", @"ac.uk",
                                         @"com.au", @"net.au", @"org.au",
                                         @"co.jp", @"ne.jp", @"or.jp",
                                         @"co.nz", @"org.nz",
                                         @"com.br", @"com.mx", @"com.sg"]];
        } else {
            NSArray<NSString *> *lines = [contents componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]];
            for (NSString *line in lines) {
                NSString *trimmed = [line stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
                if (trimmed.length == 0 || [trimmed hasPrefix:@"//"]) {
                    continue;
                }
                if ([trimmed hasPrefix:@"!"]) {
                    [exceptions addObject:[trimmed substringFromIndex:1]];
                } else if ([trimmed hasPrefix:@"*."]) {
                    [wildcards addObject:[trimmed substringFromIndex:2]];
                } else {
                    [exact addObject:trimmed];
                }
            }
        }

        s_exact = [exact copy];
        s_wildcards = [wildcards copy];
        s_exceptions = [exceptions copy];
    });

    if (exactRules) {
        *exactRules = s_exact;
    }
    if (wildcardRules) {
        *wildcardRules = s_wildcards;
    }
    if (exceptionRules) {
        *exceptionRules = s_exceptions;
    }
}

static NSString *SNBPublicSuffixForHost(NSString *host) {
    NSArray<NSString *> *labels = [host componentsSeparatedByString:@"."];
    if (labels.count == 0) {
        return @"";
    }

    NSSet<NSString *> *exact = nil;
    NSSet<NSString *> *wildcards = nil;
    NSSet<NSString *> *exceptions = nil;
    SNBLoadPublicSuffixRules(&exact, &wildcards, &exceptions);

    NSString *match = nil;
    BOOL exceptionMatch = NO;
    for (NSUInteger i = 0; i < labels.count; i++) {
        NSString *candidate = [[labels subarrayWithRange:NSMakeRange(i, labels.count - i)] componentsJoinedByString:@"."];
        if ([exceptions containsObject:candidate]) {
            match = candidate;
            exceptionMatch = YES;
            break;
        }
        if ([exact containsObject:candidate]) {
            match = candidate;
            break;
        }
        if (i + 1 < labels.count) {
            NSString *wildcardCandidate = [[labels subarrayWithRange:NSMakeRange(i + 1, labels.count - i - 1)] componentsJoinedByString:@"."];
            if ([wildcards containsObject:wildcardCandidate]) {
                match = [NSString stringWithFormat:@"%@.%@", labels[i], wildcardCandidate];
                break;
            }
        }
    }

    if (exceptionMatch && match.length > 0) {
        NSArray<NSString *> *exceptionLabels = [match componentsSeparatedByString:@"."];
        if (exceptionLabels.count > 1) {
            return [[exceptionLabels subarrayWithRange:NSMakeRange(1, exceptionLabels.count - 1)] componentsJoinedByString:@"."];
        }
    }

    if (match.length > 0) {
        return match;
    }
    return labels.count > 0 ? labels.lastObject : @"";
}

NSString *SNBDomainFamilyFromHost(NSString *host) {
    if (host.length == 0) {
        return @"";
    }
    NSString *lower = [host lowercaseString];
    NSArray<NSString *> *labels = [lower componentsSeparatedByString:@"."];
    if (labels.count < 2) {
        return lower;
    }
    NSString *suffix = SNBPublicSuffixForHost(lower);
    if (suffix.length == 0) {
        return lower;
    }
    NSArray<NSString *> *suffixLabels = [suffix componentsSeparatedByString:@"."];
    if (labels.count <= suffixLabels.count) {
        return lower;
    }
    NSUInteger registrableIndex = labels.count - (suffixLabels.count + 1);
    NSString *registrable = [labels[registrableIndex] stringByAppendingFormat:@".%@", suffix];
    return registrable;
}

//
//  TrustLearningModels.m
//  SniffNetBar
//

#import "TrustLearningModels.h"

@implementation SNBTrustFeatureVector

- (NSDictionary<NSString *, id> *)dictionaryRepresentation {
    NSMutableDictionary<NSString *, id> *dict = [NSMutableDictionary dictionary];
    if (self.ipAddress) dict[@"ipAddress"] = self.ipAddress;
    if (self.asn) dict[@"asn"] = self.asn;
    if (self.country) dict[@"country"] = self.country;
    if (self.organization) dict[@"organization"] = self.organization;

    dict[@"virusTotalScore"] = @(self.virusTotalScore);
    dict[@"abuseIPDBScore"] = @(self.abuseIPDBScore);
    if (self.greyNoiseClassification) dict[@"greyNoiseClassification"] = self.greyNoiseClassification;
    dict[@"shodanOpenPorts"] = @(self.shodanOpenPorts);

    dict[@"destinationPort"] = @(self.destinationPort);
    if (self.processName) dict[@"processName"] = self.processName;
    dict[@"bytesTransferred"] = @(self.bytesTransferred);
    dict[@"connectionCount"] = @(self.connectionCount);
    dict[@"connectionDuration"] = @(self.connectionDuration);

    dict[@"previousTrustCount"] = @(self.previousTrustCount);
    dict[@"previousUntrustCount"] = @(self.previousUntrustCount);
    dict[@"daysSinceFirstSeen"] = @(self.daysSinceFirstSeen);

    return dict;
}

- (NSString *)jsonString {
    NSDictionary *dict = [self dictionaryRepresentation];
    NSData *data = [NSJSONSerialization dataWithJSONObject:dict options:0 error:nil];
    if (!data) {
        return @"{}";
    }
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] ?: @"{}";
}

+ (instancetype)vectorFromJSONString:(NSString *)json {
    if (json.length == 0) {
        return [[SNBTrustFeatureVector alloc] init];
    }
    NSData *data = [json dataUsingEncoding:NSUTF8StringEncoding];
    if (!data) {
        return [[SNBTrustFeatureVector alloc] init];
    }
    NSDictionary *dict = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    if (![dict isKindOfClass:[NSDictionary class]]) {
        return [[SNBTrustFeatureVector alloc] init];
    }

    SNBTrustFeatureVector *vector = [[SNBTrustFeatureVector alloc] init];
    vector.ipAddress = [dict[@"ipAddress"] isKindOfClass:[NSString class]] ? dict[@"ipAddress"] : nil;
    vector.asn = [dict[@"asn"] isKindOfClass:[NSString class]] ? dict[@"asn"] : nil;
    vector.country = [dict[@"country"] isKindOfClass:[NSString class]] ? dict[@"country"] : nil;
    vector.organization = [dict[@"organization"] isKindOfClass:[NSString class]] ? dict[@"organization"] : nil;

    vector.virusTotalScore = [dict[@"virusTotalScore"] respondsToSelector:@selector(integerValue)]
        ? [dict[@"virusTotalScore"] integerValue] : 0;
    vector.abuseIPDBScore = [dict[@"abuseIPDBScore"] respondsToSelector:@selector(integerValue)]
        ? [dict[@"abuseIPDBScore"] integerValue] : 0;
    vector.greyNoiseClassification = [dict[@"greyNoiseClassification"] isKindOfClass:[NSString class]]
        ? dict[@"greyNoiseClassification"] : nil;
    vector.shodanOpenPorts = [dict[@"shodanOpenPorts"] respondsToSelector:@selector(integerValue)]
        ? [dict[@"shodanOpenPorts"] integerValue] : 0;

    vector.destinationPort = [dict[@"destinationPort"] respondsToSelector:@selector(integerValue)]
        ? [dict[@"destinationPort"] integerValue] : 0;
    vector.processName = [dict[@"processName"] isKindOfClass:[NSString class]] ? dict[@"processName"] : nil;
    vector.bytesTransferred = [dict[@"bytesTransferred"] respondsToSelector:@selector(unsignedLongLongValue)]
        ? [dict[@"bytesTransferred"] unsignedLongLongValue] : 0;
    vector.connectionCount = [dict[@"connectionCount"] respondsToSelector:@selector(integerValue)]
        ? [dict[@"connectionCount"] integerValue] : 0;
    vector.connectionDuration = [dict[@"connectionDuration"] respondsToSelector:@selector(doubleValue)]
        ? [dict[@"connectionDuration"] doubleValue] : 0.0;

    vector.previousTrustCount = [dict[@"previousTrustCount"] respondsToSelector:@selector(integerValue)]
        ? [dict[@"previousTrustCount"] integerValue] : 0;
    vector.previousUntrustCount = [dict[@"previousUntrustCount"] respondsToSelector:@selector(integerValue)]
        ? [dict[@"previousUntrustCount"] integerValue] : 0;
    vector.daysSinceFirstSeen = [dict[@"daysSinceFirstSeen"] respondsToSelector:@selector(doubleValue)]
        ? [dict[@"daysSinceFirstSeen"] doubleValue] : 0.0;

    return vector;
}

@end

@implementation SNBTrustFeedback
@end

@implementation SNBTrustConfidence
@end

@implementation SNBTrustSuggestion
@end

//
//  SNBPromotionCandidate.m
//  SniffNetBar
//

#import "SNBPromotionCandidate.h"

@implementation SNBPromotionCandidate

+ (BOOL)supportsSecureCoding {
    return YES;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _clusterID = @"";
        _score = 0;
        _confidence = 0;
        _ipOnly = NO;
        _asnAnomaly = NO;
        _seenCount = 0;
        _seen1h = 0;
        _seen24h = 0;
        _seen7d = 0;
        _beaconScore = 0.0;
        _dstPort = 0;
        _hosting = NO;
        _vpn = NO;
        _relay = NO;
        _vtScore = 0.0;
        _abuseScore = 0.0;
    }
    return self;
}

- (instancetype)initWithCoder:(NSCoder *)coder {
    self = [super init];
    if (self) {
        _clusterID = [coder decodeObjectOfClass:[NSString class] forKey:@"clusterID"] ?: @"";
        _extendedContext = [coder decodeObjectOfClass:[NSString class] forKey:@"extendedContext"];
        _label = [coder decodeObjectOfClass:[NSString class] forKey:@"label"];
        _score = [coder decodeIntegerForKey:@"score"];
        _confidence = [coder decodeIntegerForKey:@"confidence"];
        _ipOnly = [coder decodeBoolForKey:@"ipOnly"];
        _asnAnomaly = [coder decodeBoolForKey:@"asnAnomaly"];
        _seenCount = (uint64_t)[coder decodeInt64ForKey:@"seenCount"];
        _seen1h = (uint64_t)[coder decodeInt64ForKey:@"seen1h"];
        _seen24h = (uint64_t)[coder decodeInt64ForKey:@"seen24h"];
        _seen7d = (uint64_t)[coder decodeInt64ForKey:@"seen7d"];
        _beaconScore = [coder decodeDoubleForKey:@"beaconScore"];
        _firstSeen = [coder decodeObjectOfClass:[NSDate class] forKey:@"firstSeen"];
        _processName = [coder decodeObjectOfClass:[NSString class] forKey:@"processName"];
        _signingStatus = [coder decodeObjectOfClass:[NSString class] forKey:@"signingStatus"];
        _dstPort = [coder decodeIntegerForKey:@"dstPort"];
        _hosting = [coder decodeBoolForKey:@"hosting"];
        _vpn = [coder decodeBoolForKey:@"vpn"];
        _relay = [coder decodeBoolForKey:@"relay"];
        _vtScore = [coder decodeDoubleForKey:@"vtScore"];
        _abuseScore = [coder decodeDoubleForKey:@"abuseScore"];
        _greyNoiseClass = [coder decodeObjectOfClass:[NSString class] forKey:@"greyNoiseClass"];
        _userLabel = [coder decodeObjectOfClass:[NSString class] forKey:@"userLabel"];
        _asn = [coder decodeObjectOfClass:[NSString class] forKey:@"asn"];
        _org = [coder decodeObjectOfClass:[NSString class] forKey:@"org"];
        _country = [coder decodeObjectOfClass:[NSString class] forKey:@"country"];
        _dstIP = [coder decodeObjectOfClass:[NSString class] forKey:@"dstIP"];
        _dstDomain = [coder decodeObjectOfClass:[NSString class] forKey:@"dstDomain"];
    }
    return self;
}

- (void)encodeWithCoder:(NSCoder *)coder {
    [coder encodeObject:_clusterID forKey:@"clusterID"];
    [coder encodeObject:_extendedContext forKey:@"extendedContext"];
    [coder encodeObject:_label forKey:@"label"];
    [coder encodeInteger:_score forKey:@"score"];
    [coder encodeInteger:_confidence forKey:@"confidence"];
    [coder encodeBool:_ipOnly forKey:@"ipOnly"];
    [coder encodeBool:_asnAnomaly forKey:@"asnAnomaly"];
    [coder encodeInt64:(int64_t)_seenCount forKey:@"seenCount"];
    [coder encodeInt64:(int64_t)_seen1h forKey:@"seen1h"];
    [coder encodeInt64:(int64_t)_seen24h forKey:@"seen24h"];
    [coder encodeInt64:(int64_t)_seen7d forKey:@"seen7d"];
    [coder encodeDouble:_beaconScore forKey:@"beaconScore"];
    [coder encodeObject:_firstSeen forKey:@"firstSeen"];
    [coder encodeObject:_processName forKey:@"processName"];
    [coder encodeObject:_signingStatus forKey:@"signingStatus"];
    [coder encodeInteger:_dstPort forKey:@"dstPort"];
    [coder encodeBool:_hosting forKey:@"hosting"];
    [coder encodeBool:_vpn forKey:@"vpn"];
    [coder encodeBool:_relay forKey:@"relay"];
    [coder encodeDouble:_vtScore forKey:@"vtScore"];
    [coder encodeDouble:_abuseScore forKey:@"abuseScore"];
    [coder encodeObject:_greyNoiseClass forKey:@"greyNoiseClass"];
    [coder encodeObject:_userLabel forKey:@"userLabel"];
    [coder encodeObject:_asn forKey:@"asn"];
    [coder encodeObject:_org forKey:@"org"];
    [coder encodeObject:_country forKey:@"country"];
    [coder encodeObject:_dstIP forKey:@"dstIP"];
    [coder encodeObject:_dstDomain forKey:@"dstDomain"];
}

- (NSString *)description {
    return [NSString stringWithFormat:@"<SNBPromotionCandidate: %@ score=%ld confidence=%ld seen=%llu>",
            self.clusterID, (long)self.score, (long)self.confidence, self.seenCount];
}

@end

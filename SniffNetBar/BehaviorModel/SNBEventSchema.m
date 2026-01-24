//
//  SNBEventSchema.m
//  SniffNetBar
//

#import "SNBEventSchema.h"

@implementation SNBHostContext

+ (BOOL)supportsSecureCoding {
    return YES;
}

- (instancetype)initWithCoder:(NSCoder *)coder {
    self = [super init];
    if (self) {
        _deviceID = [coder decodeObjectOfClass:[NSString class] forKey:@"deviceID"] ?: @"";
        _hostname = [coder decodeObjectOfClass:[NSString class] forKey:@"hostname"] ?: @"";
        _osVersion = [coder decodeObjectOfClass:[NSString class] forKey:@"osVersion"] ?: @"";
        _timezone = [coder decodeObjectOfClass:[NSString class] forKey:@"timezone"] ?: @"";
        _networkType = [coder decodeObjectOfClass:[NSString class] forKey:@"networkType"] ?: @"";
        _vpnActive = [coder decodeBoolForKey:@"vpnActive"];
        _proxyActive = [coder decodeBoolForKey:@"proxyActive"];
    }
    return self;
}

- (void)encodeWithCoder:(NSCoder *)coder {
    [coder encodeObject:self.deviceID forKey:@"deviceID"];
    [coder encodeObject:self.hostname forKey:@"hostname"];
    [coder encodeObject:self.osVersion forKey:@"osVersion"];
    [coder encodeObject:self.timezone forKey:@"timezone"];
    [coder encodeObject:self.networkType forKey:@"networkType"];
    [coder encodeBool:self.vpnActive forKey:@"vpnActive"];
    [coder encodeBool:self.proxyActive forKey:@"proxyActive"];
}

@end

@implementation SNBFlowEvent

+ (BOOL)supportsSecureCoding {
    return YES;
}

- (instancetype)initWithCoder:(NSCoder *)coder {
    self = [super init];
    if (self) {
        _start = [coder decodeObjectOfClass:[NSDate class] forKey:@"start"] ?: [NSDate dateWithTimeIntervalSince1970:0];
        _end = [coder decodeObjectOfClass:[NSDate class] forKey:@"end"] ?: [NSDate dateWithTimeIntervalSince1970:0];
        _direction = [coder decodeObjectOfClass:[NSString class] forKey:@"direction"] ?: @"";
        _protocolName = [coder decodeObjectOfClass:[NSString class] forKey:@"protocolName"] ?: @"";
        _srcIP = [coder decodeObjectOfClass:[NSString class] forKey:@"srcIP"] ?: @"";
        _dstIP = [coder decodeObjectOfClass:[NSString class] forKey:@"dstIP"] ?: @"";
        _srcPort = [coder decodeIntegerForKey:@"srcPort"];
        _dstPort = [coder decodeIntegerForKey:@"dstPort"];
        _bytesIn = (uint64_t)[coder decodeInt64ForKey:@"bytesIn"];
        _bytesOut = (uint64_t)[coder decodeInt64ForKey:@"bytesOut"];
        _packets = (uint64_t)[coder decodeInt64ForKey:@"packets"];
        _duration = [coder decodeDoubleForKey:@"duration"];
        _dnsQuery = [coder decodeObjectOfClass:[NSString class] forKey:@"dnsQuery"] ?: @"";
        _sni = [coder decodeObjectOfClass:[NSString class] forKey:@"sni"] ?: @"";
        _ja3 = [coder decodeObjectOfClass:[NSString class] forKey:@"ja3"] ?: @"";
        _ja4 = [coder decodeObjectOfClass:[NSString class] forKey:@"ja4"] ?: @"";
        _httpHost = [coder decodeObjectOfClass:[NSString class] forKey:@"httpHost"] ?: @"";
        _processName = [coder decodeObjectOfClass:[NSString class] forKey:@"processName"] ?: @"";
        _bundleID = [coder decodeObjectOfClass:[NSString class] forKey:@"bundleID"] ?: @"";
        _parentProcess = [coder decodeObjectOfClass:[NSString class] forKey:@"parentProcess"] ?: @"";
        _signingStatus = [coder decodeObjectOfClass:[NSString class] forKey:@"signingStatus"] ?: @"";
        _codeHash = [coder decodeObjectOfClass:[NSString class] forKey:@"codeHash"] ?: @"";
        _outcome = [coder decodeObjectOfClass:[NSString class] forKey:@"outcome"] ?: @"";
        _asn = [coder decodeObjectOfClass:[NSString class] forKey:@"asn"] ?: @"";
        _org = [coder decodeObjectOfClass:[NSString class] forKey:@"org"] ?: @"";
        _country = [coder decodeObjectOfClass:[NSString class] forKey:@"country"] ?: @"";
        _region = [coder decodeObjectOfClass:[NSString class] forKey:@"region"] ?: @"";
        _hosting = [coder decodeBoolForKey:@"hosting"];
        _vpn = [coder decodeBoolForKey:@"vpn"];
        _relay = [coder decodeBoolForKey:@"relay"];
        _vtScore = [coder decodeObjectOfClass:[NSNumber class] forKey:@"vtScore"];
        _abuseScore = [coder decodeObjectOfClass:[NSNumber class] forKey:@"abuseScore"];
        _greyNoiseClass = [coder decodeObjectOfClass:[NSString class] forKey:@"greyNoiseClass"] ?: @"";
    }
    return self;
}

- (void)encodeWithCoder:(NSCoder *)coder {
    [coder encodeObject:self.start forKey:@"start"];
    [coder encodeObject:self.end forKey:@"end"];
    [coder encodeObject:self.direction forKey:@"direction"];
    [coder encodeObject:self.protocolName forKey:@"protocolName"];
    [coder encodeObject:self.srcIP forKey:@"srcIP"];
    [coder encodeObject:self.dstIP forKey:@"dstIP"];
    [coder encodeInteger:self.srcPort forKey:@"srcPort"];
    [coder encodeInteger:self.dstPort forKey:@"dstPort"];
    [coder encodeInt64:(int64_t)self.bytesIn forKey:@"bytesIn"];
    [coder encodeInt64:(int64_t)self.bytesOut forKey:@"bytesOut"];
    [coder encodeInt64:(int64_t)self.packets forKey:@"packets"];
    [coder encodeDouble:self.duration forKey:@"duration"];
    [coder encodeObject:self.dnsQuery forKey:@"dnsQuery"];
    [coder encodeObject:self.sni forKey:@"sni"];
    [coder encodeObject:self.ja3 forKey:@"ja3"];
    [coder encodeObject:self.ja4 forKey:@"ja4"];
    [coder encodeObject:self.httpHost forKey:@"httpHost"];
    [coder encodeObject:self.processName forKey:@"processName"];
    [coder encodeObject:self.bundleID forKey:@"bundleID"];
    [coder encodeObject:self.parentProcess forKey:@"parentProcess"];
    [coder encodeObject:self.signingStatus forKey:@"signingStatus"];
    [coder encodeObject:self.codeHash forKey:@"codeHash"];
    [coder encodeObject:self.outcome forKey:@"outcome"];
    [coder encodeObject:self.asn forKey:@"asn"];
    [coder encodeObject:self.org forKey:@"org"];
    [coder encodeObject:self.country forKey:@"country"];
    [coder encodeObject:self.region forKey:@"region"];
    [coder encodeBool:self.hosting forKey:@"hosting"];
    [coder encodeBool:self.vpn forKey:@"vpn"];
    [coder encodeBool:self.relay forKey:@"relay"];
    [coder encodeObject:self.vtScore forKey:@"vtScore"];
    [coder encodeObject:self.abuseScore forKey:@"abuseScore"];
    [coder encodeObject:self.greyNoiseClass forKey:@"greyNoiseClass"];
}

@end

@implementation SNBEnrichment

+ (BOOL)supportsSecureCoding {
    return YES;
}

- (instancetype)initWithCoder:(NSCoder *)coder {
    self = [super init];
    if (self) {
        _ip = [coder decodeObjectOfClass:[NSString class] forKey:@"ip"] ?: @"";
        _asn = [coder decodeObjectOfClass:[NSString class] forKey:@"asn"] ?: @"";
        _org = [coder decodeObjectOfClass:[NSString class] forKey:@"org"] ?: @"";
        _country = [coder decodeObjectOfClass:[NSString class] forKey:@"country"] ?: @"";
        _region = [coder decodeObjectOfClass:[NSString class] forKey:@"region"] ?: @"";
        _city = [coder decodeObjectOfClass:[NSString class] forKey:@"city"] ?: @"";
        _hosting = [coder decodeBoolForKey:@"hosting"];
        _vpn = [coder decodeBoolForKey:@"vpn"];
        _relay = [coder decodeBoolForKey:@"relay"];
        _vtScore = [coder decodeObjectOfClass:[NSNumber class] forKey:@"vtScore"];
        _vtStats = [coder decodeObjectOfClass:[NSDictionary class] forKey:@"vtStats"];
        _vtCategories = [coder decodeObjectOfClass:[NSArray class] forKey:@"vtCategories"];
        _abuseScore = [coder decodeObjectOfClass:[NSNumber class] forKey:@"abuseScore"];
        _abuseReports = [coder decodeObjectOfClass:[NSNumber class] forKey:@"abuseReports"];
        _abuseLastReported = [coder decodeObjectOfClass:[NSDate class] forKey:@"abuseLastReported"];
        _greyNoiseClass = [coder decodeObjectOfClass:[NSString class] forKey:@"greyNoiseClass"];
        _greyNoiseTags = [coder decodeObjectOfClass:[NSArray class] forKey:@"greyNoiseTags"];
        _greyNoiseLastSeen = [coder decodeObjectOfClass:[NSDate class] forKey:@"greyNoiseLastSeen"];
    }
    return self;
}

- (void)encodeWithCoder:(NSCoder *)coder {
    [coder encodeObject:self.ip forKey:@"ip"];
    [coder encodeObject:self.asn forKey:@"asn"];
    [coder encodeObject:self.org forKey:@"org"];
    [coder encodeObject:self.country forKey:@"country"];
    [coder encodeObject:self.region forKey:@"region"];
    [coder encodeObject:self.city forKey:@"city"];
    [coder encodeBool:self.hosting forKey:@"hosting"];
    [coder encodeBool:self.vpn forKey:@"vpn"];
    [coder encodeBool:self.relay forKey:@"relay"];
    [coder encodeObject:self.vtScore forKey:@"vtScore"];
    [coder encodeObject:self.vtStats forKey:@"vtStats"];
    [coder encodeObject:self.vtCategories forKey:@"vtCategories"];
    [coder encodeObject:self.abuseScore forKey:@"abuseScore"];
    [coder encodeObject:self.abuseReports forKey:@"abuseReports"];
    [coder encodeObject:self.abuseLastReported forKey:@"abuseLastReported"];
    [coder encodeObject:self.greyNoiseClass forKey:@"greyNoiseClass"];
    [coder encodeObject:self.greyNoiseTags forKey:@"greyNoiseTags"];
    [coder encodeObject:self.greyNoiseLastSeen forKey:@"greyNoiseLastSeen"];
}

@end

@implementation SNBAggregates

+ (BOOL)supportsSecureCoding {
    return YES;
}

- (instancetype)initWithCoder:(NSCoder *)coder {
    self = [super init];
    if (self) {
        _clusterID = [coder decodeObjectOfClass:[NSString class] forKey:@"clusterID"] ?: @"";
        _appKey = [coder decodeObjectOfClass:[NSString class] forKey:@"appKey"] ?: @"";
        _asn = [coder decodeObjectOfClass:[NSString class] forKey:@"asn"] ?: @"";
        _org = [coder decodeObjectOfClass:[NSString class] forKey:@"org"] ?: @"";
        _domainFamily = [coder decodeObjectOfClass:[NSString class] forKey:@"domainFamily"] ?: @"";
        _protocolName = [coder decodeObjectOfClass:[NSString class] forKey:@"protocolName"] ?: @"";
        _port = [coder decodeIntegerForKey:@"port"];
        _hourHistogram = [coder decodeObjectOfClass:[NSDictionary class] forKey:@"hourHistogram"] ?: @{};
        _dowHistogram = [coder decodeObjectOfClass:[NSDictionary class] forKey:@"dowHistogram"] ?: @{};
        _ewmaBytes = [coder decodeDoubleForKey:@"ewmaBytes"];
        _ewmaFreq = [coder decodeDoubleForKey:@"ewmaFreq"];
        _zScoreBytes = [coder decodeDoubleForKey:@"zScoreBytes"];
        _zScoreFreq = [coder decodeDoubleForKey:@"zScoreFreq"];
        _seenCount = (uint64_t)[coder decodeInt64ForKey:@"seenCount"];
        _lastSeen = [coder decodeObjectOfClass:[NSDate class] forKey:@"lastSeen"] ?: [NSDate dateWithTimeIntervalSince1970:0];
    }
    return self;
}

- (void)encodeWithCoder:(NSCoder *)coder {
    [coder encodeObject:self.clusterID forKey:@"clusterID"];
    [coder encodeObject:self.appKey forKey:@"appKey"];
    [coder encodeObject:self.asn forKey:@"asn"];
    [coder encodeObject:self.org forKey:@"org"];
    [coder encodeObject:self.domainFamily forKey:@"domainFamily"];
    [coder encodeObject:self.protocolName forKey:@"protocolName"];
    [coder encodeInteger:self.port forKey:@"port"];
    [coder encodeObject:self.hourHistogram forKey:@"hourHistogram"];
    [coder encodeObject:self.dowHistogram forKey:@"dowHistogram"];
    [coder encodeDouble:self.ewmaBytes forKey:@"ewmaBytes"];
    [coder encodeDouble:self.ewmaFreq forKey:@"ewmaFreq"];
    [coder encodeDouble:self.zScoreBytes forKey:@"zScoreBytes"];
    [coder encodeDouble:self.zScoreFreq forKey:@"zScoreFreq"];
    [coder encodeInt64:(int64_t)self.seenCount forKey:@"seenCount"];
    [coder encodeObject:self.lastSeen forKey:@"lastSeen"];
}

@end

@implementation SNBRecommendation

+ (BOOL)supportsSecureCoding {
    return YES;
}

- (instancetype)initWithCoder:(NSCoder *)coder {
    self = [super init];
    if (self) {
        _clusterID = [coder decodeObjectOfClass:[NSString class] forKey:@"clusterID"] ?: @"";
        _extendedContext = [coder decodeObjectOfClass:[NSString class] forKey:@"extendedContext"] ?: @"{}";
        _asnAnomaly = [coder decodeBoolForKey:@"asnAnomaly"];
        _ipOnly = [coder decodeBoolForKey:@"ipOnly"];
        _baseConfidence = [coder decodeIntegerForKey:@"baseConfidence"];
        _score = [coder decodeIntegerForKey:@"score"];
        _label = [coder decodeObjectOfClass:[NSString class] forKey:@"label"] ?: @"";
        _confidence = [coder decodeIntegerForKey:@"confidence"];
        _summary = [coder decodeObjectOfClass:[NSString class] forKey:@"summary"] ?: @"";
        _evidence = [coder decodeObjectOfClass:[NSArray class] forKey:@"evidence"] ?: @[];
        _actions = [coder decodeObjectOfClass:[NSArray class] forKey:@"actions"] ?: @[];
        _generatedAt = [coder decodeObjectOfClass:[NSDate class] forKey:@"generatedAt"] ?: [NSDate dateWithTimeIntervalSince1970:0];
    }
    return self;
}

- (void)encodeWithCoder:(NSCoder *)coder {
    [coder encodeObject:self.clusterID forKey:@"clusterID"];
    [coder encodeObject:self.extendedContext forKey:@"extendedContext"];
    [coder encodeBool:self.asnAnomaly forKey:@"asnAnomaly"];
    [coder encodeBool:self.ipOnly forKey:@"ipOnly"];
    [coder encodeInteger:self.baseConfidence forKey:@"baseConfidence"];
    [coder encodeInteger:self.score forKey:@"score"];
    [coder encodeObject:self.label forKey:@"label"];
    [coder encodeInteger:self.confidence forKey:@"confidence"];
    [coder encodeObject:self.summary forKey:@"summary"];
    [coder encodeObject:self.evidence forKey:@"evidence"];
    [coder encodeObject:self.actions forKey:@"actions"];
    [coder encodeObject:self.generatedAt forKey:@"generatedAt"];
}

@end

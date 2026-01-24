//
//  ThreatIntelModels.m
//  SniffNetBar
//

#import "ThreatIntelModels.h"
#import <Cocoa/Cocoa.h>

NSString *const TIErrorDomain = @"com.sniffnetbar.threatintel";

// MARK: - TIIndicator

@implementation TIIndicator

- (instancetype)initWithType:(TIIndicatorType)type value:(NSString *)value {
    self = [super init];
    if (self) {
        _type = type;
        _value = [value copy];
    }
    return self;
}

+ (instancetype)indicatorWithIP:(NSString *)ip {
    // Simple IPv4/IPv6 detection
    BOOL isIPv6 = [ip containsString:@":"];
    TIIndicatorType type = isIPv6 ? TIIndicatorTypeIPv6 : TIIndicatorTypeIPv4;
    return [[self alloc] initWithType:type value:ip];
}

+ (instancetype)indicatorWithDomain:(NSString *)domain {
    return [[self alloc] initWithType:TIIndicatorTypeDomain value:domain];
}

- (id)copyWithZone:(NSZone *)zone {
    return [[TIIndicator alloc] initWithType:_type value:_value];
}

- (NSUInteger)hash {
    return [_value hash] ^ _type;
}

- (BOOL)isEqual:(id)object {
    if (![object isKindOfClass:[TIIndicator class]]) {
        return NO;
    }
    TIIndicator *other = (TIIndicator *)object;
    return _type == other.type && [_value isEqualToString:other.value];
}

- (NSString *)description {
    return [NSString stringWithFormat:@"<TIIndicator type=%ld value=%@>", (long)_type, _value];
}

@end

// MARK: - TIVerdict

@implementation TIVerdict

- (instancetype)init {
    self = [super init];
    if (self) {
        _hit = NO;
        _confidence = 0;
        _categories = @[];
        _tags = @[];
    }
    return self;
}

- (NSString *)description {
    return [NSString stringWithFormat:@"<TIVerdict hit=%d confidence=%ld categories=%@>",
            _hit, (long)_confidence, _categories];
}

@end

// MARK: - TIMetadata

@implementation TIMetadata

- (instancetype)init {
    self = [super init];
    if (self) {
        _fetchedAt = [NSDate date];
        _expiresAt = [NSDate dateWithTimeIntervalSinceNow:3600];
        _ttlSeconds = 3600;
        _rateLimitRemaining = -1;
    }
    return self;
}

@end

// MARK: - TIResult

@implementation TIResult

- (NSString *)description {
    return [NSString stringWithFormat:@"<TIResult provider=%@ indicator=%@ verdict=%@>",
            _providerName, _indicator, _verdict];
}

@end

// MARK: - TIScoreBreakdown

@implementation TIScoreBreakdown

- (NSString *)description {
    return [NSString stringWithFormat:@"<TIScoreBreakdown rule=%@ score=%ld provider=%@>",
            _ruleName, (long)_scoreContribution, _provider];
}

@end

// MARK: - TIScoringResult

@implementation TIScoringResult

- (NSString *)verdictString {
    switch (_verdict) {
        case TIThreatVerdictClean:
            return @"Clean";
        case TIThreatVerdictSuspicious:
            return @"Suspicious";
        case TIThreatVerdictMalicious:
            return @"Malicious";
        case TIThreatVerdictUnknown:
            return @"Unknown";
    }
}

- (NSColor *)verdictColor {
    switch (_verdict) {
        case TIThreatVerdictClean:
            return [NSColor  systemTealColor];
        case TIThreatVerdictSuspicious:
            return [NSColor systemOrangeColor];
        case TIThreatVerdictMalicious:
            return [NSColor systemRedColor];
        case TIThreatVerdictUnknown:
            return [NSColor systemGrayColor];
    }
}

- (NSString *)description {
    return [NSString stringWithFormat:@"<TIScoringResult score=%ld verdict=%@ confidence=%.2f>",
            (long)_finalScore, [self verdictString], _confidence];
}

@end

// MARK: - TIEnrichmentResponse

@implementation TIEnrichmentResponse

- (NSString *)description {
    return [NSString stringWithFormat:@"<TIEnrichmentResponse indicator=%@ results=%lu score=%@ duration=%.2fs>",
            _indicator, (unsigned long)_providerResults.count, _scoringResult, _duration];
}

@end

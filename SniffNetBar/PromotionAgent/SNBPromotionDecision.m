//
//  SNBPromotionDecision.m
//  SniffNetBar
//

#import "SNBPromotionDecision.h"

@implementation SNBPromotionDecision

+ (BOOL)supportsSecureCoding {
    return YES;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _action = SNBPromotionActionNone;
        _factors = @[];
        _blockers = @[];
        _confidence = 0;
        _score = 0;
        _seenCount = 0;
        _evaluatedAt = [NSDate date];
    }
    return self;
}

- (instancetype)initWithCoder:(NSCoder *)coder {
    self = [super init];
    if (self) {
        _clusterID = [coder decodeObjectOfClass:[NSString class] forKey:@"clusterID"];
        _action = [coder decodeIntegerForKey:@"action"];
        _reason = [coder decodeObjectOfClass:[NSString class] forKey:@"reason"];
        _factors = [coder decodeObjectOfClasses:[NSSet setWithObjects:[NSArray class], [NSString class], nil]
                                         forKey:@"factors"];
        _blockers = [coder decodeObjectOfClasses:[NSSet setWithObjects:[NSArray class], [NSString class], nil]
                                          forKey:@"blockers"];
        _confidence = [coder decodeIntegerForKey:@"confidence"];
        _score = [coder decodeIntegerForKey:@"score"];
        _seenCount = (uint64_t)[coder decodeInt64ForKey:@"seenCount"];
        _evaluatedAt = [coder decodeObjectOfClass:[NSDate class] forKey:@"evaluatedAt"];
        _processName = [coder decodeObjectOfClass:[NSString class] forKey:@"processName"];
        _destinationFamily = [coder decodeObjectOfClass:[NSString class] forKey:@"destinationFamily"];
        _destinationIP = [coder decodeObjectOfClass:[NSString class] forKey:@"destinationIP"];
        _extendedContext = [coder decodeObjectOfClass:[NSString class] forKey:@"extendedContext"];
    }
    return self;
}

- (void)encodeWithCoder:(NSCoder *)coder {
    [coder encodeObject:_clusterID forKey:@"clusterID"];
    [coder encodeInteger:_action forKey:@"action"];
    [coder encodeObject:_reason forKey:@"reason"];
    [coder encodeObject:_factors forKey:@"factors"];
    [coder encodeObject:_blockers forKey:@"blockers"];
    [coder encodeInteger:_confidence forKey:@"confidence"];
    [coder encodeInteger:_score forKey:@"score"];
    [coder encodeInt64:(int64_t)_seenCount forKey:@"seenCount"];
    [coder encodeObject:_evaluatedAt forKey:@"evaluatedAt"];
    [coder encodeObject:_processName forKey:@"processName"];
    [coder encodeObject:_destinationFamily forKey:@"destinationFamily"];
    [coder encodeObject:_destinationIP forKey:@"destinationIP"];
    [coder encodeObject:_extendedContext forKey:@"extendedContext"];
}

- (NSString *)actionDescription {
    switch (self.action) {
        case SNBPromotionActionNone:
            return @"Continue Observing";
        case SNBPromotionActionSuggest:
            return @"Suggest Trust";
        case SNBPromotionActionAutoPromote:
            return @"Auto-Trusted";
        case SNBPromotionActionAutoBlock:
            return @"Auto-Blocked";
        case SNBPromotionActionNeedsReview:
            return @"Needs Review";
    }
    return @"Unknown";
}

- (NSString *)description {
    return [NSString stringWithFormat:@"<SNBPromotionDecision: %@ action=%@ confidence=%ld factors=%lu blockers=%lu>",
            self.clusterID, [self actionDescription], (long)self.confidence,
            (unsigned long)self.factors.count, (unsigned long)self.blockers.count];
}

@end

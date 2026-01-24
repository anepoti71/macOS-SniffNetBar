//
//  AnomalyExplanationService.m
//  SniffNetBar
//
//  Local LLM explainability for anomaly windows
//

#import "AnomalyExplanationService.h"
#import "AnomalyStore.h"
#import "ConfigurationManager.h"
#import "ThreatIntelModels.h"
#import "Logger.h"

static NSString * const SNBExplainabilityPromptVersion = @"1";
static NSString * const SNBRiskBandLikelyBenign = @"likely_benign";
static NSString * const SNBRiskBandNeedsAttention = @"needs_attention";
static NSString * const SNBRiskBandHigherRisk = @"higher_risk";

static NSString * const SNBExplainToneConservative = @"conservative";

static const double SNBExplainHighScore = 0.95;
static const double SNBExplainMediumScore = 0.90;

@interface SNBAnomalyExplanationService ()
@property (nonatomic, strong) NSURLSession *session;
@property (nonatomic, copy) NSString *baseURL;
@property (nonatomic, copy) NSString *model;
@property (nonatomic, assign) NSTimeInterval timeout;
@property (nonatomic, assign, getter=isEnabled) BOOL enabled;
@end

@implementation SNBAnomalyExplanation
@end

@implementation SNBAnomalyExplanationService

- (instancetype)initWithConfiguration:(ConfigurationManager *)configuration {
    self = [super init];
    if (self) {
        _baseURL = [configuration.explainabilityOllamaBaseURL copy];
        _model = [configuration.explainabilityOllamaModel copy];
        _timeout = configuration.explainabilityOllamaTimeout;
        _enabled = configuration.explainabilityEnabled && _baseURL.length > 0 && _model.length > 0;
        _promptVersion = SNBExplainabilityPromptVersion;
        NSURLSessionConfiguration *config = [NSURLSessionConfiguration ephemeralSessionConfiguration];
        config.URLCache = nil;
        config.requestCachePolicy = NSURLRequestReloadIgnoringLocalCacheData;
        _session = [NSURLSession sessionWithConfiguration:config];
    }
    return self;
}

- (NSDictionary *)inputForWindow:(SNBAnomalyWindowRecord *)window
                   windowSeconds:(NSTimeInterval)windowSeconds
                    threatIntel:(TIEnrichmentResponse * _Nullable)threatIntel {
    NSString *windowStartString = [self iso8601StringFromDate:[NSDate dateWithTimeIntervalSince1970:window.windowStart]];
    NSString *windowEndString = [self iso8601StringFromDate:[NSDate dateWithTimeIntervalSince1970:(window.windowStart + windowSeconds)]];

    NSInteger vtMalicious = 0;
    NSInteger vtSuspicious = 0;
    NSInteger vtTotalScans = 0;
    NSDate *vtLastSeen = nil;
    NSString *asn = nil;
    NSString *country = nil;
    BOOL hasVT = NO;

    if (threatIntel) {
        for (TIResult *result in threatIntel.providerResults) {
            if (![result.providerName isEqualToString:@"VirusTotal"]) {
                continue;
            }
            NSDictionary *evidence = result.verdict.evidence;
            if ([evidence isKindOfClass:[NSDictionary class]]) {
                NSNumber *malicious = evidence[@"malicious"];
                NSNumber *suspicious = evidence[@"suspicious"];
                NSNumber *totalVotes = evidence[@"total_votes"];
                if ([malicious isKindOfClass:[NSNumber class]]) {
                    vtMalicious = malicious.integerValue;
                }
                if ([suspicious isKindOfClass:[NSNumber class]]) {
                    vtSuspicious = suspicious.integerValue;
                }
                if ([totalVotes isKindOfClass:[NSNumber class]]) {
                    vtTotalScans = totalVotes.integerValue;
                }
                NSString *asOwner = evidence[@"as_owner"];
                NSString *countryCode = evidence[@"country"];
                if ([asOwner isKindOfClass:[NSString class]] && asOwner.length > 0) {
                    asn = asOwner;
                }
                if ([countryCode isKindOfClass:[NSString class]] && countryCode.length > 0) {
                    country = countryCode;
                }
                hasVT = YES;
            }
            if (result.verdict.lastSeen) {
                vtLastSeen = result.verdict.lastSeen;
            } else if (result.metadata.fetchedAt) {
                vtLastSeen = result.metadata.fetchedAt;
            }
            break;
        }
    }

    if (!hasVT) {
        vtMalicious = 0;
        vtSuspicious = 0;
        vtTotalScans = 0;
        vtLastSeen = nil;
    }

    NSString *riskBand = [self riskBandForScore:window.score
                                          isNew:window.isNew
                                         isRare:window.isRare
                                   vtMalicious:vtMalicious
                                  vtSuspicious:vtSuspicious];

    NSDictionary *novelty = @{
        @"is_new": @(window.isNew),
        @"seen_count_30d": @(window.seenCount),
        @"first_seen": [NSNull null]
    };

    NSDictionary *virustotal = @{
        @"malicious": @(vtMalicious),
        @"suspicious": @(vtSuspicious),
        @"total_scans": @(vtTotalScans),
        @"last_seen": vtLastSeen ? [self iso8601StringFromDate:vtLastSeen] : [NSNull null]
    };

    NSMutableDictionary *evidence = [NSMutableDictionary dictionary];
    evidence[@"novelty"] = novelty;
    evidence[@"virustotal"] = virustotal;
    evidence[@"asn"] = asn ? asn : [NSNull null];
    evidence[@"country"] = country ? country : [NSNull null];

    NSMutableDictionary *payload = [NSMutableDictionary dictionary];
    payload[@"schema_version"] = @"1.0";
    payload[@"window_start"] = windowStartString ?: @"";
    payload[@"window_end"] = windowEndString ?: @"";
    payload[@"destination_ip"] = window.dstIP ?: @"";
    payload[@"anomaly_score"] = @(window.score);
    payload[@"risk_band"] = riskBand;
    payload[@"evidence"] = evidence;
    payload[@"explain_prompt_version"] = self.promptVersion;
    return payload;
}

- (void)generateExplanationWithInput:(NSDictionary *)input
                          completion:(void (^)(SNBAnomalyExplanation * _Nullable, NSError * _Nullable))completion {
    if (!self.isEnabled) {
        if (completion) {
            NSError *error = [NSError errorWithDomain:@"AnomalyExplanationService"
                                                 code:1001
                                             userInfo:@{NSLocalizedDescriptionKey: @"Explainability disabled"}];
            completion(nil, error);
        }
        return;
    }

    NSError *jsonError = nil;
    NSData *inputData = [NSJSONSerialization dataWithJSONObject:input options:0 error:&jsonError];
    if (!inputData) {
        if (completion) {
            completion(nil, jsonError);
        }
        return;
    }

    NSString *inputString = [[NSString alloc] initWithData:inputData encoding:NSUTF8StringEncoding];
    if (inputString.length == 0) {
        if (completion) {
            NSError *error = [NSError errorWithDomain:@"AnomalyExplanationService"
                                                 code:1002
                                             userInfo:@{NSLocalizedDescriptionKey: @"Failed to encode input"}];
            completion(nil, error);
        }
        return;
    }

    NSURL *url = [NSURL URLWithString:[NSString stringWithFormat:@"%@/api/chat", self.baseURL]];
    if (!url) {
        if (completion) {
            NSError *error = [NSError errorWithDomain:@"AnomalyExplanationService"
                                                 code:1003
                                             userInfo:@{NSLocalizedDescriptionKey: @"Invalid Ollama base URL"}];
            completion(nil, error);
        }
        return;
    }

    NSDictionary *payload = @{
        @"model": self.model,
        @"messages": @[
            @{@"role": @"system", @"content": [self systemPrompt]},
            @{@"role": @"user", @"content": inputString}
        ],
        @"stream": @NO,
        @"format": @"json",
        @"options": @{
            @"temperature": @0,
            @"top_p": @0.1,
            @"seed": @42
        }
    };

    NSData *body = [NSJSONSerialization dataWithJSONObject:payload options:0 error:&jsonError];
    if (!body) {
        if (completion) {
            completion(nil, jsonError);
        }
        return;
    }

    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    request.HTTPMethod = @"POST";
    request.HTTPBody = body;
    request.timeoutInterval = self.timeout;
    [request setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];

    __weak typeof(self) weakSelf = self;
    NSURLSessionDataTask *task = [self.session dataTaskWithRequest:request
                                                 completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) {
            return;
        }
        NSHTTPURLResponse *httpResponse = [response isKindOfClass:[NSHTTPURLResponse class]]
            ? (NSHTTPURLResponse *)response : nil;
        if (httpResponse && httpResponse.statusCode != 200) {
            NSError *statusError = [NSError errorWithDomain:@"AnomalyExplanationService"
                                                       code:httpResponse.statusCode
                                                   userInfo:@{NSLocalizedDescriptionKey:
                                                                  [NSString stringWithFormat:@"HTTP %ld",
                                                                   (long)httpResponse.statusCode]}];
            SNBAnomalyExplanation *fallback = [strongSelf fallbackExplanationForInput:input];
            if (completion) {
                completion(fallback, statusError);
            }
            return;
        }
        if (error || data.length == 0) {
            SNBAnomalyExplanation *fallback = [strongSelf fallbackExplanationForInput:input];
            if (completion) {
                completion(fallback, error);
            }
            return;
        }

        NSError *parseError = nil;
        NSDictionary *responseJSON = [NSJSONSerialization JSONObjectWithData:data options:0 error:&parseError];
        if (![responseJSON isKindOfClass:[NSDictionary class]]) {
            SNBAnomalyExplanation *fallback = [strongSelf fallbackExplanationForInput:input];
            if (completion) {
                completion(fallback, parseError);
            }
            return;
        }

        NSDictionary *message = responseJSON[@"message"];
        id contentObj = message[@"content"];
        NSDictionary *output = nil;
        if ([contentObj isKindOfClass:[NSDictionary class]]) {
            output = contentObj;
        } else if ([contentObj isKindOfClass:[NSString class]]) {
            NSData *contentData = [(NSString *)contentObj dataUsingEncoding:NSUTF8StringEncoding];
            if (contentData) {
                output = [NSJSONSerialization JSONObjectWithData:contentData options:0 error:&parseError];
            }
        }

        SNBAnomalyExplanation *explanation = [strongSelf explanationFromOutput:output input:input];
        if (!explanation) {
            explanation = [strongSelf fallbackExplanationForInput:input];
            if (completion) {
                completion(explanation, parseError);
            }
            return;
        }

        if (completion) {
            completion(explanation, nil);
        }
    }];

    [task resume];
}

#pragma mark - Helpers

- (NSString *)systemPrompt {
    return @"You are a conservative security assistant. "
           "Use only the provided JSON input. Do not infer or add facts. "
           "Do not rescore or change risk_band. "
           "Return JSON only with keys: summary, risk_band, evidence_tags, tone. "
           "summary: 1 sentence, <= 160 chars, no speculation. "
           "risk_band must exactly match the input. "
           "evidence_tags must be chosen from: new_destination, rare_destination, "
           "vt_flagged, vt_clear, vt_unknown, asn_known, country_known, anomaly_high. "
           "If virustotal.total_scans is 0, treat as no reputation data and use vt_unknown.";
}

- (NSString *)riskBandForScore:(double)score
                         isNew:(BOOL)isNew
                        isRare:(BOOL)isRare
                  vtMalicious:(NSInteger)vtMalicious
                 vtSuspicious:(NSInteger)vtSuspicious {
    if (vtMalicious > 0 || vtSuspicious >= 3) {
        return SNBRiskBandHigherRisk;
    }
    if (score >= SNBExplainHighScore && (isNew || isRare)) {
        return SNBRiskBandNeedsAttention;
    }
    if (score >= SNBExplainMediumScore || isNew || isRare || vtSuspicious > 0) {
        return SNBRiskBandNeedsAttention;
    }
    return SNBRiskBandLikelyBenign;
}

- (SNBAnomalyExplanation *)explanationFromOutput:(NSDictionary *)output
                                           input:(NSDictionary *)input {
    if (![output isKindOfClass:[NSDictionary class]]) {
        return nil;
    }

    NSString *summary = output[@"summary"];
    NSString *riskBand = output[@"risk_band"];
    NSArray *tags = output[@"evidence_tags"];
    NSString *tone = output[@"tone"];
    if (![summary isKindOfClass:[NSString class]] ||
        ![riskBand isKindOfClass:[NSString class]] ||
        ![tags isKindOfClass:[NSArray class]]) {
        return nil;
    }

    NSString *inputRiskBand = input[@"risk_band"];
    if ([inputRiskBand isKindOfClass:[NSString class]] && ![riskBand isEqualToString:inputRiskBand]) {
        riskBand = inputRiskBand;
    }

    NSSet<NSString *> *allowedTags = [self allowedEvidenceTags];
    NSMutableArray<NSString *> *filtered = [NSMutableArray array];
    for (id tag in tags) {
        if ([tag isKindOfClass:[NSString class]] && [allowedTags containsObject:tag]) {
            [filtered addObject:tag];
        }
    }

    if (filtered.count == 0) {
        filtered = [[self defaultEvidenceTagsForInput:input] mutableCopy];
    }

    SNBAnomalyExplanation *explanation = [[SNBAnomalyExplanation alloc] init];
    explanation.summary = [self trimmedSummary:summary];
    explanation.riskBand = riskBand;
    explanation.evidenceTags = [filtered copy];
    explanation.tone = ([tone isKindOfClass:[NSString class]] && tone.length > 0) ? tone : SNBExplainToneConservative;
    return explanation;
}

- (SNBAnomalyExplanation *)fallbackExplanationForInput:(NSDictionary *)input {
    NSString *ip = input[@"destination_ip"];
    NSString *riskBand = input[@"risk_band"];
    NSDictionary *evidence = input[@"evidence"];
    NSDictionary *novelty = evidence[@"novelty"];
    NSDictionary *vt = evidence[@"virustotal"];

    BOOL isNew = [novelty[@"is_new"] boolValue];
    NSInteger seenCount = [novelty[@"seen_count_30d"] integerValue];
    NSInteger vtMalicious = [vt[@"malicious"] integerValue];
    NSInteger vtSuspicious = [vt[@"suspicious"] integerValue];
    NSInteger vtTotal = [vt[@"total_scans"] integerValue];

    NSMutableArray<NSString *> *parts = [NSMutableArray array];
    if ([riskBand isEqualToString:SNBRiskBandHigherRisk]) {
        [parts addObject:@"Higher-risk anomaly"];
    } else if ([riskBand isEqualToString:SNBRiskBandNeedsAttention]) {
        [parts addObject:@"Anomalous activity"];
    } else {
        [parts addObject:@"Likely benign anomaly"];
    }

    if ([ip isKindOfClass:[NSString class]] && ip.length > 0) {
        [parts addObject:[NSString stringWithFormat:@"for %@", ip]];
    }

    if (isNew) {
        [parts addObject:@"new destination"];
    } else if (seenCount > 0 && seenCount < 3) {
        [parts addObject:@"rare destination"];
    }

    if (vtTotal == 0) {
        [parts addObject:@"no reputation data"];
    } else if (vtMalicious > 0 || vtSuspicious > 0) {
        [parts addObject:[NSString stringWithFormat:@"VirusTotal %ld/%ld flags",
                          (long)(vtMalicious + vtSuspicious), (long)vtTotal]];
    } else {
        [parts addObject:@"VirusTotal no detections"];
    }

    NSString *summary = [[parts componentsJoinedByString:@", "] stringByAppendingString:@"."];
    SNBAnomalyExplanation *explanation = [[SNBAnomalyExplanation alloc] init];
    explanation.summary = [self trimmedSummary:summary];
    explanation.riskBand = [riskBand isKindOfClass:[NSString class]] ? riskBand : SNBRiskBandNeedsAttention;
    explanation.evidenceTags = [self defaultEvidenceTagsForInput:input];
    explanation.tone = SNBExplainToneConservative;
    return explanation;
}

- (NSArray<NSString *> *)defaultEvidenceTagsForInput:(NSDictionary *)input {
    NSDictionary *evidence = input[@"evidence"];
    NSDictionary *novelty = evidence[@"novelty"];
    NSDictionary *vt = evidence[@"virustotal"];

    BOOL isNew = [novelty[@"is_new"] boolValue];
    NSInteger seenCount = [novelty[@"seen_count_30d"] integerValue];
    NSInteger vtMalicious = [vt[@"malicious"] integerValue];
    NSInteger vtSuspicious = [vt[@"suspicious"] integerValue];
    NSInteger vtTotal = [vt[@"total_scans"] integerValue];
    NSString *asn = evidence[@"asn"];
    NSString *country = evidence[@"country"];
    double score = [input[@"anomaly_score"] doubleValue];

    NSMutableArray<NSString *> *tags = [NSMutableArray array];
    if (isNew) {
        [tags addObject:@"new_destination"];
    } else if (seenCount > 0 && seenCount < 3) {
        [tags addObject:@"rare_destination"];
    }
    if (vtTotal == 0) {
        [tags addObject:@"vt_unknown"];
    } else if (vtMalicious > 0 || vtSuspicious > 0) {
        [tags addObject:@"vt_flagged"];
    } else {
        [tags addObject:@"vt_clear"];
    }
    if ([asn isKindOfClass:[NSString class]] && asn.length > 0) {
        [tags addObject:@"asn_known"];
    }
    if ([country isKindOfClass:[NSString class]] && country.length > 0) {
        [tags addObject:@"country_known"];
    }
    if (score >= SNBExplainHighScore) {
        [tags addObject:@"anomaly_high"];
    }
    return tags;
}

- (NSSet<NSString *> *)allowedEvidenceTags {
    static NSSet<NSString *> *allowed = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        allowed = [NSSet setWithArray:@[
            @"new_destination",
            @"rare_destination",
            @"vt_flagged",
            @"vt_clear",
            @"vt_unknown",
            @"asn_known",
            @"country_known",
            @"anomaly_high"
        ]];
    });
    return allowed;
}

- (NSString *)trimmedSummary:(NSString *)summary {
    if (![summary isKindOfClass:[NSString class]]) {
        return @"";
    }
    NSString *trimmed = [summary stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (trimmed.length <= 160) {
        return trimmed;
    }
    return [[trimmed substringToIndex:160] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
}

- (NSString *)iso8601StringFromDate:(NSDate *)date {
    if (!date) {
        return nil;
    }
    static NSDateFormatter *formatter = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        formatter = [[NSDateFormatter alloc] init];
        formatter.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
        formatter.timeZone = [NSTimeZone timeZoneWithAbbreviation:@"UTC"];
        formatter.dateFormat = @"yyyy-MM-dd'T'HH:mm:ss'Z'";
    });
    return [formatter stringFromDate:date];
}

@end

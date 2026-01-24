//
//  TrustFeatureExtractor.m
//  SniffNetBar
//

#import "TrustFeatureExtractor.h"
#import "TrustLearningModels.h"
#import "ThreatIntelModels.h"
#import "TrafficStatistics.h"

@implementation SNBTrustFeatureExtractor

- (SNBTrustFeatureVector *)featureVectorForIP:(NSString *)ipAddress
                                     response:(TIEnrichmentResponse *)response
                                   connection:(ConnectionTraffic *)connection
                                   totalBytes:(uint64_t)totalBytes
                              connectionCount:(NSInteger)connectionCount {
    SNBTrustFeatureVector *vector = [[SNBTrustFeatureVector alloc] init];
    vector.ipAddress = ipAddress;
    vector.bytesTransferred = totalBytes;
    vector.connectionCount = connectionCount;
    vector.connectionDuration = 0.0;

    if (connection) {
        vector.destinationPort = connection.destinationPort;
        vector.processName = connection.processName;
    }

    if (!response) {
        return vector;
    }

    for (TIResult *result in response.providerResults) {
        if (![result.providerName isKindOfClass:[NSString class]]) {
            continue;
        }
        NSString *provider = result.providerName;
        NSInteger confidence = result.verdict ? result.verdict.confidence : 0;
        NSDictionary *evidence = result.verdict.evidence;

        if ([provider isEqualToString:@"VirusTotal"]) {
            NSNumber *malicious = [evidence[@"malicious"] isKindOfClass:[NSNumber class]]
                ? evidence[@"malicious"] : nil;
            vector.virusTotalScore = malicious ? malicious.integerValue : confidence;
            if (!vector.country.length && [evidence[@"country"] isKindOfClass:[NSString class]]) {
                vector.country = evidence[@"country"];
            }
            if (!vector.asn.length && [evidence[@"asn"] isKindOfClass:[NSString class]]) {
                vector.asn = evidence[@"asn"];
            }
            if (!vector.organization.length && [evidence[@"as_owner"] isKindOfClass:[NSString class]]) {
                vector.organization = evidence[@"as_owner"];
            }
        } else if ([provider isEqualToString:@"AbuseIPDB"]) {
            NSNumber *abuseScore = [evidence[@"abuse_confidence_score"] isKindOfClass:[NSNumber class]]
                ? evidence[@"abuse_confidence_score"] : nil;
            vector.abuseIPDBScore = abuseScore ? abuseScore.integerValue : confidence;
            if (!vector.country.length && [evidence[@"country"] isKindOfClass:[NSString class]]) {
                vector.country = evidence[@"country"];
            }
            if (!vector.asn.length && [evidence[@"asn"] isKindOfClass:[NSString class]]) {
                vector.asn = evidence[@"asn"];
            }
            if (!vector.organization.length && [evidence[@"isp"] isKindOfClass:[NSString class]]) {
                vector.organization = evidence[@"isp"];
            }
        } else if ([provider isEqualToString:@"GreyNoise"]) {
            NSString *classification = nil;
            if ([evidence[@"code"] isKindOfClass:[NSString class]]) {
                classification = evidence[@"code"];
            } else if ([evidence[@"name"] isKindOfClass:[NSString class]]) {
                classification = evidence[@"name"];
            } else if (result.verdict.categories.count > 0) {
                classification = result.verdict.categories.firstObject;
            }
            vector.greyNoiseClassification = classification;
        } else if ([provider isEqualToString:@"Shodan"]) {
            NSNumber *portCount = [evidence[@"port_count"] isKindOfClass:[NSNumber class]] ? evidence[@"port_count"] : nil;
            if (portCount) {
                vector.shodanOpenPorts = portCount.integerValue;
            } else if ([evidence[@"ports"] isKindOfClass:[NSArray class]]) {
                vector.shodanOpenPorts = [evidence[@"ports"] count];
            }
            if (!vector.organization.length && [evidence[@"org"] isKindOfClass:[NSString class]]) {
                vector.organization = evidence[@"org"];
            }
        }
    }

    return vector;
}

@end

//
//  ThreatIntelModelsTests.m
//  SniffNetBar
//
//  Tests for ThreatIntel data models
//

#import <XCTest/XCTest.h>
#import "ThreatIntelModels.h"

@interface ThreatIntelModelsTests : XCTestCase
@end

@implementation ThreatIntelModelsTests

#pragma mark - TIIndicator Tests

- (void)testIndicatorInitialization {
    TIIndicator *indicator = [[TIIndicator alloc] initWithType:TIIndicatorTypeIPv4 value:@"192.168.1.1"];

    XCTAssertNotNil(indicator, @"Indicator should initialize");
    XCTAssertEqual(indicator.type, TIIndicatorTypeIPv4, @"Type should match");
    XCTAssertEqualObjects(indicator.value, @"192.168.1.1", @"Value should match");
}

- (void)testIndicatorWithIPv4 {
    TIIndicator *indicator = [TIIndicator indicatorWithIP:@"10.0.0.1"];

    XCTAssertNotNil(indicator, @"Should create IPv4 indicator");
    XCTAssertEqual(indicator.type, TIIndicatorTypeIPv4, @"Should detect IPv4");
    XCTAssertEqualObjects(indicator.value, @"10.0.0.1", @"Value should match");
}

- (void)testIndicatorWithIPv6 {
    TIIndicator *indicator = [TIIndicator indicatorWithIP:@"2001:db8::1"];

    XCTAssertNotNil(indicator, @"Should create IPv6 indicator");
    XCTAssertEqual(indicator.type, TIIndicatorTypeIPv6, @"Should detect IPv6");
    XCTAssertEqualObjects(indicator.value, @"2001:db8::1", @"Value should match");
}

- (void)testIndicatorWithDomain {
    TIIndicator *indicator = [TIIndicator indicatorWithDomain:@"example.com"];

    XCTAssertNotNil(indicator, @"Should create domain indicator");
    XCTAssertEqual(indicator.type, TIIndicatorTypeDomain, @"Should be domain type");
    XCTAssertEqualObjects(indicator.value, @"example.com", @"Value should match");
}

- (void)testIndicatorCopying {
    TIIndicator *original = [[TIIndicator alloc] initWithType:TIIndicatorTypeIPv4 value:@"192.168.1.1"];
    TIIndicator *copy = [original copy];

    XCTAssertNotNil(copy, @"Copy should not be nil");
    XCTAssertEqual(copy.type, original.type, @"Copy type should match");
    XCTAssertEqualObjects(copy.value, original.value, @"Copy value should match");
}

- (void)testIndicatorEquality {
    TIIndicator *indicator1 = [[TIIndicator alloc] initWithType:TIIndicatorTypeIPv4 value:@"192.168.1.1"];
    TIIndicator *indicator2 = [[TIIndicator alloc] initWithType:TIIndicatorTypeIPv4 value:@"192.168.1.1"];
    TIIndicator *indicator3 = [[TIIndicator alloc] initWithType:TIIndicatorTypeIPv4 value:@"192.168.1.2"];

    XCTAssertEqualObjects(indicator1, indicator2, @"Same indicators should be equal");
    XCTAssertNotEqualObjects(indicator1, indicator3, @"Different indicators should not be equal");
}

- (void)testIndicatorHashing {
    TIIndicator *indicator1 = [[TIIndicator alloc] initWithType:TIIndicatorTypeIPv4 value:@"192.168.1.1"];
    TIIndicator *indicator2 = [[TIIndicator alloc] initWithType:TIIndicatorTypeIPv4 value:@"192.168.1.1"];

    XCTAssertEqual([indicator1 hash], [indicator2 hash], @"Equal indicators should have same hash");
}

#pragma mark - TIVerdict Tests

- (void)testVerdictInitialization {
    TIVerdict *verdict = [[TIVerdict alloc] init];

    XCTAssertNotNil(verdict, @"Verdict should initialize");
    XCTAssertFalse(verdict.hit, @"Default hit should be NO");
    XCTAssertEqual(verdict.confidence, 0, @"Default confidence should be 0");
    XCTAssertNotNil(verdict.categories, @"Categories should not be nil");
    XCTAssertEqual(verdict.categories.count, 0, @"Default categories should be empty");
    XCTAssertNotNil(verdict.tags, @"Tags should not be nil");
    XCTAssertEqual(verdict.tags.count, 0, @"Default tags should be empty");
}

- (void)testVerdictProperties {
    TIVerdict *verdict = [[TIVerdict alloc] init];
    verdict.hit = YES;
    verdict.confidence = 85;
    verdict.categories = @[@"malware", @"botnet"];
    verdict.tags = @[@"zeus", @"banking"];
    verdict.lastSeen = [NSDate date];
    verdict.evidence = @{@"detections": @"15/70"};

    XCTAssertTrue(verdict.hit, @"Hit should be YES");
    XCTAssertEqual(verdict.confidence, 85, @"Confidence should match");
    XCTAssertEqual(verdict.categories.count, 2, @"Should have 2 categories");
    XCTAssertEqual(verdict.tags.count, 2, @"Should have 2 tags");
    XCTAssertNotNil(verdict.lastSeen, @"Last seen should be set");
    XCTAssertNotNil(verdict.evidence, @"Evidence should be set");
}

#pragma mark - TIMetadata Tests

- (void)testMetadataInitialization {
    TIMetadata *metadata = [[TIMetadata alloc] init];

    XCTAssertNotNil(metadata, @"Metadata should initialize");
    XCTAssertNotNil(metadata.fetchedAt, @"FetchedAt should be set");
    XCTAssertNotNil(metadata.expiresAt, @"ExpiresAt should be set");
    XCTAssertEqual(metadata.ttlSeconds, 3600, @"Default TTL should be 3600");
    XCTAssertEqual(metadata.rateLimitRemaining, -1, @"Default rate limit should be -1");
}

- (void)testMetadataExpiration {
    TIMetadata *metadata = [[TIMetadata alloc] init];
    metadata.ttlSeconds = 7200;
    metadata.expiresAt = [NSDate dateWithTimeIntervalSinceNow:7200];

    NSTimeInterval timeUntilExpiry = [metadata.expiresAt timeIntervalSinceNow];
    XCTAssertGreaterThan(timeUntilExpiry, 7100, @"Should not expire for ~2 hours");
    XCTAssertLessThan(timeUntilExpiry, 7300, @"Should expire in ~2 hours");
}

#pragma mark - TIResult Tests

- (void)testResultCreation {
    TIIndicator *indicator = [[TIIndicator alloc] initWithType:TIIndicatorTypeIPv4 value:@"1.2.3.4"];

    TIVerdict *verdict = [[TIVerdict alloc] init];
    verdict.hit = YES;
    verdict.confidence = 90;

    TIMetadata *metadata = [[TIMetadata alloc] init];

    TIResult *result = [[TIResult alloc] init];
    result.indicator = indicator;
    result.providerName = @"VirusTotal";
    result.verdict = verdict;
    result.metadata = metadata;

    XCTAssertNotNil(result, @"Result should be created");
    XCTAssertEqualObjects(result.providerName, @"VirusTotal", @"Provider name should match");
    XCTAssertEqualObjects(result.indicator.value, @"1.2.3.4", @"Indicator should match");
    XCTAssertTrue(result.verdict.hit, @"Verdict hit should be YES");
    XCTAssertNil(result.error, @"Error should be nil");
}

- (void)testResultWithError {
    TIResult *result = [[TIResult alloc] init];
    result.error = [NSError errorWithDomain:TIErrorDomain
                                        code:TIErrorCodeTimeout
                                    userInfo:@{NSLocalizedDescriptionKey: @"Request timed out"}];

    XCTAssertNotNil(result.error, @"Error should be set");
    XCTAssertEqualObjects(result.error.domain, TIErrorDomain, @"Error domain should match");
    XCTAssertEqual(result.error.code, TIErrorCodeTimeout, @"Error code should match");
}

#pragma mark - TIScoreBreakdown Tests

- (void)testScoreBreakdownCreation {
    TIScoreBreakdown *breakdown = [[TIScoreBreakdown alloc] init];
    breakdown.ruleName = @"HighConfidenceMalware";
    breakdown.ruleDescription = @"Multiple threat intel sources report malicious activity";
    breakdown.provider = @"VirusTotal";
    breakdown.scoreContribution = 75;
    breakdown.confidence = 90;
    breakdown.evidence = @{@"detections": @"45/70"};

    XCTAssertNotNil(breakdown, @"Breakdown should be created");
    XCTAssertEqualObjects(breakdown.ruleName, @"HighConfidenceMalware", @"Rule name should match");
    XCTAssertEqual(breakdown.scoreContribution, 75, @"Score contribution should match");
    XCTAssertEqual(breakdown.confidence, 90, @"Confidence should match");
}

#pragma mark - TIScoringResult Tests

- (void)testScoringResultCreation {
    TIIndicator *indicator = [[TIIndicator alloc] initWithType:TIIndicatorTypeIPv4 value:@"8.8.8.8"];

    TIScoringResult *scoring = [[TIScoringResult alloc] init];
    scoring.indicator = indicator;
    scoring.finalScore = 85;
    scoring.verdict = TIThreatVerdictMalicious;
    scoring.confidence = 0.90;
    scoring.evaluatedAt = [NSDate date];
    scoring.explanation = @"High confidence malicious based on multiple sources";

    XCTAssertNotNil(scoring, @"Scoring result should be created");
    XCTAssertEqual(scoring.finalScore, 85, @"Final score should match");
    XCTAssertEqual(scoring.verdict, TIThreatVerdictMalicious, @"Verdict should be malicious");
    XCTAssertEqualWithAccuracy(scoring.confidence, 0.90, 0.01, @"Confidence should match");
}

- (void)testVerdictStringMapping {
    TIScoringResult *scoring = [[TIScoringResult alloc] init];

    scoring.verdict = TIThreatVerdictClean;
    XCTAssertEqualObjects([scoring verdictString], @"Clean", @"Clean verdict string");

    scoring.verdict = TIThreatVerdictSuspicious;
    XCTAssertEqualObjects([scoring verdictString], @"Suspicious", @"Suspicious verdict string");

    scoring.verdict = TIThreatVerdictMalicious;
    XCTAssertEqualObjects([scoring verdictString], @"Malicious", @"Malicious verdict string");

    scoring.verdict = TIThreatVerdictUnknown;
    XCTAssertEqualObjects([scoring verdictString], @"Unknown", @"Unknown verdict string");
}

- (void)testVerdictColorMapping {
    TIScoringResult *scoring = [[TIScoringResult alloc] init];

    scoring.verdict = TIThreatVerdictClean;
    XCTAssertEqualObjects([scoring verdictColor], [NSColor systemGreenColor], @"Clean should be green");

    scoring.verdict = TIThreatVerdictSuspicious;
    XCTAssertEqualObjects([scoring verdictColor], [NSColor systemOrangeColor], @"Suspicious should be orange");

    scoring.verdict = TIThreatVerdictMalicious;
    XCTAssertEqualObjects([scoring verdictColor], [NSColor systemRedColor], @"Malicious should be red");

    scoring.verdict = TIThreatVerdictUnknown;
    XCTAssertEqualObjects([scoring verdictColor], [NSColor systemGrayColor], @"Unknown should be gray");
}

#pragma mark - TIEnrichmentResponse Tests

- (void)testEnrichmentResponseCreation {
    TIIndicator *indicator = [[TIIndicator alloc] initWithType:TIIndicatorTypeIPv4 value:@"1.1.1.1"];

    TIResult *result1 = [[TIResult alloc] init];
    result1.providerName = @"VirusTotal";
    result1.indicator = indicator;
    result1.verdict = [[TIVerdict alloc] init];
    result1.metadata = [[TIMetadata alloc] init];

    TIResult *result2 = [[TIResult alloc] init];
    result2.providerName = @"AbuseIPDB";
    result2.indicator = indicator;
    result2.verdict = [[TIVerdict alloc] init];
    result2.metadata = [[TIMetadata alloc] init];

    TIScoringResult *scoring = [[TIScoringResult alloc] init];
    scoring.indicator = indicator;
    scoring.finalScore = 50;
    scoring.verdict = TIThreatVerdictSuspicious;

    TIEnrichmentResponse *enrichment = [[TIEnrichmentResponse alloc] init];
    enrichment.indicator = indicator;
    enrichment.providerResults = @[result1, result2];
    enrichment.scoringResult = scoring;
    enrichment.duration = 1.5;
    enrichment.cacheHits = 1;

    XCTAssertNotNil(enrichment, @"Enrichment response should be created");
    XCTAssertEqual(enrichment.providerResults.count, 2, @"Should have 2 provider results");
    XCTAssertNotNil(enrichment.scoringResult, @"Should have scoring result");
    XCTAssertEqualWithAccuracy(enrichment.duration, 1.5, 0.01, @"Duration should match");
    XCTAssertEqual(enrichment.cacheHits, 1, @"Cache hits should match");
}

#pragma mark - Error Domain Tests

- (void)testErrorDomain {
    XCTAssertNotNil(TIErrorDomain, @"Error domain should be defined");
    XCTAssertEqualObjects(TIErrorDomain, @"com.sniffnetbar.threatintel", @"Error domain should match");
}

- (void)testErrorCodes {
    NSError *error1 = [NSError errorWithDomain:TIErrorDomain code:TIErrorCodeTimeout userInfo:nil];
    XCTAssertEqual(error1.code, TIErrorCodeTimeout, @"Timeout error code");

    NSError *error2 = [NSError errorWithDomain:TIErrorDomain code:TIErrorCodeQuotaExceeded userInfo:nil];
    XCTAssertEqual(error2.code, TIErrorCodeQuotaExceeded, @"Quota exceeded error code");

    NSError *error3 = [NSError errorWithDomain:TIErrorDomain code:TIErrorCodeAuthenticationFailed userInfo:nil];
    XCTAssertEqual(error3.code, TIErrorCodeAuthenticationFailed, @"Auth failed error code");

    NSError *error4 = [NSError errorWithDomain:TIErrorDomain code:TIErrorCodeNetworkError userInfo:nil];
    XCTAssertEqual(error4.code, TIErrorCodeNetworkError, @"Network error code");

    NSError *error5 = [NSError errorWithDomain:TIErrorDomain code:TIErrorCodeUnsupportedIndicatorType userInfo:nil];
    XCTAssertEqual(error5.code, TIErrorCodeUnsupportedIndicatorType, @"Unsupported indicator type error code");

    NSError *error6 = [NSError errorWithDomain:TIErrorDomain code:TIErrorCodeProviderUnavailable userInfo:nil];
    XCTAssertEqual(error6.code, TIErrorCodeProviderUnavailable, @"Provider unavailable error code");

    NSError *error7 = [NSError errorWithDomain:TIErrorDomain code:TIErrorCodeRateLimited userInfo:nil];
    XCTAssertEqual(error7.code, TIErrorCodeRateLimited, @"Rate limited error code");
}

@end

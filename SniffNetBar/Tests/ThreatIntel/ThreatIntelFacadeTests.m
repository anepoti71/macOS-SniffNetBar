//
//  ThreatIntelFacadeTests.m
//  SniffNetBar
//
//  Tests for ThreatIntelFacade
//

#import <XCTest/XCTest.h>
#import "ThreatIntelFacade.h"
#import "ThreatIntelModels.h"
#import "MockThreatIntelProvider.h"

@interface ThreatIntelFacadeTests : XCTestCase
@property (nonatomic, strong) ThreatIntelFacade *facade;
@property (nonatomic, strong) MockThreatIntelProvider *mockProvider1;
@property (nonatomic, strong) MockThreatIntelProvider *mockProvider2;
@end

@implementation ThreatIntelFacadeTests

- (void)setUp {
    [super setUp];

    // Create fresh facade instance for each test
    self.facade = [[ThreatIntelFacade alloc] init];
    self.facade.enabled = YES;

    // Create mock providers
    self.mockProvider1 = [[MockThreatIntelProvider alloc] initWithName:@"MockProvider1"];
    self.mockProvider2 = [[MockThreatIntelProvider alloc] initWithName:@"MockProvider2"];
}

- (void)tearDown {
    [self.facade clearCache];
    [self.facade shutdown];
    self.facade = nil;
    self.mockProvider1 = nil;
    self.mockProvider2 = nil;
    [super tearDown];
}

#pragma mark - Basic Configuration Tests

- (void)testFacadeInitialization {
    XCTAssertNotNil(self.facade, @"Facade should initialize");
    XCTAssertTrue(self.facade.isEnabled, @"Facade should be enabled");
}

- (void)testAddProvider {
    [self.facade addProvider:self.mockProvider1];

    // Verify by enriching an indicator
    TIIndicator *indicator = [[TIIndicator alloc] initWithType:TIIndicatorTypeIPv4 value:@"1.2.3.4"];
    [self.mockProvider1 setMockScore:75 forIndicatorValue:@"1.2.3.4"];

    XCTestExpectation *expectation = [self expectationWithDescription:@"Enrichment complete"];

    [self.facade enrichIndicator:indicator completion:^(TIEnrichmentResponse *response, NSError *error) {
        XCTAssertNil(error, @"Should not have error");
        XCTAssertNotNil(response, @"Should have response");
        XCTAssertEqual(response.providerResults.count, 1, @"Should have 1 provider result");
        [expectation fulfill];
    }];

    [self waitForExpectationsWithTimeout:2.0 handler:nil];
}

- (void)testConfigureWithProviders {
    [self.facade configureWithProviders:@[self.mockProvider1, self.mockProvider2]];

    // Verify by enriching an indicator
    TIIndicator *indicator = [[TIIndicator alloc] initWithType:TIIndicatorTypeIPv4 value:@"1.2.3.4"];
    [self.mockProvider1 setMockScore:75 forIndicatorValue:@"1.2.3.4"];
    [self.mockProvider2 setMockScore:80 forIndicatorValue:@"1.2.3.4"];

    XCTestExpectation *expectation = [self expectationWithDescription:@"Enrichment complete"];

    [self.facade enrichIndicator:indicator completion:^(TIEnrichmentResponse *response, NSError *error) {
        XCTAssertNil(error, @"Should not have error");
        XCTAssertNotNil(response, @"Should have response");
        XCTAssertEqual(response.providerResults.count, 2, @"Should have 2 provider results");
        [expectation fulfill];
    }];

    [self waitForExpectationsWithTimeout:2.0 handler:nil];
}

#pragma mark - Enrichment Tests

- (void)testEnrichIndicator {
    [self.facade addProvider:self.mockProvider1];
    [self.mockProvider1 setMockScore:85 forIndicatorValue:@"8.8.8.8"];

    TIIndicator *indicator = [[TIIndicator alloc] initWithType:TIIndicatorTypeIPv4 value:@"8.8.8.8"];

    XCTestExpectation *expectation = [self expectationWithDescription:@"Enrichment complete"];

    [self.facade enrichIndicator:indicator completion:^(TIEnrichmentResponse *response, NSError *error) {
        XCTAssertNil(error, @"Should not have error");
        XCTAssertNotNil(response, @"Should have response");
        XCTAssertEqualObjects(response.indicator.value, @"8.8.8.8", @"Indicator should match");
        XCTAssertEqual(response.providerResults.count, 1, @"Should have 1 result");

        TIResult *result = response.providerResults.firstObject;
        XCTAssertEqualObjects(result.providerName, @"MockProvider1", @"Provider name should match");
        XCTAssertEqual(result.verdict.confidence, 85, @"Confidence should match");

        [expectation fulfill];
    }];

    [self waitForExpectationsWithTimeout:2.0 handler:nil];
}

- (void)testEnrichIP {
    [self.facade addProvider:self.mockProvider1];
    [self.mockProvider1 setMockScore:75 forIndicatorValue:@"1.1.1.1"];

    XCTestExpectation *expectation = [self expectationWithDescription:@"Enrichment complete"];

    [self.facade enrichIP:@"1.1.1.1" completion:^(TIEnrichmentResponse *response, NSError *error) {
        XCTAssertNil(error, @"Should not have error");
        XCTAssertNotNil(response, @"Should have response");
        XCTAssertEqual(response.indicator.type, TIIndicatorTypeIPv4, @"Should be IPv4");
        XCTAssertEqualObjects(response.indicator.value, @"1.1.1.1", @"IP should match");

        [expectation fulfill];
    }];

    [self waitForExpectationsWithTimeout:2.0 handler:nil];
}

- (void)testEnrichIPv6 {
    [self.facade addProvider:self.mockProvider1];
    [self.mockProvider1 setMockScore:60 forIndicatorValue:@"2001:db8::1"];

    XCTestExpectation *expectation = [self expectationWithDescription:@"Enrichment complete"];

    [self.facade enrichIP:@"2001:db8::1" completion:^(TIEnrichmentResponse *response, NSError *error) {
        XCTAssertNil(error, @"Should not have error");
        XCTAssertNotNil(response, @"Should have response");
        XCTAssertEqual(response.indicator.type, TIIndicatorTypeIPv6, @"Should be IPv6");

        [expectation fulfill];
    }];

    [self waitForExpectationsWithTimeout:2.0 handler:nil];
}

- (void)testEnrichWhenDisabled {
    self.facade.enabled = NO;
    [self.facade addProvider:self.mockProvider1];

    TIIndicator *indicator = [[TIIndicator alloc] initWithType:TIIndicatorTypeIPv4 value:@"1.2.3.4"];

    XCTestExpectation *expectation = [self expectationWithDescription:@"Enrichment complete"];

    [self.facade enrichIndicator:indicator completion:^(TIEnrichmentResponse *response, NSError *error) {
        // When disabled, should return nil or error
        XCTAssertTrue(response == nil || error != nil, @"Should not enrich when disabled");
        [expectation fulfill];
    }];

    [self waitForExpectationsWithTimeout:2.0 handler:nil];
}

#pragma mark - Multi-Provider Tests

- (void)testMultipleProvidersEnrichment {
    [self.facade addProvider:self.mockProvider1];
    [self.facade addProvider:self.mockProvider2];

    [self.mockProvider1 setMockScore:70 forIndicatorValue:@"10.0.0.1"];
    [self.mockProvider2 setMockScore:80 forIndicatorValue:@"10.0.0.1"];

    TIIndicator *indicator = [[TIIndicator alloc] initWithType:TIIndicatorTypeIPv4 value:@"10.0.0.1"];

    XCTestExpectation *expectation = [self expectationWithDescription:@"Enrichment complete"];

    [self.facade enrichIndicator:indicator completion:^(TIEnrichmentResponse *response, NSError *error) {
        XCTAssertNil(error, @"Should not have error");
        XCTAssertNotNil(response, @"Should have response");
        XCTAssertEqual(response.providerResults.count, 2, @"Should have results from both providers");

        // Verify both providers were called
        XCTAssertEqual(self.mockProvider1.callCount, 1, @"Provider1 should be called once");
        XCTAssertEqual(self.mockProvider2.callCount, 1, @"Provider2 should be called once");

        [expectation fulfill];
    }];

    [self waitForExpectationsWithTimeout:2.0 handler:nil];
}

- (void)testPartialProviderFailure {
    [self.facade addProvider:self.mockProvider1];
    [self.facade addProvider:self.mockProvider2];

    [self.mockProvider1 setMockScore:70 forIndicatorValue:@"10.0.0.1"];
    self.mockProvider2.shouldFail = YES;

    TIIndicator *indicator = [[TIIndicator alloc] initWithType:TIIndicatorTypeIPv4 value:@"10.0.0.1"];

    XCTestExpectation *expectation = [self expectationWithDescription:@"Enrichment complete"];

    [self.facade enrichIndicator:indicator completion:^(TIEnrichmentResponse *response, NSError *error) {
        // Facade should still return results from successful provider
        XCTAssertNotNil(response, @"Should have response even with partial failure");

        // At least one provider should have succeeded
        BOOL hasSuccessfulResult = NO;
        for (TIResult *result in response.providerResults) {
            if (!result.error) {
                hasSuccessfulResult = YES;
                break;
            }
        }
        XCTAssertTrue(hasSuccessfulResult, @"Should have at least one successful result");

        [expectation fulfill];
    }];

    [self waitForExpectationsWithTimeout:2.0 handler:nil];
}

#pragma mark - Batch Enrichment Tests

- (void)testEnrichMultipleIndicators {
    [self.facade addProvider:self.mockProvider1];

    [self.mockProvider1 setMockScore:70 forIndicatorValue:@"1.1.1.1"];
    [self.mockProvider1 setMockScore:80 forIndicatorValue:@"8.8.8.8"];
    [self.mockProvider1 setMockScore:90 forIndicatorValue:@"9.9.9.9"];

    TIIndicator *indicator1 = [[TIIndicator alloc] initWithType:TIIndicatorTypeIPv4 value:@"1.1.1.1"];
    TIIndicator *indicator2 = [[TIIndicator alloc] initWithType:TIIndicatorTypeIPv4 value:@"8.8.8.8"];
    TIIndicator *indicator3 = [[TIIndicator alloc] initWithType:TIIndicatorTypeIPv4 value:@"9.9.9.9"];

    NSArray *indicators = @[indicator1, indicator2, indicator3];

    XCTestExpectation *expectation = [self expectationWithDescription:@"Batch enrichment complete"];

    [self.facade enrichIndicators:indicators completion:^(NSArray<TIEnrichmentResponse *> *responses) {
        XCTAssertNotNil(responses, @"Should have responses");
        XCTAssertEqual(responses.count, 3, @"Should have 3 responses");

        [expectation fulfill];
    }];

    [self waitForExpectationsWithTimeout:3.0 handler:nil];
}

#pragma mark - Cache Tests

- (void)testCacheStats {
    NSDictionary *stats = [self.facade cacheStats];
    XCTAssertNotNil(stats, @"Should return cache stats");
    XCTAssertTrue([stats isKindOfClass:[NSDictionary class]], @"Stats should be a dictionary");
}

- (void)testClearCache {
    [self.facade clearCache];

    NSDictionary *stats = [self.facade cacheStats];
    XCTAssertNotNil(stats, @"Should still return stats after clear");
}

#pragma mark - Performance Tests

- (void)testConcurrentEnrichment {
    [self.facade addProvider:self.mockProvider1];
    [self.mockProvider1 setMockScore:75 forIndicatorValue:@"1.2.3.4"];
    [self.mockProvider1 setMockScore:80 forIndicatorValue:@"5.6.7.8"];

    TIIndicator *indicator1 = [[TIIndicator alloc] initWithType:TIIndicatorTypeIPv4 value:@"1.2.3.4"];
    TIIndicator *indicator2 = [[TIIndicator alloc] initWithType:TIIndicatorTypeIPv4 value:@"5.6.7.8"];

    XCTestExpectation *expectation1 = [self expectationWithDescription:@"Enrichment 1"];
    XCTestExpectation *expectation2 = [self expectationWithDescription:@"Enrichment 2"];

    // Start both enrichments concurrently
    [self.facade enrichIndicator:indicator1 completion:^(TIEnrichmentResponse *response, NSError *error) {
        XCTAssertNotNil(response, @"Should have response 1");
        [expectation1 fulfill];
    }];

    [self.facade enrichIndicator:indicator2 completion:^(TIEnrichmentResponse *response, NSError *error) {
        XCTAssertNotNil(response, @"Should have response 2");
        [expectation2 fulfill];
    }];

    [self waitForExpectationsWithTimeout:3.0 handler:nil];
}

@end

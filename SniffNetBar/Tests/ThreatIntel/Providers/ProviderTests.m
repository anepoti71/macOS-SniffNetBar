//
//  ProviderTests.m
//  SniffNetBar
//
//  Tests for ThreatIntel providers
//

#import <XCTest/XCTest.h>
#import "VirusTotalProvider.h"
#import "AbuseIPDBProvider.h"
#import "GreyNoiseProvider.h"
#import "ShodanProvider.h"
#import "ThreatIntelModels.h"

@interface ProviderTests : XCTestCase
@property (nonatomic, strong) VirusTotalProvider *vtProvider;
@property (nonatomic, strong) AbuseIPDBProvider *abuseProvider;
@property (nonatomic, strong) GreyNoiseProvider *greyNoiseProvider;
@property (nonatomic, strong) ShodanProvider *shodanProvider;
@end

@implementation ProviderTests

- (void)setUp {
    [super setUp];
    self.vtProvider = [[VirusTotalProvider alloc] initWithTTL:3600 negativeTTL:300];
    self.abuseProvider = [[AbuseIPDBProvider alloc] initWithTTL:3600
                                                     negativeTTL:300
                                                   maxAgeInDays:90];
    self.greyNoiseProvider = [[GreyNoiseProvider alloc] initWithTTL:3600 negativeTTL:300];
    self.shodanProvider = [[ShodanProvider alloc] initWithTTL:3600 negativeTTL:300];
}

- (void)tearDown {
    self.vtProvider = nil;
    self.abuseProvider = nil;
    self.greyNoiseProvider = nil;
    self.shodanProvider = nil;
    [super tearDown];
}

#pragma mark - VirusTotal Provider Tests

- (void)testVirusTotalProviderInitialization {
    XCTAssertNotNil(self.vtProvider, @"VirusTotal provider should initialize");
    XCTAssertEqualObjects(self.vtProvider.name, @"VirusTotal", @"Provider name should be VirusTotal");
    XCTAssertEqual(self.vtProvider.defaultTTL, 3600, @"Default TTL should match");
    XCTAssertEqual(self.vtProvider.negativeCacheTTL, 300, @"Negative cache TTL should match");
}

- (void)testVirusTotalConfiguration {
    XCTestExpectation *expectation = [self expectationWithDescription:@"Configuration complete"];

    [self.vtProvider configureWithBaseURL:@"https://www.virustotal.com/api/v3"
                                   APIKey:@"test-api-key"
                                  timeout:10.0
                        maxRequestsPerMin:4
                               completion:^(NSError *error) {
        XCTAssertNil(error, @"Configuration should not error");
        [expectation fulfill];
    }];

    [self waitForExpectationsWithTimeout:1.0 handler:nil];
}

- (void)testVirusTotalSupportsIPv4 {
    BOOL supports = [self.vtProvider supportsIndicatorType:TIIndicatorTypeIPv4];
    XCTAssertTrue(supports, @"Should support IPv4");
}

- (void)testVirusTotalSupportsIPv6 {
    BOOL supports = [self.vtProvider supportsIndicatorType:TIIndicatorTypeIPv6];
    XCTAssertTrue(supports, @"Should support IPv6");
}

- (void)testVirusTotalDoesNotSupportDomain {
    BOOL supports = [self.vtProvider supportsIndicatorType:TIIndicatorTypeDomain];
    XCTAssertFalse(supports, @"Should not support Domain");
}

- (void)testVirusTotalHealthCheck {
    XCTestExpectation *expectation = [self expectationWithDescription:@"Health check complete"];

    [self.vtProvider isHealthyWithCompletion:^(BOOL healthy) {
        // Provider should be healthy by default
        XCTAssertTrue(healthy, @"Provider should be healthy");
        [expectation fulfill];
    }];

    [self waitForExpectationsWithTimeout:1.0 handler:nil];
}

#pragma mark - AbuseIPDB Provider Tests

- (void)testAbuseIPDBProviderInitialization {
    XCTAssertNotNil(self.abuseProvider, @"AbuseIPDB provider should initialize");
    XCTAssertEqualObjects(self.abuseProvider.name, @"AbuseIPDB", @"Provider name should be AbuseIPDB");
    XCTAssertEqual(self.abuseProvider.defaultTTL, 3600, @"Default TTL should match");
    XCTAssertEqual(self.abuseProvider.negativeCacheTTL, 300, @"Negative cache TTL should match");
}

- (void)testAbuseIPDBConfiguration {
    XCTestExpectation *expectation = [self expectationWithDescription:@"Configuration complete"];

    [self.abuseProvider configureWithBaseURL:@"https://api.abuseipdb.com/api/v2"
                                      APIKey:@"test-api-key"
                                     timeout:10.0
                           maxRequestsPerMin:60
                                  completion:^(NSError *error) {
        XCTAssertNil(error, @"Configuration should not error");
        [expectation fulfill];
    }];

    [self waitForExpectationsWithTimeout:1.0 handler:nil];
}

- (void)testAbuseIPDBSupportsIPv4 {
    BOOL supports = [self.abuseProvider supportsIndicatorType:TIIndicatorTypeIPv4];
    XCTAssertTrue(supports, @"Should support IPv4");
}

- (void)testAbuseIPDBSupportsIPv6 {
    BOOL supports = [self.abuseProvider supportsIndicatorType:TIIndicatorTypeIPv6];
    XCTAssertTrue(supports, @"Should support IPv6");
}

- (void)testAbuseIPDBDoesNotSupportDomain {
    BOOL supports = [self.abuseProvider supportsIndicatorType:TIIndicatorTypeDomain];
    XCTAssertFalse(supports, @"Should not support Domain");
}

- (void)testAbuseIPDBHealthCheck {
    XCTestExpectation *expectation = [self expectationWithDescription:@"Health check complete"];

    [self.abuseProvider isHealthyWithCompletion:^(BOOL healthy) {
        // Provider should be healthy by default
        XCTAssertTrue(healthy, @"Provider should be healthy");
        [expectation fulfill];
    }];

    [self waitForExpectationsWithTimeout:1.0 handler:nil];
}

#pragma mark - GreyNoise Provider Tests

- (void)testGreyNoiseProviderInitialization {
    XCTAssertNotNil(self.greyNoiseProvider, @"GreyNoise provider should initialize");
    XCTAssertEqualObjects(self.greyNoiseProvider.name, @"GreyNoise", @"Provider name should be GreyNoise");
    XCTAssertEqual(self.greyNoiseProvider.defaultTTL, 3600, @"Default TTL should match");
    XCTAssertEqual(self.greyNoiseProvider.negativeCacheTTL, 300, @"Negative cache TTL should match");
}

- (void)testGreyNoiseConfiguration {
    XCTestExpectation *expectation = [self expectationWithDescription:@"Configuration complete"];

    [self.greyNoiseProvider configureWithBaseURL:@"https://api.greynoise.io/v3"
                                          APIKey:@"test-api-key"
                                         timeout:10.0
                               maxRequestsPerMin:60
                                      completion:^(NSError *error) {
        XCTAssertNil(error, @"Configuration should not error");
        [expectation fulfill];
    }];

    [self waitForExpectationsWithTimeout:1.0 handler:nil];
}

- (void)testGreyNoiseSupportsIPv4 {
    BOOL supports = [self.greyNoiseProvider supportsIndicatorType:TIIndicatorTypeIPv4];
    XCTAssertTrue(supports, @"Should support IPv4");
}

- (void)testGreyNoiseDoesNotSupportIPv6 {
    BOOL supports = [self.greyNoiseProvider supportsIndicatorType:TIIndicatorTypeIPv6];
    XCTAssertFalse(supports, @"Should not support IPv6");
}

- (void)testGreyNoiseDoesNotSupportDomain {
    BOOL supports = [self.greyNoiseProvider supportsIndicatorType:TIIndicatorTypeDomain];
    XCTAssertFalse(supports, @"Should not support Domain");
}

- (void)testGreyNoiseHealthCheck {
    XCTestExpectation *expectation = [self expectationWithDescription:@"Health check complete"];

    [self.greyNoiseProvider isHealthyWithCompletion:^(BOOL healthy) {
        XCTAssertTrue(healthy, @"Provider should be healthy");
        [expectation fulfill];
    }];

    [self waitForExpectationsWithTimeout:1.0 handler:nil];
}

#pragma mark - Shodan Provider Tests

- (void)testShodanProviderInitialization {
    XCTAssertNotNil(self.shodanProvider, @"Shodan provider should initialize");
    XCTAssertEqualObjects(self.shodanProvider.name, @"Shodan", @"Provider name should be Shodan");
    XCTAssertEqual(self.shodanProvider.defaultTTL, 3600, @"Default TTL should match");
    XCTAssertEqual(self.shodanProvider.negativeCacheTTL, 300, @"Negative cache TTL should match");
}

- (void)testShodanConfiguration {
    XCTestExpectation *expectation = [self expectationWithDescription:@"Configuration complete"];

    [self.shodanProvider configureWithBaseURL:@"https://api.shodan.io"
                                       APIKey:@"test-api-key"
                                      timeout:10.0
                            maxRequestsPerMin:60
                                   completion:^(NSError *error) {
        XCTAssertNil(error, @"Configuration should not error");
        [expectation fulfill];
    }];

    [self waitForExpectationsWithTimeout:1.0 handler:nil];
}

- (void)testShodanSupportsIPv4 {
    BOOL supports = [self.shodanProvider supportsIndicatorType:TIIndicatorTypeIPv4];
    XCTAssertTrue(supports, @"Should support IPv4");
}

- (void)testShodanSupportsIPv6 {
    BOOL supports = [self.shodanProvider supportsIndicatorType:TIIndicatorTypeIPv6];
    XCTAssertTrue(supports, @"Should support IPv6");
}

- (void)testShodanDoesNotSupportDomain {
    BOOL supports = [self.shodanProvider supportsIndicatorType:TIIndicatorTypeDomain];
    XCTAssertFalse(supports, @"Should not support Domain");
}

- (void)testShodanHealthCheck {
    XCTestExpectation *expectation = [self expectationWithDescription:@"Health check complete"];

    [self.shodanProvider isHealthyWithCompletion:^(BOOL healthy) {
        XCTAssertTrue(healthy, @"Provider should be healthy");
        [expectation fulfill];
    }];

    [self waitForExpectationsWithTimeout:1.0 handler:nil];
}

#pragma mark - Custom Initialization Tests

- (void)testVirusTotalCustomTTL {
    VirusTotalProvider *provider = [[VirusTotalProvider alloc] initWithTTL:7200 negativeTTL:600];

    XCTAssertEqual(provider.defaultTTL, 7200, @"Custom TTL should be set");
    XCTAssertEqual(provider.negativeCacheTTL, 600, @"Custom negative TTL should be set");
}

- (void)testAbuseIPDBCustomParameters {
    AbuseIPDBProvider *provider = [[AbuseIPDBProvider alloc] initWithTTL:7200
                                                              negativeTTL:600
                                                            maxAgeInDays:30];

    XCTAssertEqual(provider.defaultTTL, 7200, @"Custom TTL should be set");
    XCTAssertEqual(provider.negativeCacheTTL, 600, @"Custom negative TTL should be set");
}

- (void)testGreyNoiseCustomTTL {
    GreyNoiseProvider *provider = [[GreyNoiseProvider alloc] initWithTTL:7200 negativeTTL:600];

    XCTAssertEqual(provider.defaultTTL, 7200, @"Custom TTL should be set");
    XCTAssertEqual(provider.negativeCacheTTL, 600, @"Custom negative TTL should be set");
}

#pragma mark - Indicator Type Support Tests

- (void)testProvidersSupportCommonTypes {
    // Both providers should support IP addresses
    NSArray *providers = @[self.vtProvider, self.abuseProvider];

    for (id<ThreatIntelProvider> provider in providers) {
        XCTAssertTrue([provider supportsIndicatorType:TIIndicatorTypeIPv4],
                     @"%@ should support IPv4", provider.name);
        XCTAssertTrue([provider supportsIndicatorType:TIIndicatorTypeIPv6],
                     @"%@ should support IPv6", provider.name);
        XCTAssertFalse([provider supportsIndicatorType:TIIndicatorTypeDomain],
                      @"%@ should not support Domain", provider.name);
        XCTAssertFalse([provider supportsIndicatorType:TIIndicatorTypeURL],
                      @"%@ should not support URL", provider.name);
    }
}

- (void)testGreyNoiseSupportsOnlyIPv4 {
    XCTAssertTrue([self.greyNoiseProvider supportsIndicatorType:TIIndicatorTypeIPv4],
                  @"GreyNoise should support IPv4");
    XCTAssertFalse([self.greyNoiseProvider supportsIndicatorType:TIIndicatorTypeIPv6],
                   @"GreyNoise should not support IPv6");
    XCTAssertFalse([self.greyNoiseProvider supportsIndicatorType:TIIndicatorTypeDomain],
                   @"GreyNoise should not support Domain");
    XCTAssertFalse([self.greyNoiseProvider supportsIndicatorType:TIIndicatorTypeURL],
                   @"GreyNoise should not support URL");
}

#pragma mark - Configuration URL Tests

- (void)testVirusTotalCustomBaseURL {
    XCTestExpectation *expectation = [self expectationWithDescription:@"Configuration complete"];

    [self.vtProvider configureWithBaseURL:@"https://custom.api.virustotal.com/v3"
                                   APIKey:@"test-key"
                                  timeout:15.0
                        maxRequestsPerMin:10
                               completion:^(NSError *error) {
        XCTAssertNil(error, @"Should configure with custom URL");
        [expectation fulfill];
    }];

    [self waitForExpectationsWithTimeout:1.0 handler:nil];
}

- (void)testAbuseIPDBCustomBaseURL {
    XCTestExpectation *expectation = [self expectationWithDescription:@"Configuration complete"];

    [self.abuseProvider configureWithBaseURL:@"https://custom.api.abuseipdb.com/v2"
                                      APIKey:@"test-key"
                                     timeout:15.0
                           maxRequestsPerMin:120
                                  completion:^(NSError *error) {
        XCTAssertNil(error, @"Should configure with custom URL");
        [expectation fulfill];
    }];

    [self waitForExpectationsWithTimeout:1.0 handler:nil];
}

- (void)testGreyNoiseCustomBaseURL {
    XCTestExpectation *expectation = [self expectationWithDescription:@"Configuration complete"];

    [self.greyNoiseProvider configureWithBaseURL:@"https://custom.api.greynoise.io/v3"
                                          APIKey:@"test-key"
                                         timeout:15.0
                               maxRequestsPerMin:120
                                      completion:^(NSError *error) {
        XCTAssertNil(error, @"Should configure with custom URL");
        [expectation fulfill];
    }];

    [self waitForExpectationsWithTimeout:1.0 handler:nil];
}

@end

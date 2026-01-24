//
//  ThreatIntelCacheTests.m
//  SniffNetBar
//
//  Tests for ThreatIntelCache functionality
//

#import <XCTest/XCTest.h>
#import "ThreatIntelCache.h"
#import "ThreatIntelModels.h"

@interface ThreatIntelCacheTests : XCTestCase
@property (nonatomic, strong) ThreatIntelCache *cache;
@property (nonatomic, strong) TIIndicator *testIndicator;
@end

@implementation ThreatIntelCacheTests

- (void)setUp {
    [super setUp];
    self.cache = [[ThreatIntelCache alloc] initWithMaxSize:100];
    self.testIndicator = [[TIIndicator alloc] initWithType:TIIndicatorTypeIPv4
                                                      value:@"192.168.1.1"];
}

- (void)tearDown {
    [self.cache clear];
    [NSThread sleepForTimeInterval:0.1]; // Let async clear complete
    self.cache = nil;
    self.testIndicator = nil;
    [super tearDown];
}

- (TIResult *)createTestResultForProvider:(NSString *)provider
                                indicator:(TIIndicator *)indicator
                               confidence:(NSInteger)confidence
                               ttlSeconds:(NSTimeInterval)ttl {
    TIResult *result = [[TIResult alloc] init];
    result.providerName = provider;
    result.indicator = indicator;

    TIVerdict *verdict = [[TIVerdict alloc] init];
    verdict.hit = YES;
    verdict.confidence = confidence;
    verdict.categories = @[@"test"];
    result.verdict = verdict;

    TIMetadata *metadata = [[TIMetadata alloc] init];
    metadata.expiresAt = [NSDate dateWithTimeIntervalSinceNow:ttl];
    metadata.ttlSeconds = ttl;
    result.metadata = metadata;

    return result;
}

#pragma mark - Basic Cache Operations

- (void)testCacheInitialization {
    XCTAssertNotNil(self.cache, @"Cache should initialize");
    XCTAssertEqual([self.cache size], 0, @"New cache should be empty");
    XCTAssertEqual([self.cache hitRate], 0.0, @"New cache should have 0% hit rate");
}

- (void)testSetAndGetResult {
    // Create test result
    TIResult *result = [self createTestResultForProvider:@"TestProvider"
                                                indicator:self.testIndicator
                                               confidence:75
                                               ttlSeconds:3600];

    // Store result
    [self.cache setResult:result];

    // Give async operation time to complete
    [NSThread sleepForTimeInterval:0.1];

    // Retrieve result
    TIResult *cached = [self.cache getResultForProvider:@"TestProvider" indicator:self.testIndicator];

    XCTAssertNotNil(cached, @"Should retrieve cached result");
    XCTAssertEqual(cached.verdict.confidence, 75, @"Confidence should match");
    XCTAssertEqualObjects(cached.indicator.value, @"192.168.1.1", @"Indicator should match");
    XCTAssertEqual([self.cache size], 1, @"Cache should have one entry");
}

- (void)testGetNonExistentResult {
    TIResult *result = [self.cache getResultForProvider:@"NonExistent" indicator:self.testIndicator];
    XCTAssertNil(result, @"Should return nil for non-existent entry");
}

- (void)testCacheSizeTracking {
    // Add multiple results
    for (int i = 0; i < 5; i++) {
        TIIndicator *indicator = [[TIIndicator alloc] initWithType:TIIndicatorTypeIPv4
                                                              value:[NSString stringWithFormat:@"192.168.1.%d", i]];

        TIResult *result = [self createTestResultForProvider:@"TestProvider"
                                                    indicator:indicator
                                                   confidence:50
                                                   ttlSeconds:3600];
        [self.cache setResult:result];
    }

    // Give async operations time to complete
    [NSThread sleepForTimeInterval:0.1];

    XCTAssertEqual([self.cache size], 5, @"Cache should have 5 entries");
}

- (void)testCacheClear {
    // Add a result
    TIResult *result = [self createTestResultForProvider:@"TestProvider"
                                                indicator:self.testIndicator
                                               confidence:50
                                               ttlSeconds:3600];
    [self.cache setResult:result];
    [NSThread sleepForTimeInterval:0.1];

    XCTAssertEqual([self.cache size], 1, @"Cache should have one entry");

    // Clear cache
    [self.cache clear];
    [NSThread sleepForTimeInterval:0.1];

    XCTAssertEqual([self.cache size], 0, @"Cache should be empty after clear");

    TIResult *cached = [self.cache getResultForProvider:@"TestProvider" indicator:self.testIndicator];
    XCTAssertNil(cached, @"Should not retrieve cleared entry");
}

#pragma mark - TTL and Expiration Tests

- (void)testResultExpiration {
    // Create result with very short TTL
    TIResult *result = [self createTestResultForProvider:@"TestProvider"
                                                indicator:self.testIndicator
                                               confidence:50
                                               ttlSeconds:1];

    [self.cache setResult:result];
    [NSThread sleepForTimeInterval:0.1];

    // Should be available immediately
    TIResult *cached = [self.cache getResultForProvider:@"TestProvider" indicator:self.testIndicator];
    XCTAssertNotNil(cached, @"Should retrieve cached result immediately");

    // Wait for expiration
    [NSThread sleepForTimeInterval:1.5];

    // Should be expired
    cached = [self.cache getResultForProvider:@"TestProvider" indicator:self.testIndicator];
    XCTAssertNil(cached, @"Should not retrieve expired result");
}

- (void)testIsStaleDetection {
    // Create result with 10 second TTL
    TIResult *result = [self createTestResultForProvider:@"TestProvider"
                                                indicator:self.testIndicator
                                               confidence:50
                                               ttlSeconds:10];

    [self.cache setResult:result];
    [NSThread sleepForTimeInterval:0.1];

    // Should not be stale with 5 second refresh window (expires in 10s)
    BOOL isStale = [self.cache isStaleForProvider:@"TestProvider"
                                        indicator:self.testIndicator
                                   refreshWindow:5.0];
    XCTAssertFalse(isStale, @"Should not be stale immediately");

    // Wait 6 seconds (within refresh window)
    [NSThread sleepForTimeInterval:6.0];

    // Should be stale with 5 second refresh window (4 seconds remaining < 5 second window)
    isStale = [self.cache isStaleForProvider:@"TestProvider"
                                   indicator:self.testIndicator
                              refreshWindow:5.0];
    XCTAssertTrue(isStale, @"Should be stale within refresh window");
}

#pragma mark - Cache Eviction Tests

- (void)testCacheEvictionOnMaxSize {
    // Create cache with max size of 3
    ThreatIntelCache *smallCache = [[ThreatIntelCache alloc] initWithMaxSize:3];

    // Add 5 results
    NSMutableArray *indicators = [NSMutableArray array];
    for (int i = 0; i < 5; i++) {
        TIIndicator *indicator = [[TIIndicator alloc] initWithType:TIIndicatorTypeIPv4
                                                              value:[NSString stringWithFormat:@"192.168.1.%d", i]];
        [indicators addObject:indicator];

        TIResult *result = [self createTestResultForProvider:@"TestProvider"
                                                    indicator:indicator
                                                   confidence:50
                                                   ttlSeconds:3600];
        [smallCache setResult:result];

        // Small delay to ensure different timestamps
        [NSThread sleepForTimeInterval:0.05];
    }

    // Give time for evictions
    [NSThread sleepForTimeInterval:0.2];

    // Cache should not exceed max size
    XCTAssertLessThanOrEqual([smallCache size], 3, @"Cache should not exceed max size");

    // First entries should be evicted (LRU)
    TIResult *firstResult = [smallCache getResultForProvider:@"TestProvider" indicator:indicators[0]];
    XCTAssertNil(firstResult, @"Oldest entry should be evicted");

    // Most recent entries should still be cached
    TIResult *lastResult = [smallCache getResultForProvider:@"TestProvider" indicator:indicators[4]];
    XCTAssertNotNil(lastResult, @"Most recent entry should still be cached");
}

#pragma mark - Invalidation Tests

- (void)testInvalidateSpecificEntry {
    // Add two results from different providers
    TIResult *result1 = [self createTestResultForProvider:@"Provider1"
                                                indicator:self.testIndicator
                                               confidence:50
                                               ttlSeconds:3600];

    TIResult *result2 = [self createTestResultForProvider:@"Provider2"
                                                indicator:self.testIndicator
                                               confidence:75
                                               ttlSeconds:3600];

    [self.cache setResult:result1];
    [self.cache setResult:result2];
    [NSThread sleepForTimeInterval:0.1];

    // Invalidate Provider1 result
    [self.cache invalidateProvider:@"Provider1" indicator:self.testIndicator];
    [NSThread sleepForTimeInterval:0.1];

    // Provider1 should be invalidated
    TIResult *cached1 = [self.cache getResultForProvider:@"Provider1" indicator:self.testIndicator];
    XCTAssertNil(cached1, @"Provider1 result should be invalidated");

    // Provider2 should still be cached
    TIResult *cached2 = [self.cache getResultForProvider:@"Provider2" indicator:self.testIndicator];
    XCTAssertNotNil(cached2, @"Provider2 result should still be cached");
}

- (void)testInvalidateAllEntriesForIndicator {
    // Add results from multiple providers for the same indicator
    for (int i = 0; i < 3; i++) {
        NSString *providerName = [NSString stringWithFormat:@"Provider%d", i];
        TIResult *result = [self createTestResultForProvider:providerName
                                                    indicator:self.testIndicator
                                                   confidence:50
                                                   ttlSeconds:3600];
        [self.cache setResult:result];
    }

    [NSThread sleepForTimeInterval:0.1];
    XCTAssertEqual([self.cache size], 3, @"Should have 3 cached results");

    // Invalidate all results for this indicator
    [self.cache invalidateProvider:nil indicator:self.testIndicator];
    [NSThread sleepForTimeInterval:0.1];

    // Cache should be cleared (invalidate with nil provider calls clear)
    XCTAssertEqual([self.cache size], 0, @"Cache should be empty after invalidating with nil provider");
}

#pragma mark - Hit Rate Tests

- (void)testHitRateCalculation {
    TIResult *result = [self createTestResultForProvider:@"TestProvider"
                                                indicator:self.testIndicator
                                               confidence:50
                                               ttlSeconds:3600];

    [self.cache setResult:result];
    [NSThread sleepForTimeInterval:0.1];

    // First hit
    [self.cache getResultForProvider:@"TestProvider" indicator:self.testIndicator];

    // Miss
    TIIndicator *differentIndicator = [[TIIndicator alloc] initWithType:TIIndicatorTypeIPv4
                                                                   value:@"10.0.0.1"];
    [self.cache getResultForProvider:@"TestProvider" indicator:differentIndicator];

    // Second hit
    [self.cache getResultForProvider:@"TestProvider" indicator:self.testIndicator];

    // Hit rate should be 2/3 = 0.666...
    double hitRate = [self.cache hitRate];
    XCTAssertEqualWithAccuracy(hitRate, 0.666, 0.01, @"Hit rate should be approximately 66.6%");
}

#pragma mark - Multiple Indicator Types

- (void)testDifferentIndicatorTypes {
    // IPv4
    TIIndicator *ipv4 = [[TIIndicator alloc] initWithType:TIIndicatorTypeIPv4 value:@"192.168.1.1"];
    // IPv6
    TIIndicator *ipv6 = [[TIIndicator alloc] initWithType:TIIndicatorTypeIPv6 value:@"2001:db8::1"];

    TIResult *result1 = [self createTestResultForProvider:@"TestProvider"
                                                indicator:ipv4
                                               confidence:50
                                               ttlSeconds:3600];
    TIResult *result2 = [self createTestResultForProvider:@"TestProvider"
                                                indicator:ipv6
                                               confidence:75
                                               ttlSeconds:3600];

    [self.cache setResult:result1];
    [self.cache setResult:result2];
    [NSThread sleepForTimeInterval:0.1];

    // Should be able to retrieve both
    TIResult *cached1 = [self.cache getResultForProvider:@"TestProvider" indicator:ipv4];
    TIResult *cached2 = [self.cache getResultForProvider:@"TestProvider" indicator:ipv6];

    XCTAssertNotNil(cached1, @"Should retrieve IPv4 result");
    XCTAssertNotNil(cached2, @"Should retrieve IPv6 result");
    XCTAssertEqual(cached1.verdict.confidence, 50, @"IPv4 confidence should match");
    XCTAssertEqual(cached2.verdict.confidence, 75, @"IPv6 confidence should match");
}

@end

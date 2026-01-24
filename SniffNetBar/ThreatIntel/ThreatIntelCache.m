//
//  ThreatIntelCache.m
//  SniffNetBar
//

#import "ThreatIntelCache.h"
#import "ConfigurationManager.h"
#import "Logger.h"

// Doubly-linked list node for O(1) LRU eviction
@interface TICacheEntry : NSObject
@property (nonatomic, strong) TIResult *result;
@property (nonatomic, copy) NSString *key;                  // Key for reverse lookup
@property (nonatomic, assign) NSTimeInterval cachedAt;      // More efficient than NSDate
@property (nonatomic, assign) NSTimeInterval expiresAt;     // More efficient than NSDate
@property (nonatomic, weak) TICacheEntry *prev;             // Previous in LRU list (more recent)
@property (nonatomic, strong) TICacheEntry *next;           // Next in LRU list (older)
@end

@implementation TICacheEntry
+ (instancetype)entryWithResult:(TIResult *)result key:(NSString *)key expiresAt:(NSDate *)expiresAt {
    TICacheEntry *entry = [[TICacheEntry alloc] init];
    NSTimeInterval now = [NSDate timeIntervalSinceReferenceDate];
    entry.result = result;
    entry.key = key;
    entry.cachedAt = now;
    entry.expiresAt = expiresAt ? [expiresAt timeIntervalSinceReferenceDate] : (now + 3600);
    return entry;
}
@end

@interface ThreatIntelCache ()
@property (nonatomic, strong) NSMutableDictionary<NSString *, TICacheEntry *> *cache;
@property (nonatomic, assign) NSInteger maxSize;
@property (nonatomic, assign) NSInteger hits;
@property (nonatomic, assign) NSInteger misses;
@property (nonatomic, strong) dispatch_queue_t cacheQueue;
@property (atomic, assign) NSInteger cachedSize;
@property (atomic, assign) double cachedHitRate;
@property (nonatomic, assign) BOOL statsDirty;  // Deferred stats update flag
// O(1) LRU tracking with doubly-linked list: head=most recent, tail=least recent
@property (nonatomic, strong) TICacheEntry *lruHead;
@property (nonatomic, strong) TICacheEntry *lruTail;
@end

@implementation ThreatIntelCache

- (instancetype)initWithMaxSize:(NSInteger)maxSize {
    self = [super init];
    if (self) {
        _maxSize = maxSize;
        _cache = [NSMutableDictionary dictionary];
        _hits = 0;
        _misses = 0;
        _cacheQueue = dispatch_queue_create("com.sniffnetbar.threatintel.cache", DISPATCH_QUEUE_SERIAL);
        _cachedSize = 0;
        _cachedHitRate = 0.0;
        _statsDirty = NO;
    }
    return self;
}

- (NSString *)keyForProvider:(NSString *)provider indicator:(TIIndicator *)indicator {
    return [NSString stringWithFormat:@"%@:%ld:%@", provider, (long)indicator.type, indicator.value];
}

- (TIResult *)getResultForProvider:(NSString *)provider indicator:(TIIndicator *)indicator {
    __block TIResult *result = nil;
    __block BOOL needsStatsUpdate = NO;

    dispatch_sync(self.cacheQueue, ^{
        NSString *key = [self keyForProvider:provider indicator:indicator];
        TICacheEntry *entry = self.cache[key];

        if (entry) {
            NSTimeInterval now = [NSDate timeIntervalSinceReferenceDate];

            // Check expiration using efficient time comparison
            if (now > entry.expiresAt) {
                // Expired, remove from cache and LRU list
                [self removeEntryFromLRUListLocked:entry];
                [self.cache removeObjectForKey:key];
                self.misses++;
                SNBLogThreatIntelDebug("Expired entry for %{" SNB_IP_PRIVACY "}@", key);
                needsStatsUpdate = YES;
                return;
            }

            // Valid entry - move to front of LRU list (O(1) operation)
            [self moveEntryToFrontLocked:entry];
            result = entry.result;
            self.hits++;
            SNBLogThreatIntelDebug("Hit for %{" SNB_IP_PRIVACY "}@", key);
        } else {
            self.misses++;
            SNBLogThreatIntelDebug("Miss for %{" SNB_IP_PRIVACY "}@", key);
        }
        needsStatsUpdate = YES;
    });

    // Update stats outside the critical section (atomic properties are thread-safe)
    if (needsStatsUpdate) {
        [self updateStatsAsync];
    }

    return result;
}

- (void)setResult:(TIResult *)result {
    dispatch_async(self.cacheQueue, ^{
        NSString *key = [self keyForProvider:result.providerName indicator:result.indicator];

        // Check if entry already exists
        TICacheEntry *existingEntry = self.cache[key];
        if (existingEntry) {
            // Update existing entry and move to front
            existingEntry.result = result;
            existingEntry.expiresAt = result.metadata.expiresAt ? [result.metadata.expiresAt timeIntervalSinceReferenceDate] : ([NSDate timeIntervalSinceReferenceDate] + 3600);
            [self moveEntryToFrontLocked:existingEntry];
        } else {
            // Create new entry
            TICacheEntry *entry = [TICacheEntry entryWithResult:result key:key expiresAt:result.metadata.expiresAt];
            self.cache[key] = entry;

            // Add to front of LRU list
            [self addEntryToFrontLocked:entry];

            // Evict LRU if over capacity (O(1) operation now)
            while ((NSInteger)self.cache.count > self.maxSize) {
                [self evictLRULocked];
            }
        }

        SNBLogThreatIntelDebug("Cached %{" SNB_IP_PRIVACY "}@ (expires in %.0f seconds)",
                              key, self.cache[key].expiresAt - self.cache[key].cachedAt);

        // Mark stats as dirty for batch update
        self.statsDirty = YES;
        [self updateStatsLockedIfNeeded];
    });
}

- (BOOL)isStaleForProvider:(NSString *)provider
                 indicator:(TIIndicator *)indicator
            refreshWindow:(NSTimeInterval)refreshWindow {
    __block BOOL isStale = YES;

    dispatch_sync(self.cacheQueue, ^{
        NSString *key = [self keyForProvider:provider indicator:indicator];
        TICacheEntry *entry = self.cache[key];

        if (entry) {
            NSTimeInterval now = [NSDate timeIntervalSinceReferenceDate];
            NSTimeInterval timeUntilExpiry = entry.expiresAt - now;
            isStale = timeUntilExpiry <= refreshWindow;
        }
    });

    return isStale;
}

- (void)invalidateProvider:(NSString *)provider indicator:(TIIndicator *)indicator {
    dispatch_async(self.cacheQueue, ^{
        if (provider && indicator) {
            NSString *key = [self keyForProvider:provider indicator:indicator];
            TICacheEntry *entry = self.cache[key];
            if (entry) {
                [self removeEntryFromLRUListLocked:entry];
                [self.cache removeObjectForKey:key];
            }
            SNBLogThreatIntelDebug("Invalidated %{" SNB_IP_PRIVACY "}@", key);
        } else if (provider) {
            // Remove all entries for provider
            NSString *prefix = [NSString stringWithFormat:@"%@:", provider];
            NSArray *keys = [self.cache allKeys];
            for (NSString *key in keys) {
                if ([key hasPrefix:prefix]) {
                    TICacheEntry *entry = self.cache[key];
                    if (entry) {
                        [self removeEntryFromLRUListLocked:entry];
                    }
                    [self.cache removeObjectForKey:key];
                }
            }
            SNBLogThreatIntelDebug("Invalidated all entries for provider %{public}@", provider);
        } else {
            // Clear all - reset LRU list
            [self.cache removeAllObjects];
            self.lruHead = nil;
            self.lruTail = nil;
            SNBLogThreatIntelDebug("Cleared all entries");
        }
        self.statsDirty = YES;
        [self updateStatsLockedIfNeeded];
    });
}

- (void)clear {
    dispatch_async(self.cacheQueue, ^{
        [self.cache removeAllObjects];
        self.lruHead = nil;
        self.lruTail = nil;
        self.hits = 0;
        self.misses = 0;
        SNBLogThreatIntelDebug("Cleared all entries");
        self.statsDirty = YES;
        [self updateStatsLockedIfNeeded];
    });
}

- (NSInteger)size {
    return self.cachedSize;
}

- (double)hitRate {
    return self.cachedHitRate;
}

/// Evicts the least recently used entry - O(1) using tail of linked list
- (void)evictLRULocked {
    if (!self.lruTail) {
        return;
    }

    TICacheEntry *lruEntry = self.lruTail;
    NSString *lruKey = lruEntry.key;

    [self removeEntryFromLRUListLocked:lruEntry];
    [self.cache removeObjectForKey:lruKey];
    SNBLogThreatIntelDebug("Evicted LRU entry %{" SNB_IP_PRIVACY "}@", lruKey);
}

#pragma mark - LRU List Management (O(1) operations)

/// Add entry to front of LRU list (most recently used)
- (void)addEntryToFrontLocked:(TICacheEntry *)entry {
    entry.prev = nil;
    entry.next = self.lruHead;

    if (self.lruHead) {
        self.lruHead.prev = entry;
    }
    self.lruHead = entry;

    if (!self.lruTail) {
        self.lruTail = entry;
    }
}

/// Remove entry from LRU list
- (void)removeEntryFromLRUListLocked:(TICacheEntry *)entry {
    if (!entry) return;

    if (entry.prev) {
        entry.prev.next = entry.next;
    } else {
        // Entry is head
        self.lruHead = entry.next;
    }

    if (entry.next) {
        entry.next.prev = entry.prev;
    } else {
        // Entry is tail
        self.lruTail = entry.prev;
    }

    entry.prev = nil;
    entry.next = nil;
}

/// Move entry to front of LRU list (called on cache hit)
- (void)moveEntryToFrontLocked:(TICacheEntry *)entry {
    if (entry == self.lruHead) {
        return; // Already at front
    }
    [self removeEntryFromLRUListLocked:entry];
    [self addEntryToFrontLocked:entry];
}

- (NSDictionary *)statsSnapshot {
    return @{
        @"size": @(self.cachedSize),
        @"hitRate": @(self.cachedHitRate)
    };
}

#pragma mark - Private Stats Management

/// Update stats asynchronously (called from outside sync block)
- (void)updateStatsAsync {
    dispatch_async(self.cacheQueue, ^{
        self.statsDirty = YES;
        [self updateStatsLockedIfNeeded];
    });
}

/// Update cached stats if dirty (must be called while holding cacheQueue)
- (void)updateStatsLockedIfNeeded {
    if (!self.statsDirty) {
        return;
    }
    NSInteger total = self.hits + self.misses;
    self.cachedSize = (NSInteger)self.cache.count;
    self.cachedHitRate = total > 0 ? (double)self.hits / (double)total : 0.0;
    self.statsDirty = NO;
}

@end

//
//  ExpiringCache.m
//  SniffNetBar
//

#import "ExpiringCache.h"

/// Cache entry wrapper with doubly-linked list pointers for O(1) LRU eviction
@interface SNBCacheEntry : NSObject
@property (nonatomic, strong) id value;
@property (nonatomic, strong) id key;                       // Key for reverse lookup
@property (nonatomic, assign) NSTimeInterval timestamp;     // Seconds since reference date
@property (nonatomic, weak) SNBCacheEntry *prev;            // Previous (more recent)
@property (nonatomic, strong) SNBCacheEntry *next;          // Next (older)
@end

@implementation SNBCacheEntry
+ (instancetype)entryWithValue:(id)value key:(id)key {
    SNBCacheEntry *entry = [[SNBCacheEntry alloc] init];
    entry.value = value;
    entry.key = key;
    entry.timestamp = [NSDate timeIntervalSinceReferenceDate];
    return entry;
}
@end

@interface SNBExpiringCache ()
@property (nonatomic, strong) NSMutableDictionary<id, SNBCacheEntry *> *entries;
@property (nonatomic, assign) NSUInteger maxSize;
@property (nonatomic, assign) NSTimeInterval expirationInterval;
@property (nonatomic, strong) dispatch_queue_t accessQueue;
// O(1) LRU tracking: head=most recent, tail=oldest
@property (nonatomic, strong) SNBCacheEntry *lruHead;
@property (nonatomic, strong) SNBCacheEntry *lruTail;
@end

@implementation SNBExpiringCache

- (instancetype)initWithMaxSize:(NSUInteger)maxSize
             expirationInterval:(NSTimeInterval)expirationInterval {
    self = [super init];
    if (self) {
        _entries = [NSMutableDictionary dictionary];
        _maxSize = maxSize;
        _expirationInterval = expirationInterval;
        _accessQueue = dispatch_queue_create("com.sniffnetbar.expiringcache", DISPATCH_QUEUE_SERIAL);
    }
    return self;
}

- (id)objectForKey:(id)key {
    if (!key) {
        return nil;
    }
    __block id result = nil;
    dispatch_sync(self.accessQueue, ^{
        SNBCacheEntry *entry = self.entries[key];
        if (!entry) {
            return;
        }
        // Check expiration using efficient time comparison
        if (self.expirationInterval > 0) {
            NSTimeInterval now = [NSDate timeIntervalSinceReferenceDate];
            if ((now - entry.timestamp) > self.expirationInterval) {
                // Expired - remove from both cache and LRU list
                [self removeEntryFromLRUListLocked:entry];
                [self.entries removeObjectForKey:key];
                return;
            }
        }
        // Move to front of LRU list on access (O(1) operation)
        [self moveEntryToFrontLocked:entry];
        result = entry.value;
    });
    return result;
}

- (void)setObject:(id)object forKey:(id)key {
    if (!key || !object) {
        return;
    }
    // Performance: Use dispatch_async for write operations to avoid blocking caller
    dispatch_async(self.accessQueue, ^{
        // Check if entry already exists
        SNBCacheEntry *existingEntry = self.entries[key];
        if (existingEntry) {
            // Update value and move to front
            existingEntry.value = object;
            existingEntry.timestamp = [NSDate timeIntervalSinceReferenceDate];
            [self moveEntryToFrontLocked:existingEntry];
        } else {
            // Create new entry and add to front of LRU list
            SNBCacheEntry *entry = [SNBCacheEntry entryWithValue:object key:key];
            self.entries[key] = entry;
            [self addEntryToFrontLocked:entry];

            // Evict oldest entries if over capacity (O(1) eviction now)
            while (self.maxSize > 0 && self.entries.count > self.maxSize) {
                [self evictOldestEntryLocked];
            }
        }
    });
}

- (void)removeObjectForKey:(id)key {
    if (!key) {
        return;
    }
    // Performance: Use dispatch_async for write operations to avoid blocking caller
    dispatch_async(self.accessQueue, ^{
        SNBCacheEntry *entry = self.entries[key];
        if (entry) {
            [self removeEntryFromLRUListLocked:entry];
            [self.entries removeObjectForKey:key];
        }
    });
}

- (void)removeAllObjects {
    // Performance: Use dispatch_async for write operations to avoid blocking caller
    dispatch_async(self.accessQueue, ^{
        [self.entries removeAllObjects];
        self.lruHead = nil;
        self.lruTail = nil;
    });
}

- (NSUInteger)cleanupAndReturnExpiredCount {
    __block NSUInteger expiredCount = 0;
    dispatch_sync(self.accessQueue, ^{
        NSTimeInterval now = [NSDate timeIntervalSinceReferenceDate];
        NSMutableArray<SNBCacheEntry *> *expiredEntries = [NSMutableArray array];

        // Single pass to find expired entries
        for (id key in self.entries) {
            SNBCacheEntry *entry = self.entries[key];
            if (self.expirationInterval > 0 &&
                (now - entry.timestamp) > self.expirationInterval) {
                [expiredEntries addObject:entry];
            }
        }

        // Remove expired entries from both cache and LRU list
        for (SNBCacheEntry *entry in expiredEntries) {
            [self removeEntryFromLRUListLocked:entry];
            [self.entries removeObjectForKey:entry.key];
        }
        expiredCount = expiredEntries.count;

        // Evict oldest entries if still over capacity (O(1) per eviction now)
        while (self.maxSize > 0 && self.entries.count > self.maxSize) {
            [self evictOldestEntryLocked];
        }
    });
    return expiredCount;
}

#pragma mark - Private (must be called while holding accessQueue)

/// Evicts the single oldest entry - O(1) using tail of linked list
- (void)evictOldestEntryLocked {
    if (!self.lruTail) {
        return;
    }

    SNBCacheEntry *lruEntry = self.lruTail;
    [self removeEntryFromLRUListLocked:lruEntry];
    [self.entries removeObjectForKey:lruEntry.key];
}

#pragma mark - LRU List Management (O(1) operations)

/// Add entry to front of LRU list (most recently used)
- (void)addEntryToFrontLocked:(SNBCacheEntry *)entry {
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
- (void)removeEntryFromLRUListLocked:(SNBCacheEntry *)entry {
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
- (void)moveEntryToFrontLocked:(SNBCacheEntry *)entry {
    if (entry == self.lruHead) {
        return; // Already at front
    }
    [self removeEntryFromLRUListLocked:entry];
    [self addEntryToFrontLocked:entry];
}

@end

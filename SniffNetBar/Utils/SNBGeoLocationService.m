//
//  SNBGeoLocationService.m
//  SniffNetBar
//

#import "SNBGeoLocationService.h"
#import "ConfigurationManager.h"
#import "SNBLocationStore.h"
#import "ExpiringCache.h"
#import "Logger.h"
#import "UserDefaultsKeys.h"

static const NSTimeInterval kFailedLookupRetryInterval = 1800.0;  // 30 minutes

@interface SNBGeoLocationService ()
@property (nonatomic, strong) SNBExpiringCache<NSString *, NSDictionary *> *locationCache;
@property (nonatomic, strong) SNBLocationStore *locationStore;
@property (nonatomic, strong) NSMutableSet<NSString *> *inFlightLookups;
@property (nonatomic, strong) NSMutableSet<NSString *> *failedLookups;
@property (nonatomic, strong) NSURLSession *session;
@property (nonatomic, assign) BOOL publicIPLookupInFlight;
@property (nonatomic, copy, readwrite) NSString *publicIPAddress;
@property (nonatomic, strong, readwrite, nullable) NSValue *publicIPCoordinate;
@property (nonatomic, strong) dispatch_semaphore_t geoLocationSemaphore;
@property (nonatomic, strong) NSDate *lastFailedLookupsReset;
@property (nonatomic, copy) NSSet<NSString *> *lastTargetIPSet;
@property (nonatomic, assign) NSUInteger failedLookupResetVersion;
@property (nonatomic, assign) NSUInteger lastLookupAttemptVersion;
@property (atomic, assign, readwrite) NSUInteger locationVersion;
@end

@implementation SNBGeoLocationService

static NSString *SNBLocationStoreDirectory(void) {
    NSArray<NSString *> *paths = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, YES);
    if (paths.count == 0) {
        return NSTemporaryDirectory();
    }
    NSString *dir = [paths.firstObject stringByAppendingPathComponent:@"SniffNetBar"];
    NSError *error = nil;
    [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:&error];
    if (error) {
        SNBLogUIDebug("Unable to create App Support dir: %s", error.localizedDescription.UTF8String);
        return NSTemporaryDirectory();
    }
    return dir;
}

- (instancetype)initWithProviderName:(NSString *)providerName {
    self = [super init];
    if (self) {
        _providerName = [providerName copy];
        ConfigurationManager *config = [ConfigurationManager sharedManager];
        _locationCache = [[SNBExpiringCache alloc] initWithMaxSize:config.maxLocationCacheSize
                                               expirationInterval:config.locationCacheExpirationTime];
        NSString *supportDir = SNBLocationStoreDirectory();
        NSString *dbPath = [supportDir stringByAppendingPathComponent:@"location_cache.sqlite"];
        _locationStore = [SNBLocationStore sharedStoreWithPath:dbPath
                                            expirationInterval:config.locationCacheExpirationTime];
        _inFlightLookups = [NSMutableSet set];
        _failedLookups = [NSMutableSet set];
        _geoLocationSemaphore = dispatch_semaphore_create(4);
        _session = [NSURLSession sessionWithConfiguration:[NSURLSessionConfiguration defaultSessionConfiguration]];
        _publicIPAddress = @"";
        _publicIPLookupInFlight = NO;
        _lastFailedLookupsReset = [NSDate date];
        _lastTargetIPSet = [NSSet set];
        _locationVersion = 0;
    }
    return self;
}

- (void)setProviderName:(NSString *)providerName {
    if ([_providerName isEqualToString:providerName]) {
        return;
    }
    _providerName = [providerName copy];
    [self.failedLookups removeAllObjects];
    [self.inFlightLookups removeAllObjects];
    self.failedLookupResetVersion += 1;
}

- (NSDictionary<NSString *, NSDictionary *> *)cachedLocationsForIPs:(NSArray<NSString *> *)ips {
    NSMutableDictionary<NSString *, NSDictionary *> *result = [NSMutableDictionary dictionary];
    for (NSString *ip in ips) {
        NSDictionary *value = [self locationForIP:ip];
        if (value) {
            result[ip] = value;
        }
    }
    return result;
}

- (NSDictionary *)locationForIP:(NSString *)ip {
    if (ip.length == 0) {
        return nil;
    }
    NSDictionary *cached = [self.locationCache objectForKey:ip];
    if (cached) {
        return cached;
    }
    cached = [self.locationStore locationForIP:ip];
    if (cached) {
        [self.locationCache setObject:cached forKey:ip];
        return cached;
    }
    return nil;
}

- (void)resolveTargetIPs:(NSSet<NSString *> *)targetIPs
              completion:(void (^)(NSString *ip, CLLocationCoordinate2D coord, BOOL success))completion {
    if (targetIPs.count == 0) {
        return;
    }
    NSSet<NSString *> *previousTargetSet = self.lastTargetIPSet ?: [NSSet set];
    NSMutableSet<NSString *> *lookupTargets = [NSMutableSet setWithSet:targetIPs];
    [lookupTargets minusSet:previousTargetSet];
    if (self.lastLookupAttemptVersion != self.failedLookupResetVersion) {
        [lookupTargets unionSet:targetIPs];
        self.lastLookupAttemptVersion = self.failedLookupResetVersion;
    }
    self.lastTargetIPSet = [targetIPs copy];

    BOOL canLookup = YES;
    if ([self.providerName isEqualToString:@"custom"]) {
        NSString *template = [[NSUserDefaults standardUserDefaults] stringForKey:SNBUserDefaultsKeyMapProviderURLTemplate];
        if (template.length == 0) {
            canLookup = NO;
        }
    }

    for (NSString *ip in lookupTargets) {
        NSDictionary *cached = [self locationForIP:ip];
        if (cached) {
            continue;
        }
        if (!canLookup || [self.inFlightLookups containsObject:ip] || [self.failedLookups containsObject:ip]) {
            continue;
        }

        [self.inFlightLookups addObject:ip];
        __weak typeof(self) weakSelf = self;
        [self fetchLocationForIP:ip completion:^(CLLocationCoordinate2D coord, BOOL success) {
            dispatch_async(dispatch_get_main_queue(), ^{
                __strong typeof(weakSelf) strongSelf = weakSelf;
                if (!strongSelf) {
                    return;
                }
                [strongSelf.inFlightLookups removeObject:ip];
                if (!success) {
                    [strongSelf.failedLookups addObject:ip];
                    if (completion) {
                        completion(ip, coord, NO);
                    }
                    return;
                }
                strongSelf.locationVersion += 1;
                if (completion) {
                    completion(ip, coord, YES);
                }
            });
        }];
    }
}

- (void)updatePublicIPIfNeededWithCompletion:(void (^)(BOOL updated))completion {
    if (self.publicIPLookupInFlight || self.publicIPAddress.length > 0) {
        if (completion) {
            completion(NO);
        }
        return;
    }

    self.publicIPLookupInFlight = YES;
    NSURL *url = [NSURL URLWithString:@"https://api.ipify.org?format=json"];
    if (!url) {
        self.publicIPLookupInFlight = NO;
        if (completion) {
            completion(NO);
        }
        return;
    }

    SNBLogUIDebug(" public IP lookup via %s", url.absoluteString.UTF8String);
    __weak typeof(self) weakSelf = self;
    NSURLSessionDataTask *task = [self.session dataTaskWithURL:url completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) {
            return;
        }
        if (error || !data) {
            SNBLogUIDebug(" public IP lookup failed: %s", error.localizedDescription.UTF8String);
            strongSelf.publicIPLookupInFlight = NO;
            if (completion) {
                completion(NO);
            }
            return;
        }

        NSError *jsonError;
        id json = [NSJSONSerialization JSONObjectWithData:data options:0 error:&jsonError];
        if (jsonError || ![json isKindOfClass:[NSDictionary class]]) {
            SNBLogUIDebug(" public IP JSON error: %s", jsonError.localizedDescription.UTF8String);
            strongSelf.publicIPLookupInFlight = NO;
            if (completion) {
                completion(NO);
            }
            return;
        }

        NSString *ip = json[@"ip"];
        if (ip.length == 0) {
            SNBLogUIDebug(" public IP missing in response");
            strongSelf.publicIPLookupInFlight = NO;
            if (completion) {
                completion(NO);
            }
            return;
        }

        SNBLogUIDebug(" public IP: %s", ip.UTF8String);
        strongSelf.publicIPAddress = ip;
        [strongSelf fetchLocationForIP:ip completion:^(CLLocationCoordinate2D coord, BOOL success) {
            dispatch_async(dispatch_get_main_queue(), ^{
                strongSelf.publicIPLookupInFlight = NO;
                if (!success) {
                    SNBLogUIDebug(" public IP geolocation failed: %s", ip.UTF8String);
                    if (completion) {
                        completion(NO);
                    }
                    return;
                }
                strongSelf.publicIPCoordinate = [NSValue valueWithBytes:&coord objCType:@encode(CLLocationCoordinate2D)];
                SNBLogUIDebug(" public IP located: %s => (%f, %f)", ip.UTF8String, coord.latitude, coord.longitude);
                strongSelf.locationVersion += 1;
                if (completion) {
                    completion(YES);
                }
            });
        }];
    }];
    [task resume];
}

- (void)performCacheCleanup {
    NSUInteger expiredCount = [self.locationCache cleanupAndReturnExpiredCount];
    if (expiredCount > 0) {
        SNBLogUIDebug("MapMenuView: Cleaned up %lu expired location cache entries", (unsigned long)expiredCount);
    }

    NSTimeInterval timeSinceReset = -[self.lastFailedLookupsReset timeIntervalSinceNow];
    if (timeSinceReset > kFailedLookupRetryInterval) {
        NSUInteger failedCount = self.failedLookups.count;
        if (failedCount > 0) {
            [self.failedLookups removeAllObjects];
            self.lastFailedLookupsReset = [NSDate date];
            self.failedLookupResetVersion += 1;
            SNBLogUIDebug("MapMenuView: Reset %lu failed lookups (retry after %.0f minutes)",
                         (unsigned long)failedCount, kFailedLookupRetryInterval / 60.0);
        }
    }

    [self.locationStore cleanupExpiredEntries];
}

- (void)fetchLocationForIP:(NSString *)ip completion:(void (^)(CLLocationCoordinate2D, BOOL))completion {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        dispatch_semaphore_wait(self.geoLocationSemaphore, DISPATCH_TIME_FOREVER);

        NSString *provider = self.providerName.length > 0 ? self.providerName : @"ipinfo.io";
        NSString *encodedIP = [ip stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet URLPathAllowedCharacterSet]];
        NSString *urlString = nil;

        if ([provider isEqualToString:@"ip-api.com"]) {
            urlString = [NSString stringWithFormat:@"https://ip-api.com/json/%@?fields=status,message,lat,lon,query,city,regionName,country,countryCode,isp,as", encodedIP];
        } else if ([provider isEqualToString:@"ipinfo.io"]) {
            NSString *token = [ConfigurationManager sharedManager].ipInfoAPIToken;
            NSString *encodedToken = token.length > 0 ? [token stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet URLQueryAllowedCharacterSet]] : @"";
            if (encodedToken.length > 0) {
                urlString = [NSString stringWithFormat:@"https://ipinfo.io/%@/json?token=%@", encodedIP, encodedToken];
            } else {
                urlString = [NSString stringWithFormat:@"https://ipinfo.io/%@/json", encodedIP];
            }
        } else {
            NSString *template = [[NSUserDefaults standardUserDefaults] stringForKey:SNBUserDefaultsKeyMapProviderURLTemplate];
            if (template.length == 0) {
                dispatch_semaphore_signal(self.geoLocationSemaphore);
                completion(kCLLocationCoordinate2DInvalid, NO);
                return;
            }
            urlString = [NSString stringWithFormat:template, encodedIP];
        }

        NSURL *url = [NSURL URLWithString:urlString];
        if (!url) {
            dispatch_semaphore_signal(self.geoLocationSemaphore);
            completion(kCLLocationCoordinate2DInvalid, NO);
            return;
        }

        SNBLogUIDebug(" lookup %s via %s", ip.UTF8String, urlString.UTF8String);

        NSURLSessionDataTask *task = [self.session dataTaskWithURL:url completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
            dispatch_semaphore_signal(self.geoLocationSemaphore);
            NSHTTPURLResponse *httpResponse = [response isKindOfClass:[NSHTTPURLResponse class]] ? (NSHTTPURLResponse *)response : nil;
            if (error || !data) {
                SNBLogUIDebug(" lookup failed for %s: %s", ip.UTF8String, error.localizedDescription.UTF8String);
                completion(kCLLocationCoordinate2DInvalid, NO);
                return;
            }
            if (httpResponse) {
                SNBLogUIDebug(" response %s status %ld", ip.UTF8String, (long)httpResponse.statusCode);
            }

            if ([provider isEqualToString:@"ip-api.com"] && httpResponse.statusCode == 403) {
                SNBLogUIDebug(" fallback to ipinfo.io for %s", ip.UTF8String);
                dispatch_async(dispatch_get_main_queue(), ^{
                    NSString *savedProvider = self.providerName;
                    self.providerName = @"ipinfo.io";
                    [self fetchLocationForIP:ip completion:completion];
                    self.providerName = savedProvider;
                });
                return;
            }

            NSError *jsonError;
            id json = [NSJSONSerialization JSONObjectWithData:data options:0 error:&jsonError];
            if (jsonError || ![json isKindOfClass:[NSDictionary class]]) {
                SNBLogUIDebug(" JSON error for %s: %s", ip.UTF8String, jsonError.localizedDescription.UTF8String);
                completion(kCLLocationCoordinate2DInvalid, NO);
                return;
            }

            NSDictionary *dict = (NSDictionary *)json;
            CLLocationDegrees lat = 0;
            CLLocationDegrees lon = 0;
            BOOL success = NO;
            NSString *name = nil;
            NSString *isp = nil;
            NSString *country = nil;
            NSString *asn = nil;

            if ([provider isEqualToString:@"ip-api.com"]) {
                NSString *status = dict[@"status"];
                if ([status isEqualToString:@"success"]) {
                    lat = [dict[@"lat"] doubleValue];
                    lon = [dict[@"lon"] doubleValue];
                    NSString *city = dict[@"city"];
                    NSString *region = dict[@"regionName"];
                    NSString *countryName = dict[@"country"];
                    NSString *countryCode = dict[@"countryCode"];
                    isp = dict[@"isp"];
                    asn = dict[@"as"];
                    NSMutableArray<NSString *> *parts = [NSMutableArray array];
                    if (city.length > 0) [parts addObject:city];
                    if (region.length > 0) [parts addObject:region];
                    if (countryName.length > 0) [parts addObject:countryName];
                    name = parts.count > 0 ? [parts componentsJoinedByString:@", "] : nil;
                    country = countryCode.length > 0 ? countryCode : countryName;
                    success = YES;
                }
            } else if ([provider isEqualToString:@"ipinfo.io"]) {
                NSString *loc = dict[@"loc"];
                NSArray<NSString *> *parts = [loc componentsSeparatedByString:@","];
                if (parts.count == 2) {
                    lat = [parts[0] doubleValue];
                    lon = [parts[1] doubleValue];
                    NSString *city = dict[@"city"];
                    NSString *region = dict[@"region"];
                    country = dict[@"country"];
                    NSString *org = dict[@"org"];
                    NSString *company = dict[@"company"];
                    if (org.length > 0) {
                        isp = org;
                    } else if (company.length > 0) {
                        isp = company;
                    }
                    asn = org.length > 0 ? org : company;
                    NSMutableArray<NSString *> *nameParts = [NSMutableArray array];
                    if (city.length > 0) [nameParts addObject:city];
                    if (region.length > 0) [nameParts addObject:region];
                    if (country.length > 0) [nameParts addObject:country];
                    name = nameParts.count > 0 ? [nameParts componentsJoinedByString:@", "] : nil;
                    success = YES;
                }
            } else {
                NSString *latKey = [[NSUserDefaults standardUserDefaults] stringForKey:SNBUserDefaultsKeyMapProviderLatKey] ?: @"lat";
                NSString *lonKey = [[NSUserDefaults standardUserDefaults] stringForKey:SNBUserDefaultsKeyMapProviderLonKey] ?: @"lon";
                id latValue = [dict valueForKeyPath:latKey];
                id lonValue = [dict valueForKeyPath:lonKey];
                if ([latValue respondsToSelector:@selector(doubleValue)] &&
                    [lonValue respondsToSelector:@selector(doubleValue)]) {
                    lat = [latValue doubleValue];
                    lon = [lonValue doubleValue];
                    success = YES;
                }
            }

            if (success) {
                SNBLogUIDebug(" location %s => (%f, %f)", ip.UTF8String, lat, lon);
                NSMutableDictionary *payload = [NSMutableDictionary dictionaryWithDictionary:@{@"lat": @(lat), @"lon": @(lon)}];
                if (name.length > 0) {
                    payload[@"name"] = name;
                }
                if (isp.length > 0) {
                    payload[@"isp"] = isp;
                }
                if (country.length > 0) {
                    payload[@"country"] = country;
                }
                if (asn.length > 0) {
                    payload[@"asn"] = asn;
                }
                dispatch_async(dispatch_get_main_queue(), ^{
                    [self.locationCache setObject:payload forKey:ip];
                    [self.locationStore storeLocation:payload forIP:ip];
                    completion(CLLocationCoordinate2DMake(lat, lon), YES);
                });
            } else {
                SNBLogUIDebug(" location missing for %s (%s)", ip.UTF8String, provider.UTF8String);
                completion(kCLLocationCoordinate2DInvalid, NO);
            }
        }];
        [task resume];
    });
}

@end

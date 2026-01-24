//
//  AdaptiveScoring.m
//  SniffNetBar
//

#import "AdaptiveScoring.h"
#import "TrustLearningModels.h"
#import "Config/UserDefaultsKeys.h"

static NSString *const SNBAdaptiveWeightVirusTotalKey = @"AdaptiveWeightVirusTotal";
static NSString *const SNBAdaptiveWeightAbuseIPDBKey = @"AdaptiveWeightAbuseIPDB";
static NSString *const SNBAdaptiveWeightGreyNoiseKey = @"AdaptiveWeightGreyNoise";
static NSString *const SNBAdaptiveWeightShodanKey = @"AdaptiveWeightShodan";

static const double SNBAdaptiveWeightMin = 0.2;
static const double SNBAdaptiveWeightMax = 2.0;

@interface SNBAdaptiveScoring ()
@property (nonatomic, assign) double virusTotalWeight;
@property (nonatomic, assign) double abuseIPDBWeight;
@property (nonatomic, assign) double greyNoiseWeight;
@property (nonatomic, assign) double shodanWeight;
@property (nonatomic, strong) dispatch_queue_t syncQueue;
@end

@implementation SNBAdaptiveScoring

+ (instancetype)sharedScoring {
    static SNBAdaptiveScoring *shared = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        shared = [[SNBAdaptiveScoring alloc] init];
    });
    return shared;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _syncQueue = dispatch_queue_create("com.sniffnetbar.adaptiveScoring", DISPATCH_QUEUE_SERIAL);
        [self loadWeights];
    }
    return self;
}

- (void)loadWeights {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    double vt = [defaults doubleForKey:SNBAdaptiveWeightVirusTotalKey];
    double abuse = [defaults doubleForKey:SNBAdaptiveWeightAbuseIPDBKey];
    double grey = [defaults doubleForKey:SNBAdaptiveWeightGreyNoiseKey];
    double shodan = [defaults doubleForKey:SNBAdaptiveWeightShodanKey];

    self.virusTotalWeight = vt > 0.0 ? vt : 1.0;
    self.abuseIPDBWeight = abuse > 0.0 ? abuse : 0.9;
    self.greyNoiseWeight = grey > 0.0 ? grey : 0.8;
    self.shodanWeight = shodan > 0.0 ? shodan : 0.7;
}

- (void)saveWeights {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    [defaults setDouble:self.virusTotalWeight forKey:SNBAdaptiveWeightVirusTotalKey];
    [defaults setDouble:self.abuseIPDBWeight forKey:SNBAdaptiveWeightAbuseIPDBKey];
    [defaults setDouble:self.greyNoiseWeight forKey:SNBAdaptiveWeightGreyNoiseKey];
    [defaults setDouble:self.shodanWeight forKey:SNBAdaptiveWeightShodanKey];
}

- (NSDictionary<NSString *, NSNumber *> *)providerWeights {
    __block NSDictionary<NSString *, NSNumber *> *weights = nil;
    dispatch_sync(self.syncQueue, ^{
        weights = @{
            @"VirusTotal": @(self.virusTotalWeight),
            @"AbuseIPDB": @(self.abuseIPDBWeight),
            @"GreyNoise": @(self.greyNoiseWeight),
            @"Shodan": @(self.shodanWeight)
        };
    });
    return weights;
}

- (double)adjustedWeight:(double)weight delta:(double)delta {
    double updated = weight + delta;
    if (updated < SNBAdaptiveWeightMin) {
        return SNBAdaptiveWeightMin;
    }
    if (updated > SNBAdaptiveWeightMax) {
        return SNBAdaptiveWeightMax;
    }
    return updated;
}

- (double)deltaForScore:(NSInteger)score trusted:(BOOL)trusted {
    double normalized = MIN(MAX((double)score / 100.0, 0.0), 1.0);
    double step = 0.05 * normalized;
    return trusted ? -step : step;
}

- (void)updateWeightsFromFeedback:(SNBTrustFeedback *)feedback {
    if (!feedback.featureVector) {
        return;
    }
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    BOOL adaptiveEnabled = [defaults boolForKey:SNBUserDefaultsKeyAdaptiveProviderWeights];
    if (!adaptiveEnabled) {
        return;
    }

    dispatch_async(self.syncQueue, ^{
        SNBTrustFeatureVector *vector = feedback.featureVector;
        if (vector.virusTotalScore > 0) {
            double delta = [self deltaForScore:vector.virusTotalScore trusted:feedback.trusted];
            self.virusTotalWeight = [self adjustedWeight:self.virusTotalWeight delta:delta];
        }
        if (vector.abuseIPDBScore > 0) {
            double delta = [self deltaForScore:vector.abuseIPDBScore trusted:feedback.trusted];
            self.abuseIPDBWeight = [self adjustedWeight:self.abuseIPDBWeight delta:delta];
        }
        if (vector.greyNoiseClassification.length > 0) {
            double delta = [self deltaForScore:50 trusted:feedback.trusted];
            self.greyNoiseWeight = [self adjustedWeight:self.greyNoiseWeight delta:delta];
        }
        if (vector.shodanOpenPorts > 0) {
            double delta = [self deltaForScore:MIN(vector.shodanOpenPorts * 10, 100) trusted:feedback.trusted];
            self.shodanWeight = [self adjustedWeight:self.shodanWeight delta:delta];
        }
        [self saveWeights];
    });
}

@end

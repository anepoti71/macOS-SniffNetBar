//
//  SNBOllamaClient.m
//  SniffNetBar
//

#import "SNBOllamaClient.h"
#import "SNBPromotionCandidate.h"
#import "SNBPromotionDecision.h"
#import "ConfigurationManager.h"
#import "Logger.h"

@interface SNBOllamaClient ()
@property (nonatomic, strong) NSURLSession *session;
@end

@implementation SNBOllamaClient

- (instancetype)init {
    ConfigurationManager *config = [ConfigurationManager sharedManager];
    SNBOllamaClient *client = [self initWithBaseURL:config.promotionOllamaBaseURL
                                            model:config.promotionOllamaModel];
    client.timeout = config.promotionOllamaTimeout;
    return client;
}

- (instancetype)initWithBaseURL:(NSString *)baseURL model:(NSString *)model {
    self = [super init];
    if (self) {
        // SSRF protection: Only allow localhost URLs for Ollama
        if (![self isAllowedURL:baseURL]) {
            SNBLogAgentWarn("Ollama client rejected non-localhost URL: %{public}@", baseURL);
            return nil;
        }

        _baseURL = [baseURL copy];
        _model = [model copy];
        _timeout = 30.0;

        NSURLSessionConfiguration *config = [NSURLSessionConfiguration defaultSessionConfiguration];
        config.timeoutIntervalForRequest = _timeout;
        config.timeoutIntervalForResource = _timeout * 2;
        _session = [NSURLSession sessionWithConfiguration:config];
        SNBLogAgentDebug("Ollama client configured baseURL=%{public}@ model=%{public}@ timeout=%.1fs",
                         _baseURL, _model, _timeout);
    }
    return self;
}

- (BOOL)isAllowedURL:(NSString *)urlString {
    // Only allow localhost/loopback addresses - prevents SSRF attacks
    NSArray *allowedPrefixes = @[
        @"http://localhost",
        @"http://127.0.0.1",
        @"http://[::1]",
        @"https://localhost",
        @"https://127.0.0.1",
        @"https://[::1]"
    ];
    NSString *lowercaseURL = [urlString lowercaseString];
    for (NSString *prefix in allowedPrefixes) {
        if ([lowercaseURL hasPrefix:prefix]) {
            return YES;
        }
    }
    return NO;
}

- (void)dealloc {
    [_session invalidateAndCancel];
}

#pragma mark - Public Methods

- (void)pingWithCompletion:(void (^)(BOOL available))completion {
    NSURL *url = [NSURL URLWithString:[NSString stringWithFormat:@"%@/api/tags", self.baseURL]];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    request.HTTPMethod = @"GET";
    request.timeoutInterval = 5.0;

    SNBLogAgentDebug("Ollama ping -> %{public}@", url.absoluteString);
    NSURLSessionDataTask *task = [self.session dataTaskWithRequest:request
                                                 completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (error) {
                SNBLogAgentWarn("Ollama ping failed: %{public}@", error.localizedDescription);
                completion(NO);
                return;
            }

            NSHTTPURLResponse *httpResponse = (NSHTTPURLResponse *)response;
            BOOL available = (httpResponse.statusCode == 200);
            SNBLogAgentDebug("Ollama ping status=%ld bytes=%lu", (long)httpResponse.statusCode, (unsigned long)data.length);
            if (available) {
                SNBLogAgentInfo("Ollama service available at %{public}@", self.baseURL);
            }
            completion(available);
        });
    }];
    [task resume];
}

- (void)listModelsWithCompletion:(void (^)(NSArray<NSString *> * _Nullable, NSError * _Nullable))completion {
    NSURL *url = [NSURL URLWithString:[NSString stringWithFormat:@"%@/api/tags", self.baseURL]];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    request.HTTPMethod = @"GET";
    request.timeoutInterval = self.timeout;

    SNBLogAgentDebug("Ollama list models -> %{public}@", url.absoluteString);
    NSURLSessionDataTask *task = [self.session dataTaskWithRequest:request
                                                 completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (error) {
                SNBLogAgentWarn("Ollama list models failed: %{public}@", error.localizedDescription);
                completion(nil, error);
                return;
            }

            NSError *parseError = nil;
            NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:&parseError];
            if (parseError) {
                SNBLogAgentWarn("Ollama list models parse error: %{public}@", parseError.localizedDescription);
                completion(nil, parseError);
                return;
            }

            NSArray *models = json[@"models"];
            NSMutableArray<NSString *> *modelNames = [NSMutableArray array];
            for (NSDictionary *modelInfo in models) {
                NSString *name = modelInfo[@"name"];
                if (name) {
                    [modelNames addObject:name];
                }
            }
            SNBLogAgentDebug("Ollama list models count=%lu", (unsigned long)modelNames.count);
            completion(modelNames, nil);
        });
    }];
    [task resume];
}

- (void)evaluateCandidate:(SNBPromotionCandidate *)candidate
               completion:(void (^)(SNBPromotionDecision * _Nullable, NSError * _Nullable))completion {
    NSString *prompt = [self buildPromptForCandidate:candidate];

    NSURL *url = [NSURL URLWithString:[NSString stringWithFormat:@"%@/api/generate", self.baseURL]];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    request.HTTPMethod = @"POST";
    request.timeoutInterval = self.timeout;
    [request setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];

    NSDictionary *body = @{
        @"model": self.model,
        @"prompt": prompt,
        @"stream": @NO,
        @"format": @"json"
    };

    NSError *jsonError = nil;
    request.HTTPBody = [NSJSONSerialization dataWithJSONObject:body options:0 error:&jsonError];
    if (jsonError) {
        completion(nil, jsonError);
        return;
    }

    SNBLogAgentDebug("Ollama evaluate start cluster=%{public}@ model=%{public}@ promptBytes=%lu",
                     candidate.clusterID ?: @"unknown",
                     self.model,
                     (unsigned long)[prompt lengthOfBytesUsingEncoding:NSUTF8StringEncoding]);
    NSURLSessionDataTask *task = [self.session dataTaskWithRequest:request
                                                 completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (error) {
                SNBLogAgentWarn("Ollama request failed: %{public}@", error.localizedDescription);
                completion(nil, error);
                return;
            }

            NSHTTPURLResponse *httpResponse = (NSHTTPURLResponse *)response;
            if (httpResponse.statusCode != 200) {
                NSError *statusError = [NSError errorWithDomain:@"SNBOllamaClient"
                                                           code:httpResponse.statusCode
                                                       userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"HTTP %ld", (long)httpResponse.statusCode]}];
                SNBLogAgentWarn("Ollama evaluate status=%ld", (long)httpResponse.statusCode);
                completion(nil, statusError);
                return;
            }

            SNBLogAgentDebug("Ollama evaluate response bytes=%lu", (unsigned long)data.length);
            SNBPromotionDecision *decision = [self parseResponseData:data forCandidate:candidate];
            if (!decision) {
                NSError *parseError = [NSError errorWithDomain:@"SNBOllamaClient"
                                                          code:-1
                                                      userInfo:@{NSLocalizedDescriptionKey: @"Failed to parse Ollama response"}];
                completion(nil, parseError);
                return;
            }

            completion(decision, nil);
        });
    }];
    [task resume];
}

- (void)generateWithPrompt:(NSString *)prompt
                completion:(void (^)(NSString * _Nullable, NSError * _Nullable))completion {
    NSURL *url = [NSURL URLWithString:[NSString stringWithFormat:@"%@/api/generate", self.baseURL]];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    request.HTTPMethod = @"POST";
    request.timeoutInterval = self.timeout;
    [request setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];

    NSDictionary *body = @{
        @"model": self.model,
        @"prompt": prompt,
        @"stream": @NO
    };

    NSError *jsonError = nil;
    request.HTTPBody = [NSJSONSerialization dataWithJSONObject:body options:0 error:&jsonError];
    if (jsonError) {
        completion(nil, jsonError);
        return;
    }

    SNBLogAgentDebug("Ollama generate start model=%{public}@ promptBytes=%lu",
                     self.model,
                     (unsigned long)[prompt lengthOfBytesUsingEncoding:NSUTF8StringEncoding]);
    NSURLSessionDataTask *task = [self.session dataTaskWithRequest:request
                                                 completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (error) {
                SNBLogAgentWarn("Ollama generate failed: %{public}@", error.localizedDescription);
                completion(nil, error);
                return;
            }

            NSError *parseError = nil;
            NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:&parseError];
            if (parseError) {
                SNBLogAgentWarn("Ollama generate parse error: %{public}@", parseError.localizedDescription);
                completion(nil, parseError);
                return;
            }

            NSString *responseText = json[@"response"];
            SNBLogAgentDebug("Ollama generate response bytes=%lu", (unsigned long)[responseText lengthOfBytesUsingEncoding:NSUTF8StringEncoding]);
            completion(responseText, nil);
        });
    }];
    [task resume];
}

#pragma mark - Private Methods

- (NSString *)buildPromptForCandidate:(SNBPromotionCandidate *)candidate {
    NSString *observationPeriod = @"unknown";
    if (candidate.firstSeen) {
        NSTimeInterval interval = [[NSDate date] timeIntervalSinceDate:candidate.firstSeen];
        if (interval < 3600) {
            observationPeriod = [NSString stringWithFormat:@"%.0f minutes", interval / 60];
        } else if (interval < 86400) {
            observationPeriod = [NSString stringWithFormat:@"%.1f hours", interval / 3600];
        } else {
            observationPeriod = [NSString stringWithFormat:@"%.1f days", interval / 86400];
        }
    }

    return [NSString stringWithFormat:
        @"You are a network security analyst. Evaluate this network connection and decide if it should be trusted.\n\n"
        @"CLUSTER: %@\n"
        @"PROCESS: %@ (signing: %@)\n"
        @"DESTINATION: %@ port %ld\n"
        @"BEHAVIORAL SCORE: %ld/100\n"
        @"CONFIDENCE: %ld/100\n"
        @"SEEN COUNT: %llu times over %@\n"
        @"ROLLING WINDOWS: 1h=%llu, 24h=%llu, 7d=%llu\n"
        @"BEACON SCORE: %.2f (0=random, 1=periodic)\n"
        @"FLAGS: ipOnly=%@, asnAnomaly=%@, vpn=%@, hosting=%@, relay=%@\n"
        @"THREAT INTEL: vtScore=%.1f, abuseScore=%.1f, greyNoise=%@\n"
        @"ASN/ORG: %@ / %@ (%@)\n\n"
        @"Based on this data, respond with JSON only:\n"
        @"{\n"
        @"  \"action\": \"trust\" | \"block\" | \"observe\" | \"review\",\n"
        @"  \"reason\": \"brief explanation\",\n"
        @"  \"confidence\": 0-100,\n"
        @"  \"factors\": [\"factor1\", \"factor2\"]\n"
        @"}",
        candidate.clusterID ?: @"unknown",
        candidate.processName ?: @"unknown",
        candidate.signingStatus ?: @"unknown",
        candidate.dstDomain ?: candidate.dstIP ?: @"unknown",
        (long)candidate.dstPort,
        (long)candidate.score,
        (long)candidate.confidence,
        candidate.seenCount,
        observationPeriod,
        candidate.seen1h,
        candidate.seen24h,
        candidate.seen7d,
        candidate.beaconScore,
        candidate.ipOnly ? @"YES" : @"NO",
        candidate.asnAnomaly ? @"YES" : @"NO",
        candidate.vpn ? @"YES" : @"NO",
        candidate.hosting ? @"YES" : @"NO",
        candidate.relay ? @"YES" : @"NO",
        candidate.vtScore,
        candidate.abuseScore,
        candidate.greyNoiseClass ?: @"unknown",
        candidate.asn ?: @"unknown",
        candidate.org ?: @"unknown",
        candidate.country ?: @"unknown"
    ];
}

- (SNBPromotionDecision *)parseResponseData:(NSData *)data forCandidate:(SNBPromotionCandidate *)candidate {
    NSError *error = nil;
    NSDictionary *outerJson = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
    if (error || !outerJson) {
        SNBLogAgentWarn("Failed to parse outer Ollama JSON: %{public}@", error.localizedDescription);
        return nil;
    }

    NSString *responseString = outerJson[@"response"];
    if (!responseString || responseString.length == 0) {
        SNBLogAgentWarn("Empty response from Ollama");
        return nil;
    }

    NSData *innerData = [responseString dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *responseJson = [NSJSONSerialization JSONObjectWithData:innerData options:0 error:&error];
    if (error || !responseJson) {
        SNBLogAgentWarn("Failed to parse inner Ollama JSON: %{public}@", error.localizedDescription);
        return nil;
    }

    SNBPromotionDecision *decision = [[SNBPromotionDecision alloc] init];
    decision.clusterID = candidate.clusterID;
    decision.score = candidate.score;
    decision.seenCount = candidate.seenCount;
    decision.processName = candidate.processName;
    decision.destinationFamily = candidate.dstDomain;
    decision.destinationIP = candidate.dstIP;
    decision.extendedContext = candidate.extendedContext;

    NSString *action = responseJson[@"action"];
    if ([action isEqualToString:@"trust"]) {
        decision.action = SNBPromotionActionAutoPromote;
    } else if ([action isEqualToString:@"block"]) {
        decision.action = SNBPromotionActionAutoBlock;
    } else if ([action isEqualToString:@"observe"]) {
        decision.action = SNBPromotionActionNone;
    } else if ([action isEqualToString:@"review"]) {
        decision.action = SNBPromotionActionNeedsReview;
    } else {
        decision.action = SNBPromotionActionNone;
    }

    decision.reason = responseJson[@"reason"] ?: @"AI evaluation";

    NSNumber *aiConfidence = responseJson[@"confidence"];
    decision.confidence = aiConfidence ? [aiConfidence integerValue] : 50;

    NSArray *factors = responseJson[@"factors"];
    if ([factors isKindOfClass:[NSArray class]]) {
        decision.factors = factors;
    }

    return decision;
}

@end

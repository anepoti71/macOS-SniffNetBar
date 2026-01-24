//
//  ProcessRiskEvaluator.m
//  SniffNetBar
//

#import "ProcessRiskEvaluator.h"
#import "ProcessRiskModels.h"
#import "MenuBuilder+ThreatDisplay.h"
#import "ProcessIdentityStore.h"
#import "ProcessIdentityModels.h"
#import "ThreatIntelModels.h"
#import "TrafficStatistics.h"
#import "Logger.h"
#import <Security/Security.h>
#import <Security/CSCommon.h>
#import <CommonCrypto/CommonDigest.h>
#import <sys/proc_info.h>
#import <libproc.h>

@interface SNBProcessRiskEvaluator ()
@property (nonatomic, strong) NSCache<NSString *, SNBProcessRiskReport *> *cache;
@end

@implementation SNBProcessRiskEvaluator

+ (instancetype)sharedEvaluator {
    static SNBProcessRiskEvaluator *shared = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        shared = [[SNBProcessRiskEvaluator alloc] init];
    });
    return shared;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _cache = [[NSCache alloc] init];
    }
    return self;
}

- (nullable SNBProcessRiskReport *)evaluatePID:(pid_t)pid
                                   processName:(nullable NSString *)processName
                                    connection:(nullable ConnectionTraffic *)connection
                                        threat:(nullable ThreatInfo *)threat {
    if (pid <= 0) {
        return nil;
    }

    NSString *cacheKey = [NSString stringWithFormat:@"%d", pid];
    SNBProcessRiskReport *cached = [self.cache objectForKey:cacheKey];
    if (cached) {
        return cached;
    }

    SNBProcessRiskReport *report = [[SNBProcessRiskReport alloc] init];
    report.pid = pid;
    NSMutableArray<SNBRiskSignal *> *signals = [NSMutableArray array];
    NSMutableArray<NSString *> *infoLines = [NSMutableArray array];
    uid_t uid = 0;
    pid_t ppid = 0;

    NSString *path = [self executablePathForPID:pid];
    report.executablePath = path;
    if (path.length > 0) {
        [infoLines addObject:[NSString stringWithFormat:@"Path: %@", path]];
    }

    struct proc_bsdinfo bsdinfo = {0};
    int bsdInfoResult = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bsdinfo, PROC_PIDTBSDINFO_SIZE);
    if (bsdInfoResult == PROC_PIDTBSDINFO_SIZE) {
        uid = bsdinfo.pbi_uid;
        ppid = bsdinfo.pbi_ppid;
        [infoLines addObject:[NSString stringWithFormat:@"UID: %u", uid]];
        NSString *parentInfo = [self parentInfoForPID:ppid];
        if (parentInfo.length > 0) {
            [infoLines addObject:[NSString stringWithFormat:@"Parent: %@", parentInfo]];
        }
        [self evaluateRuntimeFlags:bsdinfo.pbi_flags signals:signals];
        [self evaluateProvenanceWithUID:bsdinfo.pbi_uid
                               parentName:[self parentNameForPID:ppid]
                           executablePath:path
                                  signals:signals];
    }

    NSDictionary *signing = [self signingInfoForPath:path];
    report.teamID = signing[@"teamID"];
    report.bundleID = signing[@"bundleID"];
    report.signingID = signing[@"signingID"];
    NSString *signingSummary = signing[@"summary"];
    if (signingSummary.length > 0) {
        [infoLines addObject:[NSString stringWithFormat:@"Signing: %@", signingSummary]];
    }
    [self evaluateSigningSignals:signing signals:signals];

    NSArray<NSString *> *persistence = [self persistenceMatchesForPath:path];
    if (persistence.count > 0) {
        [signals addObject:[self signalWithTitle:@"LaunchAgent/Daemon persistence match"
                                           score:10
                                        category:@"persistence"]];
        [infoLines addObject:[NSString stringWithFormat:@"Persistence: %lu match%@",
                              (unsigned long)persistence.count,
                              persistence.count == 1 ? @"" : @"es"]];
    }

    [self evaluateNetworkSignalsForThreat:threat connection:connection signals:signals];

    NSInteger totalScore = 0;
    for (SNBRiskSignal *signal in signals) {
        totalScore += signal.score;
    }
    report.score = MIN(MAX(totalScore, 0), 100);
    report.level = [self riskLevelForScore:report.score];
    report.summary = [NSString stringWithFormat:@"%@ (score %ld)",
                      [self riskLevelString:report.level],
                      (long)report.score];

    NSString *cdhash = signing[@"cdhash"];
    NSString *entitlementsHash = signing[@"entitlementsHash"];
    NSString *signatureKind = signing[@"signatureKind"];
    NSString *sha256 = nil;
    if (cdhash.length == 0 && (report.teamID.length == 0 || report.signingID.length == 0)) {
        sha256 = [self sha256ForFileAtPath:path];
        if (sha256.length > 0) {
            [infoLines addObject:[NSString stringWithFormat:@"SHA256: %@", sha256]];
        }
    }

    SNBProcessIdentityStore *store = [SNBProcessIdentityStore sharedStore];
    SNBProcessIdentityRecord *known = [store resolveIdentityWithCDHash:cdhash
                                                                teamID:report.teamID
                                                             signingID:report.signingID
                                                                sha256:sha256];
    NSString *verdict = known.verdict ?: [self verdictForRiskLevel:report.level];
    double confidence = [self confidenceForSignals:signals
                                           signing:signing
                                       knownRecord:known];
    SNBProcessIdentityRecord *record = [[SNBProcessIdentityRecord alloc] init];
    record.cdhash = cdhash;
    record.teamID = report.teamID;
    record.bundleID = report.bundleID;
    record.signingID = report.signingID;
    record.signatureValid = [signing[@"valid"] boolValue];
    record.signatureKind = signatureKind;
    record.entitlementsHash = entitlementsHash;
    record.sha256 = sha256;
    record.pathHint = path;
    NSTimeInterval now = [NSDate date].timeIntervalSince1970;
    record.firstSeen = known ? known.firstSeen : now;
    record.lastSeen = now;
    record.riskScore = report.score;
    record.verdict = verdict;
    record.confidence = confidence;
    SNBProcessIdentityRecord *stored = [store upsertIdentity:record];

    if (stored) {
        NSString *knownVerdict = stored.verdict.length > 0 ? stored.verdict : verdict;
        [infoLines addObject:[NSString stringWithFormat:@"Identity: %@ (confidence %.2f)",
                              known ? @"Known" : @"New", stored.confidence]];
        if (knownVerdict.length > 0) {
            [infoLines addObject:[NSString stringWithFormat:@"Identity verdict: %@", knownVerdict]];
        }
        [store recordObservationForIdentityID:stored.identityID
                                          pid:pid
                                         ppid:ppid
                                          uid:uid
                                         path:path
                                     riskScore:report.score
                                       verdict:knownVerdict
                                 telemetryJSON:nil];
    } else {
        [infoLines addObject:[NSString stringWithFormat:@"Identity: %@", known ? @"Known" : @"New"]];
    }

    NSArray<SNBRiskSignal *> *sortedSignals = [signals sortedArrayUsingComparator:^NSComparisonResult(SNBRiskSignal *a, SNBRiskSignal *b) {
        if (a.score == b.score) {
            return [a.title compare:b.title];
        }
        return a.score > b.score ? NSOrderedAscending : NSOrderedDescending;
    }];
    report.signals = sortedSignals;
    report.infoLines = infoLines;

    [self.cache setObject:report forKey:cacheKey];
    return report;
}

- (NSString *)executablePathForPID:(pid_t)pid {
    char buffer[PROC_PIDPATHINFO_MAXSIZE] = {0};
    int length = proc_pidpath(pid, buffer, sizeof(buffer));
    if (length > 0) {
        return [NSString stringWithUTF8String:buffer];
    }
    return nil;
}

- (NSString *)parentNameForPID:(pid_t)pid {
    if (pid <= 0) {
        return nil;
    }
    char nameBuffer[PROC_PIDPATHINFO_MAXSIZE] = {0};
    int length = proc_name(pid, nameBuffer, sizeof(nameBuffer));
    if (length > 0) {
        return [NSString stringWithUTF8String:nameBuffer];
    }
    return nil;
}

- (NSString *)parentInfoForPID:(pid_t)pid {
    NSString *name = [self parentNameForPID:pid];
    if (name.length == 0) {
        return nil;
    }
    return [NSString stringWithFormat:@"%@ (%d)", name, pid];
}

- (NSDictionary *)signingInfoForPath:(NSString *)path {
    if (path.length == 0) {
        return @{};
    }
    NSURL *url = [NSURL fileURLWithPath:path];
    SecStaticCodeRef codeRef = NULL;
    OSStatus createStatus = SecStaticCodeCreateWithPath((__bridge CFURLRef)url, kSecCSDefaultFlags, &codeRef);
    if (createStatus != errSecSuccess || !codeRef) {
        return @{@"summary": @"Unavailable"};
    }

    OSStatus validStatus = SecStaticCodeCheckValidity(codeRef, kSecCSDefaultFlags, NULL);
    CFDictionaryRef info = NULL;
    SecCodeCopySigningInformation(codeRef, kSecCSSigningInformation, &info);
    NSDictionary *infoDict = CFBridgingRelease(info) ?: @{};
    NSString *teamID = infoDict[(__bridge NSString *)kSecCodeInfoTeamIdentifier];
    NSString *bundleID = infoDict[(__bridge NSString *)kSecCodeInfoIdentifier];
    id signingIDValue = infoDict[(__bridge NSString *)kSecCodeInfoUnique];
    NSString *signingID = nil;
    if ([signingIDValue isKindOfClass:[NSString class]]) {
        signingID = (NSString *)signingIDValue;
    } else if ([signingIDValue isKindOfClass:[NSData class]]) {
        signingID = [self hexStringFromData:signingIDValue];
    }
    NSNumber *flags = infoDict[(__bridge NSString *)kSecCodeInfoFlags];
    NSDictionary *entitlements = infoDict[(__bridge NSString *)kSecCodeInfoEntitlementsDict];
    NSArray *cdhashes = infoDict[(__bridge NSString *)kSecCodeInfoCdHashes];
    NSData *cdhashData = ([cdhashes isKindOfClass:[NSArray class]] && cdhashes.count > 0) ? cdhashes.firstObject : nil;
    NSString *cdhash = [self hexStringFromData:cdhashData];
    NSString *entitlementsHash = [self hashForEntitlements:entitlements];
    BOOL adhoc = flags ? ((flags.unsignedIntValue & kSecCodeSignatureAdhoc) != 0) : NO;
    BOOL hardened = flags ? ((flags.unsignedIntValue & kSecCodeSignatureRuntime) != 0) : NO;
    NSString *signatureKind = nil;
    if (adhoc) {
        signatureKind = @"adhoc";
    } else if (validStatus == errSecSuccess) {
        signatureKind = teamID.length > 0 ? @"dev_id" : @"signed";
    } else {
        signatureKind = @"unsigned";
    }

    NSMutableString *summary = [NSMutableString string];
    if (validStatus == errSecSuccess) {
        [summary appendString:@"Valid"];
    } else {
        [summary appendString:@"Invalid"];
    }
    if (adhoc) {
        [summary appendString:@", Ad-hoc"];
    }
    if (hardened) {
        [summary appendString:@", Hardened"];
    }
    if (teamID.length > 0) {
        [summary appendFormat:@", Team %@", teamID];
    }

    CFRelease(codeRef);
    return @{
        @"valid": @(validStatus == errSecSuccess),
        @"adhoc": @(adhoc),
        @"hardened": @(hardened),
        @"teamID": teamID ?: @"",
        @"bundleID": bundleID ?: @"",
        @"signingID": signingID ?: @"",
        @"cdhash": cdhash ?: @"",
        @"entitlementsHash": entitlementsHash ?: @"",
        @"entitlements": entitlements ?: @{},
        @"signatureKind": signatureKind ?: @"",
        @"summary": summary ?: @""
    };
}

- (void)evaluateSigningSignals:(NSDictionary *)signing signals:(NSMutableArray<SNBRiskSignal *> *)signals {
    if (signing.count == 0) {
        return;
    }
    BOOL valid = [signing[@"valid"] boolValue];
    BOOL adhoc = [signing[@"adhoc"] boolValue];
    BOOL hardened = [signing[@"hardened"] boolValue];
    NSString *teamID = signing[@"teamID"];
    NSDictionary *entitlements = signing[@"entitlements"];

    if (!valid) {
        [signals addObject:[self signalWithTitle:@"Invalid code signature" score:35 category:@"identity"]];
    }
    if (adhoc) {
        [signals addObject:[self signalWithTitle:@"Ad-hoc signed binary" score:20 category:@"identity"]];
    }
    if (teamID.length == 0) {
        [signals addObject:[self signalWithTitle:@"Missing Team ID" score:10 category:@"identity"]];
    }
    if (!hardened) {
        [signals addObject:[self signalWithTitle:@"No hardened runtime" score:5 category:@"identity"]];
    }
    if ([entitlements[@"com.apple.security.get-task-allow"] boolValue]) {
        [signals addObject:[self signalWithTitle:@"Debugger entitlement present" score:5 category:@"identity"]];
    }
}

- (void)evaluateRuntimeFlags:(uint32_t)flags signals:(NSMutableArray<SNBRiskSignal *> *)signals {
    if (flags & PROC_FLAG_TRACED) {
        [signals addObject:[self signalWithTitle:@"Process is being traced" score:10 category:@"runtime"]];
    }
    if (flags & PROC_FLAG_PSUGID) {
        [signals addObject:[self signalWithTitle:@"Privilege change since exec" score:10 category:@"runtime"]];
    }
}

- (void)evaluateProvenanceWithUID:(uid_t)uid
                       parentName:(NSString *)parentName
                   executablePath:(NSString *)path
                          signals:(NSMutableArray<SNBRiskSignal *> *)signals {
    NSArray<NSString *> *suspiciousParents = @[@"osascript", @"bash", @"sh", @"zsh", @"python", @"perl", @"ruby", @"node", @"curl", @"wget"];
    if (parentName.length > 0 && [suspiciousParents containsObject:parentName]) {
        [signals addObject:[self signalWithTitle:@"Suspicious parent process" score:10 category:@"provenance"]];
    }

    if (path.length > 0) {
        if ([path containsString:@"/AppTranslocation/"]) {
            [signals addObject:[self signalWithTitle:@"App translocation path" score:10 category:@"provenance"]];
        }
        if ([path hasPrefix:@"/tmp/"] || [path hasPrefix:@"/private/var/tmp/"] || [path containsString:@"/Downloads/"]) {
            [signals addObject:[self signalWithTitle:@"Executable in temporary/downloads path" score:15 category:@"provenance"]];
        }
        if (uid == 0 && [path containsString:@"/Users/"]) {
            [signals addObject:[self signalWithTitle:@"Root process from user path" score:20 category:@"provenance"]];
        }
    }
}

- (void)evaluateNetworkSignalsForThreat:(ThreatInfo *)threat
                             connection:(ConnectionTraffic *)connection
                                signals:(NSMutableArray<SNBRiskSignal *> *)signals {
    if (!threat) {
        return;
    }
    TIScoringResult *scoring = threat.response.scoringResult;
    if (scoring) {
        if (scoring.verdict == TIThreatVerdictMalicious) {
            [signals addObject:[self signalWithTitle:@"Threat intel: malicious verdict" score:20 category:@"network"]];
        } else if (scoring.verdict == TIThreatVerdictSuspicious) {
            [signals addObject:[self signalWithTitle:@"Threat intel: suspicious verdict" score:10 category:@"network"]];
        }
    }
    if (connection) {
        NSSet<NSNumber *> *highRiskPorts = [NSSet setWithArray:@[@22, @23, @3389, @445, @5900, @6667, @8080, @8443]];
        if ([highRiskPorts containsObject:@(connection.destinationPort)]) {
            [signals addObject:[self signalWithTitle:@"High-risk destination port" score:10 category:@"network"]];
        }
    }
    if (threat.connectionCount >= 20 && threat.totalBytes < (1024 * 1024)) {
        [signals addObject:[self signalWithTitle:@"Repeated low-volume connections" score:5 category:@"network"]];
    }
}

- (NSArray<NSString *> *)persistenceMatchesForPath:(NSString *)path {
    if (path.length == 0) {
        return @[];
    }
    static NSMutableDictionary<NSString *, NSArray<NSString *> *> *cachedMappings = nil;
    static NSTimeInterval lastRefresh = 0;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        cachedMappings = [NSMutableDictionary dictionary];
    });

    NSTimeInterval now = [NSDate date].timeIntervalSince1970;
    if ((now - lastRefresh) > 300.0 || cachedMappings.count == 0) {
        NSArray<NSString *> *plistDirs = @[
            [NSHomeDirectory() stringByAppendingPathComponent:@"Library/LaunchAgents"],
            @"/Library/LaunchAgents",
            @"/Library/LaunchDaemons"
        ];
        NSMutableDictionary<NSString *, NSMutableArray<NSString *> *> *newMappings = [NSMutableDictionary dictionary];
        NSFileManager *fm = [NSFileManager defaultManager];
        for (NSString *dir in plistDirs) {
            NSArray<NSString *> *files = [fm contentsOfDirectoryAtPath:dir error:nil];
            for (NSString *file in files) {
                if (![file hasSuffix:@".plist"]) {
                    continue;
                }
                NSString *plistPath = [dir stringByAppendingPathComponent:file];
                NSDictionary *plist = [NSDictionary dictionaryWithContentsOfFile:plistPath];
                if (![plist isKindOfClass:[NSDictionary class]]) {
                    continue;
                }
                NSString *program = [plist[@"Program"] isKindOfClass:[NSString class]] ? plist[@"Program"] : nil;
                NSArray *programArgs = [plist[@"ProgramArguments"] isKindOfClass:[NSArray class]]
                    ? plist[@"ProgramArguments"] : nil;
                NSString *programPath = program ?: (programArgs.count > 0 ? programArgs.firstObject : nil);
                if (programPath.length == 0) {
                    continue;
                }
                NSMutableArray<NSString *> *paths = newMappings[programPath];
                if (!paths) {
                    paths = [NSMutableArray array];
                    newMappings[programPath] = paths;
                }
                [paths addObject:plistPath];
            }
        }

        [cachedMappings removeAllObjects];
        for (NSString *key in newMappings) {
            cachedMappings[key] = [newMappings[key] copy];
        }
        lastRefresh = now;
    }

    NSArray<NSString *> *matches = cachedMappings[path];
    return matches ?: @[];
}

- (SNBRiskSignal *)signalWithTitle:(NSString *)title score:(NSInteger)score category:(NSString *)category {
    SNBRiskSignal *signal = [[SNBRiskSignal alloc] init];
    signal.title = title;
    signal.score = score;
    signal.category = category;
    return signal;
}

- (SNBRiskLevel)riskLevelForScore:(NSInteger)score {
    if (score >= 80) {
        return SNBRiskLevelCritical;
    } else if (score >= 60) {
        return SNBRiskLevelHigh;
    } else if (score >= 30) {
        return SNBRiskLevelMedium;
    }
    return SNBRiskLevelLow;
}

- (NSString *)riskLevelString:(SNBRiskLevel)level {
    switch (level) {
        case SNBRiskLevelCritical:
            return @"Critical";
        case SNBRiskLevelHigh:
            return @"High";
        case SNBRiskLevelMedium:
            return @"Medium";
        case SNBRiskLevelLow:
        default:
            return @"Low";
    }
}

- (NSString *)verdictForRiskLevel:(SNBRiskLevel)level {
    switch (level) {
        case SNBRiskLevelCritical:
        case SNBRiskLevelHigh:
            return @"suspicious";
        case SNBRiskLevelMedium:
            return @"unknown";
        case SNBRiskLevelLow:
        default:
            return @"unknown";
    }
}

- (double)confidenceForSignals:(NSArray<SNBRiskSignal *> *)signals
                        signing:(NSDictionary *)signing
                    knownRecord:(SNBProcessIdentityRecord * _Nullable)known {
    double confidence = 0.4;
    if ([signing[@"valid"] boolValue] && [signing[@"teamID"] length] > 0) {
        confidence = 0.7;
    } else if ([signing[@"adhoc"] boolValue]) {
        confidence = 0.35;
    } else if (![signing[@"valid"] boolValue]) {
        confidence = 0.3;
    }

    if (signals.count == 0) {
        confidence = MAX(confidence, 0.6);
    }
    if (known) {
        confidence = MAX(confidence, known.confidence);
    }
    return MIN(MAX(confidence, 0.1), 0.95);
}

- (nullable NSString *)sha256ForFileAtPath:(NSString *)path {
    if (path.length == 0) {
        return nil;
    }
    NSFileHandle *handle = [NSFileHandle fileHandleForReadingAtPath:path];
    if (!handle) {
        return nil;
    }

    CC_SHA256_CTX ctx;
    CC_SHA256_Init(&ctx);
    while (true) {
        @autoreleasepool {
            NSData *data = [handle readDataOfLength:65536];
            if (data.length == 0) {
                break;
            }
            CC_SHA256_Update(&ctx, data.bytes, (CC_LONG)data.length);
        }
    }
    [handle closeFile];

    unsigned char digest[CC_SHA256_DIGEST_LENGTH] = {0};
    CC_SHA256_Final(digest, &ctx);
    NSData *hashData = [NSData dataWithBytes:digest length:CC_SHA256_DIGEST_LENGTH];
    return [self hexStringFromData:hashData];
}

- (nullable NSString *)hashForEntitlements:(NSDictionary *)entitlements {
    if (entitlements.count == 0) {
        return nil;
    }
    NSError *error = nil;
    NSData *data = nil;
    if (@available(macOS 10.13, *)) {
        data = [NSJSONSerialization dataWithJSONObject:entitlements
                                               options:NSJSONWritingSortedKeys
                                                 error:&error];
    } else {
        data = [NSJSONSerialization dataWithJSONObject:entitlements options:0 error:&error];
    }
    if (!data || error) {
        return nil;
    }
    unsigned char digest[CC_SHA256_DIGEST_LENGTH] = {0};
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    NSData *hashData = [NSData dataWithBytes:digest length:CC_SHA256_DIGEST_LENGTH];
    return [self hexStringFromData:hashData];
}

- (nullable NSString *)hexStringFromData:(NSData *)data {
    if (data.length == 0) {
        return nil;
    }
    const unsigned char *bytes = data.bytes;
    NSMutableString *hex = [NSMutableString stringWithCapacity:data.length * 2];
    for (NSUInteger i = 0; i < data.length; i++) {
        [hex appendFormat:@"%02x", bytes[i]];
    }
    return hex;
}

@end

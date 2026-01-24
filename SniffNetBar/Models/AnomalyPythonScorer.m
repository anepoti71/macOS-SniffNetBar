//
//  AnomalyPythonScorer.m
//  SniffNetBar
//
//  Executes a local Python scoring script
//

#import "AnomalyPythonScorer.h"

static const NSTimeInterval kAnomalyPythonTimeoutSeconds = 5.0;

@interface SNBAnomalyPythonScorer ()
@property (nonatomic, copy) NSString *scriptPath;
@property (nonatomic, copy) NSString *modelPath;
@end

@implementation SNBAnomalyPythonScorer

- (instancetype)initWithScriptPath:(NSString *)scriptPath
                         modelPath:(NSString *)modelPath {
    self = [super init];
    if (self) {
        _scriptPath = [scriptPath copy] ?: @"";
        _modelPath = [modelPath copy] ?: @"";
    }
    return self;
}

- (NSNumber *)scoreFeaturePayload:(NSDictionary<NSString *, NSNumber *> *)payload
                            error:(NSError **)error {
    if (self.scriptPath.length == 0 || self.modelPath.length == 0) {
        return nil;
    }
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:self.scriptPath] || ![fm fileExistsAtPath:self.modelPath]) {
        return nil;
    }

    NSTask *task = [[NSTask alloc] init];
    task.launchPath = @"/usr/bin/python3";
    task.arguments = @[self.scriptPath, self.modelPath];

    NSPipe *stdinPipe = [NSPipe pipe];
    NSPipe *stdoutPipe = [NSPipe pipe];
    task.standardInput = stdinPipe;
    task.standardOutput = stdoutPipe;
    task.standardError = stdoutPipe;

    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:payload options:0 error:error];
    if (!jsonData) {
        return nil;
    }

    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    task.terminationHandler = ^(NSTask *terminatedTask) {
        dispatch_semaphore_signal(done);
    };

    @try {
        [task launch];
    } @catch (NSException *exception) {
        return nil;
    }

    [[stdinPipe fileHandleForWriting] writeData:jsonData];
    [[stdinPipe fileHandleForWriting] closeFile];

    dispatch_time_t timeout = dispatch_time(DISPATCH_TIME_NOW,
                                            (int64_t)(kAnomalyPythonTimeoutSeconds * NSEC_PER_SEC));
    if (dispatch_semaphore_wait(done, timeout) != 0) {
        [task terminate];
        dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)));
        return nil;
    }

    NSData *outData = [[stdoutPipe fileHandleForReading] readDataToEndOfFile];

    if (task.terminationStatus != 0 || outData.length == 0) {
        return nil;
    }

    NSDictionary *result = [NSJSONSerialization JSONObjectWithData:outData options:0 error:error];
    if (![result isKindOfClass:[NSDictionary class]]) {
        return nil;
    }
    NSNumber *score = result[@"score"];
    if (![score isKindOfClass:[NSNumber class]]) {
        return nil;
    }
    return score;
}

@end

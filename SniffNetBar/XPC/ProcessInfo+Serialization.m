//
//  ProcessInfo+Serialization.m
//  SniffNetBar
//

#import "ProcessInfo+Serialization.h"

@implementation ProcessInfo (Serialization)

- (NSDictionary *)toDictionary {
    return @{
        @"pid": @(self.pid),
        @"processName": self.processName ?: @"",
        @"executablePath": self.executablePath ?: @""
    };
}

+ (ProcessInfo *)fromDictionary:(NSDictionary *)dictionary {
    if (!dictionary) {
        return nil;
    }

    ProcessInfo *info = [[ProcessInfo alloc] init];
    info.pid = [dictionary[@"pid"] intValue];
    info.processName = dictionary[@"processName"] ?: @"";
    info.executablePath = dictionary[@"executablePath"];
    return info;
}

@end

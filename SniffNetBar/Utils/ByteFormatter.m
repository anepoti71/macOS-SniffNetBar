//
//  ByteFormatter.m
//  SniffNetBar
//

#import "ByteFormatter.h"

@implementation SNBByteFormatter

+ (NSString *)stringFromBytes:(uint64_t)bytes {
    if (bytes < 1024) {
        return [NSString stringWithFormat:@"%llu B", bytes];
    }
    if (bytes < 1024 * 1024) {
        return [NSString stringWithFormat:@"%.2f KB", bytes / 1024.0];
    }
    if (bytes < 1024 * 1024 * 1024) {
        return [NSString stringWithFormat:@"%.2f MB", bytes / (1024.0 * 1024.0)];
    }
    return [NSString stringWithFormat:@"%.2f GB", bytes / (1024.0 * 1024.0 * 1024.0)];
}

@end

//
//  ByteFormatter.h
//  SniffNetBar
//

#import <Foundation/Foundation.h>

@interface SNBByteFormatter : NSObject

+ (NSString *)stringFromBytes:(uint64_t)bytes;

@end

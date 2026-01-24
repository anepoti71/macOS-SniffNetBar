//
//  main.m
//  SniffNetBarHelper
//

#import <Foundation/Foundation.h>
#import "SNBPrivilegedHelperService.h"

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        SNBPrivilegedHelperService *service = [[SNBPrivilegedHelperService alloc] init];
        [service run];
    }
    return 0;
}

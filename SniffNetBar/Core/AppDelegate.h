//
//  AppDelegate.h
//  SniffNetBar
//
//  Created from Rust networking code refactoring
//

#import <Cocoa/Cocoa.h>

@class AppCoordinator;

@interface AppDelegate : NSObject <NSApplicationDelegate, NSMenuDelegate>

@property (nonatomic, strong) NSStatusItem *statusItem;
@property (nonatomic, strong) NSMenu *statusMenu;
@property (nonatomic, strong) AppCoordinator *coordinator;

- (void)initializeApplication;

@end

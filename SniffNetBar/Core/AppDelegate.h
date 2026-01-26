//
//  AppDelegate.h
//  SniffNetBar
//
//  Created from Rust networking code refactoring
//

#import <Cocoa/Cocoa.h>

@class AppCoordinator;
@class SNBStatusBarManager;

@interface AppDelegate : NSObject <NSApplicationDelegate, NSMenuDelegate>

@property (nonatomic, strong) SNBStatusBarManager *statusBarManager;
@property (nonatomic, strong) NSMenu *statusMenu;
@property (nonatomic, strong) AppCoordinator *coordinator;

- (void)initializeApplication;

@end

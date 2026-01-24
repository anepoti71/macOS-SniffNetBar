//
//  AppDelegate.m
//  SniffNetBar
//
//  Created from Rust networking code refactoring
//

#import "AppDelegate.h"
#import "AppCoordinator.h"
#import "ConfigurationManager.h"
#import "SMAppServiceHelper.h"
#import "SNBPrivilegedHelperClient.h"
#import "KeychainManager.h"
#import "Logger.h"

@implementation AppDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)notification {
    SNBLogInfo("=== applicationDidFinishLaunching START ===");

    BOOL helperInstalled = [SMAppServiceHelper isHelperInstalled];
    SNBLogInfo("isHelperInstalled returned: %d", helperInstalled);

    if (!helperInstalled) {
        SNBLogInfo("Entering helper installation block...");
        NSError *error = nil;
        BOOL success = [SMAppServiceHelper installHelperWithError:&error];
        if (!success) {
            NSAlert *alert = [[NSAlert alloc] init];
            alert.messageText = @"Installation Required";
            alert.informativeText = [NSString stringWithFormat:@"SniffNetBar requires a privileged helper to capture network packets. Installation failed: %@",
                                     error.localizedDescription ?: @"Unknown error"];
            alert.alertStyle = NSAlertStyleWarning;
            [alert addButtonWithTitle:@"OK"];
            [alert runModal];
            [NSApp terminate:nil];
            return;
        }

        NSString *status = [SMAppServiceHelper helperStatus];
        if ([status isEqualToString:@"Requires Approval"]) {
            NSAlert *alert = [[NSAlert alloc] init];
            alert.messageText = @"Approval Required";
            alert.informativeText = @"SniffNetBar Helper has been registered but needs your approval.\n\nPlease:\n1. Open System Settings > Login Items\n2. Enable 'SniffNetBar Helper' under 'Allow in the Background'\n3. Restart SniffNetBar\n\nThe application will now quit.";
            alert.alertStyle = NSAlertStyleInformational;
            [alert addButtonWithTitle:@"Open System Settings"];
            [alert addButtonWithTitle:@"Quit"];

            NSModalResponse response = [alert runModal];
            if (response == NSAlertFirstButtonReturn) {
                [[NSWorkspace sharedWorkspace] openURL:[NSURL URLWithString:@"x-apple.systempreferences:com.apple.LoginItems-Settings.extension"]];
            }

            [NSApp terminate:nil];
            return;
        }
    }

    [[SNBPrivilegedHelperClient sharedClient] connectToHelper];
    [self initializeApplication];
}

- (void)initializeApplication {
    SNBLogInfo("Initializing application");

    // Enable keychain access now that helper is installed
    NSError *error = nil;
    [KeychainManager requestKeychainAccessWithError:&error];

    // Create status item
    NSStatusBar *statusBar = [NSStatusBar systemStatusBar];
    self.statusItem = [statusBar statusItemWithLength:NSVariableStatusItemLength];
    NSImage *statusImage = [NSImage imageNamed:@"icon_macos"];
    if (!statusImage) {
        NSString *iconPath = [[NSBundle mainBundle] pathForResource:@"icon_macos" ofType:@"png"];
        statusImage = iconPath ? [[NSImage alloc] initWithContentsOfFile:iconPath] : nil;
    }
    if (statusImage) {
        CGFloat targetSize = statusBar.thickness - 2.0;
        statusImage.size = NSMakeSize(targetSize, targetSize);
        statusImage.template = NO;
        self.statusItem.button.image = statusImage;
        self.statusItem.button.imageScaling = NSImageScaleProportionallyDown;
        self.statusItem.button.title = @"";
    } else {
        SNBLogError("Status icon not found in bundle resources.");
        self.statusItem.button.title = @"📊";
    }
    self.statusItem.button.target = self;
    self.statusItem.button.action = @selector(statusItemClicked:);
    [self.statusItem.button sendActionOn:NSEventMaskLeftMouseUp | NSEventMaskRightMouseUp];

    // Create menu
    self.statusMenu = [[NSMenu alloc] init];
    self.statusMenu.delegate = self;

    // Initialize coordinator
    self.coordinator = [[AppCoordinator alloc] initWithStatusItem:self.statusItem
                                                       statusMenu:self.statusMenu];

    // Start the coordinator
    [self.coordinator start];
}

- (void)statusItemClicked:(id)sender {
    NSEvent *event = [NSApp currentEvent];
    if (event.type == NSEventTypeRightMouseUp) {
        [self.statusItem popUpStatusItemMenu:self.statusMenu];
    } else {
        [self.coordinator updateMenu];
        [self.statusItem popUpStatusItemMenu:self.statusMenu];
    }
}

- (void)menuWillOpen:(NSMenu *)menu {
    if (menu != self.statusMenu) {
        return;
    }
    [self.coordinator menuWillOpenWithStats];
}

- (void)menuDidClose:(NSMenu *)menu {
    if (menu != self.statusMenu) {
        return;
    }
    [self.coordinator menuDidClose];
}

- (void)applicationWillTerminate:(NSNotification *)notification {
    [self.coordinator stop];
}

@end

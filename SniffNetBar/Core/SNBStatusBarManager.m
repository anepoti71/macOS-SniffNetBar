//
//  SNBStatusBarManager.m
//  SniffNetBar
//

#import "SNBStatusBarManager.h"
#import "Logger.h"

@interface SNBStatusBarManager ()
@property (nonatomic, strong) NSStatusItem *statusItem;
@end

@implementation SNBStatusBarManager

- (instancetype)initWithStatusMenu:(NSMenu *)statusMenu {
    self = [super init];
    if (self) {
        _statusMenu = statusMenu;
        NSStatusBar *statusBar = [NSStatusBar systemStatusBar];
        _statusItem = [statusBar statusItemWithLength:NSVariableStatusItemLength];
    }
    return self;
}

- (void)configureStatusItemWithImageNamed:(NSString *)imageName
                           fallbackTitle:(NSString *)fallbackTitle {
    NSImage *statusImage = [NSImage imageNamed:imageName];
    if (!statusImage) {
        NSString *iconPath = [[NSBundle mainBundle] pathForResource:imageName ofType:@"png"];
        statusImage = iconPath ? [[NSImage alloc] initWithContentsOfFile:iconPath] : nil;
    }
    if (statusImage) {
        CGFloat targetSize = [NSStatusBar systemStatusBar].thickness - 2.0;
        statusImage.size = NSMakeSize(targetSize, targetSize);
        statusImage.template = NO;
        self.statusItem.button.image = statusImage;
        self.statusItem.button.imageScaling = NSImageScaleProportionallyDown;
        self.statusItem.button.title = @"";
    } else {
        SNBLogError("Status icon not found in bundle resources.");
        self.statusItem.button.title = fallbackTitle ?: @"";
    }
}

- (void)setButtonTarget:(id)target action:(SEL)action {
    self.statusItem.button.target = target;
    self.statusItem.button.action = action;
}

- (void)sendActionOn:(NSEventMask)mask {
    [self.statusItem.button sendActionOn:mask];
}

- (void)popUpStatusMenu {
    if (!self.statusMenu) {
        return;
    }
    [self.statusItem popUpStatusItemMenu:self.statusMenu];
}

- (void)updateButtonTitle:(NSString *)title {
    self.statusItem.button.title = title ?: @"";
}

- (void)updateButtonAttributedTitle:(NSAttributedString *)title {
    self.statusItem.button.attributedTitle = title ?: [[NSAttributedString alloc] initWithString:@""];
}

@end

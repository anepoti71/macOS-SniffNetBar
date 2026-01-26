//
//  SNBStatusBarManager.h
//  SniffNetBar
//

#import <Cocoa/Cocoa.h>

NS_ASSUME_NONNULL_BEGIN

@interface SNBStatusBarManager : NSObject

@property (nonatomic, strong, readonly) NSStatusItem *statusItem;
@property (nonatomic, weak) NSMenu *statusMenu;

- (instancetype)initWithStatusMenu:(NSMenu *)statusMenu;
- (void)configureStatusItemWithImageNamed:(NSString *)imageName
                           fallbackTitle:(NSString *)fallbackTitle;
- (void)setButtonTarget:(id)target action:(SEL)action;
- (void)sendActionOn:(NSEventMask)mask;
- (void)popUpStatusMenu;
- (void)updateButtonTitle:(NSString *)title;
- (void)updateButtonAttributedTitle:(NSAttributedString *)title;

@end

NS_ASSUME_NONNULL_END

#import "SNBBadgeRegistry.h"

static NSString *SNBBadgeKeyForProcess(NSString *name, pid_t pid) {
    NSString *processName = name.length > 0 ? name : @"<unknown>";
    return [NSString stringWithFormat:@"process:%@|%d", processName, (int)pid];
}

static NSString *SNBBadgeKeyForLabel(NSString *label) {
    NSString *source = label.length > 0 ? label : @"<unknown>";
    return [NSString stringWithFormat:@"label:%@", source];
}

static NSArray<NSColor *> *SNBBadgeColorPalette(void) {
    static NSArray<NSColor *> *palette = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        palette = @[
            [NSColor colorWithCalibratedRed:0.91 green:0.35 blue:0.31 alpha:1.0],
            [NSColor colorWithCalibratedRed:0.20 green:0.63 blue:0.86 alpha:1.0],
            [NSColor colorWithCalibratedRed:0.55 green:0.65 blue:0.31 alpha:1.0],
            [NSColor colorWithCalibratedRed:0.75 green:0.48 blue:0.95 alpha:1.0],
            [NSColor colorWithCalibratedRed:0.97 green:0.72 blue:0.19 alpha:1.0]
        ];
    });
    return palette;
}

@interface SNBBadgeRegistry ()
@property (nonatomic, strong) NSMutableDictionary<NSString *, NSColor *> *colorMap;
@property (nonatomic, strong) NSArray<NSColor *> *palette;
@property (nonatomic, assign) NSUInteger nextColorIndex;
@end

@implementation SNBBadgeRegistry

+ (instancetype)sharedRegistry {
    static SNBBadgeRegistry *registry;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        registry = [[SNBBadgeRegistry alloc] init];
    });
    return registry;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _colorMap = [NSMutableDictionary dictionary];
        _palette = SNBBadgeColorPalette();
        _nextColorIndex = 0;
    }
    return self;
}

- (NSColor *)colorForKey:(NSString *)key createIfMissing:(BOOL)create {
    if (key.length == 0) {
        return [NSColor labelColor];
    }
    NSColor *color = self.colorMap[key];
    if (!color && create && self.palette.count > 0) {
        color = self.palette[self.nextColorIndex % self.palette.count];
        self.nextColorIndex += 1;
        self.colorMap[key] = color;
    }
    return color ?: [NSColor labelColor];
}

- (NSColor *)colorForProcessName:(NSString *)processName
                              pid:(pid_t)pid
              createIfMissing:(BOOL)create {
    NSString *key = SNBBadgeKeyForProcess(processName, pid);
    return [self colorForKey:key createIfMissing:create];
}

- (NSColor *)colorForLabel:(NSString *)label
            createIfMissing:(BOOL)create {
    NSString *key = SNBBadgeKeyForLabel(label);
    return [self colorForKey:key createIfMissing:create];
}

- (NSString *)badgeIconForProcessName:(NSString *)processName
                                   pid:(pid_t)pid
                        fallbackLabel:(NSString *)fallback {
    if (processName.length > 0) {
        return [self initialForLabel:processName];
    }
    if (fallback.length > 0) {
        return [self initialForLabel:fallback];
    }
    return @"?";
}

- (NSString *)badgeIconForLabel:(NSString *)label fallback:(NSString *)fallback {
    NSString *source = label.length > 0 ? label : fallback;
    if (source.length > 0) {
        return [self initialForLabel:source];
    }
    return @"•";
}

- (NSString *)initialForLabel:(NSString *)label {
    for (NSUInteger i = 0; i < label.length; i++) {
        unichar character = [label characterAtIndex:i];
        if ([[NSCharacterSet alphanumericCharacterSet] characterIsMember:character]) {
            NSString *string = [[NSString stringWithCharacters:&character length:1] uppercaseString];
            return string;
        }
    }
    return @"•";
}

@end

//
//  TrafficGraphView.m
//  SniffNetBar
//

#import "TrafficGraphView.h"

@interface SNBTrafficGraphView ()
@property (nonatomic, copy) NSArray<NSNumber *> *incomingRates;
@property (nonatomic, copy) NSArray<NSNumber *> *outgoingRates;
@end

@implementation SNBTrafficGraphView

- (instancetype)initWithFrame:(NSRect)frameRect {
    self = [super initWithFrame:frameRect];
    if (self) {
        _incomingRates = @[];
        _outgoingRates = @[];
        self.wantsLayer = YES;
        self.layer.backgroundColor = [NSColor clearColor].CGColor;
    }
    return self;
}

- (BOOL)isFlipped {
    return YES;
}

- (void)updateWithIncomingRates:(NSArray<NSNumber *> *)incomingRates
                  outgoingRates:(NSArray<NSNumber *> *)outgoingRates {
    self.incomingRates = incomingRates ?: @[];
    self.outgoingRates = outgoingRates ?: @[];
    [self setNeedsDisplay:YES];
}

- (void)drawRect:(NSRect)dirtyRect {
    [super drawRect:dirtyRect];

    if (self.incomingRates.count == 0 && self.outgoingRates.count == 0) {
        return;
    }

    NSRect bounds = self.bounds;
    CGFloat padding = 3.0;
    CGFloat width = MAX(1.0, bounds.size.width - padding * 2.0);
    CGFloat height = MAX(1.0, bounds.size.height - padding * 2.0);
    CGFloat midY = padding + height * 0.5;

    NSUInteger sampleCount = MAX(self.incomingRates.count, self.outgoingRates.count);
    if (sampleCount < 2) {
        sampleCount = 2;
    }

    CGFloat maxRate = 0.0;
    for (NSNumber *value in self.incomingRates) {
        maxRate = MAX(maxRate, value.doubleValue);
    }
    for (NSNumber *value in self.outgoingRates) {
        maxRate = MAX(maxRate, value.doubleValue);
    }
    if (maxRate <= 0.0) {
        maxRate = 1.0;
    }

    NSColor *gridColor = [[NSColor secondaryLabelColor] colorWithAlphaComponent:0.15];
    [gridColor setStroke];
    NSBezierPath *gridPath = [NSBezierPath bezierPath];
    gridPath.lineWidth = 1.0;
    [gridPath moveToPoint:NSMakePoint(padding, midY)];
    [gridPath lineToPoint:NSMakePoint(padding + width, midY)];
    [gridPath stroke];

    [self drawSeries:self.incomingRates
             maxRate:maxRate
              width:width
             height:height * 0.5
            padding:padding
               midY:midY
            isUpper:YES
               color:[NSColor systemGreenColor]];

    [self drawSeries:self.outgoingRates
             maxRate:maxRate
              width:width
             height:height * 0.5
            padding:padding
               midY:midY
            isUpper:NO
               color:[NSColor systemBlueColor]];
}

- (void)drawSeries:(NSArray<NSNumber *> *)rates
           maxRate:(CGFloat)maxRate
            width:(CGFloat)width
           height:(CGFloat)halfHeight
          padding:(CGFloat)padding
             midY:(CGFloat)midY
          isUpper:(BOOL)isUpper
             color:(NSColor *)color {
    NSUInteger count = rates.count;
    if (count == 0) {
        return;
    }

    NSBezierPath *fillPath = [NSBezierPath bezierPath];
    NSBezierPath *linePath = [NSBezierPath bezierPath];
    linePath.lineWidth = 1.0;

    CGFloat step = width / (MAX(1, count - 1));
    for (NSUInteger i = 0; i < count; i++) {
        CGFloat value = rates[i].doubleValue;
        CGFloat normalized = MIN(1.0, MAX(0.0, value / maxRate));
        CGFloat x = padding + step * i;
        CGFloat yOffset = normalized * (halfHeight - 1.0);
        CGFloat y = isUpper ? (midY - yOffset) : (midY + yOffset);

        if (i == 0) {
            [fillPath moveToPoint:NSMakePoint(x, midY)];
            [fillPath lineToPoint:NSMakePoint(x, y)];
            [linePath moveToPoint:NSMakePoint(x, y)];
        } else {
            [fillPath lineToPoint:NSMakePoint(x, y)];
            [linePath lineToPoint:NSMakePoint(x, y)];
        }
    }

    CGFloat endX = padding + step * (count - 1);
    [fillPath lineToPoint:NSMakePoint(endX, midY)];
    [fillPath closePath];

    NSColor *startColor = [color colorWithAlphaComponent:0.35];
    NSColor *endColor = [color colorWithAlphaComponent:0.08];
    NSGradient *gradient = [[NSGradient alloc] initWithStartingColor:startColor endingColor:endColor];
    NSRect gradientRect = NSMakeRect(padding, isUpper ? padding : midY, width, halfHeight);
    [gradient drawInBezierPath:fillPath angle:isUpper ? -90.0 : 90.0];

    [[color colorWithAlphaComponent:0.85] setStroke];
    [linePath stroke];
}

@end

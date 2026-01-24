//
//  TrafficGraphView.h
//  SniffNetBar
//

#import <Cocoa/Cocoa.h>

NS_ASSUME_NONNULL_BEGIN

@interface SNBTrafficGraphView : NSView

- (void)updateWithIncomingRates:(NSArray<NSNumber *> *)incomingRates
                  outgoingRates:(NSArray<NSNumber *> *)outgoingRates;

@end

NS_ASSUME_NONNULL_END

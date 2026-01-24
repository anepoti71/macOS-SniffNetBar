//
//  SNBPromotionDecision.h
//  SniffNetBar
//
//  Output of the promotion evaluation.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, SNBPromotionAction) {
    SNBPromotionActionNone = 0,          // No action (keep observing)
    SNBPromotionActionSuggest,           // Suggest to user
    SNBPromotionActionAutoPromote,       // Auto-promote to trusted
    SNBPromotionActionAutoBlock,         // Auto-block (high threat intel)
    SNBPromotionActionNeedsReview        // Flag for manual review
};

@interface SNBPromotionDecision : NSObject <NSSecureCoding>

@property (nonatomic, copy) NSString *clusterID;
@property (nonatomic, assign) SNBPromotionAction action;
@property (nonatomic, copy) NSString *reason;
@property (nonatomic, copy) NSArray<NSString *> *factors;
@property (nonatomic, copy) NSArray<NSString *> *blockers;
@property (nonatomic, assign) NSInteger confidence;
@property (nonatomic, assign) NSInteger score;
@property (nonatomic, assign) uint64_t seenCount;
@property (nonatomic, strong) NSDate *evaluatedAt;

// Extended context for UI display
@property (nonatomic, copy, nullable) NSString *processName;
@property (nonatomic, copy, nullable) NSString *destinationFamily;
@property (nonatomic, copy, nullable) NSString *destinationIP;
@property (nonatomic, copy, nullable) NSString *extendedContext;

- (NSString *)actionDescription;

@end

NS_ASSUME_NONNULL_END

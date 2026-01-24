//
//  SNBModelingUtilities.h
//  SniffNetBar
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@class SNBFlowEvent;

NSString *SNBClusterIDForEvent(SNBFlowEvent *event);
NSString *SNBExtendedContextJSONForEvent(SNBFlowEvent *event);
BOOL SNBEventIsIPOnly(SNBFlowEvent *event);
NSString *SNBDomainFamilyFromHost(NSString *host);

NS_ASSUME_NONNULL_END

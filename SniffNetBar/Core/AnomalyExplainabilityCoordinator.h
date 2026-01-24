//
//  AnomalyExplainabilityCoordinator.h
//  SniffNetBar
//
//  Orchestrates local LLM explainability for anomaly windows
//

#import <Foundation/Foundation.h>

@class ConfigurationManager;
@class ThreatIntelCoordinator;

NS_ASSUME_NONNULL_BEGIN

@interface SNBAnomalyExplainabilityCoordinator : NSObject

- (instancetype)initWithConfiguration:(ConfigurationManager *)configuration
              threatIntelCoordinator:(ThreatIntelCoordinator *)threatIntelCoordinator;

- (void)processPendingExplanations;

@end

NS_ASSUME_NONNULL_END

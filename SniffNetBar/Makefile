#
# Makefile for macOS-SniffNetBar (repo) and SniffNetBar (app)
# Objective-C menubar application for network traffic monitoring
#

APP_NAME = SniffNetBar
BUILD_DIR = build
APP_BUNDLE = $(BUILD_DIR)/$(APP_NAME).app
CONTENTS_DIR = $(APP_BUNDLE)/Contents
MACOS_DIR = $(CONTENTS_DIR)/MacOS
RESOURCES_DIR = $(CONTENTS_DIR)/Resources
XPC_SERVICES_DIR = $(CONTENTS_DIR)/XPCServices
HELPER_NAME = com.sniffnetbar.helper
HELPER_BUNDLE = $(BUILD_DIR)/$(HELPER_NAME).app
HELPER_BINARY = $(HELPER_BUNDLE)/Contents/MacOS/$(HELPER_NAME)
APP_LAUNCHDAEMONS_DIR = $(CONTENTS_DIR)/Library/LaunchDaemons
INSTALL_DIR = $(HOME)/Applications
INSTALL_APP = $(INSTALL_DIR)/$(APP_NAME).app
INFO_PLIST_SRC = Info.plist
ICON_SRC = ../resources/logo/icon_macos.png
OUI_SRC = ../resources/oui.csv
FRAMEWORKS = -framework Cocoa -framework SystemConfiguration -framework WebKit -framework CoreLocation -framework Security -framework CoreML -framework ServiceManagement
PCAP_LIBS = -lpcap
SQLITE_LIBS = -lsqlite3
CC = clang
CFLAGS = -std=c11 -Wall -Wextra -O2
OBJCFLAGS = -fobjc-arc -fobjc-weak -std=gnu11 -Wall -Wextra -O2 -DSNB_LOG_LEVEL_MINIMUM=SNBLogLevelDebug

# Find macOS SDK
SDKROOT = $(shell xcrun --show-sdk-path 2>/dev/null || echo /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk)
SDK_FLAGS = -isysroot $(SDKROOT) -mmacosx-version-min=10.13

# Find libpcap (assuming installed via Homebrew)
PCAP_INCLUDE = -I/opt/homebrew/include -I/usr/local/include
PCAP_LIBDIR = -L/opt/homebrew/lib -L/usr/local/lib

# Include paths for organized folders
PROJECT_INCLUDES = -I. -ICore -IConfig -IModels -IBehaviorModel -INetwork -IThreatIntel -IThreatIntel/Providers -IUI -IUtils -IXPC -ITests -ITests/ThreatIntel -ITests/ThreatIntel/Providers -IPromotionAgent
HELPER_INCLUDES = -I../SniffNetBar -I../SniffNetBar/Models -I../SniffNetBar/Network -I../SniffNetBar/Utils -I../SniffNetBar/XPC -I../SniffNetBar/Config

# Source files (organized by domain)
CORE_SOURCES = Core/main.m Core/AppDelegate.m Core/AppCoordinator.m \
               Core/AnomalyExplainabilityCoordinator.m
CONFIG_SOURCES = Config/ConfigurationManager.m Config/KeychainManager.m Config/UserDefaultsKeys.m
MODEL_SOURCES = Models/PacketInfo.m Models/TrafficStatistics.m Models/StatisticsHistory.m \
                Models/AnomalyDetector.m Models/AnomalyStore.m \
                Models/AnomalyPythonScorer.m Models/AnomalyCoreMLScorer.m \
                Models/AnomalyExplanationService.m Models/TrustedIPStore.m \
                Models/TrustLearningModels.m Models/TrustFeatureExtractor.m \
                Models/TrustLearningEngine.m Models/AdaptiveScoring.m \
                Models/ProcessRiskModels.m Models/ProcessRiskEvaluator.m \
                Models/ProcessIdentityModels.m Models/ProcessIdentityStore.m
MODELING_SOURCES = BehaviorModel/SNBEventSchema.m BehaviorModel/SNBEventPublisher.m \
                   BehaviorModel/SNBModelingXPCService.m BehaviorModel/SNBEventStore.m \
                   BehaviorModel/SNBAggregateEngine.m BehaviorModel/SNBRecommendationStore.m \
                   BehaviorModel/SNBScoringEngine.m BehaviorModel/SNBModelingUtilities.m \
                   BehaviorModel/SNBBehaviorDatabase.m BehaviorModel/SNBScoringConfig.m
NETWORK_SOURCES = Network/PacketCaptureManager.m Network/NetworkDevice.m \
                  Network/DeviceManager.m Network/NetworkAssetMonitor.m
THREATINTEL_SOURCES = ThreatIntel/ThreatIntelModels.m \
                      ThreatIntel/ThreatIntelProvider.m \
                      ThreatIntel/ThreatIntelCache.m \
                      ThreatIntel/ThreatIntelStore.m \
                      ThreatIntel/ThreatIntelFacade.m \
                      ThreatIntel/ThreatIntelCoordinator.m \
                      ThreatIntel/Providers/VirusTotalProvider.m \
                      ThreatIntel/Providers/AbuseIPDBProvider.m \
                      ThreatIntel/Providers/GreyNoiseProvider.m \
                      ThreatIntel/Providers/ShodanProvider.m
UI_SOURCES = UI/MapMenuView.m UI/MenuBuilder.m UI/MenuBuilder+ThreatDisplay.m UI/TrafficGraphView.m
PROMOTION_SOURCES = PromotionAgent/SNBPromotionAgent.m PromotionAgent/SNBPromotionPolicy.m \
                    PromotionAgent/SNBPromotionDecision.m PromotionAgent/SNBPromotionCandidate.m \
                    PromotionAgent/SNBPromotionEvaluator.m PromotionAgent/SNBPromotionLog.m \
                    PromotionAgent/SNBOllamaClient.m
UTIL_SOURCES = Utils/ByteFormatter.m Utils/ExpiringCache.m Utils/IPAddressUtilities.m Utils/Logger.m Utils/ProcessLookup.m Utils/ProcessLookup_lsof.m Utils/ProcessLookup_Native.m Utils/SNBSocketPIDMap.m Utils/SMAppServiceHelper.m Utils/SNBPrivilegedHelperClient.m Utils/SNBLocationStore.m Utils/SNBTimerCoordinator.m UI/SNBBadgeRegistry.m
XPC_SOURCES = XPC/PacketInfo+Serialization.m XPC/ProcessInfo+Serialization.m XPC/NetworkDevice+Serialization.m

# Test sources
TEST_SOURCES = Tests/ThreatIntel/ThreatIntelCacheTests.m \
               Tests/ThreatIntel/ThreatIntelModelsTests.m \
               Tests/ThreatIntel/ThreatIntelFacadeTests.m \
               Tests/ThreatIntel/MockThreatIntelProvider.m \
               Tests/ThreatIntel/Providers/ProviderTests.m

# All sources
SOURCES = $(CORE_SOURCES) $(CONFIG_SOURCES) $(MODEL_SOURCES) $(MODELING_SOURCES) \
          $(NETWORK_SOURCES) $(THREATINTEL_SOURCES) $(UI_SOURCES) $(PROMOTION_SOURCES) \
          $(UTIL_SOURCES) $(XPC_SOURCES)

# Library sources (for tests - exclude main.m and AppDelegate.m)
LIB_SOURCES = $(CONFIG_SOURCES) $(MODEL_SOURCES) $(MODELING_SOURCES) $(NETWORK_SOURCES) \
              $(THREATINTEL_SOURCES) $(UI_SOURCES) $(PROMOTION_SOURCES) $(UTIL_SOURCES) $(XPC_SOURCES)

OBJECTS = $(SOURCES:%.m=$(BUILD_DIR)/%.o)
LIB_OBJECTS = $(LIB_SOURCES:%.m=$(BUILD_DIR)/%.o)
TEST_OBJECTS = $(TEST_SOURCES:%.m=$(BUILD_DIR)/%.o)

# Helper sources
HELPER_SOURCES = $(shell find ../SniffNetBarHelper -name '*.m')

# Code signing identity (set locally for SMAppService)
# Note: No quotes here - they'll be added in codesign commands
CODESIGN_IDENTITY ?=

# Local overrides
-include Makefile.local

# Targets
all: helper $(APP_BUNDLE) tools

$(APP_BUNDLE): $(MACOS_DIR)/$(APP_NAME) $(HELPER_BINARY) $(BUILD_DIR)/unregister_helper $(BUILD_DIR)/ModelingXPCService.xpc $(INFO_PLIST_SRC) | $(RESOURCES_DIR)
	@cp $(INFO_PLIST_SRC) $(CONTENTS_DIR)/Info.plist
	@cp Config/Configuration.plist $(RESOURCES_DIR)/Configuration.plist
	@cp $(ICON_SRC) $(RESOURCES_DIR)/icon_macos.png
	@cp $(OUI_SRC) $(RESOURCES_DIR)/oui.csv
	@cp Scripts/anomaly_score.py $(RESOURCES_DIR)/anomaly_score.py
	@cp Scripts/anomaly_train.py $(RESOURCES_DIR)/anomaly_train.py
	@cp Scripts/convert_iforest_to_coreml.py $(RESOURCES_DIR)/convert_iforest_to_coreml.py
	@cp Resources/traffic_report_template.html $(RESOURCES_DIR)/traffic_report_template.html
	@cp Resources/public_suffix_list.dat $(RESOURCES_DIR)/public_suffix_list.dat
	@if [ ! -d Resources/vendor ]; then echo "Missing Resources/vendor; run vendor asset download step."; exit 1; fi
	@if [ -d Resources/vendor ]; then cp -R Resources/vendor $(RESOURCES_DIR)/vendor; fi
	@if [ -d ../resources/anomaly_model.mlmodelc ]; then cp -R ../resources/anomaly_model.mlmodelc $(RESOURCES_DIR)/anomaly_model.mlmodelc; fi
	@cp $(BUILD_DIR)/unregister_helper $(MACOS_DIR)/unregister_helper
	@mkdir -p $(XPC_SERVICES_DIR)
	@cp -R $(BUILD_DIR)/ModelingXPCService.xpc $(XPC_SERVICES_DIR)/
	@if [ -n "$(CODESIGN_IDENTITY)" ]; then \
		echo "Signing ModelingXPCService.xpc..."; \
		codesign --force --options runtime --sign "$(CODESIGN_IDENTITY)" \
			$(XPC_SERVICES_DIR)/ModelingXPCService.xpc; \
	else \
		echo "Warning: CODESIGN_IDENTITY not set, XPC service unsigned"; \
	fi
	@mkdir -p $(APP_LAUNCHDAEMONS_DIR)
	@cp -R $(HELPER_BUNDLE) $(APP_LAUNCHDAEMONS_DIR)/
	@cp ../SniffNetBarHelper/launchd.plist $(APP_LAUNCHDAEMONS_DIR)/$(HELPER_NAME).plist
	@/usr/libexec/PlistBuddy -c "Set :ProgramArguments:0 $(abspath $(APP_BUNDLE))/Contents/Library/LaunchDaemons/$(HELPER_NAME).app/Contents/MacOS/$(HELPER_NAME)" \
		$(APP_LAUNCHDAEMONS_DIR)/$(HELPER_NAME).plist
	@echo "Signing main application bundle..."
	@if [ -n "$(CODESIGN_IDENTITY)" ]; then \
		codesign --force --options runtime --entitlements Config/SniffNetBar.entitlements \
			--sign "$(CODESIGN_IDENTITY)" --deep $(APP_BUNDLE); \
		echo "Main app signed successfully"; \
	else \
		echo "Warning: CODESIGN_IDENTITY not set, skipping code signing"; \
	fi

$(MACOS_DIR)/$(APP_NAME): $(OBJECTS) | $(MACOS_DIR)
	$(CC) $(OBJCFLAGS) $(SDK_FLAGS) $(OBJECTS) -o $@ $(FRAMEWORKS) $(PCAP_LIBDIR) $(PCAP_LIBS) $(SQLITE_LIBS)

$(BUILD_DIR)/%.o: %.m | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	$(CC) $(OBJCFLAGS) $(SDK_FLAGS) $(PROJECT_INCLUDES) $(PCAP_INCLUDE) -c $< -o $@

helper: $(HELPER_BINARY)

$(HELPER_BINARY): $(HELPER_SOURCES) | $(BUILD_DIR)
	@echo "Building privileged helper bundle..."
	@mkdir -p $(HELPER_BUNDLE)/Contents/MacOS
	@mkdir -p $(HELPER_BUNDLE)/Contents/LaunchDaemons
	$(CC) $(OBJCFLAGS) $(SDK_FLAGS) $(HELPER_INCLUDES) $(PCAP_INCLUDE) \
		$(HELPER_SOURCES) \
		../SniffNetBar/Models/PacketInfo.m \
		../SniffNetBar/XPC/PacketInfo+Serialization.m \
		../SniffNetBar/XPC/ProcessInfo+Serialization.m \
		-o $(HELPER_BINARY) \
		$(PCAP_LIBDIR) $(PCAP_LIBS) -framework Foundation -framework Security
	@cp ../SniffNetBarHelper/Info.plist $(HELPER_BUNDLE)/Contents/Info.plist
	@cp ../SniffNetBarHelper/launchd.plist $(HELPER_BUNDLE)/Contents/LaunchDaemons/$(HELPER_NAME).plist
	@echo "Signing helper binary and bundle..."
	@if [ -n "$(CODESIGN_IDENTITY)" ]; then \
		codesign --force --options runtime --entitlements ../SniffNetBarHelper/SniffNetBarHelper.entitlements \
			--sign "$(CODESIGN_IDENTITY)" $(HELPER_BINARY); \
		codesign --force --options runtime --sign "$(CODESIGN_IDENTITY)" $(HELPER_BUNDLE); \
		echo "Helper signed successfully"; \
	else \
		echo "Warning: CODESIGN_IDENTITY not set, skipping helper code signing"; \
	fi

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(MACOS_DIR):
	mkdir -p $(MACOS_DIR)

$(RESOURCES_DIR):
	mkdir -p $(RESOURCES_DIR)

# Command-line tools for API key management and testing
tools: $(BUILD_DIR)/set_apikey $(BUILD_DIR)/remove_apikey $(BUILD_DIR)/list_apikeys $(BUILD_DIR)/unregister_helper $(BUILD_DIR)/register_helper $(BUILD_DIR)/status_helper $(BUILD_DIR)/behavior_model_cli

# Test utilities
test-threat-intel: $(BUILD_DIR)/test_threat_intel
test-process-lookup: $(BUILD_DIR)/test_process_lookup
test-native-lookup: $(BUILD_DIR)/test_native_lookup

$(BUILD_DIR)/test_threat_intel: Tools/test_threat_intel.m $(BUILD_DIR)/Tests/ThreatIntel/MockThreatIntelProvider.o $(BUILD_DIR)/ThreatIntel/ThreatIntelFacade.o $(BUILD_DIR)/ThreatIntel/ThreatIntelModels.o $(BUILD_DIR)/ThreatIntel/ThreatIntelCache.o $(BUILD_DIR)/ThreatIntel/ThreatIntelProvider.o $(BUILD_DIR)/Utils/ExpiringCache.o $(BUILD_DIR)/Utils/Logger.o $(BUILD_DIR)/Config/ConfigurationManager.o $(BUILD_DIR)/Utils/IPAddressUtilities.o $(BUILD_DIR)/Config/KeychainManager.o | $(BUILD_DIR)
	@echo "Building test_threat_intel tool..."
	$(CC) $(OBJCFLAGS) $(SDK_FLAGS) $(PROJECT_INCLUDES) Tools/test_threat_intel.m \
		$(BUILD_DIR)/Tests/ThreatIntel/MockThreatIntelProvider.o \
		$(BUILD_DIR)/ThreatIntel/ThreatIntelFacade.o \
		$(BUILD_DIR)/ThreatIntel/ThreatIntelModels.o \
		$(BUILD_DIR)/ThreatIntel/ThreatIntelCache.o \
		$(BUILD_DIR)/ThreatIntel/ThreatIntelProvider.o \
		$(BUILD_DIR)/Utils/ExpiringCache.o \
		$(BUILD_DIR)/Utils/Logger.o \
		$(BUILD_DIR)/Config/ConfigurationManager.o \
		$(BUILD_DIR)/Utils/IPAddressUtilities.o \
		$(BUILD_DIR)/Config/KeychainManager.o \
		-o $@ $(FRAMEWORKS)

$(BUILD_DIR)/test_process_lookup: Tools/test_process_lookup.m $(BUILD_DIR)/Utils/ProcessLookup.o $(BUILD_DIR)/Utils/Logger.o $(BUILD_DIR)/Config/ConfigurationManager.o $(BUILD_DIR)/Config/KeychainManager.o | $(BUILD_DIR)
	@echo "Building test_process_lookup tool..."
	$(CC) $(OBJCFLAGS) $(SDK_FLAGS) $(PROJECT_INCLUDES) Tools/test_process_lookup.m \
		$(BUILD_DIR)/Utils/ProcessLookup.o \
		$(BUILD_DIR)/Utils/Logger.o \
		$(BUILD_DIR)/Config/ConfigurationManager.o \
		$(BUILD_DIR)/Config/KeychainManager.o \
		-o $@ $(FRAMEWORKS)

$(BUILD_DIR)/test_native_lookup: Tools/test_native_lookup.m $(BUILD_DIR)/Utils/ProcessLookup.o $(BUILD_DIR)/Utils/ProcessLookup_Native.o $(BUILD_DIR)/Utils/ProcessLookup_lsof.o $(BUILD_DIR)/Utils/SNBPrivilegedHelperClient.o $(BUILD_DIR)/XPC/ProcessInfo+Serialization.o $(BUILD_DIR)/XPC/PacketInfo+Serialization.o $(BUILD_DIR)/XPC/NetworkDevice+Serialization.o $(BUILD_DIR)/Models/PacketInfo.o $(BUILD_DIR)/Network/NetworkDevice.o $(BUILD_DIR)/Utils/Logger.o $(BUILD_DIR)/Config/ConfigurationManager.o $(BUILD_DIR)/Config/KeychainManager.o | $(BUILD_DIR)
	@echo "Building test_native_lookup tool..."
	$(CC) $(OBJCFLAGS) $(SDK_FLAGS) $(PROJECT_INCLUDES) Tools/test_native_lookup.m \
		$(BUILD_DIR)/Utils/ProcessLookup.o \
		$(BUILD_DIR)/Utils/ProcessLookup_Native.o \
		$(BUILD_DIR)/Utils/ProcessLookup_lsof.o \
		$(BUILD_DIR)/Utils/SNBPrivilegedHelperClient.o \
		$(BUILD_DIR)/XPC/ProcessInfo+Serialization.o \
		$(BUILD_DIR)/XPC/PacketInfo+Serialization.o \
		$(BUILD_DIR)/XPC/NetworkDevice+Serialization.o \
		$(BUILD_DIR)/Models/PacketInfo.o \
		$(BUILD_DIR)/Network/NetworkDevice.o \
		$(BUILD_DIR)/Utils/Logger.o \
		$(BUILD_DIR)/Config/ConfigurationManager.o \
		$(BUILD_DIR)/Config/KeychainManager.o \
		-o $@ $(FRAMEWORKS) $(PCAP_LIBDIR) $(PCAP_LIBS)

$(BUILD_DIR)/set_apikey: Scripts/set_apikey.m $(BUILD_DIR)/Config/KeychainManager.o $(BUILD_DIR)/Config/ConfigurationManager.o $(BUILD_DIR)/Config/UserDefaultsKeys.o $(BUILD_DIR)/Utils/Logger.o
	@echo "Building set_apikey tool..."
	$(CC) $(OBJCFLAGS) $(SDK_FLAGS) $(PROJECT_INCLUDES) Scripts/set_apikey.m $(BUILD_DIR)/Config/KeychainManager.o $(BUILD_DIR)/Config/ConfigurationManager.o $(BUILD_DIR)/Config/UserDefaultsKeys.o $(BUILD_DIR)/Utils/Logger.o -o $(BUILD_DIR)/set_apikey $(FRAMEWORKS)

$(BUILD_DIR)/remove_apikey: Scripts/remove_apikey.m $(BUILD_DIR)/Config/KeychainManager.o $(BUILD_DIR)/Config/ConfigurationManager.o $(BUILD_DIR)/Config/UserDefaultsKeys.o $(BUILD_DIR)/Utils/Logger.o
	@echo "Building remove_apikey tool..."
	$(CC) $(OBJCFLAGS) $(SDK_FLAGS) $(PROJECT_INCLUDES) Scripts/remove_apikey.m $(BUILD_DIR)/Config/KeychainManager.o $(BUILD_DIR)/Config/ConfigurationManager.o $(BUILD_DIR)/Config/UserDefaultsKeys.o $(BUILD_DIR)/Utils/Logger.o -o $(BUILD_DIR)/remove_apikey $(FRAMEWORKS)

$(BUILD_DIR)/list_apikeys: Scripts/list_apikeys.m $(BUILD_DIR)/Config/KeychainManager.o $(BUILD_DIR)/Config/ConfigurationManager.o $(BUILD_DIR)/Config/UserDefaultsKeys.o $(BUILD_DIR)/Utils/Logger.o
	@echo "Building list_apikeys tool..."
	$(CC) $(OBJCFLAGS) $(SDK_FLAGS) $(PROJECT_INCLUDES) Scripts/list_apikeys.m $(BUILD_DIR)/Config/KeychainManager.o $(BUILD_DIR)/Config/ConfigurationManager.o $(BUILD_DIR)/Config/UserDefaultsKeys.o $(BUILD_DIR)/Utils/Logger.o -o $(BUILD_DIR)/list_apikeys $(FRAMEWORKS)

$(BUILD_DIR)/unregister_helper: Tools/unregister_helper.m $(BUILD_DIR)/Utils/SMAppServiceHelper.o $(BUILD_DIR)/Utils/Logger.o $(BUILD_DIR)/Config/ConfigurationManager.o $(BUILD_DIR)/Config/UserDefaultsKeys.o $(BUILD_DIR)/Config/KeychainManager.o | $(BUILD_DIR)
	@echo "Building unregister_helper tool..."
	$(CC) $(OBJCFLAGS) $(SDK_FLAGS) $(PROJECT_INCLUDES) Tools/unregister_helper.m \
		$(BUILD_DIR)/Utils/SMAppServiceHelper.o \
		$(BUILD_DIR)/Utils/Logger.o \
		$(BUILD_DIR)/Config/ConfigurationManager.o \
		$(BUILD_DIR)/Config/UserDefaultsKeys.o \
		$(BUILD_DIR)/Config/KeychainManager.o \
		-o $(BUILD_DIR)/unregister_helper $(FRAMEWORKS)

$(BUILD_DIR)/register_helper: Tools/register_helper.m $(BUILD_DIR)/Utils/SMAppServiceHelper.o $(BUILD_DIR)/Utils/Logger.o $(BUILD_DIR)/Config/ConfigurationManager.o $(BUILD_DIR)/Config/UserDefaultsKeys.o $(BUILD_DIR)/Config/KeychainManager.o | $(BUILD_DIR)
	@echo "Building register_helper tool..."
	$(CC) $(OBJCFLAGS) $(SDK_FLAGS) $(PROJECT_INCLUDES) Tools/register_helper.m \
		$(BUILD_DIR)/Utils/SMAppServiceHelper.o \
		$(BUILD_DIR)/Utils/Logger.o \
		$(BUILD_DIR)/Config/ConfigurationManager.o \
		$(BUILD_DIR)/Config/UserDefaultsKeys.o \
		$(BUILD_DIR)/Config/KeychainManager.o \
		-o $(BUILD_DIR)/register_helper $(FRAMEWORKS)

$(BUILD_DIR)/status_helper: Tools/status_helper.m $(BUILD_DIR)/Utils/SMAppServiceHelper.o $(BUILD_DIR)/Utils/Logger.o $(BUILD_DIR)/Config/ConfigurationManager.o $(BUILD_DIR)/Config/UserDefaultsKeys.o $(BUILD_DIR)/Config/KeychainManager.o | $(BUILD_DIR)
	@echo "Building status_helper tool..."
	$(CC) $(OBJCFLAGS) $(SDK_FLAGS) $(PROJECT_INCLUDES) Tools/status_helper.m \
		$(BUILD_DIR)/Utils/SMAppServiceHelper.o \
		$(BUILD_DIR)/Utils/Logger.o \
		$(BUILD_DIR)/Config/ConfigurationManager.o \
		$(BUILD_DIR)/Config/UserDefaultsKeys.o \
		$(BUILD_DIR)/Config/KeychainManager.o \
		-o $(BUILD_DIR)/status_helper $(FRAMEWORKS)

$(BUILD_DIR)/behavior_model_cli: Tests/behavior_model_cli.m | $(BUILD_DIR)
	@echo "Building behavior_model_cli tool..."
	$(CC) $(OBJCFLAGS) $(SDK_FLAGS) $(PROJECT_INCLUDES) Tests/behavior_model_cli.m \
		-o $(BUILD_DIR)/behavior_model_cli $(SQLITE_LIBS) $(FRAMEWORKS)

clean:
	rm -rf $(BUILD_DIR)
	rm -rf $(INSTALL_APP)

install: $(APP_BUNDLE) tools
	@echo "Installing $(APP_NAME)..."
	@echo "Stopping running $(APP_NAME) instances (if any)..."
	@pkill -x $(APP_NAME) >/dev/null 2>&1 || true
	@mkdir -p $(INSTALL_DIR)
	@cp -R $(APP_BUNDLE) $(INSTALL_DIR)/
	@cp $(BUILD_DIR)/register_helper $(INSTALL_APP)/Contents/MacOS/register_helper
	@/usr/libexec/PlistBuddy -c "Set :ProgramArguments:0 $(abspath $(INSTALL_APP))/Contents/Library/LaunchDaemons/$(HELPER_NAME).app/Contents/MacOS/$(HELPER_NAME)" \
		$(INSTALL_APP)/Contents/Library/LaunchDaemons/$(HELPER_NAME).plist
	@if [ -n "$(CODESIGN_IDENTITY)" ]; then \
		echo "Re-signing installed bundles..."; \
		codesign --force --options runtime --entitlements ../SniffNetBarHelper/SniffNetBarHelper.entitlements \
			--sign "$(CODESIGN_IDENTITY)" $(INSTALL_APP)/Contents/Library/LaunchDaemons/$(HELPER_NAME).app/Contents/MacOS/$(HELPER_NAME); \
		codesign --force --options runtime --sign "$(CODESIGN_IDENTITY)" \
			$(INSTALL_APP)/Contents/Library/LaunchDaemons/$(HELPER_NAME).app; \
		codesign --force --options runtime --entitlements Config/SniffNetBar.entitlements \
			--sign "$(CODESIGN_IDENTITY)" --deep $(INSTALL_APP); \
		echo "Installed bundles re-signed"; \
	else \
		echo "Warning: CODESIGN_IDENTITY not set, installed bundles not re-signed"; \
	fi
	@echo "Installed to $(INSTALL_APP)"
	@echo ""
	@echo "Note: The application will request root privileges on startup for packet capture."

dmg: $(APP_BUNDLE)
	@echo "Creating DMG installer..."
	@./Scripts/create_dmg.sh

run:
	@if [ ! -d "$(INSTALL_APP)" ]; then \
		echo "Error: $(INSTALL_APP) not found – run 'make install' first."; \
		exit 1; \
	fi
	@echo "Ensuring helper is registered..."
	@if [ -x "$(INSTALL_APP)/Contents/MacOS/register_helper" ]; then \
		if "$(INSTALL_APP)/Contents/MacOS/register_helper" --status >/dev/null 2>&1; then \
			echo "Helper already registered."; \
		else \
			echo "Registering helper..."; \
			"$(INSTALL_APP)/Contents/MacOS/register_helper"; \
		fi \
	else \
		echo "Warning: register_helper missing at $(INSTALL_APP)/Contents/MacOS/register_helper"; \
	fi
	@echo "Running $(APP_NAME)..."
	@pkill -x $(APP_NAME) >/dev/null 2>&1 || true
	@open -n $(INSTALL_APP) || $(INSTALL_APP)/Contents/MacOS/$(APP_NAME)

# Test targets
TEST_BUNDLE = $(BUILD_DIR)/Tests.xctest
TEST_BUNDLE_DIR = $(TEST_BUNDLE)/Contents/MacOS
TEST_FRAMEWORKS = -framework XCTest

test: $(BUILD_DIR)/TestRunner
	@echo "Running tests..."
	$(BUILD_DIR)/TestRunner

$(BUILD_DIR)/TestRunner: $(LIB_OBJECTS) $(TEST_OBJECTS) | $(BUILD_DIR)
	@echo "Building test runner..."
	$(CC) $(OBJCFLAGS) $(SDK_FLAGS) $(LIB_OBJECTS) $(TEST_OBJECTS) -o $@ \
		$(FRAMEWORKS) $(TEST_FRAMEWORKS) $(PCAP_LIBDIR) $(PCAP_LIBS) $(SQLITE_LIBS) \
		-Xlinker -bundle_loader -Xlinker /Applications/Xcode.app/Contents/Developer/usr/bin/xctest

test-build: $(LIB_OBJECTS) $(TEST_OBJECTS)
	@echo "Test files compiled successfully"

.PHONY: all clean install dmg run test tools test-build test-threat-intel test-process-lookup helper
$(BUILD_DIR)/ModelingXPCService.xpc: $(BUILD_DIR)/ModelingXPCService | $(BUILD_DIR)
	@echo "Packaging ModelingXPCService.xpc..."
	@mkdir -p $(BUILD_DIR)/ModelingXPCService.xpc/Contents/MacOS
	@cp Services/ModelingXPCService/Info.plist $(BUILD_DIR)/ModelingXPCService.xpc/Contents/Info.plist
	@cp $(BUILD_DIR)/ModelingXPCService $(BUILD_DIR)/ModelingXPCService.xpc/Contents/MacOS/ModelingXPCService

$(BUILD_DIR)/ModelingXPCService: Services/ModelingXPCService/main.m $(LIB_OBJECTS) | $(BUILD_DIR)
	@echo "Building ModelingXPCService..."
	$(CC) $(OBJCFLAGS) $(SDK_FLAGS) $(PROJECT_INCLUDES) Services/ModelingXPCService/main.m \
		$(LIB_OBJECTS) -o $(BUILD_DIR)/ModelingXPCService $(FRAMEWORKS) $(SQLITE_LIBS)

//
//  Logger.h
//  SniffNetBar
//
//  Unified logging system with level-aware macros and os_log integration
//

#import <Foundation/Foundation.h>
#import <os/log.h>

// MARK: - Log Levels

typedef NS_ENUM(NSInteger, SNBLogLevel) {
    SNBLogLevelOff = -1,    // Disable all logging
    SNBLogLevelError = 0,   // Critical errors, always logged
    SNBLogLevelWarn = 1,    // Warnings, important issues
    SNBLogLevelInfo = 2,    // Informational messages
    SNBLogLevelDebug = 3    // Detailed debugging information
};

// MARK: - Compile-Time Configuration

// Compile-time minimum log level (can be overridden via build flags)
#ifndef SNB_LOG_LEVEL_MINIMUM
    #ifdef DEBUG
        #define SNB_LOG_LEVEL_MINIMUM SNBLogLevelDebug
    #else
        #define SNB_LOG_LEVEL_MINIMUM SNBLogLevelInfo
    #endif
#endif

// MARK: - Subsystem and Categories

// Subsystem identifier for os_log
#define SNB_LOG_SUBSYSTEM "com.sniffnetbar"

// Category identifiers
#define SNB_LOG_CATEGORY_CORE "core"
#define SNB_LOG_CATEGORY_NETWORK "network"
#define SNB_LOG_CATEGORY_THREAT_INTEL "threat-intel"
#define SNB_LOG_CATEGORY_UI "ui"
#define SNB_LOG_CATEGORY_CONFIG "config"
#define SNB_LOG_CATEGORY_AGENT "agent"
#define SNB_LOG_CATEGORY_BEHAVIOR "behavior"

// MARK: - Runtime Log Level Control

// Returns the runtime log level based on configuration and build type
extern SNBLogLevel SNBGetRuntimeLogLevel(void);

// Enable/disable console output (in addition to os_log)
// When enabled, logs are printed to stderr as well as os_log
extern void SNBSetConsoleLoggingEnabled(BOOL enabled);
extern BOOL SNBIsConsoleLoggingEnabled(void);

// MARK: - Privacy Helpers

// Privacy annotations for IP addresses
// In DEBUG builds, show IPs; in RELEASE builds, redact them
#ifdef DEBUG
    #define SNB_IP_PRIVACY "public"
#else
    #define SNB_IP_PRIVACY "private"
#endif

// MARK: - Core Logging Implementation

// Helper to get level name
static inline const char* SNBLogLevelName(SNBLogLevel level) {
    switch (level) {
        case SNBLogLevelOff:   return "OFF  ";
        case SNBLogLevelError: return "ERROR";
        case SNBLogLevelWarn:  return "WARN ";
        case SNBLogLevelInfo:  return "INFO ";
        case SNBLogLevelDebug: return "DEBUG";
        default: return "?????";
    }
}

// Internal logging implementation macro
// Performance: Use __builtin_expect for branch prediction optimization
#define SNB_LOG_IMPL(level, category, fmt, ...) \
    do { \
        if (__builtin_expect(level <= SNB_LOG_LEVEL_MINIMUM && level <= SNBGetRuntimeLogLevel(), 0)) { \
            os_log_t log_obj = os_log_create(SNB_LOG_SUBSYSTEM, category); \
            if (level == SNBLogLevelError) { \
                os_log_error(log_obj, fmt, ##__VA_ARGS__); \
            } else if (level == SNBLogLevelWarn) { \
                os_log_fault(log_obj, fmt, ##__VA_ARGS__); \
            } else if (level == SNBLogLevelInfo) { \
                os_log_info(log_obj, fmt, ##__VA_ARGS__); \
            } else { \
                os_log_debug(log_obj, fmt, ##__VA_ARGS__); \
            } \
            if (SNBIsConsoleLoggingEnabled()) { \
                fprintf(stderr, "[%s][%s] " fmt "\n", SNBLogLevelName(level), category, ##__VA_ARGS__); \
                fflush(stderr); \
            } \
        } \
    } while(0)

// Public logging entrypoint for explicit level/category usage
#define SNB_LOG(level, category, fmt, ...) \
    SNB_LOG_IMPL(level, category, fmt, ##__VA_ARGS__)

// MARK: - Core Logging Macros

#define SNBLogError(fmt, ...)   SNB_LOG_IMPL(SNBLogLevelError, SNB_LOG_CATEGORY_CORE, fmt, ##__VA_ARGS__)
#define SNBLogWarn(fmt, ...)    SNB_LOG_IMPL(SNBLogLevelWarn, SNB_LOG_CATEGORY_CORE, fmt, ##__VA_ARGS__)
#define SNBLogInfo(fmt, ...)    SNB_LOG_IMPL(SNBLogLevelInfo, SNB_LOG_CATEGORY_CORE, fmt, ##__VA_ARGS__)
#define SNBLogDebug(fmt, ...)   SNB_LOG_IMPL(SNBLogLevelDebug, SNB_LOG_CATEGORY_CORE, fmt, ##__VA_ARGS__)

// MARK: - Network Category Macros

#define SNBLogNetworkError(fmt, ...)   SNB_LOG_IMPL(SNBLogLevelError, SNB_LOG_CATEGORY_NETWORK, fmt, ##__VA_ARGS__)
#define SNBLogNetworkWarn(fmt, ...)    SNB_LOG_IMPL(SNBLogLevelWarn, SNB_LOG_CATEGORY_NETWORK, fmt, ##__VA_ARGS__)
#define SNBLogNetworkInfo(fmt, ...)    SNB_LOG_IMPL(SNBLogLevelInfo, SNB_LOG_CATEGORY_NETWORK, fmt, ##__VA_ARGS__)
#define SNBLogNetworkDebug(fmt, ...)   SNB_LOG_IMPL(SNBLogLevelDebug, SNB_LOG_CATEGORY_NETWORK, fmt, ##__VA_ARGS__)

// MARK: - Threat Intelligence Category Macros

#define SNBLogThreatIntelError(fmt, ...)   SNB_LOG_IMPL(SNBLogLevelError, SNB_LOG_CATEGORY_THREAT_INTEL, fmt, ##__VA_ARGS__)
#define SNBLogThreatIntelWarn(fmt, ...)    SNB_LOG_IMPL(SNBLogLevelWarn, SNB_LOG_CATEGORY_THREAT_INTEL, fmt, ##__VA_ARGS__)
#define SNBLogThreatIntelInfo(fmt, ...)    SNB_LOG_IMPL(SNBLogLevelInfo, SNB_LOG_CATEGORY_THREAT_INTEL, fmt, ##__VA_ARGS__)
#define SNBLogThreatIntelDebug(fmt, ...)   SNB_LOG_IMPL(SNBLogLevelDebug, SNB_LOG_CATEGORY_THREAT_INTEL, fmt, ##__VA_ARGS__)

// MARK: - UI Category Macros

#define SNBLogUIError(fmt, ...)   SNB_LOG_IMPL(SNBLogLevelError, SNB_LOG_CATEGORY_UI, fmt, ##__VA_ARGS__)
#define SNBLogUIWarn(fmt, ...)    SNB_LOG_IMPL(SNBLogLevelWarn, SNB_LOG_CATEGORY_UI, fmt, ##__VA_ARGS__)
#define SNBLogUIInfo(fmt, ...)    SNB_LOG_IMPL(SNBLogLevelInfo, SNB_LOG_CATEGORY_UI, fmt, ##__VA_ARGS__)
#define SNBLogUIDebug(fmt, ...)   SNB_LOG_IMPL(SNBLogLevelDebug, SNB_LOG_CATEGORY_UI, fmt, ##__VA_ARGS__)

// MARK: - Config Category Macros

#define SNBLogConfigError(fmt, ...)   SNB_LOG_IMPL(SNBLogLevelError, SNB_LOG_CATEGORY_CONFIG, fmt, ##__VA_ARGS__)
#define SNBLogConfigWarn(fmt, ...)    SNB_LOG_IMPL(SNBLogLevelWarn, SNB_LOG_CATEGORY_CONFIG, fmt, ##__VA_ARGS__)
#define SNBLogConfigInfo(fmt, ...)    SNB_LOG_IMPL(SNBLogLevelInfo, SNB_LOG_CATEGORY_CONFIG, fmt, ##__VA_ARGS__)
#define SNBLogConfigDebug(fmt, ...)   SNB_LOG_IMPL(SNBLogLevelDebug, SNB_LOG_CATEGORY_CONFIG, fmt, ##__VA_ARGS__)

// MARK: - Agent Category Macros

#define SNBLogAgentError(fmt, ...)   SNB_LOG_IMPL(SNBLogLevelError, SNB_LOG_CATEGORY_AGENT, fmt, ##__VA_ARGS__)
#define SNBLogAgentWarn(fmt, ...)    SNB_LOG_IMPL(SNBLogLevelWarn, SNB_LOG_CATEGORY_AGENT, fmt, ##__VA_ARGS__)
#define SNBLogAgentInfo(fmt, ...)    SNB_LOG_IMPL(SNBLogLevelInfo, SNB_LOG_CATEGORY_AGENT, fmt, ##__VA_ARGS__)
#define SNBLogAgentDebug(fmt, ...)   SNB_LOG_IMPL(SNBLogLevelDebug, SNB_LOG_CATEGORY_AGENT, fmt, ##__VA_ARGS__)

// MARK: - Behavior Category Macros

#define SNBLogBehaviorError(fmt, ...)   SNB_LOG_IMPL(SNBLogLevelError, SNB_LOG_CATEGORY_BEHAVIOR, fmt, ##__VA_ARGS__)
#define SNBLogBehaviorWarn(fmt, ...)    SNB_LOG_IMPL(SNBLogLevelWarn, SNB_LOG_CATEGORY_BEHAVIOR, fmt, ##__VA_ARGS__)
#define SNBLogBehaviorInfo(fmt, ...)    SNB_LOG_IMPL(SNBLogLevelInfo, SNB_LOG_CATEGORY_BEHAVIOR, fmt, ##__VA_ARGS__)
#define SNBLogBehaviorDebug(fmt, ...)   SNB_LOG_IMPL(SNBLogLevelDebug, SNB_LOG_CATEGORY_BEHAVIOR, fmt, ##__VA_ARGS__)

// MARK: - Deprecated Legacy Macro

// Deprecated: Use level-aware macros instead
// This macro is kept for backward compatibility only
#define SNBLog(fmt, ...) \
    SNBLogDebug(fmt, ##__VA_ARGS__) \
    __attribute__((deprecated("Use SNBLogDebug, SNBLogInfo, SNBLogWarn, or SNBLogError instead")))

//
//  main.m
//  SniffNetBar
//
//  Created from Rust networking code refactoring
//

#import <Cocoa/Cocoa.h>
#import <execinfo.h>
#import <signal.h>
#import <unistd.h>
#import "AppDelegate.h"
#import "Logger.h"

static void handle_signal(int signalNumber) {
    const char *signalName = strsignal(signalNumber);
    if (!signalName) {
        signalName = "UNKNOWN";
    }
    dprintf(STDERR_FILENO, "SniffNetBar crash: signal %d (%s)\n", signalNumber, signalName);
    
    void *callstack[64];
    int frames = backtrace(callstack, 64);
    backtrace_symbols_fd(callstack, frames, STDERR_FILENO);
    _exit(128 + signalNumber);
}

static void install_crash_handlers(void) {
    signal(SIGSEGV, handle_signal);
    signal(SIGBUS, handle_signal);
    signal(SIGILL, handle_signal);
    signal(SIGABRT, handle_signal);
}

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        install_crash_handlers();

        // Enable console logging if running from a terminal (stderr is a TTY)
        // or if environment variable SNIFFNETBAR_CONSOLE_LOG is set
        BOOL isTTY = isatty(STDERR_FILENO);
        BOOL forceConsoleLog = getenv("SNIFFNETBAR_CONSOLE_LOG") != NULL;

        if (isTTY || forceConsoleLog) {
            SNBSetConsoleLoggingEnabled(YES);
        }

        NSApplication *app = [NSApplication sharedApplication];
        AppDelegate *delegate = [[AppDelegate alloc] init];
        app.delegate = delegate;
        [app run];
        return 0;
    }
}

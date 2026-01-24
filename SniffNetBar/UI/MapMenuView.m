//
//  MapMenuView.m
//  SniffNetBar
//
//  Map visualization embedded in the menu (Leaflet via WebKit)
//

#import "MapMenuView.h"
#import "ByteFormatter.h"
#import "ConfigurationManager.h"
#import "ExpiringCache.h"
#import "IPAddressUtilities.h"
#import "UserDefaultsKeys.h"
#import "SNBLocationStore.h"
#import "SNBBadgeRegistry.h"
#import "SNBTimerCoordinator.h"
#import "Logger.h"
#import <WebKit/WebKit.h>
#import <CoreLocation/CoreLocation.h>

// Cache cleanup interval
static const NSTimeInterval kCacheCleanupInterval = 300.0;  // 5 minutes
// Failed lookups retry interval (after which failed IPs can be retried)
static const NSTimeInterval kFailedLookupRetryInterval = 1800.0;  // 30 minutes
// Render debounce interval to reduce UI churn
static const NSTimeInterval kRenderDebounceInterval = 0.25;

@interface MapMenuView () <WKNavigationDelegate, WKScriptMessageHandler>
@property (nonatomic, strong) WKWebView *webView;
@property (nonatomic, strong) NSButton *zoomInButton;
@property (nonatomic, strong) NSButton *zoomOutButton;
@property (nonatomic, strong) NSButton *layerButton;
@property (nonatomic, strong) NSButton *satelliteButton;
@property (nonatomic, strong) NSButton *heatMapButton;
@property (nonatomic, strong) NSButton *legendButton;
@property (nonatomic, strong) NSButton *filterButton;
@property (nonatomic, strong) SNBExpiringCache<NSString *, NSDictionary *> *locationCache;
@property (nonatomic, strong) SNBLocationStore *locationStore;
@property (nonatomic, strong) NSMutableSet<NSString *> *inFlightLookups;
@property (nonatomic, strong) NSMutableSet<NSString *> *failedLookups;
@property (nonatomic, strong) NSURLSession *session;
@property (nonatomic, copy) NSArray<ConnectionTraffic *> *lastConnections;
@property (nonatomic, copy) NSString *publicIPAddress;
@property (nonatomic, strong) NSValue *publicIPCoordinate;
@property (nonatomic, assign) BOOL publicIPLookupInFlight;
@property (nonatomic, assign) BOOL mapReady;
@property (nonatomic, copy) NSArray<NSString *> *lastTargetIPs;
@property (nonatomic, strong) dispatch_queue_t renderQueue;
@property (nonatomic, assign) NSUInteger renderGeneration;
@property (nonatomic, copy) SNBTimerID renderDebounceTimerID;
@property (nonatomic, assign) BOOL renderPending;
@property (nonatomic, assign) NSUInteger renderDataGeneration;
@property (nonatomic, assign) NSUInteger lastRenderedGeneration;
@property (nonatomic, assign) NSUInteger scheduledRenderGeneration;
@property (nonatomic, assign) NSUInteger lastRenderSignature;
@property (nonatomic, strong) NSDate *lastCacheCleanupTime;
@property (nonatomic, strong) dispatch_semaphore_t geoLocationSemaphore;
// Thread-safe: written on background queue, read on main thread
@property (atomic, assign, readwrite) NSUInteger drawnConnectionCount;
// Event monitor for capturing clicks in menu context
@property (nonatomic, strong) id clickEventMonitor;
// Periodic cleanup timer
@property (nonatomic, copy) SNBTimerID cleanupTimerID;
// Track when failed lookups can be retried
@property (nonatomic, strong) NSDate *lastFailedLookupsReset;
@end

@implementation MapMenuView

static NSString *SNBLocationStoreDirectory(void) {
    NSArray<NSString *> *paths = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, YES);
    if (paths.count == 0) {
        return NSTemporaryDirectory();
    }
    NSString *dir = [paths.firstObject stringByAppendingPathComponent:@"SniffNetBar"];
    NSError *error = nil;
    [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:&error];
    if (error) {
        SNBLogUIDebug("Unable to create App Support dir: %s", error.localizedDescription.UTF8String);
        return NSTemporaryDirectory();
    }
    return dir;
}

- (instancetype)initWithFrame:(NSRect)frame {
    self = [super initWithFrame:frame];
    if (self) {
        // Enable layer backing for proper z-ordering
        self.wantsLayer = YES;

        WKWebViewConfiguration *config = [[WKWebViewConfiguration alloc] init];
        [config.userContentController addScriptMessageHandler:self name:@"connectionSelect"];
        BOOL enableConsoleBridge = (SNBGetRuntimeLogLevel() >= SNBLogLevelDebug);
        if (enableConsoleBridge) {
            [config.userContentController addScriptMessageHandler:self name:@"consoleLog"];
        }

        // Inject script to capture console.log
        if (enableConsoleBridge) {
            NSString *consoleScript = @"(function(){"
                "var origLog=console.log;"
                "console.log=function(){"
                "  var args=Array.prototype.slice.call(arguments);"
                "  var msg=args.map(function(a){return typeof a==='object'?JSON.stringify(a):String(a);}).join(' ');"
                "  if(window.webkit&&window.webkit.messageHandlers&&window.webkit.messageHandlers.consoleLog){"
                "    window.webkit.messageHandlers.consoleLog.postMessage(msg);"
                "  }"
                "  origLog.apply(console,arguments);"
                "};"
                "})();";
            WKUserScript *script = [[WKUserScript alloc] initWithSource:consoleScript
                                                          injectionTime:WKUserScriptInjectionTimeAtDocumentStart
                                                       forMainFrameOnly:YES];
            [config.userContentController addUserScript:script];
        }

        _webView = [[WKWebView alloc] initWithFrame:self.bounds configuration:config];
        _webView.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;
        _webView.navigationDelegate = self;
        _webView.wantsLayer = YES;
        [self addSubview:_webView];

        _locationCache = [[SNBExpiringCache alloc] initWithMaxSize:[ConfigurationManager sharedManager].maxLocationCacheSize
                                                expirationInterval:[ConfigurationManager sharedManager].locationCacheExpirationTime];
        _inFlightLookups = [NSMutableSet set];
        _failedLookups = [NSMutableSet set];
        NSURLSessionConfiguration *sessionConfig = [NSURLSessionConfiguration ephemeralSessionConfiguration];
        sessionConfig.URLCache = nil;
        sessionConfig.requestCachePolicy = NSURLRequestReloadIgnoringLocalCacheData;
        _session = [NSURLSession sessionWithConfiguration:sessionConfig];
        _renderQueue = dispatch_queue_create("com.sniffnetbar.map.render", DISPATCH_QUEUE_SERIAL);
        NSUInteger semaphoreLimit = [ConfigurationManager sharedManager].geoLocationSemaphoreLimit;
        _geoLocationSemaphore = dispatch_semaphore_create((long)semaphoreLimit);

        NSString *savedProvider = [[NSUserDefaults standardUserDefaults] stringForKey:SNBUserDefaultsKeyMapProvider];
        NSString *defaultProvider = [ConfigurationManager sharedManager].defaultMapProvider;
        _providerName = savedProvider.length > 0 ? savedProvider : defaultProvider;

        NSString *supportDir = SNBLocationStoreDirectory();
        NSString *dbPath = [supportDir stringByAppendingPathComponent:@"location_cache.sqlite"];
        _locationStore = [SNBLocationStore sharedStoreWithPath:dbPath
                                            expirationInterval:[ConfigurationManager sharedManager].locationCacheExpirationTime];

        [self loadMapHTML];
        [self updateLayout];

        // Install event monitor immediately - NSMenuItem views may not trigger viewDidMoveToWindow
        [self installClickEventMonitor];

        // Start periodic cache cleanup timer
        [self startCacheCleanupTimer];
        _lastFailedLookupsReset = [NSDate date];
    }
    return self;
}

- (NSSize)intrinsicContentSize {
    // Return the size we want the view to be
    return self.frame.size;
}

#pragma mark - Event Handling for Menu Item

- (void)updateTrackingAreas {
    [super updateTrackingAreas];

    // Remove existing tracking areas
    for (NSTrackingArea *area in self.trackingAreas) {
        [self removeTrackingArea:area];
    }

    // Add new tracking area for the entire view
    NSTrackingArea *trackingArea = [[NSTrackingArea alloc]
        initWithRect:self.bounds
             options:(NSTrackingMouseEnteredAndExited |
                      NSTrackingMouseMoved |
                      NSTrackingActiveAlways |
                      NSTrackingInVisibleRect)
               owner:self
            userInfo:nil];
    [self addTrackingArea:trackingArea];
}

- (void)handleClickGesture:(NSClickGestureRecognizer *)gesture {
    if (gesture.state == NSGestureRecognizerStateEnded) {
        NSPoint locationInView = [gesture locationInView:self.webView];
        SNBLogUIDebug("Click gesture at (%f, %f)", locationInView.x, locationInView.y);

        // Inject click at this position
        [self injectClickAtPoint:locationInView];
    }
}

- (void)injectClickAtPoint:(NSPoint)point {
    // WKWebView has Y=0 at bottom, web has Y=0 at top
    CGFloat webY = self.webView.bounds.size.height - point.y;

    NSString *js = [NSString stringWithFormat:
        @"(function(){"
        "  var x=%f, y=%f;"
        "  console.log('Injected click at', x, y);"
        "  var el = document.elementFromPoint(x, y);"
        "  console.log('Element at point:', el ? el.tagName : 'null', el ? el.className : '');"
        "  if(el){"
        "    var evt = new MouseEvent('click', {bubbles:true,cancelable:true,clientX:x,clientY:y,view:window});"
        "    el.dispatchEvent(evt);"
        "    console.log('Click dispatched to', el.tagName);"
        "  }"
        "})();",
        point.x, webY];

    [self.webView evaluateJavaScript:js completionHandler:^(id result, NSError *error) {
        if (error) {
            SNBLogUIDebug("JS click error: %s", error.localizedDescription.UTF8String);
        }
    }];
}

- (BOOL)acceptsFirstMouse:(NSEvent *)event {
    return YES;
}

- (BOOL)acceptsFirstResponder {
    return YES;
}

- (NSView *)hitTest:(NSPoint)point {
    NSPoint localPoint = [self convertPoint:point fromView:self.superview];
    if (NSPointInRect(localPoint, self.bounds)) {
        // Check all control buttons (if any)
        NSMutableArray<NSButton *> *buttons = [NSMutableArray array];
        if (self.zoomInButton) {
            [buttons addObject:self.zoomInButton];
        }
        if (self.zoomOutButton) {
            [buttons addObject:self.zoomOutButton];
        }
        for (NSButton *button in buttons) {
            NSPoint buttonPoint = [button convertPoint:point fromView:self.superview];
            if (NSPointInRect(buttonPoint, button.bounds)) {
                return button;
            }
        }
        return self.webView;
    }
    return nil;
}

- (void)mouseDown:(NSEvent *)event {
    SNBLogUIDebug("MapMenuView mouseDown at (%f, %f)", event.locationInWindow.x, event.locationInWindow.y);

    // Convert to webview coordinates and inject click
    NSPoint locationInWebView = [self.webView convertPoint:event.locationInWindow fromView:nil];
    [self injectClickAtPoint:locationInWebView];
}

- (void)mouseUp:(NSEvent *)event {
    // Do nothing, click is handled in mouseDown
}

- (void)mouseMoved:(NSEvent *)event {
    // Forward mouse movement for hover effects
    NSPoint locationInWebView = [self.webView convertPoint:event.locationInWindow fromView:nil];

    NSString *js = [NSString stringWithFormat:
        @"(function(){"
        "  var x=%f, y=%f;"
        "  var el = document.elementFromPoint(x, y);"
        "  if(el){"
        "    var evt = new MouseEvent('mouseover', {bubbles:true,cancelable:true,clientX:x,clientY:y,view:window});"
        "    el.dispatchEvent(evt);"
        "  }"
        "})();",
        locationInWebView.x, self.webView.bounds.size.height - locationInWebView.y];

    [self.webView evaluateJavaScript:js completionHandler:nil];
}

- (void)mouseEntered:(NSEvent *)event {
    SNBLogUIDebug("MapMenuView mouseEntered");
}

- (void)mouseExited:(NSEvent *)event {
    SNBLogUIDebug("MapMenuView mouseExited");
}

- (void)dealloc {
    [self removeClickEventMonitor];
    [_session invalidateAndCancel];

    // Cancel cleanup timer
    if (_cleanupTimerID) {
        [[SNBTimerCoordinator sharedCoordinator] cancelTimer:_cleanupTimerID];
        _cleanupTimerID = nil;
    }
    if (_renderDebounceTimerID) {
        [[SNBTimerCoordinator sharedCoordinator] cancelTimer:_renderDebounceTimerID];
        _renderDebounceTimerID = nil;
    }
}

#pragma mark - Cache Management

- (void)startCacheCleanupTimer {
    __weak typeof(self) weakSelf = self;
    SNBTimerCoordinator *coordinator = [SNBTimerCoordinator sharedCoordinator];
    self.cleanupTimerID = [coordinator scheduleRepeatingTimerWithInterval:kCacheCleanupInterval
                                                                    queue:dispatch_get_main_queue()
                                                                  handler:^{
        [weakSelf performCacheCleanup];
    }];
    SNBLogUIDebug("MapMenuView: Started cache cleanup timer (interval: %.0f seconds)", kCacheCleanupInterval);
}

- (void)performCacheCleanup {
    // Clean up expired entries from in-memory cache
    NSUInteger expiredCount = [self.locationCache cleanupAndReturnExpiredCount];
    if (expiredCount > 0) {
        SNBLogUIDebug("MapMenuView: Cleaned up %lu expired location cache entries", (unsigned long)expiredCount);
    }

    // Reset failed lookups periodically to allow retry of transient failures
    NSTimeInterval timeSinceReset = -[self.lastFailedLookupsReset timeIntervalSinceNow];
    if (timeSinceReset > kFailedLookupRetryInterval) {
        NSUInteger failedCount = self.failedLookups.count;
        if (failedCount > 0) {
            [self.failedLookups removeAllObjects];
            self.lastFailedLookupsReset = [NSDate date];
            SNBLogUIDebug("MapMenuView: Reset %lu failed lookups (retry after %.0f minutes)",
                         (unsigned long)failedCount, kFailedLookupRetryInterval / 60.0);
        }
    }

    // Clean up expired entries from persistent SQLite store
    [self.locationStore cleanupExpiredEntries];

    self.lastCacheCleanupTime = [NSDate date];
}

- (void)setProviderName:(NSString *)providerName {
    if ([_providerName isEqualToString:providerName]) {
        return;
    }
    _providerName = [providerName copy];
    [self.failedLookups removeAllObjects];
    [self.inFlightLookups removeAllObjects];
}

- (void)viewDidMoveToWindow {
    [super viewDidMoveToWindow];
    if (self.window) {
        // Use local event monitor to capture clicks - this works even when NSMenu intercepts events
        [self installClickEventMonitor];

        if (self.lastConnections.count > 0) {
            [self updateWithConnections:self.lastConnections];
        }
    } else {
        // Remove the monitor when view is removed from window
        [self removeClickEventMonitor];
    }
}

- (void)installClickEventMonitor {
    if (self.clickEventMonitor) {
        return; // Already installed
    }

    __weak typeof(self) weakSelf = self;
    self.clickEventMonitor = [NSEvent addLocalMonitorForEventsMatchingMask:NSEventMaskLeftMouseDown
                                                                   handler:^NSEvent *(NSEvent *event) {
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) {
            return event;
        }

        NSWindow *myWindow = strongSelf.window;
        if (!myWindow) {
            return event;
        }

        // Use screen coordinates for reliable cross-window conversion
        NSPoint screenPoint;
        if (event.window) {
            // Convert from event window coordinates to screen coordinates
            NSPoint windowPoint = event.locationInWindow;
            screenPoint = [event.window convertPointToScreen:windowPoint];
        } else {
            // Event has no window (shouldn't happen for local monitor, but be safe)
            return event;
        }

        // Convert screen coordinates to our window coordinates
        NSPoint ourWindowPoint = [myWindow convertPointFromScreen:screenPoint];

        // Convert to our view's coordinates
        NSPoint viewPoint = [strongSelf convertPoint:ourWindowPoint fromView:nil];

        // Check if click is within our bounds
        if (NSPointInRect(viewPoint, strongSelf.bounds)) {
            // Convert to webview coordinates
            NSPoint webViewPoint = [strongSelf.webView convertPoint:ourWindowPoint fromView:nil];

            SNBLogUIDebug("Click in MapMenuView at screen(%f, %f) -> view(%f, %f) -> webView(%f, %f)",
                    screenPoint.x, screenPoint.y, viewPoint.x, viewPoint.y, webViewPoint.x, webViewPoint.y);

            // Check it's not on any control buttons
            NSMutableArray<NSButton *> *buttons = [NSMutableArray array];
            if (strongSelf.zoomInButton) {
                [buttons addObject:strongSelf.zoomInButton];
            }
            if (strongSelf.zoomOutButton) {
                [buttons addObject:strongSelf.zoomOutButton];
            }
            BOOL onButton = NO;
            for (NSButton *button in buttons) {
                NSPoint buttonPoint = [button convertPoint:ourWindowPoint fromView:nil];
                if (NSPointInRect(buttonPoint, button.bounds)) {
                    onButton = YES;
                    break;
                }
            }

            if (!onButton) {
                SNBLogUIDebug("Injecting click at webView(%f, %f)", webViewPoint.x, webViewPoint.y);
                [strongSelf injectClickAtPoint:webViewPoint];
            } else {
                SNBLogUIDebug("Click on control button, ignoring");
            }
        }

        return event; // Let the event continue (don't block it)
    }];

    SNBLogUIDebug("Installed local event monitor for clicks");
}

- (void)removeClickEventMonitor {
    if (self.clickEventMonitor) {
        [NSEvent removeMonitor:self.clickEventMonitor];
        self.clickEventMonitor = nil;
        SNBLogUIDebug("Removed local event monitor");
    }
}

- (void)viewDidMoveToSuperview {
    [super viewDidMoveToSuperview];
}

- (void)setFrameSize:(NSSize)newSize {
    [super setFrameSize:newSize];
    [self updateLayout];
}

- (void)updateWithConnections:(NSArray<ConnectionTraffic *> *)connections {
    if (![NSThread isMainThread]) {
        dispatch_async(dispatch_get_main_queue(), ^{
            [self updateWithConnections:connections];
        });
        return;
    }

    self.lastConnections = connections;
    if (!self.window) {
        return;
    }

    NSDate *now = [NSDate date];
    if (!self.lastCacheCleanupTime || [now timeIntervalSinceDate:self.lastCacheCleanupTime] > 5.0) {
        self.lastCacheCleanupTime = now;
        NSUInteger expiredCount = [self.locationCache cleanupAndReturnExpiredCount];
        [self.locationStore cleanupExpiredEntries];
        if (expiredCount > 0) {
            SNBLogUIDebug(": cleaned up %lu expired location cache entries",
                   (unsigned long)expiredCount);
        }
    }
    SNBLogUIDebug(" update: %lu connections", (unsigned long)connections.count);
    [self updatePublicIPLocationIfNeeded];
    if (connections.count == 0) {
        self.lastTargetIPs = @[];
        if ([self updateRenderSignatureWithConnections:connections targetIPs:self.lastTargetIPs]) {
            [self markRenderDataDirty];
            [self refreshMarkers];
        }
        return;
    }
    
    NSMutableSet<NSString *> *ips = [NSMutableSet set];
    for (ConnectionTraffic *connection in connections) {
        if (connection.sourceAddress.length > 0) {
            [ips addObject:connection.sourceAddress];
        }
        if (connection.destinationAddress.length > 0) {
            [ips addObject:connection.destinationAddress];
        }
    }
    
    NSMutableSet<NSString *> *targetIps = [NSMutableSet set];
    for (NSString *ip in ips) {
        if ([self shouldGeolocateIPAddress:ip]) {
            [targetIps addObject:ip];
        } else {
            SNBLogUIDebug(" skip local IP: %s", ip.UTF8String);
        }
    }
    self.lastTargetIPs = [targetIps.allObjects sortedArrayUsingSelector:@selector(compare:)];
    
    SNBLogUIDebug(" target IPs: %s", targetIps.description.UTF8String);
    BOOL signatureChanged = [self updateRenderSignatureWithConnections:connections
                                                             targetIPs:self.lastTargetIPs];
    
    BOOL canLookup = YES;
    if ([self.providerName isEqualToString:@"custom"]) {
        NSString *template = [[NSUserDefaults standardUserDefaults] stringForKey:SNBUserDefaultsKeyMapProviderURLTemplate];
        if (template.length == 0) {
            canLookup = NO;
        }
    }
    
    for (NSString *ip in targetIps) {
        NSDictionary *cached = [self.locationCache objectForKey:ip];
        if (!cached) {
            cached = [self.locationStore locationForIP:ip];
            if (cached) {
                [self.locationCache setObject:cached forKey:ip];
            }
        }
        if (cached) {
            continue;
        }
        if (!canLookup || [self.inFlightLookups containsObject:ip] || [self.failedLookups containsObject:ip]) {
            continue;
        }
        
        [self.inFlightLookups addObject:ip];
        [self fetchLocationForIP:ip completion:^(CLLocationCoordinate2D coord, BOOL success) {
            dispatch_async(dispatch_get_main_queue(), ^{
                [self.inFlightLookups removeObject:ip];
                if (!success) {
                    [self.failedLookups addObject:ip];
                    return;
                }
                SNBLogUIDebug(" pin ready for %s (%f, %f)", ip.UTF8String, coord.latitude, coord.longitude);
                [self markRenderDataDirty];
                [self refreshMarkers];
            });
        }];
    }
    
    if (signatureChanged) {
        [self markRenderDataDirty];
        [self refreshMarkers];
    }
}

- (void)updatePublicIPLocationIfNeeded {
    if (self.publicIPLookupInFlight || self.publicIPAddress.length > 0) {
        return;
    }
    
    self.publicIPLookupInFlight = YES;
    NSURL *url = [NSURL URLWithString:@"https://api.ipify.org?format=json"];
    if (!url) {
        self.publicIPLookupInFlight = NO;
        return;
    }
    
    SNBLogUIDebug(" public IP lookup via %s", url.absoluteString.UTF8String);
    NSURLSessionDataTask *task = [self.session dataTaskWithURL:url completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        if (error || !data) {
            SNBLogUIDebug(" public IP lookup failed: %s", error.localizedDescription.UTF8String);
            self.publicIPLookupInFlight = NO;
            return;
        }
        
        NSError *jsonError;
        id json = [NSJSONSerialization JSONObjectWithData:data options:0 error:&jsonError];
        if (jsonError || ![json isKindOfClass:[NSDictionary class]]) {
            SNBLogUIDebug(" public IP JSON error: %s", jsonError.localizedDescription.UTF8String);
            self.publicIPLookupInFlight = NO;
            return;
        }
        
        NSString *ip = json[@"ip"];
        if (ip.length == 0) {
            SNBLogUIDebug(" public IP missing in response");
            self.publicIPLookupInFlight = NO;
            return;
        }
        
        SNBLogUIDebug(" public IP: %s", ip.UTF8String);
        self.publicIPAddress = ip;
        [self fetchLocationForIP:ip completion:^(CLLocationCoordinate2D coord, BOOL success) {
            dispatch_async(dispatch_get_main_queue(), ^{
                self.publicIPLookupInFlight = NO;
                if (!success) {
                    SNBLogUIDebug(" public IP geolocation failed: %s", ip.UTF8String);
                    return;
                }
                self.publicIPCoordinate = [NSValue valueWithBytes:&coord objCType:@encode(CLLocationCoordinate2D)];
                SNBLogUIDebug(" public IP located: %s => (%f, %f)", ip.UTF8String, coord.latitude, coord.longitude);
                [self markRenderDataDirty];
                [self refreshMarkers];
            });
        }];
    }];
    [task resume];
}

- (void)markRenderDataDirty {
    self.renderDataGeneration += 1;
}

- (BOOL)updateRenderSignatureWithConnections:(NSArray<ConnectionTraffic *> *)connections
                                   targetIPs:(NSArray<NSString *> *)targetIPs {
    NSUInteger signature = connections.count;
    for (ConnectionTraffic *connection in connections) {
        signature = signature * 33u + connection.sourceAddress.hash;
        signature = signature * 33u + connection.destinationAddress.hash;
        signature = signature * 33u + (NSUInteger)connection.sourcePort;
        signature = signature * 33u + (NSUInteger)connection.destinationPort;

        BOOL srcPublic = [self shouldGeolocateIPAddress:connection.sourceAddress];
        BOOL dstPublic = [self shouldGeolocateIPAddress:connection.destinationAddress];
        NSUInteger directionKey = (srcPublic && !dstPublic) ? 1u : ((!srcPublic && dstPublic) ? 2u : 0u);
        signature = signature * 33u + directionKey;
    }
    signature = signature * 33u + targetIPs.count;
    for (NSString *ip in targetIPs) {
        signature = signature * 33u + ip.hash;
    }

    if (signature == self.lastRenderSignature) {
        return NO;
    }
    self.lastRenderSignature = signature;
    return YES;
}

- (void)refreshMarkers {
    if (!self.mapReady) {
        return;
    }
    if (self.renderDataGeneration == self.lastRenderedGeneration) {
        return;
    }
    if (self.renderDebounceTimerID) {
        self.renderPending = YES;
        return;
    }

    __weak typeof(self) weakSelf = self;
    self.scheduledRenderGeneration = self.renderDataGeneration;
    self.renderDebounceTimerID = [[SNBTimerCoordinator sharedCoordinator] scheduleOneShotTimerWithDelay:kRenderDebounceInterval
                                                                                                 queue:dispatch_get_main_queue()
                                                                                               handler:^{
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) {
            return;
        }
        strongSelf.renderDebounceTimerID = nil;
        [strongSelf performRefreshMarkers];
        strongSelf.lastRenderedGeneration = strongSelf.renderDataGeneration;
        if (strongSelf.renderPending) {
            strongSelf.renderPending = NO;
            if (strongSelf.renderDataGeneration > strongSelf.scheduledRenderGeneration) {
                [strongSelf refreshMarkers];
            }
        }
    }];
}

- (void)performRefreshMarkers {
    if (!self.mapReady) {
        return;
    }

    self.renderGeneration += 1;
    NSUInteger generation = self.renderGeneration;
    NSArray<NSString *> *targetIPs = [self.lastTargetIPs copy] ?: @[];
    NSArray<ConnectionTraffic *> *connections = [self.lastConnections copy] ?: @[];
    NSString *publicIP = [self.publicIPAddress copy];
    NSValue *publicCoordValue = self.publicIPCoordinate;
    ConfigurationManager *config = [ConfigurationManager sharedManager];

    NSMutableDictionary<NSString *, NSDictionary *> *locationByIP = [NSMutableDictionary dictionary];
    for (NSString *ip in targetIPs) {
        NSDictionary *value = [self.locationCache objectForKey:ip];
        if (value) {
            locationByIP[ip] = value;
        }
    }

    NSMutableDictionary<NSString *, NSDictionary *> *badgeInfoByIP = [NSMutableDictionary dictionary];
    for (ConnectionTraffic *connection in connections) {
        [self addBadgeInfoForIPAddress:connection.sourceAddress connection:connection map:badgeInfoByIP];
        [self addBadgeInfoForIPAddress:connection.destinationAddress connection:connection map:badgeInfoByIP];
    }

    NSInteger maxLines = MIN(config.maxConnectionLinesToShow, connections.count);
    for (NSInteger i = 0; i < maxLines; i++) {
        ConnectionTraffic *connection = connections[i];
        if (connection.sourceAddress.length > 0 && !locationByIP[connection.sourceAddress]) {
            NSDictionary *value = [self.locationCache objectForKey:connection.sourceAddress];
            if (value) {
                locationByIP[connection.sourceAddress] = value;
            }
        }
        if (connection.destinationAddress.length > 0 && !locationByIP[connection.destinationAddress]) {
            NSDictionary *value = [self.locationCache objectForKey:connection.destinationAddress];
            if (value) {
                locationByIP[connection.destinationAddress] = value;
            }
        }
    }

    __weak typeof(self) weakSelf = self;
    dispatch_async(self.renderQueue, ^{
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) {
            return;
        }

        NSMutableDictionary<NSString *, NSMutableArray<NSDictionary *> *> *pointsByCoord = [NSMutableDictionary dictionary];
        for (NSString *ip in targetIPs) {
            NSDictionary *value = locationByIP[ip];
            if (!value) {
                continue;
            }
            CLLocationCoordinate2D coord;
            coord.latitude = [value[@"lat"] doubleValue];
            coord.longitude = [value[@"lon"] doubleValue];
            if (!CLLocationCoordinate2DIsValid(coord)) {
                continue;
            }
            NSString *name = value[@"name"];
            NSString *isp = value[@"isp"];
            NSString *locationPart = name.length > 0 ? [NSString stringWithFormat:@"%@ — %@", ip, name] : ip;
            NSMutableDictionary *payload = [NSMutableDictionary dictionary];
            payload[@"lat"] = @(coord.latitude);
            payload[@"lon"] = @(coord.longitude);
            payload[@"ip"] = ip;
            payload[@"title"] = isp.length > 0 ? [NSString stringWithFormat:@"%@\nISP: %@", locationPart, isp] : locationPart;
            payload[@"name"] = name ?: @"";
            payload[@"isp"] = isp ?: @"";

            // Group by 3 decimal places (~111m precision) to cluster nearby IPs
            NSString *coordKey = [NSString stringWithFormat:@"%.3f,%.3f", coord.latitude, coord.longitude];
            NSMutableArray<NSDictionary *> *group = pointsByCoord[coordKey];
            if (!group) {
                group = [NSMutableArray array];
                pointsByCoord[coordKey] = group;
            }
            [group addObject:payload];
        }

        NSMutableArray<NSDictionary *> *points = [NSMutableArray array];
        [pointsByCoord enumerateKeysAndObjectsUsingBlock:^(NSString *key, NSArray<NSDictionary *> *group, BOOL *stop) {
            NSDictionary *firstPoint = group.firstObject;
            NSMutableDictionary *pointData = [NSMutableDictionary dictionary];
            pointData[@"lat"] = firstPoint[@"lat"];
            pointData[@"lon"] = firstPoint[@"lon"];
            pointData[@"ips"] = [group valueForKey:@"ip"];
            pointData[@"names"] = [group valueForKey:@"name"];
            pointData[@"isps"] = [group valueForKey:@"isp"];
            pointData[@"locationName"] = firstPoint[@"name"] ?: @"";
            NSMutableArray<NSDictionary *> *badges = [NSMutableArray array];
            for (NSDictionary *payload in group) {
                NSString *ip = payload[@"ip"];
                NSDictionary *badge = badgeInfoByIP[ip];
                if (!badge) {
                    NSString *label = payload[@"name"] ?: ip;
                    NSString *icon = [[SNBBadgeRegistry sharedRegistry] badgeIconForLabel:label fallback:ip];
                    NSColor *badgeColor = [[SNBBadgeRegistry sharedRegistry] colorForLabel:label
                                                                 createIfMissing:YES];
                    NSString *colorHex = [self hexStringForColor:badgeColor];
                    badge = @{@"icon": icon ?: @"", @"color": colorHex};
                }
                [badges addObject:badge];
            }
            pointData[@"badgeInfos"] = badges;
            if (group.count > 1) {
                pointData[@"isDuplicate"] = @YES;
                pointData[@"color"] = @"#ffad60";
            } else {
                pointData[@"isDuplicate"] = @NO;
            }
            [points addObject:pointData];
            SNBLogUIDebug("Map marker: %s @ (%f, %f) duplicates=%s",
                          [pointData[@"ips"] description].UTF8String,
                          [pointData[@"lat"] doubleValue],
                          [pointData[@"lon"] doubleValue],
                          [pointData[@"isDuplicate"] description].UTF8String);
        }];

        CLLocationCoordinate2D publicCoord = kCLLocationCoordinate2DInvalid;
        if (publicCoordValue) {
            [publicCoordValue getValue:&publicCoord];
        }
        if (publicIP.length > 0 && CLLocationCoordinate2DIsValid(publicCoord)) {
            [points addObject:@{@"lat": @(publicCoord.latitude),
                                @"lon": @(publicCoord.longitude),
                                @"title": [NSString stringWithFormat:@"Public IP: %@", publicIP]}];
        }

        NSError *jsonError;
        NSData *data = [NSJSONSerialization dataWithJSONObject:points options:0 error:&jsonError];
        if (!data) {
            SNBLogUIDebug(" JSON encode error: %s", jsonError.localizedDescription.UTF8String);
            return;
        }
        NSString *json = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];

        NSMutableArray<NSDictionary *> *lines = [NSMutableArray array];
        for (NSInteger i = 0; i < maxLines; i++) {
            ConnectionTraffic *connection = connections[i];

            NSDictionary *src = locationByIP[connection.sourceAddress];
            BOOL srcIsLocal = ![strongSelf shouldGeolocateIPAddress:connection.sourceAddress];
            if (!src && srcIsLocal && CLLocationCoordinate2DIsValid(publicCoord)) {
                src = @{@"lat": @(publicCoord.latitude), @"lon": @(publicCoord.longitude)};
            }

            NSDictionary *dst = locationByIP[connection.destinationAddress];
            BOOL dstIsLocal = ![strongSelf shouldGeolocateIPAddress:connection.destinationAddress];
            if (!dst && dstIsLocal && CLLocationCoordinate2DIsValid(publicCoord)) {
                dst = @{@"lat": @(publicCoord.latitude), @"lon": @(publicCoord.longitude)};
            }

            if (!src || !dst) {
                continue;
            }

            CLLocationCoordinate2D srcCoord = CLLocationCoordinate2DMake([src[@"lat"] doubleValue], [src[@"lon"] doubleValue]);
            CLLocationCoordinate2D dstCoord = CLLocationCoordinate2DMake([dst[@"lat"] doubleValue], [dst[@"lon"] doubleValue]);
            if (!CLLocationCoordinate2DIsValid(srcCoord) || !CLLocationCoordinate2DIsValid(dstCoord)) {
                continue;
            }

            NSString *lineTitle = [NSString stringWithFormat:@"%@ → %@ (%@)",
                                   connection.sourceAddress,
                                   connection.destinationAddress,
                                   [SNBByteFormatter stringFromBytes:connection.bytes]];
            [lines addObject:@{@"srcLat": @(srcCoord.latitude),
                               @"srcLon": @(srcCoord.longitude),
                               @"dstLat": @(dstCoord.latitude),
                               @"dstLon": @(dstCoord.longitude),
                               @"title": lineTitle,
                               @"srcIP": connection.sourceAddress,
                               @"dstIP": connection.destinationAddress}];
            SNBLogUIDebug("Map line: %s.%ld (%s) -> %s.%ld (%s)",
                          connection.sourceAddress.UTF8String,
                          connection.sourcePort,
                          [SNBByteFormatter stringFromBytes:connection.bytes].UTF8String,
                          connection.destinationAddress.UTF8String,
                          connection.destinationPort,
                          [NSString stringWithFormat:@"src(%f,%f) dst(%f,%f)",
                             srcCoord.latitude, srcCoord.longitude, dstCoord.latitude, dstCoord.longitude].UTF8String);
        }
        SNBLogUIDebug(": created %lu connection lines from %lu connections", (unsigned long)lines.count, (unsigned long)connections.count);

        // Update the count of actually drawn connections for display synchronization
        strongSelf.drawnConnectionCount = lines.count;
        SNBLogUIDebug("Map draw count=%lu (capped at %ld lines)", (unsigned long)lines.count, (long)maxLines);

        if (lines.count > 0) {
            SNBLogUIDebug(": First line example: %s", [lines[0] description].UTF8String);
        }

        NSData *lineData = [NSJSONSerialization dataWithJSONObject:lines options:0 error:&jsonError];
        if (!lineData) {
            SNBLogUIDebug(" JSON encode error (lines): %s", jsonError.localizedDescription.UTF8String);
            return;
        }
        NSString *lineJson = [[NSString alloc] initWithData:lineData encoding:NSUTF8StringEncoding];
        NSString *script = [NSString stringWithFormat:@"window.SniffNetBar && window.SniffNetBar.setMarkers(%@, %@);", json, lineJson];

        dispatch_async(dispatch_get_main_queue(), ^{
            if (generation != strongSelf.renderGeneration || !strongSelf.mapReady) {
                return;
            }
            [strongSelf.webView evaluateJavaScript:script completionHandler:^(id result, NSError *error) {
                if (error) {
                    SNBLogUIDebug(" JS error: %s", error.localizedDescription.UTF8String);
                }
            }];
        });
    });
}

- (void)loadMapHTML {
    ConfigurationManager *config = [ConfigurationManager sharedManager];
    NSString *lineColor = config.connectionLineColor;
    NSInteger lineWeight = config.connectionLineWeight;
    CGFloat lineOpacity = config.connectionLineOpacity;

  NSString *html = [NSString stringWithFormat:
@"<!doctype html>\n"
@"<html lang='en'>\n"
@"<head>\n"
@"  <meta charset='utf-8'>\n"
@"  <meta name='viewport' content='width=device-width, initial-scale=1.0, viewport-fit=cover'>\n"
@"  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; img-src 'self' data: https://*.basemaps.cartocdn.com https://server.arcgisonline.com; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self' https://*.basemaps.cartocdn.com https://server.arcgisonline.com;\">\n"
@"  <link rel='stylesheet' href='vendor/leaflet/leaflet.css'>\n"
@"  <style>\n"
@"    html,body,#map{height:100%%;margin:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;}\n"
@"    body{background:#f8fafc;overflow:hidden;}\n"
@"    #map{background:#f8fafc;}\n"
@"\n"
@"    /* Popup UI */\n"
@"    .leaflet-popup-content-wrapper{background:#ffffff;color:#1e293b;border-radius:10px;box-shadow:0 6px 24px rgba(0,0,0,0.16),0 0 0 1px rgba(0,0,0,0.05);max-width:320px;min-width:220px;}\n"
@"    .leaflet-popup-content{margin:14px 16px;font-size:13px;line-height:1.55;}\n"
@"    .leaflet-popup-tip{background:#ffffff;}\n"
@"    .leaflet-popup-content .location-header{color:#0f172a;font-weight:650;font-size:14px;margin-bottom:8px;display:flex;align-items:center;gap:6px;}\n"
@"    .leaflet-popup-content .location-name{color:#64748b;font-size:12px;margin-bottom:10px;}\n"
@"    .leaflet-popup-content .ip-list{list-style:none;padding:0;margin:0;}\n"
@"    .leaflet-popup-content .ip-list li{padding:8px 0;border-bottom:1px solid rgba(0,0,0,0.06);}\n"
@"    .leaflet-popup-content .ip-list li:last-child{border-bottom:none;padding-bottom:0;}\n"
@"    .leaflet-popup-content .ip-address{color:#0f172a;font-weight:560;font-size:13px;display:block;margin-bottom:2px;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;}\n"
@"    .leaflet-popup-content .ip-company{color:#64748b;font-size:12px;display:block;}\n"
@"    .leaflet-popup-content .ip-item{display:flex;align-items:flex-start;gap:8px;font-size:13px;}\n"
@"    .leaflet-popup-content .ip-badge{display:inline-flex;align-items:center;gap:5px;padding:3px 7px;border:1px solid currentColor;border-radius:999px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:0.02em;box-shadow:0 1px 3px rgba(15,23,42,0.10);white-space:nowrap;}\n"
@"    .leaflet-popup-content .ip-badge-dot{width:6px;height:6px;border-radius:50%%;display:inline-block;}\n"
@"    .leaflet-popup-content .ip-badge-icon{line-height:1;}\n"
@"    .leaflet-popup-content .ip-text{flex:1;display:flex;flex-direction:column;gap:2px;min-width:0;}\n"
@"\n"
@"    /* Markers */\n"
@"    .cluster-marker{background:linear-gradient(135deg,#ef4444 0%%,#dc2626 100%%);border:3px solid rgba(255,255,255,0.95);border-radius:50%%;box-shadow:0 3px 12px rgba(239,68,68,0.40),0 0 0 4px rgba(239,68,68,0.15);display:flex;align-items:center;justify-content:center;color:white;font-weight:800;font-size:13px;transition:transform 0.2s ease;text-align:center;line-height:1;}\n"
@"    .cluster-marker>div{display:flex;align-items:center;justify-content:center;width:100%%;height:100%%;}\n"
@"    .cluster-marker:hover{transform:scale(1.12);}\n"
@"    .single-marker{width:28px;height:36px;position:relative;}\n"
@"    .single-marker::before{content:'';position:absolute;bottom:0;left:50%%;transform:translateX(-50%%);width:0;height:0;border-left:14px solid transparent;border-right:14px solid transparent;border-top:20px solid #2563eb;filter:drop-shadow(0 2px 4px rgba(0,0,0,0.20));}\n"
@"    .single-marker::after{content:'';position:absolute;top:4px;left:50%%;transform:translateX(-50%%);width:18px;height:18px;border-radius:50%%;background:#3b82f6;box-shadow:0 0 0 3px rgba(255,255,255,0.92),0 2px 8px rgba(37,99,235,0.40),inset 0 1px 3px rgba(255,255,255,0.50);}\n"
@"\n"
@"    /* Connections */\n"
@"    .connection-line{filter:drop-shadow(0 1px 2px rgba(0,0,0,0.15));cursor:pointer;pointer-events:stroke;}\n"
@"    .leaflet-overlay-pane svg{pointer-events:auto;}\n"
@"    .leaflet-overlay-pane svg path{pointer-events:stroke;}\n"
@"    @keyframes dash{0%%{stroke-dashoffset:20;}100%%{stroke-dashoffset:0;}}\n"
@"    @keyframes glow-pulse{0%%,100%%{opacity:0.40;}50%%{opacity:0.80;}}\n"
@"    @keyframes selected-pulse{0%%,100%%{opacity:0.60;stroke-width:inherit;}50%%{opacity:1;stroke-width:inherit;}}\n"
@"    .leaflet-interactive.connection-line{animation:dash 1.5s linear infinite;}\n"
@"    body.no-anim .leaflet-interactive.connection-line{animation:none;}\n"
@"    .glow-line{pointer-events:none;}\n"
@"    .glow-line-hover{animation:glow-pulse 1s ease-in-out infinite;}\n"
@"    .glow-line-selected{animation:selected-pulse 1.2s ease-in-out infinite;}\n"
@"    @media (prefers-reduced-motion: reduce){\n"
@"      .leaflet-interactive.connection-line,.glow-line-hover,.glow-line-selected{animation:none !important;}\n"
@"    }\n"
@"\n"
@"    /* Panels */\n"
@"    .leaflet-pane,.leaflet-control,.leaflet-top,.leaflet-bottom{z-index:1000;}\n"
@"    .legend-panel{position:absolute;bottom:calc(10px + env(safe-area-inset-bottom));right:50px;background:rgba(255,255,255,0.95);border-radius:10px;padding:12px;font-size:11px;box-shadow:0 2px 10px rgba(0,0,0,0.15);z-index:2000;display:none;min-width:150px;backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);}\n"
@"    .legend-panel.visible{display:block;}\n"
@"    .legend-title{font-weight:700;font-size:12px;margin-bottom:8px;color:#1e293b;}\n"
@"    .legend-item{display:flex;align-items:center;gap:8px;margin-bottom:6px;color:#475569;}\n"
@"    .legend-item:last-child{margin-bottom:0;}\n"
@"    .legend-line{width:24px;height:3px;border-radius:2px;}\n"
@"    .legend-marker{width:12px;height:12px;border-radius:50%%;}\n"
@"    .legend-gradient{width:60px;height:10px;border-radius:3px;background:linear-gradient(to right,blue,cyan,lime,yellow,red);}\n"
@"\n"
@"    .filter-panel{position:absolute;bottom:calc(10px + env(safe-area-inset-bottom));left:50px;background:rgba(255,255,255,0.95);border-radius:10px;padding:12px;font-size:11px;box-shadow:0 2px 10px rgba(0,0,0,0.15);z-index:2000;display:none;min-width:170px;backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);}\n"
@"    .filter-panel.visible{display:block;}\n"
@"    .filter-title{font-weight:700;font-size:12px;margin-bottom:8px;color:#1e293b;}\n"
@"    .filter-group{margin-bottom:10px;}\n"
@"    .filter-group:last-child{margin-bottom:0;}\n"
@"    .filter-label{font-weight:600;color:#64748b;margin-bottom:4px;}\n"
@"    .filter-option{display:flex;align-items:center;gap:6px;margin-bottom:4px;cursor:pointer;color:#475569;user-select:none;}\n"
@"    .filter-option:hover{color:#1e293b;}\n"
@"    .filter-option input{margin:0;cursor:pointer;}\n"
@"    .filter-option.disabled{opacity:0.55;pointer-events:none;}\n"
@"\n"
@"    /* Toolbar */\n"
@"    :root{--control-color:#111827;--control-bg:rgba(255,255,255,0.92);--control-border:rgba(15,23,42,0.12);--control-shadow:0 10px 30px rgba(0,0,0,0.18);}\n"
@"    .mac-toolbar{position:absolute;top:calc(14px + env(safe-area-inset-top));left:14px;z-index:2500;display:flex;gap:10px;padding:10px;border-radius:14px;background:var(--control-bg);border:1px solid var(--control-border);box-shadow:var(--control-shadow);backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);}\n"
@"    .mac-toolbar.is-collapsed .mac-btn:not(.toolbar-toggle){display:none;}\n"
@"    .mac-toolbar.is-collapsed{padding:6px 8px;gap:0;}\n"
@"    .mac-btn.toolbar-toggle{border-radius:12px;background:rgba(17,24,39,0.06);font-weight:700;}\n"
@"    .mac-btn.toolbar-toggle svg{width:16px;height:16px;}\n"
@"    .mac-btn{width:34px;height:34px;border-radius:999px;border:1px solid var(--control-border);background:rgba(255,255,255,0.70);display:flex;align-items:center;justify-content:center;color:var(--control-color);cursor:pointer;user-select:none;-webkit-tap-highlight-color:transparent;transition:transform .08s ease, background .12s ease, box-shadow .12s ease;padding:0;}\n"
@"    .mac-btn:hover{background:rgba(255,255,255,0.95);box-shadow:0 6px 14px rgba(0,0,0,0.14);}\n"
@"    .mac-btn:active{transform:scale(0.96);}\n"
@"    .mac-btn.is-on{background:rgba(17,24,39,0.10);border-color:rgba(17,24,39,0.28);}\n"
@"    .mac-btn svg{width:18px;height:18px;display:block;}\n"
@"  </style>\n"
@"</head>\n"
@"<body>\n"
@"  <div id='map'></div>\n"
@"\n"
@"  <div class='mac-toolbar' id='macToolbar'>\n"
@"    <button class='mac-btn toolbar-toggle' id='btnToolbar' title='Toggle toolbar' aria-label='Toggle toolbar'>\n"
@"      <svg viewBox='0 0 24 24' fill='none'>\n"
@"        <path d='M8 10l4-4 4 4M8 14l4 4 4-4' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'/>\n"
@"      </svg>\n"
@"    </button>\n"
@"    <button class='mac-btn' id='btnZoomIn' title='Zoom in' aria-label='Zoom in'>\n"
@"      <svg viewBox='0 0 24 24' fill='none'><path d='M12 5v14M5 12h14' stroke='currentColor' stroke-width='2' stroke-linecap='round'/></svg>\n"
@"    </button>\n"
@"    <button class='mac-btn' id='btnZoomOut' title='Zoom out' aria-label='Zoom out'>\n"
@"      <svg viewBox='0 0 24 24' fill='none'><path d='M5 12h14' stroke='currentColor' stroke-width='2' stroke-linecap='round'/></svg>\n"
@"    </button>\n"
@"    <button class='mac-btn' id='btnHeat' title='Heatmap' aria-label='Heatmap'>\n"
@"      <svg viewBox='0 0 24 24' fill='none'>\n"
@"        <path d='M13 2s1 3-1 5-2 3 0 5 3 4 1 7' stroke='currentColor' stroke-width='2' stroke-linecap='round'/>\n"
@"        <path d='M9 6s1 2-1 4-2 3 0 5 2 4 0 7' stroke='currentColor' stroke-width='2' stroke-linecap='round' opacity='0.85'/>\n"
@"      </svg>\n"
@"    </button>\n"
@"    <button class='mac-btn' id='btnLegend' title='Legend' aria-label='Legend'>\n"
@"      <svg viewBox='0 0 24 24' fill='none'><path d='M4 7h10M4 12h16M4 17h12' stroke='currentColor' stroke-width='2' stroke-linecap='round'/></svg>\n"
@"    </button>\n"
@"    <button class='mac-btn' id='btnMap' title='Map Style' aria-label='Map Style'>\n"
@"      <svg viewBox='0 0 24 24' fill='none'>\n"
@"        <path d='M3 6l6-2 6 2 6-2v14l-6 2-6-2-6 2V6z' stroke='currentColor' stroke-width='2' stroke-linejoin='round'/>\n"
@"        <path d='M9 4v14M15 6v14' stroke='currentColor' stroke-width='2' stroke-linecap='round' opacity='0.85'/>\n"
@"      </svg>\n"
@"    </button>\n"
@"    <button class='mac-btn' id='btnFilters' title='Filters' aria-label='Filters'>\n"
@"      <svg viewBox='0 0 24 24' fill='none'>\n"
@"        <path d='M4 6h16M7 12h10M10 18h4' stroke='currentColor' stroke-width='2' stroke-linecap='round'/>\n"
@"        <circle cx='9' cy='6' r='2' fill='currentColor' opacity='0.25'/>\n"
@"        <circle cx='14' cy='12' r='2' fill='currentColor' opacity='0.25'/>\n"
@"        <circle cx='12' cy='18' r='2' fill='currentColor' opacity='0.25'/>\n"
@"      </svg>\n"
@"    </button>\n"
@"  </div>\n"
@"\n"
@"  <div id='legend' class='legend-panel'>\n"
@"    <div class='legend-title'>Legend</div>\n"
@"    <div class='legend-item'><div class='legend-line' style='background:%@'></div><span>Connection</span></div>\n"
@"    <div class='legend-item'><div class='legend-line' style='background:#60a5fa'></div><span>Hovered</span></div>\n"
@"    <div class='legend-item'><div class='legend-line' style='background:#f59e0b'></div><span>Selected</span></div>\n"
@"    <div class='legend-item'><div class='legend-marker' style='background:#3b82f6'></div><span>Single IP</span></div>\n"
@"    <div class='legend-item'><div class='legend-marker' style='background:#ef4444'></div><span>Clustered IPs</span></div>\n"
@"    <div class='legend-item'><div class='legend-gradient'></div><span>Heat intensity</span></div>\n"
@"  </div>\n"
@"\n"
@"  <div id='filters' class='filter-panel'>\n"
@"    <div class='filter-title'>Filters</div>\n"
@"    <div class='filter-group'>\n"
@"      <div class='filter-label'>Show connections:</div>\n"
@"      <label class='filter-option'><input type='checkbox' id='filter-all' checked onchange='applyFilters()'>All</label>\n"
@"      <label class='filter-option'><input type='checkbox' id='filter-incoming' checked onchange='applyFilters()'>Incoming</label>\n"
@"      <label class='filter-option'><input type='checkbox' id='filter-outgoing' checked onchange='applyFilters()'>Outgoing</label>\n"
@"    </div>\n"
@"    <div class='filter-group'>\n"
@"      <div class='filter-label'>Min traffic:</div>\n"
@"      <label class='filter-option'><input type='radio' name='traffic' value='0' checked onchange='applyFilters()'>Any</label>\n"
@"      <label class='filter-option'><input type='radio' name='traffic' value='1024' onchange='applyFilters()'>&gt; 1 KB</label>\n"
@"      <label class='filter-option'><input type='radio' name='traffic' value='10240' onchange='applyFilters()'>&gt; 10 KB</label>\n"
@"    </div>\n"
@"  </div>\n"
@"\n"
@"  <script src='vendor/leaflet/leaflet.js'></script>\n"
@"  <script src='vendor/leaflet-heat/leaflet-heat.js'></script>\n"
@"  <script>\n"
@"    'use strict';\n"
@"    var DEBUG=false;function log(){if(DEBUG)console.log.apply(console,arguments);}\n"
@"\n"
@"    var canvasRenderer=L.canvas({padding:0.5});\n"
@"    var map=L.map('map',{zoomControl:false,attributionControl:false,renderer:canvasRenderer}).setView([20,0],2);\n"
@"\n"
@"    var baseLayers=[\n"
@"      L.tileLayer('https://{s}.basemaps.cartocdn.com/rastertiles/voyager/{z}/{x}/{y}{r}.png',{maxZoom:19,updateWhenZooming:false,updateWhenIdle:true,keepBuffer:2}),\n"
@"      L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}',{maxZoom:19,updateWhenZooming:false,updateWhenIdle:true,keepBuffer:2}),\n"
@"      L.tileLayer('https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png',{maxZoom:19,updateWhenZooming:false,updateWhenIdle:true,keepBuffer:2})\n"
@"    ];\n"
@"    var baseLayerIndex=0;var currentBaseLayer=baseLayers[0];currentBaseLayer.addTo(map);\n"
@"\n"
@"    var heatLayer=null,heatMapEnabled=false,heatData=[];\n"
@"    var heatPluginAvailable=typeof L.heatLayer==='function';\n"
@"\n"
@"    var svg=document.createElementNS('http://www.w3.org/2000/svg','svg');\n"
@"    svg.setAttribute('width','0');svg.setAttribute('height','0');\n"
@"    svg.innerHTML='<defs><marker id=\\'arrowhead\\' markerWidth=\\'6\\' markerHeight=\\'6\\' refX=\\'5\\' refY=\\'2\\' orient=\\'auto\\'><polygon points=\\'0 0, 6 2, 0 4\\' fill=\\'%@\\' opacity=\\'0.7\\'/></marker></defs>';\n"
@"    document.body.appendChild(svg);\n"
@"\n"
@"    var markerLayer=L.layerGroup().addTo(map);\n"
@"    var lineLayer=L.layerGroup().addTo(map);\n"
@"    var glowLayer=L.layerGroup().addTo(map);\n"
@"\n"
@"    var hasAutoFitted=false;\n"
@"    var popupOpen=false;\n"
@"    var selectedLine=null,selectedGlow=null,hoverGlow=null;\n"
@"    var pendingUpdate=null;\n"
@"    var lastData=null;\n"
@"\n"
@"    var connectionCache=null;\n"
@"    var lastConnCount=0;\n"
@"\n"
@"    function esc(s){\n"
@"      s=(s===undefined||s===null)?'':String(s);\n"
@"      return s\n"
@"        .replace(/&/g,'&amp;')\n"
@"        .replace(/</g,'&lt;')\n"
@"        .replace(/>/g,'&gt;')\n"
@"        .replace(/\"/g,'&quot;')\n"
@"        .replace(/'/g,'&#39;');\n"
@"    }\n"
@"\n"
@"    function applyPendingUpdate(){\n"
@"      if(pendingUpdate){var u=pendingUpdate;pendingUpdate=null;setTimeout(function(){setMarkers(u.points,u.connections);},0);}\n"
@"    }\n"
@"\n"
@"    function clearMarkers(){markerLayer.clearLayers();}\n"
@"    function clearLines(){lineLayer.clearLayers();glowLayer.clearLayers();hoverGlow=null;selectedGlow=null;selectedLine=null;}\n"
@"\n"
@"    function arcPoints(a,b){\n"
@"      var lat1=a.lat,lon1=a.lon,lat2=b.lat,lon2=b.lon;\n"
@"      var dx=lon2-lon1,dy=lat2-lat1;\n"
@"      var dist=Math.sqrt(dx*dx+dy*dy)||1;\n"
@"      var curve=Math.min(10,Math.max(2,dist*0.3));\n"
@"      var mx=(lat1+lat2)/2,my=(lon1+lon2)/2;\n"
@"      var cx=mx+(-dx/dist)*curve,cy=my+(dy/dist)*curve;\n"
@"      var steps=Math.max(6,Math.min(18,Math.round(dist*0.35)));\n"
@"      var pts=[];\n"
@"      for(var i=0;i<=steps;i++){\n"
@"        var t=i/steps;\n"
@"        var lat=(1-t)*(1-t)*lat1+2*(1-t)*t*cx+t*t*lat2;\n"
@"        var lon=(1-t)*(1-t)*lon1+2*(1-t)*t*cy+t*t*lon2;\n"
@"        pts.push([lat,lon]);\n"
@"      }\n"
@"      return pts;\n"
@"    }\n"
@"\n"
@"    function cycleBaseLayer(){\n"
@"      map.removeLayer(currentBaseLayer);\n"
@"      baseLayerIndex=(baseLayerIndex+1)%%3;\n"
@"      currentBaseLayer=baseLayers[baseLayerIndex];\n"
@"      currentBaseLayer.addTo(map);\n"
@"      return baseLayerIndex;\n"
@"    }\n"
@"\n"
@"    var legendVisible=false;function toggleLegend(){legendVisible=!legendVisible;var el=document.getElementById('legend');if(el)el.classList.toggle('visible',legendVisible);return legendVisible;}\n"
@"    var filtersVisible=false;function toggleFilters(){filtersVisible=!filtersVisible;var el=document.getElementById('filters');if(el)el.classList.toggle('visible',filtersVisible);return filtersVisible;}\n"
@"\n"
@"    var filterState={showAll:true,showIncoming:true,showOutgoing:true,minTraffic:0};\n"
@"    function connectionPassesFilter(c){\n"
@"      var bytes=(c&&typeof c.bytes==='number')?c.bytes:0;\n"
@"      if(filterState.minTraffic>0 && bytes<filterState.minTraffic) return false;\n"
@"      if(filterState.showAll) return true;\n"
@"      var dir=c&&c.direction?c.direction:'';\n"
@"      if(!filterState.showIncoming && dir==='incoming') return false;\n"
@"      if(!filterState.showOutgoing && dir==='outgoing') return false;\n"
@"      return true;\n"
@"    }\n"
@"\n"
@"    function applyFilters(){\n"
@"      var allCheck=document.getElementById('filter-all');\n"
@"      var inCheck=document.getElementById('filter-incoming');\n"
@"      var outCheck=document.getElementById('filter-outgoing');\n"
@"      var trafficRadios=document.querySelectorAll('input[name=\"traffic\"]');\n"
@"      filterState.showAll=allCheck&&allCheck.checked;\n"
@"      filterState.showIncoming=inCheck&&inCheck.checked;\n"
@"      filterState.showOutgoing=outCheck&&outCheck.checked;\n"
@"      trafficRadios.forEach(function(r){if(r.checked)filterState.minTraffic=parseInt(r.value)||0;});\n"
@"      var disable=filterState.showAll;\n"
@"      if(inCheck){inCheck.disabled=disable;inCheck.closest('label').classList.toggle('disabled',disable);}\n"
@"      if(outCheck){outCheck.disabled=disable;outCheck.closest('label').classList.toggle('disabled',disable);}\n"
@"      renderConnections();\n"
@"    }\n"
@"\n"
@"    function createHeatLayer(data){\n"
@"      if(!heatPluginAvailable) return null;\n"
@"      return L.heatLayer(data,{radius:30,blur:20,maxZoom:12,max:1.0,gradient:{0.0:'rgba(0,0,255,0)',0.2:'blue',0.4:'cyan',0.6:'lime',0.8:'yellow',1.0:'red'}});\n"
@"    }\n"
@"\n"
@"    function toggleHeatMap(){\n"
@"      if(!heatPluginAvailable) return false;\n"
@"      heatMapEnabled=!heatMapEnabled;\n"
@"      if(heatMapEnabled){\n"
@"        if(heatData.length>0){if(!heatLayer)heatLayer=createHeatLayer(heatData);if(heatLayer)heatLayer.addTo(map);}\n"
@"      }else{\n"
@"        if(heatLayer)map.removeLayer(heatLayer);\n"
@"      }\n"
@"      return heatMapEnabled;\n"
@"    }\n"
@"\n"
@"    function updateHeatData(points){\n"
@"      heatData=[];\n"
@"      if(points&&points.length){\n"
@"        for(var i=0;i<points.length;i++){\n"
@"          var p=points[i];\n"
@"          if(typeof p.lat==='number'&&typeof p.lon==='number'){\n"
@"            var intensity=p.ips&&p.ips.length?Math.min(1.0,p.ips.length*0.2+0.3):0.5;\n"
@"            heatData.push([p.lat,p.lon,intensity]);\n"
@"          }\n"
@"        }\n"
@"      }\n"
@"      if(heatPluginAvailable){\n"
@"        if(heatLayer && heatLayer.setLatLngs){heatLayer.setLatLngs(heatData);}\n"
@"        else if(heatMapEnabled && heatData.length){heatLayer=createHeatLayer(heatData);if(heatLayer)heatLayer.addTo(map);}\n"
@"      }\n"
@"    }\n"
@"\n"
@"    function createGlowLine(arcPts,color,weight,className){\n"
@"      return L.polyline(arcPts,{renderer:canvasRenderer,color:color,weight:weight,opacity:0.6,lineCap:'round',lineJoin:'round',className:'glow-line '+className,interactive:false});\n"
@"    }\n"
@"    function showHoverGlow(line){\n"
@"      if(hoverGlow){glowLayer.removeLayer(hoverGlow);hoverGlow=null;}\n"
@"      if(line===selectedLine) return;\n"
@"      hoverGlow=createGlowLine(line._arcPts,'#60a5fa',line._baseWeight+8,'glow-line-hover');\n"
@"      hoverGlow.addTo(glowLayer);\n"
@"    }\n"
@"    function hideHoverGlow(){if(hoverGlow){glowLayer.removeLayer(hoverGlow);hoverGlow=null;}}\n"
@"    function showSelectedGlow(line){\n"
@"      if(selectedGlow){glowLayer.removeLayer(selectedGlow);selectedGlow=null;}\n"
@"      selectedGlow=createGlowLine(line._arcPts,'#f59e0b',line._baseWeight+12,'glow-line-selected');\n"
@"      selectedGlow.addTo(glowLayer);\n"
@"    }\n"
@"    function hideSelectedGlow(){if(selectedGlow){glowLayer.removeLayer(selectedGlow);selectedGlow=null;}}\n"
@"\n"
@"    function buildPopupForPoint(p){\n"
@"      var popupContent='';\n"
@"      if(Array.isArray(p.ips)&&p.ips.length>0){\n"
@"        var count=p.ips.length;\n"
@"        popupContent='<div class=\"location-header\">📍 '+count+' Connection'+(count>1?'s':'')+'</div>';\n"
@"        if(p.locationName&&p.locationName.length>0){popupContent+='<div class=\"location-name\">'+esc(p.locationName)+'</div>';}\n"
@"        popupContent+='<ul class=\"ip-list\">';\n"
@"        for(var i=0;i<p.ips.length;i++){\n"
@"          var ip=p.ips[i];\n"
@"          var isp=p.isps&&p.isps[i]?p.isps[i]:'';\n"
@"          var badge=p.badgeInfos&&p.badgeInfos[i]?p.badgeInfos[i]:null;\n"
@"          var badgeMarkup='';\n"
@"          if(badge){\n"
@"            var color=badge.color||'#94a3b8';\n"
@"            var icon=badge.icon||'';\n"
@"            badgeMarkup='<span class=\"ip-badge\" style=\"border-color:'+esc(color)+';color:'+esc(color)+';\">'\n"
@"              +'<span class=\"ip-badge-dot\" style=\"background:'+esc(color)+'\"></span>'\n"
@"              +'<span class=\"ip-badge-icon\">'+esc(icon)+'</span></span>';\n"
@"          }\n"
@"          popupContent+='<li class=\"ip-item\">'+badgeMarkup+'<span class=\"ip-text\">'\n"
@"            +'<span class=\"ip-address\">'+esc(ip)+'</span>'\n"
@"            +(isp&&isp.length?'<span class=\"ip-company\">'+esc(isp)+'</span>':'')\n"
@"            +'</span></li>';\n"
@"        }\n"
@"        popupContent+='</ul>';\n"
@"      }else if(p.title){\n"
@"        popupContent='<div class=\"location-header\">📍 Location</div>'+esc(p.title).replace(/\\n/g,'<br>');\n"
@"      }\n"
@"      return popupContent;\n"
@"    }\n"
@"\n"
@"    function rebuildConnectionCache(connections){\n"
@"      connectionCache=[];\n"
@"      if(!connections||!connections.length){lastConnCount=0;document.body.classList.remove('no-anim');return;}\n"
@"      lastConnCount=connections.length;\n"
@"      document.body.classList.toggle('no-anim', lastConnCount>120);\n"
@"      for(var i=0;i<connections.length;i++){\n"
@"        var c=connections[i];\n"
@"        if(typeof c.srcLat!=='number'||typeof c.srcLon!=='number'||typeof c.dstLat!=='number'||typeof c.dstLon!=='number') continue;\n"
@"        var arcPts=arcPoints({lat:c.srcLat,lon:c.srcLon},{lat:c.dstLat,lon:c.dstLon});\n"
@"        var opacity=Math.max(0.3,1-(i*0.08));\n"
@"        var w=Math.max(1,%ld-(i*0.3));\n"
@"        connectionCache.push({c:c,arcPts:arcPts,opacity:opacity,weight:w});\n"
@"      }\n"
@"    }\n"
@"\n"
@"    var hoverRAF=0;var hoverFn=null;\n"
@"    function scheduleHover(fn){\n"
@"      hoverFn=fn;\n"
@"      if(hoverRAF) return;\n"
@"      hoverRAF=requestAnimationFrame(function(){hoverRAF=0;var f=hoverFn;hoverFn=null;if(f)f();});\n"
@"    }\n"
@"\n"
@"    function renderConnections(){\n"
@"      if(!connectionCache) return;\n"
@"      clearLines();\n"
@"      var defaultColor='%@';\n"
@"      for(var i=0;i<connectionCache.length;i++){\n"
@"        var item=connectionCache[i];\n"
@"        var c=item.c;\n"
@"        if(!connectionPassesFilter(c)) continue;\n"
@"        var line=L.polyline(item.arcPts,{renderer:canvasRenderer,color:defaultColor,weight:item.weight,opacity:item.opacity*%f,dashArray:'8,12',className:'connection-line',interactive:true});\n"
@"        line._arcPts=item.arcPts;\n"
@"        line._baseWeight=item.weight;\n"
@"        line._defaultColor=defaultColor;\n"
@"        line._srcIP=c.srcIP; line._dstIP=c.dstIP;\n"
@"\n"
@"        line.on('click',function(e){\n"
@"          var ln=this;\n"
@"          if(selectedLine&&selectedLine!==ln){selectedLine.setStyle({color:selectedLine._defaultColor,weight:selectedLine._baseWeight});hideSelectedGlow();}\n"
@"          selectedLine=ln;\n"
@"          ln.setStyle({color:'#f59e0b',weight:ln._baseWeight+2});\n"
@"          showSelectedGlow(ln);\n"
@"          hideHoverGlow();\n"
@"          if(window.webkit&&window.webkit.messageHandlers&&window.webkit.messageHandlers.connectionSelect){\n"
@"            window.webkit.messageHandlers.connectionSelect.postMessage({source:ln._srcIP,destination:ln._dstIP});\n"
@"          }\n"
@"          L.DomEvent.stopPropagation(e);\n"
@"        });\n"
@"\n"
@"        line.on('mouseover',function(){\n"
@"          var ln=this;\n"
@"          if(selectedLine===ln) return;\n"
@"          scheduleHover(function(){ln.setStyle({color:'#60a5fa',weight:ln._baseWeight+1});showHoverGlow(ln);});\n"
@"          if(window.webkit&&window.webkit.messageHandlers&&window.webkit.messageHandlers.connectionSelect){\n"
@"            window.webkit.messageHandlers.connectionSelect.postMessage({source:ln._srcIP,destination:ln._dstIP,isHover:true});\n"
@"          }\n"
@"        });\n"
@"\n"
@"        line.on('mouseout',function(){\n"
@"          var ln=this;\n"
@"          scheduleHover(function(){hideHoverGlow();if(selectedLine!==ln){ln.setStyle({color:ln._defaultColor,weight:ln._baseWeight});}});\n"
@"        });\n"
@"\n"
@"        if(c.title){\n"
@"          var pc='<strong>🔄 Connection</strong><br>'+esc(c.title).replace(/→/g,'<br>→ ');\n"
@"          line.bindPopup(pc);\n"
@"        }\n"
@"        line.addTo(lineLayer);\n"
@"      }\n"
@"    }\n"
@"\n"
@"    function setMarkers(points,connections){\n"
@"      lastData={points:points,connections:connections};\n"
@"      if(popupOpen){pendingUpdate={points:points,connections:connections};return;}\n"
@"      pendingUpdate=null;\n"
@"\n"
@"      clearMarkers();\n"
@"      updateHeatData(points);\n"
@"\n"
@"      var bounds=[];\n"
@"      if(points&&points.length){\n"
@"        for(var i=0;i<points.length;i++){\n"
@"          var p=points[i];\n"
@"          if(typeof p.lat!=='number'||typeof p.lon!=='number') continue;\n"
@"          var popupContent=buildPopupForPoint(p);\n"
@"          var marker;\n"
@"          if(p.isDuplicate){\n"
@"            var count2=p.ips?p.ips.length:0;\n"
@"            var size=Math.min(44,Math.max(28,count2*3+20));\n"
@"            var icon2=L.divIcon({className:'cluster-marker',html:'<div>'+count2+'</div>',iconSize:[size,size],iconAnchor:[size/2,size/2]});\n"
@"            marker=L.marker([p.lat,p.lon],{icon:icon2});\n"
@"          }else{\n"
@"            var icon3=L.divIcon({className:'single-marker',html:'<div class=\"single-marker\"></div>',iconSize:[24,32],iconAnchor:[12,32]});\n"
@"            marker=L.marker([p.lat,p.lon],{icon:icon3});\n"
@"          }\n"
@"          if(popupContent){marker.bindPopup(popupContent);}\n"
@"          marker.on('popupopen',function(){popupOpen=true;});\n"
@"          marker.on('popupclose',function(){popupOpen=false;applyPendingUpdate();});\n"
@"          marker.addTo(markerLayer);\n"
@"          bounds.push([p.lat,p.lon]);\n"
@"        }\n"
@"      }\n"
@"\n"
@"      rebuildConnectionCache(connections);\n"
@"      renderConnections();\n"
@"\n"
@"      if(bounds.length>0&&!hasAutoFitted){map.fitBounds(bounds,{padding:[20,20],maxZoom:6});hasAutoFitted=true;}\n"
@"    }\n"
@"\n"
@"    function zoomIn(){map.zoomIn();}\n"
@"    function zoomOut(){map.zoomOut();}\n"
@"    function resetView(){hasAutoFitted=false;}\n"
@"\n"
@"    function setBtnOn(id,on){var el=document.getElementById(id);if(!el)return;el.classList.toggle('is-on',!!on);}\n"
@"\n"
@"    (function wireMacButtons(){\n"
@"      var toolbar=document.getElementById('macToolbar');\n"
@"      var btnToolbar=document.getElementById('btnToolbar');\n"
@"      var btnZoomIn=document.getElementById('btnZoomIn');\n"
@"      var btnZoomOut=document.getElementById('btnZoomOut');\n"
@"      var btnHeat=document.getElementById('btnHeat');\n"
@"      var btnLegend=document.getElementById('btnLegend');\n"
@"      var btnMap=document.getElementById('btnMap');\n"
@"      var btnFilters=document.getElementById('btnFilters');\n"
@"      if(btnToolbar&&toolbar){btnToolbar.addEventListener('click',function(){toolbar.classList.toggle('is-collapsed');});}\n"
@"      if(btnZoomIn){btnZoomIn.addEventListener('click',function(){zoomIn();});}\n"
@"      if(btnZoomOut){btnZoomOut.addEventListener('click',function(){zoomOut();});}\n"
@"      if(btnHeat){btnHeat.addEventListener('click',function(){var on=toggleHeatMap();setBtnOn('btnHeat',on);});}\n"
@"      if(btnLegend){btnLegend.addEventListener('click',function(){var on=toggleLegend();setBtnOn('btnLegend',on);});}\n"
@"      if(btnMap){btnMap.addEventListener('click',function(){cycleBaseLayer();setBtnOn('btnMap',true);setTimeout(function(){setBtnOn('btnMap',false);},180);});}\n"
@"      if(btnFilters){btnFilters.addEventListener('click',function(){var on=toggleFilters();setBtnOn('btnFilters',on);});}\n"
@"    })();\n"
@"\n"
@"    window.SniffNetBar={setMarkers:setMarkers,zoomIn:zoomIn,zoomOut:zoomOut,resetView:resetView,cycleBaseLayer:cycleBaseLayer,toggleHeatMap:toggleHeatMap,toggleLegend:toggleLegend,toggleFilters:toggleFilters};\n"
@"  </script>\n"
@"</body>\n"
@"</html>\n"
, lineColor, lineColor, (long)lineWeight, lineColor, lineOpacity];
    NSURL *resourceURL = [[NSBundle mainBundle] resourceURL];
    [self.webView loadHTMLString:html baseURL:resourceURL];
}

// Helper badge generation
- (void)addBadgeInfoForIPAddress:(NSString *)address
                    connection:(ConnectionTraffic *)connection
                          map:(NSMutableDictionary<NSString *, NSDictionary *> *)map {
    if (!address.length || !map) {
        return;
    }
    if (map[address]) {
        return;
    }
    BOOL hasProcessInfo = connection.processName.length > 0 || connection.processPID != 0;
    NSColor *color;
    if (hasProcessInfo) {
        color = [[SNBBadgeRegistry sharedRegistry] colorForProcessName:connection.processName
                                                                   pid:connection.processPID
                                                  createIfMissing:YES];
    } else {
        color = [[SNBBadgeRegistry sharedRegistry] colorForLabel:address
                                                 createIfMissing:YES];
    }
    NSString *icon = [[SNBBadgeRegistry sharedRegistry] badgeIconForProcessName:connection.processName
                                                                             pid:connection.processPID
                                                                  fallbackLabel:address];
    NSString *colorHex = [self hexStringForColor:color];
    map[address] = @{@"icon": icon ?: @"", @"color": colorHex};
}

- (NSString *)hexStringForColor:(NSColor *)color {
    NSColor *rgbColor = (color ?: [NSColor labelColor]);
    rgbColor = [rgbColor colorUsingColorSpace:[NSColorSpace sRGBColorSpace]] ?: [NSColor labelColor];
    CGFloat red = 0, green = 0, blue = 0, alpha = 0;
    [rgbColor getRed:&red green:&green blue:&blue alpha:&alpha];
    return [NSString stringWithFormat:@"#%02lX%02lX%02lX",
            (long)(red * 255.0),
            (long)(green * 255.0),
            (long)(blue * 255.0)];
}

- (NSButton *)zoomButtonWithTitle:(NSString *)title action:(SEL)action {
    NSButton *button = [[NSButton alloc] initWithFrame:NSMakeRect(0, 0, 32, 32)];
    button.title = title;
    button.target = self;
    button.action = action;
    [self applyCommonButtonStyle:button fontSize:16.0 weight:NSFontWeightSemibold];

    return button;
}

- (NSButton *)layerButtonWithTitle:(NSString *)title action:(SEL)action tooltip:(NSString *)tooltip {
    NSButton *button = [[NSButton alloc] initWithFrame:NSMakeRect(0, 0, 32, 32)];
    button.title = title;
    button.target = self;
    button.action = action;
    button.toolTip = tooltip;

    [self applyCommonButtonStyle:button fontSize:16.0 weight:NSFontWeightRegular];

    return button;
}

- (void)applyCommonButtonStyle:(NSButton *)button fontSize:(CGFloat)fontSize weight:(NSFontWeight)weight {
    button.bezelStyle = NSBezelStyleShadowlessSquare;
    button.bordered = YES;
    button.wantsLayer = YES;
    button.layer.backgroundColor = [[NSColor colorWithWhite:1.0 alpha:0.95] CGColor];
    button.layer.cornerRadius = 8.0;
    button.layer.borderWidth = 1.0;
    button.layer.borderColor = [[NSColor colorWithRed:0 green:0 blue:0 alpha:0.1] CGColor];
    button.layer.shadowColor = [[NSColor blackColor] CGColor];
    button.layer.shadowOpacity = 0.15;
    button.layer.shadowOffset = NSMakeSize(0, 2);
    button.layer.shadowRadius = 4.0;

    NSMutableParagraphStyle *style = [[NSMutableParagraphStyle alloc] init];
    style.alignment = NSTextAlignmentCenter;
    NSDictionary *attributes = @{
        NSForegroundColorAttributeName: [NSColor colorWithRed:0.09 green:0.09 blue:0.11 alpha:1.0],
        NSFontAttributeName: [NSFont systemFontOfSize:fontSize weight:weight],
        NSParagraphStyleAttributeName: style
    };
    button.attributedTitle = [[NSAttributedString alloc] initWithString:button.title attributes:attributes];
}

- (void)updateLayout {
    self.webView.frame = self.bounds;
    CGFloat padding = 10.0;
    CGFloat buttonSize = 32.0;
    CGFloat buttonSpacing = 6.0;

    // Ensure buttons stay on top of webview
    NSMutableArray<NSButton *> *buttons = [NSMutableArray array];
    if (self.zoomInButton) {
        [buttons addObject:self.zoomInButton];
    }
    if (self.zoomOutButton) {
        [buttons addObject:self.zoomOutButton];
    }
    for (NSButton *button in buttons) {
        [button removeFromSuperview];
        [self addSubview:button];
    }
}

- (void)zoomIn:(id)sender {
    [self.webView evaluateJavaScript:@"window.SniffNetBar && window.SniffNetBar.zoomIn();" completionHandler:nil];
}

- (void)zoomOut:(id)sender {
    [self.webView evaluateJavaScript:@"window.SniffNetBar && window.SniffNetBar.zoomOut();" completionHandler:nil];
}

- (void)cycleBaseLayer {
    __weak typeof(self) weakSelf = self;
    [self.webView evaluateJavaScript:@"window.SniffNetBar && window.SniffNetBar.cycleBaseLayer();"
                   completionHandler:^(id result, NSError *error) {
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) return;
        (void)error;

        NSInteger layerIndex = [result integerValue];
        strongSelf.baseLayerType = (SNBMapLayerType)layerIndex;

        // Update button icon based on layer type
        NSString *icon = @"🗺";
        switch (layerIndex) {
            case 0: icon = @"🗺"; break;  // Standard
            case 1: icon = @"🛰"; break;  // Satellite
            case 2: icon = @"◻️"; break;  // Grayscale
        }
        strongSelf.layerButton.title = icon;
        [strongSelf updateLayerButtonAppearance:strongSelf.layerButton active:(layerIndex != 0)];
        SNBLogUIDebug("Base layer changed to %ld", (long)layerIndex);
    }];
}

- (void)toggleHeatMap {
    __weak typeof(self) weakSelf = self;
    [self.webView evaluateJavaScript:@"window.SniffNetBar && window.SniffNetBar.toggleHeatMap();"
                   completionHandler:^(id result, NSError *error) {
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) return;
        (void)error;

        BOOL isEnabled = [result boolValue];
        strongSelf.heatMapEnabled = isEnabled;

        // Update button appearance to show active state
        [strongSelf updateLayerButtonAppearance:strongSelf.heatMapButton active:isEnabled];
        SNBLogUIDebug("Heat map %s", isEnabled ? "enabled" : "disabled");
    }];
}

- (void)updateLayerButtonAppearance:(NSButton *)button active:(BOOL)active {
    if (active) {
        button.layer.backgroundColor = [[NSColor colorWithRed:0.2 green:0.5 blue:0.9 alpha:0.95] CGColor];
        button.layer.borderColor = [[NSColor colorWithRed:0.1 green:0.4 blue:0.8 alpha:1.0] CGColor];
    } else {
        button.layer.backgroundColor = [[NSColor colorWithWhite:1.0 alpha:0.95] CGColor];
        button.layer.borderColor = [[NSColor colorWithRed:0 green:0 blue:0 alpha:0.1] CGColor];
    }
}

- (void)toggleLegend {
    __weak typeof(self) weakSelf = self;
    [self.webView evaluateJavaScript:@"window.SniffNetBar && window.SniffNetBar.toggleLegend();"
                   completionHandler:^(id result, NSError *error) {
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) return;
        (void)error;

        BOOL isVisible = [result boolValue];
        strongSelf.legendVisible = isVisible;
        [strongSelf updateLayerButtonAppearance:strongSelf.legendButton active:isVisible];
        SNBLogUIDebug("Legend %s", isVisible ? "shown" : "hidden");
    }];
}

- (void)toggleFilters {
    __weak typeof(self) weakSelf = self;
    [self.webView evaluateJavaScript:@"window.SniffNetBar && window.SniffNetBar.toggleFilters();"
                   completionHandler:^(id result, NSError *error) {
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) return;
        (void)error;

        BOOL isVisible = [result boolValue];
        [strongSelf updateLayerButtonAppearance:strongSelf.filterButton active:isVisible];
        SNBLogUIDebug("Filters panel %s", isVisible ? "shown" : "hidden");
    }];
}

- (BOOL)shouldGeolocateIPAddress:(NSString *)ip {
    // Use centralized validation - only geolocate public IPs
    return [IPAddressUtilities isPublicIPAddress:ip];
}

- (void)fetchLocationForIP:(NSString *)ip completion:(void (^)(CLLocationCoordinate2D, BOOL))completion {
    // Acquire semaphore to limit concurrent requests (prevents rate limiting)
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        dispatch_semaphore_wait(self.geoLocationSemaphore, DISPATCH_TIME_FOREVER);

        NSString *provider = self.providerName.length > 0 ? self.providerName : @"ipinfo.io";
        NSString *encodedIP = [ip stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet URLPathAllowedCharacterSet]];
        NSString *urlString = nil;

        if ([provider isEqualToString:@"ip-api.com"]) {
            urlString = [NSString stringWithFormat:@"https://ip-api.com/json/%@?fields=status,message,lat,lon,query", encodedIP];
        } else if ([provider isEqualToString:@"ipinfo.io"]) {
            NSString *token = [ConfigurationManager sharedManager].ipInfoAPIToken;
            NSString *encodedToken = token.length > 0 ? [token stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet URLQueryAllowedCharacterSet]] : @"";
            if (encodedToken.length > 0) {
                urlString = [NSString stringWithFormat:@"https://ipinfo.io/%@/json?token=%@", encodedIP, encodedToken];
            } else {
                urlString = [NSString stringWithFormat:@"https://ipinfo.io/%@/json", encodedIP];
            }
        } else {
            NSString *template = [[NSUserDefaults standardUserDefaults] stringForKey:SNBUserDefaultsKeyMapProviderURLTemplate];
            if (template.length == 0) {
                dispatch_semaphore_signal(self.geoLocationSemaphore);
                completion(kCLLocationCoordinate2DInvalid, NO);
                return;
            }
            urlString = [NSString stringWithFormat:template, encodedIP];
        }

        NSURL *url = [NSURL URLWithString:urlString];
        if (!url) {
            dispatch_semaphore_signal(self.geoLocationSemaphore);
            completion(kCLLocationCoordinate2DInvalid, NO);
            return;
        }

        SNBLogUIDebug(" lookup %s via %s", ip.UTF8String, urlString.UTF8String);

        NSURLSessionDataTask *task = [self.session dataTaskWithURL:url completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
            // Release semaphore when request completes
            dispatch_semaphore_signal(self.geoLocationSemaphore);
        NSHTTPURLResponse *httpResponse = [response isKindOfClass:[NSHTTPURLResponse class]] ? (NSHTTPURLResponse *)response : nil;
        if (error || !data) {
            SNBLogUIDebug(" lookup failed for %s: %s", ip.UTF8String, error.localizedDescription.UTF8String);
            completion(kCLLocationCoordinate2DInvalid, NO);
            return;
        }
        if (httpResponse) {
            SNBLogUIDebug(" response %s status %ld", ip.UTF8String, (long)httpResponse.statusCode);
        }
        
        if ([provider isEqualToString:@"ip-api.com"] && httpResponse.statusCode == 403) {
            SNBLogUIDebug(" fallback to ipinfo.io for %s", ip.UTF8String);
            dispatch_async(dispatch_get_main_queue(), ^{
                NSString *savedProvider = self.providerName;
                self.providerName = @"ipinfo.io";
                [self fetchLocationForIP:ip completion:completion];
                self.providerName = savedProvider;
            });
            return;
        }
        
        NSError *jsonError;
        id json = [NSJSONSerialization JSONObjectWithData:data options:0 error:&jsonError];
        if (jsonError || ![json isKindOfClass:[NSDictionary class]]) {
            SNBLogUIDebug(" JSON error for %s: %s", ip.UTF8String, jsonError.localizedDescription.UTF8String);
            completion(kCLLocationCoordinate2DInvalid, NO);
            return;
        }
        
        NSDictionary *dict = (NSDictionary *)json;
        CLLocationDegrees lat = 0;
        CLLocationDegrees lon = 0;
        BOOL success = NO;
        NSString *name = nil;
        NSString *isp = nil;
        
        if ([provider isEqualToString:@"ip-api.com"]) {
            NSString *status = dict[@"status"];
            if ([status isEqualToString:@"success"]) {
                lat = [dict[@"lat"] doubleValue];
                lon = [dict[@"lon"] doubleValue];
                NSString *city = dict[@"city"];
                NSString *region = dict[@"regionName"];
                NSString *country = dict[@"country"];
                isp = dict[@"isp"];
                NSMutableArray<NSString *> *parts = [NSMutableArray array];
                if (city.length > 0) [parts addObject:city];
                if (region.length > 0) [parts addObject:region];
                if (country.length > 0) [parts addObject:country];
                name = parts.count > 0 ? [parts componentsJoinedByString:@", "] : nil;
                success = YES;
            }
        } else if ([provider isEqualToString:@"ipinfo.io"]) {
            NSString *loc = dict[@"loc"];
            NSArray<NSString *> *parts = [loc componentsSeparatedByString:@","];
            if (parts.count == 2) {
                lat = [parts[0] doubleValue];
                lon = [parts[1] doubleValue];
                NSString *city = dict[@"city"];
                NSString *region = dict[@"region"];
                NSString *country = dict[@"country"];
                NSString *org = dict[@"org"];
                NSString *company = dict[@"company"];
                if (org.length > 0) {
                    isp = org;
                } else if (company.length > 0) {
                    isp = company;
                }
                NSMutableArray<NSString *> *nameParts = [NSMutableArray array];
                if (city.length > 0) [nameParts addObject:city];
                if (region.length > 0) [nameParts addObject:region];
                if (country.length > 0) [nameParts addObject:country];
                name = nameParts.count > 0 ? [nameParts componentsJoinedByString:@", "] : nil;
                success = YES;
            }
        } else {
            NSString *latKey = [[NSUserDefaults standardUserDefaults] stringForKey:SNBUserDefaultsKeyMapProviderLatKey] ?: @"lat";
            NSString *lonKey = [[NSUserDefaults standardUserDefaults] stringForKey:SNBUserDefaultsKeyMapProviderLonKey] ?: @"lon";
            id latValue = [dict valueForKeyPath:latKey];
            id lonValue = [dict valueForKeyPath:lonKey];
            if ([latValue respondsToSelector:@selector(doubleValue)] &&
                [lonValue respondsToSelector:@selector(doubleValue)]) {
                lat = [latValue doubleValue];
                lon = [lonValue doubleValue];
                success = YES;
            }
        }
        
        if (success) {
            SNBLogUIDebug(" location %s => (%f, %f)", ip.UTF8String, lat, lon);
            NSMutableDictionary *payload = [NSMutableDictionary dictionaryWithDictionary:@{@"lat": @(lat), @"lon": @(lon)}];
            if (name.length > 0) {
                payload[@"name"] = name;
            }
            if (isp.length > 0) {
                payload[@"isp"] = isp;
            }
            dispatch_async(dispatch_get_main_queue(), ^{
                [self.locationCache setObject:payload forKey:ip];
                [self.locationStore storeLocation:payload forIP:ip];
                completion(CLLocationCoordinate2DMake(lat, lon), YES);
            });
        } else {
            SNBLogUIDebug(" location missing for %s (%s)", ip.UTF8String, provider.UTF8String);
            completion(kCLLocationCoordinate2DInvalid, NO);
        }
        }];
        [task resume];
    });
}

#pragma mark - WKNavigationDelegate

- (void)webView:(WKWebView *)webView didFinishNavigation:(WKNavigation *)navigation {
    self.mapReady = YES;
    [self markRenderDataDirty];
    [self refreshMarkers];
}

#pragma mark - WKScriptMessageHandler

- (void)userContentController:(WKUserContentController *)userContentController
      didReceiveScriptMessage:(WKScriptMessage *)message {
    if ([message.name isEqualToString:@"consoleLog"]) {
        NSString *logMessage = [message.body description];
        SNBLogUIDebug("[JS] %s", logMessage.UTF8String);
        return;
    }

    if ([message.name isEqualToString:@"connectionSelect"]) {
        SNBLogUIDebug("connectionSelect message received");
        NSDictionary *data = message.body;
        if (![data isKindOfClass:[NSDictionary class]]) {
            SNBLogUIDebug("connectionSelect: Invalid data type");
            return;
        }

        NSString *sourceIP = data[@"source"];
        NSString *destinationIP = data[@"destination"];
        SNBLogUIDebug("connectionSelect: sourceIP=%s destIP=%s", sourceIP.UTF8String, destinationIP.UTF8String);

        if (sourceIP && destinationIP) {
            if ([self.delegate respondsToSelector:@selector(mapMenuView:didSelectConnectionWithSource:destination:)]) {
                SNBLogUIDebug("connectionSelect: Calling delegate");
                [self.delegate mapMenuView:self didSelectConnectionWithSource:sourceIP destination:destinationIP];
            } else {
                SNBLogUIDebug("connectionSelect: Delegate does not respond to selector or is nil");
            }
        }
    }
}

@end

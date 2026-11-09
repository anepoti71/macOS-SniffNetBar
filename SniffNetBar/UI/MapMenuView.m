//
//  MapMenuView.m
//  SniffNetBar
//
//  Map visualization embedded in the menu (Leaflet via WebKit)
//

#import "MapMenuView.h"
#import "ConfigurationManager.h"
#import "IPAddressUtilities.h"
#import "UserDefaultsKeys.h"
#import "SNBBadgeRegistry.h"
#import "SNBTimerCoordinator.h"
#import "ThreatIntelModels.h"
#import "TrustedIPStore.h"
#import "Logger.h"
#import "SNBGeoLocationService.h"
#import "SNBMapRenderer.h"
#import <WebKit/WebKit.h>
#import <CoreLocation/CoreLocation.h>

// Cache cleanup interval
static const NSTimeInterval kCacheCleanupInterval = 300.0;  // 5 minutes
// Render debounce interval to reduce UI churn
static const NSTimeInterval kRenderDebounceInterval = 0.25;

@interface MapMenuView () <WKNavigationDelegate, WKScriptMessageHandler, NSWindowDelegate>
@property (nonatomic, strong) WKWebView *webView;
@property (nonatomic, strong) NSButton *zoomInButton;
@property (nonatomic, strong) NSButton *zoomOutButton;
@property (nonatomic, strong) NSButton *layerButton;
@property (nonatomic, strong) NSButton *satelliteButton;
@property (nonatomic, strong) NSButton *heatMapButton;
@property (nonatomic, strong) NSButton *legendButton;
@property (nonatomic, strong) NSButton *filterButton;
@property (nonatomic, strong) SNBGeoLocationService *geoService;
@property (nonatomic, strong) SNBMapRenderer *mapRenderer;
@property (nonatomic, copy) NSArray<ConnectionTraffic *> *lastConnections;
@property (nonatomic, copy) NSDictionary<NSString *, TIEnrichmentResponse *> *threatIntelResults;
@property (nonatomic, copy) NSSet<NSString *> *blockedIPs;
@property (nonatomic, strong) SNBTrustedIPStore *trustedStore;
@property (nonatomic, strong) NSMutableDictionary<NSString *, NSDate *> *firstSeenByIP;
@property (nonatomic, strong) NSMutableDictionary<NSString *, NSDate *> *lastSeenByIP;
@property (nonatomic, assign) BOOL mapReady;
@property (nonatomic, copy) NSArray<NSString *> *lastTargetIPs;
@property (nonatomic, assign) uint64_t lastConnectionsHash;
@property (nonatomic, assign) NSUInteger riskVersion;
@property (nonatomic, assign) uint64_t cachedConnectionsHash;
@property (nonatomic, assign) NSUInteger cachedLocationVersion;
@property (nonatomic, assign) NSUInteger cachedRiskVersion;
@property (nonatomic, assign) NSInteger cachedMaxLines;
@property (nonatomic, copy) NSString *cachedPointsJSON;
@property (nonatomic, copy) NSString *cachedLinesJSON;
@property (nonatomic, strong) dispatch_queue_t renderQueue;
@property (nonatomic, assign) NSUInteger renderGeneration;
@property (nonatomic, copy) SNBTimerID renderDebounceTimerID;
@property (nonatomic, assign) BOOL renderPending;
@property (nonatomic, assign) NSUInteger renderDataGeneration;
@property (nonatomic, assign) NSUInteger lastRenderedGeneration;
@property (nonatomic, assign) NSUInteger scheduledRenderGeneration;
@property (nonatomic, assign) NSUInteger lastRenderSignature;
@property (nonatomic, strong) NSDate *lastCacheCleanupTime;
@property (nonatomic, strong) NSWindow *detachedWindow;
@property (nonatomic, strong) MapMenuView *detachedMapView;
@property (nonatomic, assign) BOOL isDetachedInstance;
// Thread-safe: written on background queue, read on main thread
@property (atomic, assign, readwrite) NSUInteger drawnConnectionCount;
// Event monitor for capturing clicks in menu context
@property (nonatomic, strong) id clickEventMonitor;
// Periodic cleanup timer
@property (nonatomic, copy) SNBTimerID cleanupTimerID;
@end

// WebKit on macOS 27.2+ no longer loads file:// subresources for pages loaded via
// -loadHTMLString:baseURL: with a file base URL, so Leaflet never ran and the map
// stayed blank. Inline the bundled vendor CSS/JS into the HTML instead.
static NSString *SNBInlineVendorAssets(NSString *html, NSURL *resourceURL) {
    NSArray<NSArray<NSString *> *> *assets = @[
        @[@"<link rel='stylesheet' href='vendor/leaflet/leaflet.css'>", @"vendor/leaflet/leaflet.css", @"style"],
        @[@"<script src='vendor/leaflet/leaflet.js'></script>", @"vendor/leaflet/leaflet.js", @"script"],
        @[@"<script src='vendor/leaflet-heat/leaflet-heat.js'></script>", @"vendor/leaflet-heat/leaflet-heat.js", @"script"],
    ];
    NSMutableString *result = [html mutableCopy];
    for (NSArray<NSString *> *asset in assets) {
        NSURL *fileURL = [resourceURL URLByAppendingPathComponent:asset[1]];
        NSError *error = nil;
        NSString *contents = [NSString stringWithContentsOfURL:fileURL encoding:NSUTF8StringEncoding error:&error];
        if (!contents) {
            SNBLogUIError("Failed to read map asset %{public}@: %{public}@", asset[1], error);
            continue;
        }
        NSString *inlined = [NSString stringWithFormat:@"<%@>%@</%@>", asset[2], contents, asset[2]];
        [result replaceOccurrencesOfString:asset[0] withString:inlined options:0 range:NSMakeRange(0, result.length)];
    }
    return result;
}

@implementation MapMenuView

static inline uint64_t SNBHashCombine(uint64_t hash, uint64_t value) {
    hash ^= value;
    return hash * 1099511628211ULL;
}

static uint64_t SNBHashConnectionTuple(ConnectionTraffic *connection) {
    uint64_t hash = 1469598103934665603ULL;
    hash = SNBHashCombine(hash, connection.sourceAddress.hash);
    hash = SNBHashCombine(hash, connection.destinationAddress.hash);
    hash = SNBHashCombine(hash, (uint64_t)connection.sourcePort);
    hash = SNBHashCombine(hash, (uint64_t)connection.destinationPort);
    hash = SNBHashCombine(hash, connection.bytes);
    hash = SNBHashCombine(hash, connection.incomingBytes);
    hash = SNBHashCombine(hash, connection.outgoingBytes);
    hash = SNBHashCombine(hash, (uint64_t)connection.packetCount);
    hash = SNBHashCombine(hash, (uint64_t)connection.processPID);
    hash = SNBHashCombine(hash, connection.processName.hash);
    hash = SNBHashCombine(hash, (uint64_t)connection.lastActivity);
    return hash;
}

- (instancetype)initWithFrame:(NSRect)frame {
    self = [super initWithFrame:frame];
    if (self) {
        // Enable layer backing for proper z-ordering
        self.wantsLayer = YES;

        WKWebViewConfiguration *config = [[WKWebViewConfiguration alloc] init];
        [config.userContentController addScriptMessageHandler:self name:@"connectionSelect"];
        [config.userContentController addScriptMessageHandler:self name:@"mapAction"];
        [config.userContentController addScriptMessageHandler:self name:@"mapDetach"];
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
                "window.addEventListener('error',function(e){"
                "  var t=e.target;"
                "  var src=(t&&t!==window&&(t.src||t.href))?(' resource='+(t.src||t.href)):'';"
                "  console.log('window.error: '+(e.message||'')+' @'+(e.filename||'')+':'+(e.lineno||0)+src);"
                "},true);"
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

        _mapRenderer = [[SNBMapRenderer alloc] init];
        _trustedStore = [SNBTrustedIPStore sharedStore];
        _firstSeenByIP = [NSMutableDictionary dictionary];
        _lastSeenByIP = [NSMutableDictionary dictionary];
        _blockedIPs = [NSSet set];
        _threatIntelResults = @{};
        _renderQueue = dispatch_queue_create("com.sniffnetbar.map.render", DISPATCH_QUEUE_SERIAL);
        _isDetachedInstance = NO;

        NSString *savedProvider = [[NSUserDefaults standardUserDefaults] stringForKey:SNBUserDefaultsKeyMapProvider];
        NSString *defaultProvider = [ConfigurationManager sharedManager].defaultMapProvider;
        _providerName = savedProvider.length > 0 ? savedProvider : defaultProvider;
        _geoService = [[SNBGeoLocationService alloc] initWithProviderName:_providerName];

        [self loadMapHTML];
        [self updateLayout];

        // Install event monitor immediately - NSMenuItem views may not trigger viewDidMoveToWindow
        [self installClickEventMonitor];

        // Start periodic cache cleanup timer
        [self startCacheCleanupTimer];
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
    if (self.detachedWindow) {
        [self.detachedWindow close];
        self.detachedWindow = nil;
        self.detachedMapView = nil;
    }

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

- (void)openDetachedWindow {
    if (self.detachedWindow) {
        [self.detachedWindow makeKeyAndOrderFront:nil];
        return;
    }

    NSRect frame = NSMakeRect(0, 0, 900, 600);
    NSWindowStyleMask style = NSWindowStyleMaskTitled | NSWindowStyleMaskClosable |
                              NSWindowStyleMaskResizable | NSWindowStyleMaskMiniaturizable;
    NSWindow *window = [[NSWindow alloc] initWithContentRect:frame
                                                  styleMask:style
                                                    backing:NSBackingStoreBuffered
                                                      defer:NO];
    window.title = @"SniffNetBar MapToolbox";
    window.delegate = self;
    window.minSize = NSMakeSize(800.0, 600.0);

    MapMenuView *detachedView = [[MapMenuView alloc] initWithFrame:window.contentView.bounds];
    detachedView.isDetachedInstance = YES;
    detachedView.providerName = self.providerName;
    detachedView.delegate = self.delegate;
    detachedView.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;
    [detachedView loadMapHTML];
    [detachedView updateLayout];

    window.contentView = detachedView;
    [window center];
    [window makeKeyAndOrderFront:nil];

    self.detachedWindow = window;
    self.detachedMapView = detachedView;

    if (self.lastConnections) {
        [detachedView updateWithConnections:self.lastConnections
                         threatIntelResults:self.threatIntelResults
                                  blockedIPs:self.blockedIPs];
    }

    if ([self.delegate respondsToSelector:@selector(mapMenuViewDidDetachMap:)]) {
        [self.delegate mapMenuViewDidDetachMap:self];
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
    [self.geoService performCacheCleanup];
    self.lastCacheCleanupTime = [NSDate date];
}

- (void)setProviderName:(NSString *)providerName {
    if ([_providerName isEqualToString:providerName]) {
        return;
    }
    _providerName = [providerName copy];
    self.geoService.providerName = _providerName;
}

- (void)viewDidMoveToWindow {
    [super viewDidMoveToWindow];
    if (self.window) {
        // Use local event monitor to capture clicks - this works even when NSMenu intercepts events
        [self installClickEventMonitor];

        if (self.lastConnections.count > 0) {
            [self updateWithConnections:self.lastConnections
                     threatIntelResults:self.threatIntelResults
                              blockedIPs:self.blockedIPs];
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
    [self updateWithConnections:connections threatIntelResults:self.threatIntelResults blockedIPs:self.blockedIPs];
}

- (void)updateWithConnections:(NSArray<ConnectionTraffic *> *)connections
           threatIntelResults:(NSDictionary<NSString *, TIEnrichmentResponse *> *)threatIntelResults
                    blockedIPs:(NSSet<NSString *> *)blockedIPs {
    if (![NSThread isMainThread]) {
        dispatch_async(dispatch_get_main_queue(), ^{
            [self updateWithConnections:connections threatIntelResults:threatIntelResults blockedIPs:blockedIPs];
        });
        return;
    }

    self.lastConnections = connections;
    uint64_t connectionsHash = 1469598103934665603ULL;
    for (ConnectionTraffic *connection in connections) {
        connectionsHash = SNBHashCombine(connectionsHash, SNBHashConnectionTuple(connection));
    }
    BOOL connectionsChanged = (connectionsHash != self.lastConnectionsHash);
    self.lastConnectionsHash = connectionsHash;

    BOOL riskStateChanged = (self.threatIntelResults != threatIntelResults);
    NSSet<NSString *> *safeBlocked = blockedIPs ?: [NSSet set];
    if (!riskStateChanged && ![self.blockedIPs isEqualToSet:safeBlocked]) {
        riskStateChanged = YES;
    }
    self.threatIntelResults = threatIntelResults ?: @{};
    self.blockedIPs = safeBlocked;
    if (riskStateChanged) {
        self.riskVersion += 1;
    }

    if (!self.isDetachedInstance && self.detachedMapView) {
        [self.detachedMapView updateWithConnections:connections
                                 threatIntelResults:self.threatIntelResults
                                          blockedIPs:self.blockedIPs];
    }
    if (!self.window) {
        return;
    }

    if (connectionsChanged) {
        [self updateSeenForConnections:connections];
    }
    if (riskStateChanged) {
        [self markRenderDataDirty];
    }

    NSDate *now = [NSDate date];
    if (!self.lastCacheCleanupTime || [now timeIntervalSinceDate:self.lastCacheCleanupTime] > 5.0) {
        self.lastCacheCleanupTime = now;
        [self.geoService performCacheCleanup];
    }
    SNBLogUIDebug(" update: %lu connections", (unsigned long)connections.count);
    [self.geoService updatePublicIPIfNeededWithCompletion:^(BOOL updated) {
        if (updated) {
            [self markRenderDataDirty];
            [self refreshMarkers];
        }
    }];
    if (!connectionsChanged && !riskStateChanged && self.lastTargetIPs.count > 0) {
        return;
    }
    if (connections.count == 0) {
        self.lastTargetIPs = @[];
        if ([self updateRenderSignatureWithConnections:connections targetIPs:self.lastTargetIPs]) {
            [self markRenderDataDirty];
            [self refreshMarkers];
        } else if (riskStateChanged) {
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
    NSSet<NSString *> *targetIPSet = [targetIps copy];
    self.lastTargetIPs = [targetIps.allObjects sortedArrayUsingSelector:@selector(compare:)];
    
    SNBLogUIDebug(" target IPs: %s", targetIps.description.UTF8String);
    BOOL signatureChanged = [self updateRenderSignatureWithConnections:connections
                                                             targetIPs:self.lastTargetIPs];
    
    [self.geoService resolveTargetIPs:targetIPSet completion:^(NSString *ip, CLLocationCoordinate2D coord, BOOL success) {
        if (!success) {
            return;
        }
        SNBLogUIDebug(" pin ready for %s (%f, %f)", ip.UTF8String, coord.latitude, coord.longitude);
        [self markRenderDataDirty];
        [self refreshMarkers];
    }];
    
    if (signatureChanged) {
        [self markRenderDataDirty];
        [self refreshMarkers];
    }
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

- (void)updateSeenForConnections:(NSArray<ConnectionTraffic *> *)connections {
    for (ConnectionTraffic *connection in connections) {
        NSDate *activityDate = [self dateFromActivity:connection.lastActivity];
        if (!activityDate) {
            continue;
        }
        [self updateSeenForIP:connection.sourceAddress atDate:activityDate];
        [self updateSeenForIP:connection.destinationAddress atDate:activityDate];
    }
}

- (void)updateSeenForIP:(NSString *)ipAddress atDate:(NSDate *)date {
    if (ipAddress.length == 0 || !date) {
        return;
    }
    if (!self.firstSeenByIP[ipAddress]) {
        self.firstSeenByIP[ipAddress] = date;
    }
    NSDate *lastSeen = self.lastSeenByIP[ipAddress];
    if (!lastSeen || [lastSeen compare:date] == NSOrderedAscending) {
        self.lastSeenByIP[ipAddress] = date;
    }
}

- (NSDate *)dateFromActivity:(CFAbsoluteTime)activity {
    if (activity <= 0) {
        return nil;
    }
    return [NSDate dateWithTimeIntervalSinceReferenceDate:activity];
}

- (void)performRefreshMarkers {
    if (!self.mapReady) {
        return;
    }

    self.renderGeneration += 1;
    NSUInteger generation = self.renderGeneration;
    NSArray<NSString *> *targetIPs = [self.lastTargetIPs copy] ?: @[];
    NSArray<ConnectionTraffic *> *connections = [self.lastConnections copy] ?: @[];
    NSString *publicIP = [self.geoService.publicIPAddress copy];
    NSValue *publicCoordValue = self.geoService.publicIPCoordinate;
    ConfigurationManager *config = [ConfigurationManager sharedManager];
    NSInteger maxLines = MIN(config.maxConnectionLinesToShow, connections.count);

    BOOL canReuseJSON = (self.cachedPointsJSON.length > 0 &&
                         self.cachedLinesJSON.length > 0 &&
                         self.cachedConnectionsHash == self.lastConnectionsHash &&
                         self.cachedLocationVersion == self.geoService.locationVersion &&
                         self.cachedRiskVersion == self.riskVersion &&
                         self.cachedMaxLines == maxLines);
    if (canReuseJSON) {
        NSString *pointsJSON = [self.cachedPointsJSON copy];
        NSString *linesJSON = [self.cachedLinesJSON copy];
        dispatch_async(dispatch_get_main_queue(), ^{
            if (generation != self.renderGeneration || !self.mapReady) {
                return;
            }
            NSString *script = [NSString stringWithFormat:@"window.SniffNetBar && window.SniffNetBar.setMarkers(%@, %@);", pointsJSON, linesJSON];
            [self.webView evaluateJavaScript:script completionHandler:^(id result, NSError *error) {
                if (error) {
                    SNBLogUIDebug(" JS error: %s", error.localizedDescription.UTF8String);
                }
            }];
        });
        return;
    }

    CLLocationCoordinate2D publicCoord = kCLLocationCoordinate2DInvalid;
    if (publicCoordValue) {
        [publicCoordValue getValue:&publicCoord];
    }
    NSMutableDictionary<NSString *, NSDictionary *> *locationByIP = [[self.geoService cachedLocationsForIPs:targetIPs] mutableCopy];

    NSMutableDictionary<NSString *, NSDictionary *> *badgeInfoByIP = [NSMutableDictionary dictionary];
    for (ConnectionTraffic *connection in connections) {
        [self addBadgeInfoForIPAddress:connection.sourceAddress connection:connection map:badgeInfoByIP];
        [self addBadgeInfoForIPAddress:connection.destinationAddress connection:connection map:badgeInfoByIP];
    }

    NSMutableDictionary<NSString *, NSMutableSet<NSString *> *> *processesByIP = [NSMutableDictionary dictionary];
    NSMutableDictionary<NSString *, NSNumber *> *connectionCountsByIP = [NSMutableDictionary dictionary];
    for (ConnectionTraffic *connection in connections) {
        NSString *processLabel = nil;
        if (connection.processName.length > 0) {
            if (connection.processPID != 0) {
                processLabel = [NSString stringWithFormat:@"%@ (PID %d)", connection.processName, connection.processPID];
            } else {
                processLabel = connection.processName;
            }
        }
        NSArray<NSString *> *addresses = @[connection.sourceAddress ?: @"", connection.destinationAddress ?: @""];
        for (NSString *address in addresses) {
            if (address.length == 0) {
                continue;
            }
            NSNumber *count = connectionCountsByIP[address] ?: @0;
            connectionCountsByIP[address] = @(count.integerValue + 1);
            if (processLabel.length > 0) {
                NSMutableSet<NSString *> *set = processesByIP[address];
                if (!set) {
                    set = [NSMutableSet set];
                    processesByIP[address] = set;
                }
                [set addObject:processLabel];
            }
        }
    }

    for (NSInteger i = 0; i < maxLines; i++) {
        ConnectionTraffic *connection = connections[i];
        if (connection.sourceAddress.length > 0 && !locationByIP[connection.sourceAddress]) {
            NSDictionary *value = [self.geoService locationForIP:connection.sourceAddress];
            if (value) {
                locationByIP[connection.sourceAddress] = value;
            } else if (![self shouldGeolocateIPAddress:connection.sourceAddress] && CLLocationCoordinate2DIsValid(publicCoord)) {
                locationByIP[connection.sourceAddress] = @{@"lat": @(publicCoord.latitude), @"lon": @(publicCoord.longitude)};
            }
        }
        if (connection.destinationAddress.length > 0 && !locationByIP[connection.destinationAddress]) {
            NSDictionary *value = [self.geoService locationForIP:connection.destinationAddress];
            if (value) {
                locationByIP[connection.destinationAddress] = value;
            } else if (![self shouldGeolocateIPAddress:connection.destinationAddress] && CLLocationCoordinate2DIsValid(publicCoord)) {
                locationByIP[connection.destinationAddress] = @{@"lat": @(publicCoord.latitude), @"lon": @(publicCoord.longitude)};
            }
        }
    }

    __weak typeof(self) weakSelf = self;
    dispatch_async(self.renderQueue, ^{
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) {
            return;
        }

        SNBMapRenderResult *renderResult = [strongSelf.mapRenderer renderWithTargetIPs:targetIPs
                                                                           connections:connections
                                                                          locationByIP:locationByIP
                                                                         badgeInfoByIP:badgeInfoByIP
                                                                        processesByIP:processesByIP
                                                                 connectionCountsByIP:connectionCountsByIP
                                                                        firstSeenByIP:strongSelf.firstSeenByIP
                                                                         lastSeenByIP:strongSelf.lastSeenByIP
                                                                              publicIP:publicIP
                                                                            publicCoord:publicCoord
                                                                        riskStateForIP:^NSString * _Nonnull(NSString *ip) {
            return [strongSelf riskStateForIP:ip] ?: @"Observed";
        }
                                                                              maxLines:maxLines];
        if (!renderResult) {
            return;
        }
        strongSelf.drawnConnectionCount = renderResult.drawnConnectionCount;
        strongSelf.cachedConnectionsHash = strongSelf.lastConnectionsHash;
        strongSelf.cachedLocationVersion = strongSelf.geoService.locationVersion;
        strongSelf.cachedRiskVersion = strongSelf.riskVersion;
        strongSelf.cachedMaxLines = maxLines;
        strongSelf.cachedPointsJSON = renderResult.pointsJSON;
        strongSelf.cachedLinesJSON = renderResult.linesJSON;
        NSString *script = [NSString stringWithFormat:@"window.SniffNetBar && window.SniffNetBar.setMarkers(%@, %@);", renderResult.pointsJSON, renderResult.linesJSON];

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

    NSString *isDetachedFlag = self.isDetachedInstance ? @"true" : @"false";
    NSString *html = [NSString stringWithFormat:
@"<!doctype html>\n"
@"<html lang='en'>\n"
@"<head>\n"
@"  <meta charset='utf-8'>\n"
@"  <meta name='viewport' content='width=device-width, initial-scale=1.0, viewport-fit=cover'>\n"
@"  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; img-src 'self' data: https://server.arcgisonline.com; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self' https://server.arcgisonline.com;\">\n"
@"  <link rel='stylesheet' href='vendor/leaflet/leaflet.css'>\n"
@"  <style>\n"
@"    html,body,#map{height:100%%;margin:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;}\n"
@"    body{background:#f8fafc;overflow:hidden;}\n"
@"    #map{background:#f8fafc;}\n"
@"\n"
@"    /* Popup UI */\n"
@"    .leaflet-popup-content-wrapper{background:#ffffff;color:#1e293b;border-radius:10px;box-shadow:0 6px 24px rgba(0,0,0,0.16),0 0 0 1px rgba(0,0,0,0.05);max-width:320px;min-width:220px;}\n"
@"    .leaflet-popup-content{margin:14px 16px;font-size:13px;line-height:1.55;max-height:220px;overflow-y:auto;-webkit-overflow-scrolling:touch;}\n"
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
@"    .cluster-marker{--cluster-color:#ef4444;--cluster-color-dark:#dc2626;background:linear-gradient(135deg,var(--cluster-color) 0%%,var(--cluster-color-dark) 100%%);border:3px solid rgba(255,255,255,0.95);border-radius:999px;box-shadow:0 3px 12px rgba(15,23,42,0.20),0 0 0 4px rgba(15,23,42,0.08);display:flex;align-items:center;justify-content:center;color:white;font-weight:800;font-size:13px;transition:transform 0.2s ease;text-align:center;line-height:1;box-sizing:border-box;width:100%%;height:100%%;}\n"
@"    .cluster-marker>div{display:flex;align-items:center;justify-content:center;width:100%%;height:100%%;}\n"
@"    .cluster-marker:hover{transform:scale(1.12);}\n"
@"    .single-marker{--pin-color:#3b82f6;--pin-color-dark:#2563eb;width:28px;height:36px;position:relative;}\n"
@"    .single-marker::before{content:'';position:absolute;bottom:0;left:50%%;transform:translateX(-50%%);width:0;height:0;border-left:14px solid transparent;border-right:14px solid transparent;border-top:20px solid var(--pin-color-dark);filter:drop-shadow(0 2px 4px rgba(0,0,0,0.20));}\n"
@"    .single-marker::after{content:'';position:absolute;top:4px;left:50%%;transform:translateX(-50%%);width:18px;height:18px;border-radius:50%%;background:var(--pin-color);box-shadow:0 0 0 3px rgba(255,255,255,0.92),0 2px 8px rgba(15,23,42,0.20),inset 0 1px 3px rgba(255,255,255,0.50);}\n"
@"    .risk-pill{display:inline-flex;align-items:center;gap:6px;padding:3px 8px;border-radius:999px;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:0.04em;background:rgba(15,23,42,0.06);color:#1e293b;border:1px solid rgba(15,23,42,0.12);}\n"
@"    .risk-pill::before{content:'';width:6px;height:6px;border-radius:50%%;background:currentColor;}\n"
@"    .risk-trusted{color:#10b981;border-color:rgba(16,185,129,0.35);background:rgba(16,185,129,0.12);}\n"
@"    .risk-observed{color:#3b82f6;border-color:rgba(59,130,246,0.35);background:rgba(59,130,246,0.12);}\n"
@"    .risk-investigate{color:#f59e0b;border-color:rgba(245,158,11,0.35);background:rgba(245,158,11,0.12);}\n"
@"    .risk-blocked{color:#ef4444;border-color:rgba(239,68,68,0.35);background:rgba(239,68,68,0.12);}\n"
@"    .meta-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px;margin:10px 0 12px;}\n"
@"    .meta-item{background:rgba(15,23,42,0.04);border:1px solid rgba(15,23,42,0.08);border-radius:8px;padding:6px 8px;}\n"
@"    .meta-item span{display:block;color:#64748b;font-size:10px;text-transform:uppercase;letter-spacing:0.04em;margin-bottom:2px;}\n"
@"    .meta-item strong{font-size:12px;color:#0f172a;font-weight:600;}\n"
@"    .ip-meta{display:flex;align-items:center;gap:6px;flex-wrap:wrap;color:#64748b;font-size:11px;}\n"
@"    .ip-subline{color:#94a3b8;font-size:11px;}\n"
@"    .ip-actions{display:flex;gap:6px;margin-top:6px;}\n"
@"    .action-btn{border-radius:999px;border:1px solid rgba(15,23,42,0.12);background:#f8fafc;color:#0f172a;font-size:10px;font-weight:700;padding:4px 8px;cursor:pointer;}\n"
@"    .action-btn:hover{background:#ffffff;}\n"
@"    .action-btn[data-action='block']{color:#b91c1c;border-color:rgba(185,28,28,0.3);}\n"
@"    .ip-new{display:inline-flex;align-items:center;gap:4px;padding:2px 6px;border-radius:999px;font-size:10px;font-weight:700;color:#0f172a;background:rgba(14,165,233,0.12);border:1px solid rgba(14,165,233,0.3);}\n"
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
@"    .legend-panel{position:absolute;top:calc(14px + env(safe-area-inset-top));right:10px;background:rgba(255,255,255,0.96);border-radius:12px;padding:12px;font-size:11px;box-shadow:0 8px 24px rgba(0,0,0,0.16);z-index:2000;min-width:170px;backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);display:none;}\n"
@"    .legend-panel.visible{display:block;}\n"
@"    .panel-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;}\n"
@"    .panel-close{width:26px;height:26px;border-radius:999px;border:1px solid var(--control-border);background:rgba(255,255,255,0.8);display:inline-flex;align-items:center;justify-content:center;color:var(--control-color);cursor:pointer;}\n"
@"    .panel-close:hover{background:#ffffff;}\n"
@"    .panel-close svg{pointer-events:none;}\n"
@"    .legend-title{font-weight:700;font-size:12px;margin-bottom:8px;color:#1e293b;}\n"
@"    .legend-item{display:flex;align-items:center;gap:8px;margin-bottom:6px;color:#475569;}\n"
@"    .legend-item:last-child{margin-bottom:0;}\n"
@"    .legend-line{width:24px;height:3px;border-radius:2px;}\n"
@"    .legend-marker{width:12px;height:12px;border-radius:50%%;}\n"
@"    .legend-marker.new-today{border:2px solid #0ea5e9;background:rgba(14,165,233,0.12);box-shadow:0 0 0 3px rgba(14,165,233,0.10);position:relative;}\n"
@"    .legend-marker.new-today::after{content:'';position:absolute;left:50%%;top:50%%;width:4px;height:4px;border-radius:50%%;background:#0ea5e9;transform:translate(-50%%,-50%%);}\n"
@"    .legend-gradient{width:60px;height:10px;border-radius:3px;background:linear-gradient(to right,blue,cyan,lime,yellow,red);}\n"
@"\n"
@"    .filter-panel{position:absolute;top:calc(70px + env(safe-area-inset-top));left:10px;background:rgba(255,255,255,0.96);border-radius:12px;padding:12px;font-size:11px;box-shadow:0 8px 24px rgba(0,0,0,0.16);z-index:2000;min-width:170px;backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);display:none;}\n"
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
@"    .mac-toolbar.is-collapsed .mac-btn:not(.toolbar-toggle):not(.btn-essential):not(.btn-overflow){display:none;}\n"
@"    .mac-toolbar.is-collapsed{padding:6px 8px;gap:0;}\n"
@"    .mac-btn.toolbar-toggle{border-radius:12px;background:rgba(17,24,39,0.06);font-weight:700;}\n"
@"    .mac-btn.toolbar-toggle svg{width:16px;height:16px;}\n"
@"    .mac-btn{width:40px;height:40px;border-radius:999px;border:1px solid var(--control-border);background:rgba(255,255,255,0.70);display:flex;align-items:center;justify-content:center;color:var(--control-color);cursor:pointer;user-select:none;-webkit-tap-highlight-color:transparent;transition:transform .08s ease, background .12s ease, box-shadow .12s ease;padding:0;}\n"
@"    .mac-btn:hover{background:rgba(255,255,255,0.95);box-shadow:0 6px 14px rgba(0,0,0,0.14);}\n"
@"    .mac-btn:active{transform:scale(0.96);}\n"
@"    .mac-btn.is-on{background:rgba(17,24,39,0.10);border-color:rgba(17,24,39,0.28);}\n"
@"    .mac-btn svg{width:20px;height:20px;display:block;pointer-events:none;}\n"
@"    .overflow-panel{position:absolute;top:calc(68px + env(safe-area-inset-top));left:14px;background:var(--control-bg);border:1px solid var(--control-border);border-radius:12px;padding:10px;box-shadow:var(--control-shadow);display:none;flex-direction:column;gap:4px;z-index:2600;min-width:180px;}\n"
@"    .overflow-panel.visible{display:flex;}\n"
@"    .overflow-btn{display:flex;align-items:center;gap:8px;font-size:12px;font-weight:600;color:#0f172a;border:1px solid rgba(15,23,42,0.12);background:#ffffff;border-radius:10px;padding:6px 10px;cursor:pointer;}\n"
@"    .overflow-btn:hover{background:#f1f5f9;}\n"
@"    .overflow-item{display:flex;align-items:center;gap:10px;padding:6px 8px;border-radius:8px;cursor:pointer;}\n"
@"    .overflow-item:hover{background:rgba(15,23,42,0.06);}\n"
@"    .overflow-item:active{background:rgba(15,23,42,0.10);}\n"
@"    .overflow-item *{pointer-events:none;}\n"
@"    .overflow-item .mac-btn{width:30px;height:30px;flex-shrink:0;}\n"
@"    .overflow-label{font-size:12px;font-weight:500;color:#1e293b;white-space:nowrap;}\n"
@"    .newip-marker{width:18px;height:18px;border-radius:50%%;background:rgba(14,165,233,0.18);border:2px solid #0ea5e9;box-shadow:0 0 0 4px rgba(14,165,233,0.12),0 6px 14px rgba(15,23,42,0.18);position:relative;}\n"
@"    .newip-marker::after{content:'';position:absolute;left:50%%;top:50%%;width:6px;height:6px;border-radius:50%%;background:#0ea5e9;transform:translate(-50%%,-50%%);box-shadow:0 0 6px rgba(14,165,233,0.55);}\n"
@"  </style>\n"
@"</head>\n"
@"<body>\n"
@"  <div id='map'></div>\n"
@"\n"
@"  <div class='mac-toolbar is-collapsed' id='macToolbar'>\n"
@"    <button class='mac-btn toolbar-toggle' id='btnToolbar' title='Toggle toolbar' aria-label='Toggle toolbar'>\n"
@"      <svg viewBox='0 0 24 24' fill='none'>\n"
@"        <path d='M8 10l4-4 4 4M8 14l4 4 4-4' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'/>\n"
@"      </svg>\n"
@"    </button>\n"
@"    <button class='mac-btn btn-essential' id='btnZoomIn' title='Zoom in' aria-label='Zoom in'>\n"
@"      <svg viewBox='0 0 24 24' fill='none'><path d='M12 5v14M5 12h14' stroke='currentColor' stroke-width='2' stroke-linecap='round'/></svg>\n"
@"    </button>\n"
@"    <button class='mac-btn btn-essential' id='btnZoomOut' title='Zoom out' aria-label='Zoom out'>\n"
@"      <svg viewBox='0 0 24 24' fill='none'><path d='M5 12h14' stroke='currentColor' stroke-width='2' stroke-linecap='round'/></svg>\n"
@"    </button>\n"
@"    <button class='mac-btn btn-essential' id='btnDetach' title='Detach map' aria-label='Detach map'>\n"
@"      <svg viewBox='0 0 24 24' fill='none'>\n"
@"        <path d='M8 6h10v10' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'/>\n"
@"        <path d='M16 6l-8 8' stroke='currentColor' stroke-width='2' stroke-linecap='round'/>\n"
@"        <rect x='4' y='8' width='10' height='12' rx='2' stroke='currentColor' stroke-width='2' opacity='0.6'/>\n"
@"      </svg>\n"
@"    </button>\n"
@"    <button class='mac-btn btn-overflow' id='btnMore' title='More' aria-label='More'>\n"
@"      <svg viewBox='0 0 24 24' fill='none'>\n"
@"        <circle cx='6' cy='12' r='2' fill='currentColor'/>\n"
@"        <circle cx='12' cy='12' r='2' fill='currentColor'/>\n"
@"        <circle cx='18' cy='12' r='2' fill='currentColor'/>\n"
@"      </svg>\n"
@"    </button>\n"
@"  </div>\n"
@"  <div class='overflow-panel' id='overflowPanel'>\n"
@"    <div class='overflow-item' id='ovHeat'>\n"
@"      <div class='mac-btn' aria-hidden='true'>\n"
@"        <svg viewBox='0 0 24 24' fill='none'>\n"
@"          <path d='M13 2s1 3-1 5-2 3 0 5 3 4 1 7' stroke='currentColor' stroke-width='2' stroke-linecap='round'/>\n"
@"          <path d='M9 6s1 2-1 4-2 3 0 5 2 4 0 7' stroke='currentColor' stroke-width='2' stroke-linecap='round' opacity='0.85'/>\n"
@"        </svg>\n"
@"      </div>\n"
@"      <span class='overflow-label'>Heatmap</span>\n"
@"    </div>\n"
@"    <div class='overflow-item' id='ovLegend'>\n"
@"      <div class='mac-btn' aria-hidden='true'>\n"
@"        <svg viewBox='0 0 24 24' fill='none'><path d='M4 7h10M4 12h16M4 17h12' stroke='currentColor' stroke-width='2' stroke-linecap='round'/></svg>\n"
@"      </div>\n"
@"      <span class='overflow-label'>Legend</span>\n"
@"    </div>\n"
@"    <div class='overflow-item' id='ovMap'>\n"
@"      <div class='mac-btn' aria-hidden='true'>\n"
@"        <svg viewBox='0 0 24 24' fill='none'>\n"
@"          <path d='M3 6l6-2 6 2 6-2v14l-6 2-6-2-6 2V6z' stroke='currentColor' stroke-width='2' stroke-linejoin='round'/>\n"
@"          <path d='M9 4v14M15 6v14' stroke='currentColor' stroke-width='2' stroke-linecap='round' opacity='0.85'/>\n"
@"        </svg>\n"
@"      </div>\n"
@"      <span class='overflow-label'>Map Style</span>\n"
@"    </div>\n"
@"    <div class='overflow-item' id='ovGroup'>\n"
@"      <div class='mac-btn' aria-hidden='true'>\n"
@"        <svg viewBox='0 0 24 24' fill='none'>\n"
@"          <path d='M7 7h10M7 12h10M7 17h10' stroke='currentColor' stroke-width='2' stroke-linecap='round'/>\n"
@"          <circle cx='5' cy='7' r='2' fill='currentColor' opacity='0.35'/>\n"
@"          <circle cx='5' cy='12' r='2' fill='currentColor' opacity='0.35'/>\n"
@"          <circle cx='5' cy='17' r='2' fill='currentColor' opacity='0.35'/>\n"
@"        </svg>\n"
@"      </div>\n"
@"      <span class='overflow-label'>Group ASN/Country</span>\n"
@"    </div>\n"
@"    <div class='overflow-item' id='ovNew'>\n"
@"      <div class='mac-btn' aria-hidden='true'>\n"
@"        <svg viewBox='0 0 24 24' fill='none'>\n"
@"          <path d='M12 3v6M12 15v6M3 12h6M15 12h6' stroke='currentColor' stroke-width='2' stroke-linecap='round'/>\n"
@"          <circle cx='12' cy='12' r='3' stroke='currentColor' stroke-width='2' fill='none'/>\n"
@"        </svg>\n"
@"      </div>\n"
@"      <span class='overflow-label'>New IPs Today</span>\n"
@"    </div>\n"
@"    <div class='overflow-item' id='ovFilters'>\n"
@"      <div class='mac-btn' aria-hidden='true'>\n"
@"        <svg viewBox='0 0 24 24' fill='none'>\n"
@"          <path d='M4 6h16M7 12h10M10 18h4' stroke='currentColor' stroke-width='2' stroke-linecap='round'/>\n"
@"          <circle cx='9' cy='6' r='2' fill='currentColor' opacity='0.25'/>\n"
@"          <circle cx='14' cy='12' r='2' fill='currentColor' opacity='0.25'/>\n"
@"          <circle cx='12' cy='18' r='2' fill='currentColor' opacity='0.25'/>\n"
@"        </svg>\n"
@"      </div>\n"
@"      <span class='overflow-label'>Filters</span>\n"
@"    </div>\n"
@"  </div>\n"
@"\n"
@"  <div id='legend' class='legend-panel'>\n"
@"    <div class='panel-header'>\n"
@"      <div class='legend-title'>Legend</div>\n"
@"      <button class='panel-close' id='legendClose' aria-label='Close legend'>\n"
@"        <svg viewBox='0 0 24 24' fill='none'><path d='M6 6l12 12M18 6l-12 12' stroke='currentColor' stroke-width='2' stroke-linecap='round'/></svg>\n"
@"      </button>\n"
@"    </div>\n"
@"    <div class='legend-item'><div class='legend-line' style='background:%@'></div><span>Connection</span></div>\n"
@"    <div class='legend-item'><div class='legend-line' style='background:#60a5fa'></div><span>Hovered</span></div>\n"
@"    <div class='legend-item'><div class='legend-line' style='background:#f59e0b'></div><span>Selected</span></div>\n"
@"    <div class='legend-item'><div class='legend-marker' style='background:#10b981'></div><span>Trusted</span></div>\n"
@"    <div class='legend-item'><div class='legend-marker' style='background:#3b82f6'></div><span>Observed</span></div>\n"
@"    <div class='legend-item'><div class='legend-marker' style='background:#f59e0b'></div><span>Investigate</span></div>\n"
@"    <div class='legend-item'><div class='legend-marker' style='background:#ef4444'></div><span>Blocked</span></div>\n"
@"    <div class='legend-item'><div class='legend-marker' style='background:#3b82f6'></div><span>Single IP</span></div>\n"
@"    <div class='legend-item'><div class='legend-marker' style='background:#ef4444'></div><span>Clustered IPs</span></div>\n"
@"    <div class='legend-item'><div class='legend-marker new-today'></div><span>New today</span></div>\n"
@"    <div class='legend-item'><div class='legend-gradient'></div><span>Heat intensity</span></div>\n"
@"  </div>\n"
@"\n"
@"  <div id='filters' class='filter-panel'>\n"
@"    <div class='panel-header'>\n"
@"      <div class='filter-title'>Filters</div>\n"
@"      <button class='panel-close' id='filtersClose' aria-label='Close filters'>\n"
@"        <svg viewBox='0 0 24 24' fill='none'><path d='M6 6l12 12M18 6l-12 12' stroke='currentColor' stroke-width='2' stroke-linecap='round'/></svg>\n"
@"      </button>\n"
@"    </div>\n"
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
@"      L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/World_Street_Map/MapServer/tile/{z}/{y}/{x}',{maxZoom:19,updateWhenZooming:false,updateWhenIdle:true,keepBuffer:2}),\n"
@"      L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}',{maxZoom:19,updateWhenZooming:false,updateWhenIdle:true,keepBuffer:2}),\n"
@"      L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Light_Gray_Base/MapServer/tile/{z}/{y}/{x}',{maxZoom:16,updateWhenZooming:false,updateWhenIdle:true,keepBuffer:2})\n"
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
@"    var isDetached=%@;\n"
@"    var groupByASN=false;\n"
@"    var newLayerEnabled=false;\n"
@"    var newLayer=L.layerGroup().addTo(map);\n"
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
@"    var legendVisible=false;\n"
@"    function closeLegend(){console.log('closeLegend called');var el=document.getElementById('legend');if(el){el.classList.remove('visible');console.log('legend hidden');}legendVisible=false;return legendVisible;}\n"
@"    function toggleLegend(){console.log('toggleLegend called');var el=document.getElementById('legend');if(!el){console.error('Legend element not found!');return false;}var isVisible=el.classList.contains('visible');legendVisible=!isVisible;el.classList.toggle('visible',legendVisible);console.log('legend now visible:',legendVisible,'classes:',el.className);return legendVisible;}\n"
@"    var filtersVisible=false;\n"
@"    function closeFilters(){console.log('closeFilters called');var el=document.getElementById('filters');if(el){el.classList.remove('visible');console.log('filters hidden');}filtersVisible=false;return filtersVisible;}\n"
@"    function toggleFilters(){console.log('toggleFilters called');var el=document.getElementById('filters');if(!el){console.error('Filters element not found!');return false;}var isVisible=el.classList.contains('visible');filtersVisible=!isVisible;el.classList.toggle('visible',filtersVisible);console.log('filters now visible:',filtersVisible,'classes:',el.className);return filtersVisible;}\n"
@"\n"
@"    var filterState={showAll:true,showIncoming:true,showOutgoing:true,minTraffic:0};\n"
@"    function connectionPassesFilter(c){\n"
@"      var bytes=(c&&typeof c.bytes==='number')?c.bytes:0;\n"
@"      if(filterState.minTraffic>0 && bytes<filterState.minTraffic) return false;\n"
@"      if(filterState.showAll) return true;\n"
@"      var dir=c&&c.direction?String(c.direction).toLowerCase():'';\n"
@"      var isIncoming=(dir==='incoming'||dir==='in');\n"
@"      var isOutgoing=(dir==='outgoing'||dir==='out');\n"
@"      if(!filterState.showIncoming && isIncoming) return false;\n"
@"      if(!filterState.showOutgoing && isOutgoing) return false;\n"
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
@"    function toggleGroupByASN(){\n"
@"      groupByASN=!groupByASN;\n"
@"      if(lastData){setMarkers(lastData.points,lastData.connections);}\n"
@"      return groupByASN;\n"
@"    }\n"
@"\n"
@"    function toggleNewLayer(){\n"
@"      newLayerEnabled=!newLayerEnabled;\n"
@"      if(lastData){setMarkers(lastData.points,lastData.connections);}\n"
@"      return newLayerEnabled;\n"
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
@"    function updateNewLayer(points){\n"
@"      newLayer.clearLayers();\n"
@"      if(!newLayerEnabled||!points||!points.length) return;\n"
@"      for(var i=0;i<points.length;i++){\n"
@"        var p=points[i];\n"
@"        if(typeof p.lat!=='number'||typeof p.lon!=='number') continue;\n"
@"        var details=p.ipDetails||[];\n"
@"        var isNew=false;\n"
@"        for(var j=0;j<details.length;j++){\n"
@"          if(details[j].isNewToday){isNew=true;break;}\n"
@"        }\n"
@"        if(!isNew) continue;\n"
@"        var newIcon=L.divIcon({className:'',html:'<div class=\"newip-marker\"></div>',iconSize:[18,18],iconAnchor:[9,9]});\n"
@"        L.marker([p.lat,p.lon],{icon:newIcon}).addTo(newLayer);\n"
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
@"    var riskPalette={Trusted:'#10b981',Observed:'#3b82f6',Investigate:'#f59e0b',Blocked:'#ef4444'};\n"
@"    function riskRank(state){\n"
@"      switch(state){case 'Blocked':return 4;case 'Investigate':return 3;case 'Observed':return 2;case 'Trusted':return 1;default:return 2;}\n"
@"    }\n"
@"    function riskColor(state){return riskPalette[state]||riskPalette.Observed;}\n"
@"    function darkenColor(hex,factor){\n"
@"      if(!hex||hex[0]!=='#'||hex.length<7) return hex;\n"
@"      var r=parseInt(hex.slice(1,3),16),g=parseInt(hex.slice(3,5),16),b=parseInt(hex.slice(5,7),16);\n"
@"      r=Math.max(0,Math.min(255,Math.round(r*factor)));\n"
@"      g=Math.max(0,Math.min(255,Math.round(g*factor)));\n"
@"      b=Math.max(0,Math.min(255,Math.round(b*factor)));\n"
@"      return '#' + [r,g,b].map(function(v){return ('0'+v.toString(16)).slice(-2);}).join('');\n"
@"    }\n"
@"    function formatTimestamp(ts){\n"
@"      if(!ts||isNaN(ts)) return '—';\n"
@"      var d=new Date(ts*1000);\n"
@"      if(isNaN(d.getTime())) return '—';\n"
@"      return d.toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'}) + ' · ' + d.toLocaleDateString();\n"
@"    }\n"
@"    function aggregateDetails(details){\n"
@"      var connectionCount=0,firstSeen=null,lastSeen=null,processSet={},risk='Observed';\n"
@"      for(var i=0;i<details.length;i++){\n"
@"        var d=details[i]||{};\n"
@"        connectionCount+=d.connectionCount||0;\n"
@"        if(Array.isArray(d.processes)){\n"
@"          d.processes.forEach(function(p){if(p)processSet[p]=true;});\n"
@"        }\n"
@"        if(d.firstSeen&&(!firstSeen||d.firstSeen<firstSeen)) firstSeen=d.firstSeen;\n"
@"        if(d.lastSeen&&(!lastSeen||d.lastSeen>lastSeen)) lastSeen=d.lastSeen;\n"
@"        var r=d.riskState||'Observed';\n"
@"        if(riskRank(r)>riskRank(risk)) risk=r;\n"
@"      }\n"
@"      return {connectionCount:connectionCount,processes:Object.keys(processSet),firstSeen:firstSeen,lastSeen:lastSeen,riskState:risk};\n"
@"    }\n"
@"    function groupKey(detail){\n"
@"      var asn=detail.asn||'Unknown ASN';\n"
@"      var country=detail.country||'Unknown';\n"
@"      return asn+'|'+country;\n"
@"    }\n"
@"    function groupPointsByASN(points){\n"
@"      var grouped={};\n"
@"      for(var i=0;i<points.length;i++){\n"
@"        var p=points[i];\n"
@"        var details=p.ipDetails||[];\n"
@"        for(var j=0;j<details.length;j++){\n"
@"          var d=details[j];\n"
@"          if(typeof d.lat!=='number'||typeof d.lon!=='number') continue;\n"
@"          var key=groupKey(d);\n"
@"          var bucket=grouped[key];\n"
@"          if(!bucket){bucket={count:0,lat:0,lon:0,ipDetails:[],asn:d.asn||'',country:d.country||''};grouped[key]=bucket;}\n"
@"          bucket.count+=1;bucket.lat+=d.lat;bucket.lon+=d.lon;bucket.ipDetails.push(d);\n"
@"        }\n"
@"      }\n"
@"      var result=[];\n"
@"      Object.keys(grouped).forEach(function(key){\n"
@"        var b=grouped[key];\n"
@"        if(b.count===0) return;\n"
@"        var lat=b.lat/b.count, lon=b.lon/b.count;\n"
@"        result.push({\n"
@"          lat:lat, lon:lon, ipDetails:b.ipDetails, ips:b.ipDetails.map(function(d){return d.ip;}),\n"
@"          locationName:'', isDuplicate:b.ipDetails.length>1, groupTitle:(b.asn||'Unknown ASN')+' · '+(b.country||'Unknown')\n"
@"        });\n"
@"      });\n"
@"      return result;\n"
@"    }\n"
@"\n"
@"    function buildPopupForPoint(p){\n"
@"      var popupContent='';\n"
@"      var details=Array.isArray(p.ipDetails)?p.ipDetails:[];\n"
@"      if(!details.length && Array.isArray(p.ips)){\n"
@"        details=p.ips.map(function(ip,idx){return {ip:ip,isp:(p.isps&&p.isps[idx])||'',name:(p.names&&p.names[idx])||''};});\n"
@"      }\n"
@"      if(details.length){\n"
@"        var agg=aggregateDetails(details);\n"
@"        var headerTitle=p.groupTitle||p.locationName||'Location';\n"
@"        var riskClass='risk-'+(agg.riskState||'Observed').toLowerCase();\n"
@"        popupContent='<div class=\"location-header\">'\n"
@"          +'<span class=\"risk-pill '+riskClass+'\">'+esc(agg.riskState||'Observed')+'</span>'\n"
@"          +esc(headerTitle)+'</div>';\n"
@"        if(p.locationName&&p.locationName.length>0&&p.groupTitle){\n"
@"          popupContent+='<div class=\"location-name\">'+esc(p.locationName)+'</div>';\n"
@"        }else if(p.locationName&&p.locationName.length>0){\n"
@"          popupContent+='<div class=\"location-name\">'+esc(p.locationName)+'</div>';\n"
@"        }\n"
@"        var processText='—';\n"
@"        if(agg.processes&&agg.processes.length){\n"
@"          processText=agg.processes.slice(0,3).join(', ');\n"
@"          if(agg.processes.length>3){processText+=' +'+(agg.processes.length-3)+' more';}\n"
@"        }\n"
@"        popupContent+='<div class=\"meta-grid\">'\n"
@"          +'<div class=\"meta-item\"><span>Connections</span><strong>'+agg.connectionCount+'</strong></div>'\n"
@"          +'<div class=\"meta-item\"><span>Processes</span><strong>'+esc(processText)+'</strong></div>'\n"
@"          +'<div class=\"meta-item\"><span>First seen</span><strong>'+esc(formatTimestamp(agg.firstSeen))+'</strong></div>'\n"
@"          +'<div class=\"meta-item\"><span>Last seen</span><strong>'+esc(formatTimestamp(agg.lastSeen))+'</strong></div>'\n"
@"          +'</div>';\n"
@"        popupContent+='<ul class=\"ip-list\">';\n"
@"        for(var i=0;i<details.length;i++){\n"
@"          var d=details[i]||{};\n"
@"          var ip=d.ip||'';\n"
@"          var isp=d.isp||d.name||'';\n"
@"          var badge=d.badge||null;\n"
@"          var badgeMarkup='';\n"
@"          if(badge){\n"
@"            var color=badge.color||'#94a3b8';\n"
@"            var icon=badge.icon||'';\n"
@"            badgeMarkup='<span class=\"ip-badge\" style=\"border-color:'+esc(color)+';color:'+esc(color)+';\">'\n"
@"              +'<span class=\"ip-badge-dot\" style=\"background:'+esc(color)+'\"></span>'\n"
@"              +'<span class=\"ip-badge-icon\">'+esc(icon)+'</span></span>';\n"
@"          }\n"
@"          var metaParts=[];\n"
@"          if(d.asn) metaParts.push(esc(d.asn));\n"
@"          if(d.country) metaParts.push(esc(d.country));\n"
@"          if(d.connectionCount) metaParts.push(d.connectionCount+' conn');\n"
@"          var risk=d.riskState||'Observed';\n"
@"          var riskBadge='<span class=\"risk-pill risk-'+risk.toLowerCase()+'\">'+esc(risk)+'</span>';\n"
@"          var newBadge=d.isNewToday?'<span class=\"ip-new\">New today</span>':'';\n"
@"          popupContent+='<li class=\"ip-item\">'+badgeMarkup+'<span class=\"ip-text\">'\n"
@"            +'<span class=\"ip-address\">'+esc(ip)+'</span>'\n"
@"            +(isp&&isp.length?'<span class=\"ip-company\">'+esc(isp)+'</span>':'')\n"
@"            +(metaParts.length?'<span class=\"ip-subline\">'+metaParts.join(' · ')+'</span>':'')\n"
@"            +'<span class=\"ip-meta\">'+riskBadge+newBadge+'</span>'\n"
@"            +'<div class=\"ip-actions\">'\n"
@"              +'<button class=\"action-btn\" data-action=\"label\" data-ip=\"'+esc(ip)+'\">Label</button>'\n"
@"              +'<button class=\"action-btn\" data-action=\"block\" data-ip=\"'+esc(ip)+'\">Block</button>'\n"
@"              +'<button class=\"action-btn\" data-action=\"ignore\" data-ip=\"'+esc(ip)+'\">Ignore</button>'\n"
@"            +'</div>'\n"
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
@"      var displayPoints=groupByASN?groupPointsByASN(points||[]):(points||[]);\n"
@"      updateHeatData(displayPoints);\n"
@"      updateNewLayer(displayPoints);\n"
@"\n"
@"      var bounds=[];\n"
@"      if(displayPoints&&displayPoints.length){\n"
@"        for(var i=0;i<displayPoints.length;i++){\n"
@"          var p=displayPoints[i];\n"
@"          if(typeof p.lat!=='number'||typeof p.lon!=='number') continue;\n"
@"          var popupContent=buildPopupForPoint(p);\n"
@"          var details=p.ipDetails||[];\n"
@"          var agg=aggregateDetails(details);\n"
@"          var color=riskColor(agg.riskState);\n"
@"          var colorDark=darkenColor(color,0.8);\n"
@"          var marker;\n"
@"          if(p.isDuplicate){\n"
@"            var count2=p.ips?p.ips.length:details.length;\n"
@"            var size=Math.min(56,Math.max(36,count2*4+24));\n"
@"            var icon2=L.divIcon({className:'',html:'<div class=\"cluster-marker\" style=\"--cluster-color:'+color+';--cluster-color-dark:'+colorDark+'\"><div>'+count2+'</div></div>',iconSize:[size,size],iconAnchor:[size/2,size/2]});\n"
@"            marker=L.marker([p.lat,p.lon],{icon:icon2});\n"
@"          }else{\n"
@"            var icon3=L.divIcon({className:'',html:'<div class=\"single-marker\" style=\"--pin-color:'+color+';--pin-color-dark:'+colorDark+'\"></div>',iconSize:[24,32],iconAnchor:[12,32]});\n"
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
@"      var btnDetach=document.getElementById('btnDetach');\n"
@"      var btnGroup=document.getElementById('btnGroup');\n"
@"      var btnNew=document.getElementById('btnNew');\n"
@"      var btnFilters=document.getElementById('btnFilters');\n"
@"      var overflowPanel=document.getElementById('overflowPanel');\n"
@"      var ovHeat=document.getElementById('ovHeat');\n"
@"      var ovLegend=document.getElementById('ovLegend');\n"
@"      var ovMap=document.getElementById('ovMap');\n"
@"      var ovGroup=document.getElementById('ovGroup');\n"
@"      var ovNew=document.getElementById('ovNew');\n"
@"      var ovFilters=document.getElementById('ovFilters');\n"
@"      var legendClose=document.getElementById('legendClose');\n"
@"      var filtersClose=document.getElementById('filtersClose');\n"
@"      var btnMore=document.getElementById('btnMore');\n"
@"      if(btnToolbar&&toolbar){btnToolbar.addEventListener('click',function(){toolbar.classList.toggle('is-collapsed');});}\n"
@"      if(btnZoomIn){btnZoomIn.addEventListener('click',function(){zoomIn();});}\n"
@"      if(btnZoomOut){btnZoomOut.addEventListener('click',function(){zoomOut();});}\n"
@"      if(btnHeat){btnHeat.addEventListener('click',function(){var on=toggleHeatMap();setBtnOn('btnHeat',on);});}\n"
@"      if(btnLegend){btnLegend.addEventListener('click',function(){var on=toggleLegend();setBtnOn('btnLegend',on);});}\n"
@"      if(btnMap){btnMap.addEventListener('click',function(){cycleBaseLayer();setBtnOn('btnMap',true);setTimeout(function(){setBtnOn('btnMap',false);},180);});}\n"
@"      if(btnDetach){\n"
@"        if(isDetached){btnDetach.style.display='none';}\n"
@"        else{btnDetach.addEventListener('click',function(){\n"
@"          if(window.webkit&&window.webkit.messageHandlers&&window.webkit.messageHandlers.mapDetach){\n"
@"            window.webkit.messageHandlers.mapDetach.postMessage({action:'detach'});\n"
@"          }\n"
@"        });}\n"
@"      }\n"
@"      if(btnGroup){btnGroup.addEventListener('click',function(){var on=toggleGroupByASN();setBtnOn('btnGroup',on);});}\n"
@"      if(btnNew){btnNew.addEventListener('click',function(){var on=toggleNewLayer();setBtnOn('btnNew',on);});}\n"
@"      if(btnFilters){btnFilters.addEventListener('click',function(){var on=toggleFilters();setBtnOn('btnFilters',on);});}\n"
@"      if(btnMore){\n"
@"        btnMore.addEventListener('click',function(){\n"
@"          if(overflowPanel){overflowPanel.classList.toggle('visible');}\n"
@"        });\n"
@"      }\n"
@"      if(ovHeat){ovHeat.addEventListener('click',function(){var on=toggleHeatMap();setBtnOn('btnHeat',on);if(overflowPanel)overflowPanel.classList.remove('visible');});}\n"
@"      if(ovLegend){console.log('ovLegend found, adding handler');ovLegend.addEventListener('click',function(e){console.log('ovLegend clicked',e.target);e.target.style.background='#ff0';setTimeout(function(){e.target.style.background='';},200);var on=toggleLegend();console.log('toggleLegend returned:',on);if(overflowPanel)overflowPanel.classList.remove('visible');});}else{console.log('ovLegend NOT found');}\n"
@"      if(ovMap){ovMap.addEventListener('click',function(){cycleBaseLayer();if(overflowPanel)overflowPanel.classList.remove('visible');});}\n"
@"      if(ovGroup){ovGroup.addEventListener('click',function(e){console.log('ovGroup clicked - calling toggleGroupByASN');var on=toggleGroupByASN();setBtnOn('btnGroup',on);if(overflowPanel)overflowPanel.classList.remove('visible');});}\n"
@"      if(ovNew){ovNew.addEventListener('click',function(){var on=toggleNewLayer();setBtnOn('btnNew',on);if(overflowPanel)overflowPanel.classList.remove('visible');});}\n"
@"      if(ovFilters){console.log('ovFilters found, adding handler');ovFilters.addEventListener('click',function(e){console.log('ovFilters clicked',e.target);var on=toggleFilters();setBtnOn('btnFilters',on);if(overflowPanel)overflowPanel.classList.remove('visible');});}else{console.log('ovFilters NOT found');}\n"
@"      if(legendClose){legendClose.addEventListener('click',function(){closeLegend();setBtnOn('btnLegend',false);});}\n"
@"      if(filtersClose){filtersClose.addEventListener('click',function(){closeFilters();setBtnOn('btnFilters',false);});}\n"
@"    })();\n"
@"\n"
@"    document.addEventListener('click',function(e){\n"
@"      console.log('Document click on:', e.target.tagName, e.target.className, e.target.id);\n"
@"      var btn=e.target.closest('.action-btn');\n"
@"      if(!btn) return;\n"
@"      var action=btn.getAttribute('data-action');\n"
@"      var ip=btn.getAttribute('data-ip');\n"
@"      if(action&&ip&&window.webkit&&window.webkit.messageHandlers&&window.webkit.messageHandlers.mapAction){\n"
@"        window.webkit.messageHandlers.mapAction.postMessage({action:action,ip:ip});\n"
@"      }\n"
@"      e.preventDefault();\n"
@"    });\n"
@"\n"
@"    window.SniffNetBar={setMarkers:setMarkers,zoomIn:zoomIn,zoomOut:zoomOut,resetView:resetView,cycleBaseLayer:cycleBaseLayer,toggleHeatMap:toggleHeatMap,toggleLegend:toggleLegend,toggleFilters:toggleFilters,toggleGroupByASN:toggleGroupByASN,toggleNewLayer:toggleNewLayer};\n"
@"  </script>\n"
@"</body>\n"
@"</html>\n"
, lineColor, lineColor, isDetachedFlag, (long)lineWeight, lineColor, lineOpacity];
    NSURL *resourceURL = [[NSBundle mainBundle] resourceURL];
    html = SNBInlineVendorAssets(html, resourceURL);
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

- (BOOL)detachedWindowVisible {
    return self.detachedWindow != nil;
}

- (NSString *)riskStateForIP:(NSString *)ipAddress {
    if (ipAddress.length == 0) {
        return @"Observed";
    }
    if ([self.blockedIPs containsObject:ipAddress]) {
        return @"Blocked";
    }
    if ([self.trustedStore isTrustedIP:ipAddress]) {
        return @"Trusted";
    }
    TIEnrichmentResponse *response = self.threatIntelResults[ipAddress];
    TIThreatVerdict verdict = response.scoringResult.verdict;
    if (verdict == TIThreatVerdictMalicious || verdict == TIThreatVerdictSuspicious) {
        return @"Investigate";
    }
    return @"Observed";
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

#pragma mark - WKNavigationDelegate

- (void)webView:(WKWebView *)webView didFailNavigation:(WKNavigation *)navigation withError:(NSError *)error {
    SNBLogUIError("Map navigation failed: %{public}@", error);
}

- (void)webView:(WKWebView *)webView didFailProvisionalNavigation:(WKNavigation *)navigation withError:(NSError *)error {
    SNBLogUIError("Map provisional navigation failed: %{public}@", error);
}

- (void)webViewWebContentProcessDidTerminate:(WKWebView *)webView {
    SNBLogUIError("Map web content process terminated");
}

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
        SNBLogUIDebug("[JS] %{public}s", logMessage.UTF8String);
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
        return;
    }

    if ([message.name isEqualToString:@"mapAction"]) {
        NSDictionary *data = message.body;
        if (![data isKindOfClass:[NSDictionary class]]) {
            SNBLogUIDebug("mapAction: Invalid data type");
            return;
        }
        NSString *action = data[@"action"];
        NSString *ipAddress = data[@"ip"];
        if (action.length > 0 && ipAddress.length > 0) {
            if ([self.delegate respondsToSelector:@selector(mapMenuView:didRequestAction:forIP:)]) {
                [self.delegate mapMenuView:self didRequestAction:action forIP:ipAddress];
            }
        }
        return;
    }

    if ([message.name isEqualToString:@"mapDetach"]) {
        [self openDetachedWindow];
    }
}

#pragma mark - NSWindowDelegate

- (void)windowWillClose:(NSNotification *)notification {
    if (notification.object == self.detachedWindow) {
        self.detachedWindow = nil;
        self.detachedMapView = nil;
    }
}

- (BOOL)windowShouldClose:(NSWindow *)sender {
    if (sender == self.detachedWindow) {
        if ([self.delegate respondsToSelector:@selector(mapMenuViewDidAttachMap:)]) {
            [self.delegate mapMenuViewDidAttachMap:self];
        }
        [self.detachedWindow orderOut:nil];
        self.detachedWindow = nil;
        self.detachedMapView = nil;
        return NO;
    }
    return YES;
}

@end

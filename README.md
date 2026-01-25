# macOS-SniffNetBar

macOS menu bar network observer with process-level visibility, geo map, passive alerts, agentic decision-making, and emerging machine learning for smarter threat promotion & anomaly spotting. Extended from Sniffnet.


## What it does

- Monitors live network traffic from the macOS menu bar with at-a-glance status
- Captures and analyzes packets via libpcap for protocol-level visibility
- Tracks totals, packet counts, top hosts, and top connections over time
- Shows which local process is responsible for each network connection
- Resolves hostnames using reverse DNS for easier identification
- Supports TCP, UDP, ICMP, IPv4, and IPv6 traffic
- Includes an embedded Leaflet map for public IP geolocation
- Adds agentic decision-making to promote, label, or flag connections based on trust signals
- Uses emerging machine-learning heuristics to surface anomalies and elevate likely threats

Note: macOS-SniffNetBar does not use Network Extension entitlements. It identifies connections via
libpcap capture plus a privileged helper that maps sockets to PIDs.

## Architecture overview

macOS-SniffNetBar is a macOS status-bar app with an AppCoordinator that wires together capture, modeling, threat intel, and UI rendering. The UI is centered around a MenuBuilder that builds a rich visualization menu and detail submenu, fed by TrafficStatistics and multiple service coordinators. Map and graph views render in-menu visualizations with supporting utilities like IP classification and badge registries.

Behavior modeling and promotion are split into services: a modeling XPC service (with an in-process fallback) stores events and generates recommendations, while the promotion agent evaluates candidates and applies trust decisions or labels. A privileged helper XPC service handles packet capture and process lookup with elevated privileges. Storage relies on SQLite for behavioral data, trust history, anomaly records, and promotion logs, while threat intel is handled via provider integrations with caching and keychain-backed credentials.

## Requirements

- macOS 10.13 or later
- libpcap (install via Homebrew: `brew install libpcap`)
- Xcode Command Line Tools
- A valid Apple code signing certificate (see "Helper signing" below)

## Helper signing (required for install)

macOS-SniffNetBar uses a privileged helper installed via `SMAppService`. The helper only accepts
connections from a signed app with the same Team ID, so you must sign both the app and
helper with a real Apple certificate (ad-hoc signing will fail).

1. Create or install a signing certificate in Keychain (for local dev, "Apple Development"
   works; for distribution, use "Developer ID Application").
2. Set the `CODESIGN_IDENTITY` used by the Makefile:
   - One-off: `CODESIGN_IDENTITY="Apple Development: Your Name (TEAMID)" make`
   - Or create `SniffNetBar/Makefile.local` and set `CODESIGN_IDENTITY = Apple Development: Your Name (TEAMID)`

If `CODESIGN_IDENTITY` is not set, the build will succeed but the helper install/connection
will fail at runtime.

## Build

```bash
make
```

This creates `build/SniffNetBar.app`.

## Compilation

1. **Prepare the environment** – install Xcode command line tools (`xcode-select --install`) and `libpcap` (`brew install libpcap`). The Makefile (`SniffNetBar/Makefile`) assumes Homebrew puts headers in `/opt/homebrew` or `/usr/local`, so adjust `PCAP_INCLUDE` and `PCAP_LIBDIR` if that differs.
2. **Configure signing** – the privileged helper must be signed with the same identity as the main app. Export your certificate into `CODESIGN_IDENTITY` before running `make`, for example `CODESIGN_IDENTITY="Apple Development: Your Name (TEAMID)" make`. To keep builds repeatable, copy your identity name into `SniffNetBar/Makefile.local` and set `CODESIGN_IDENTITY = Apple Development: Your Name (TEAMID)` there.
3. **Build from scratch** – clean stale artifacts (`make clean`) and build with `make` or `CODESIGN_IDENTITY="…" make`. The default target compiles the app, helper, scripts, and CLI utilities while signing both bundles and updating the helper plist if a code signature is present.
4. **Optional tooling** – the target also builds helpers such as `register_helper`, `status_helper`, `set_apikey`, etc., which are copied into the bundle for installation/registration later.

## Certificate constraints

The helper explicitly validates the connecting app's bundle and team identifiers (`SniffNetBarHelper/SNBPrivilegedHelperService.m:120-235`). It caches its own `teamIdentifier` (via `SNBTeamIdentifierForSelf`) and returns `NO` from `validateConnection:` whenever `kSecCodeInfoTeamIdentifier` is missing or does not match (`SniffNetBarHelper/SNBPrivilegedHelperService.m:224-235`). Self-signed identities lack an Apple-issued team ID, so the helper refuses their connections; only Apple Development/Developer ID certificates that embed the same team ID for both app and helper can run SniffNetBar end-to-end.

## Development without Apple Developer Account

If you don't have an Apple Developer account ($99/year), you can still build and run SniffNetBar for development purposes using the **development mode** targets. This bypasses SMJobBless and team ID validation by manually installing the helper.

### Quick Start (Development Mode)

```bash
# 1. Build the app and development helper
make
make helper-dev

# 2. Install the development helper (requires sudo)
sudo make install-helper-dev

# 3. Run the app
make run-dev
```

### How It Works

Development mode differs from production in two ways:

1. **Helper Build**: The helper is compiled with `-DSNIFFNETBAR_DEV_MODE`, which disables team ID validation. It only checks that the connecting app has the correct bundle ID (`com.sniffnetbar.app`).

2. **Manual Installation**: Instead of using SMJobBless (which requires matching code signatures), the helper is manually installed to:
   - Binary: `/Library/PrivilegedHelperTools/com.sniffnetbar.helper`
   - Plist: `/Library/LaunchDaemons/com.sniffnetbar.helper.plist`

### Development Targets

| Target | Description |
|--------|-------------|
| `make helper-dev` | Build the development helper (no team ID validation) |
| `sudo make install-helper-dev` | Install helper to system directories |
| `sudo make uninstall-helper-dev` | Remove the development helper |
| `make run-dev` | Run the app (after installing helper) |

### Security Note

Development mode is **not recommended for production use**. It bypasses security validations that ensure only your signed app can communicate with the privileged helper. For distribution, use the standard build with a valid Apple Developer certificate.

## Install

```bash
make install
```

This copies `SniffNetBar.app` to `~/Applications/`.

## Run

Packet capture requires root privileges on macOS.

```bash
sudo ~/Applications/SniffNetBar.app/Contents/MacOS/SniffNetBar
```

Or if building locally:

```bash
sudo ./build/SniffNetBar.app/Contents/MacOS/SniffNetBar
```

## Usage

1. Launch the application (requires sudo for packet capture)
2. Click the menubar icon to view traffic statistics
3. Select "Network Interface" to choose which interface to monitor
4. Toggle top hosts/connections and the map view as needed

## Passive threat visibility

- Highlights public IPs from active connections in the map view
- Helps spot unexpected destinations and unusual traffic patterns
- Designed for quick, passive situational awareness from the menubar

## Limitations

- Requires `sudo` to capture packets on macOS
- Simplified IPv6 parsing (extension headers not fully parsed)
- No port-to-service name mapping
- Menubar UI only (no full desktop UI)

## Map provider

The map uses Leaflet + OpenStreetMap tiles and looks up IP locations via a provider:

- `ipinfo.io` (default)
- `ip-api.com` (fallback to `ipinfo.io` on 403)
- Custom provider via UserDefaults:
  - `MapProvider` = `custom`
  - `MapProviderURLTemplate` = e.g. `https://example.com/geo/%@`
  - `MapProviderLatKey` = key path to latitude (default `lat`)
  - `MapProviderLonKey` = key path to longitude (default `lon`)

## License

Inspired by the original Sniffnet codebase (MIT OR Apache-2.0)

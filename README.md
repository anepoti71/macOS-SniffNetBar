# SniffNetBar

A macOS menu bar app for real-time network traffic monitoring with process identification, geo-mapping, and threat intelligence.

## Features

- **Live Traffic Monitoring** – View network statistics directly from the menu bar
- **Process Identification** – See which app is responsible for each connection
- **Geo Map** – Embedded Leaflet map showing public IP locations
- **Protocol Support** – TCP, UDP, ICMP over IPv4 and IPv6
- **Threat Intelligence** – Integration with VirusTotal, AbuseIPDB, GreyNoise, Shodan
- **Anomaly Detection** – ML-based heuristics to surface suspicious traffic
- **Promotion Agent** – Agentic decision-making to promote, label, or flag connections based on trust signals and behavioral patterns

## Requirements

- macOS 10.13+
- Xcode Command Line Tools (`xcode-select --install`)
- libpcap (`brew install libpcap`)

## Quick Start

### For Developers

**With Apple Developer Account:**

```bash
# Set your signing identity
export CODESIGN_IDENTITY="Apple Development: Your Name (TEAMID)"

# Build and install
make
make install
make run
```

**Without Apple Developer Account:**

```bash
# Build
make
make helper-dev

# Install helper (one time)
sudo make install-helper-dev

# Run
make run-dev
```

## Build Targets

| Target          | Description                |
|-----------------|----------------------------|
| `make`          | Build app and helper       |
| `make install`  | Install to ~/Applications  |
| `make run`      | Run installed app          |
| `make dmg`      | Create distributable DMG   |
| `make clean`    | Remove build artifacts     |

### Development Mode (No Apple Certificate)

| Target                          | Description                              |
|---------------------------------|------------------------------------------|
| `make helper-dev`               | Build helper without team ID validation  |
| `sudo make install-helper-dev`  | Install development helper               |
| `sudo make uninstall-helper-dev`| Remove development helper                |
| `make run-dev`                  | Run from build directory                 |

## Code Signing

The app uses a privileged helper for packet capture. In production mode, the helper validates that the connecting app has a matching Apple Team ID.

**Options:**

1. **Apple Developer Account** ($99/year) – Required for distribution and SMJobBless
2. **Development Mode** – Bypasses team ID check; use `make helper-dev` targets

To configure signing, either:

- Pass inline: `CODESIGN_IDENTITY="..." make`
- Or create `SniffNetBar/Makefile.local`:

  ```makefile
  CODESIGN_IDENTITY = Apple Development: Your Name (TEAMID)
  ```

## Configuration

### Threat Intel API Keys

Store API keys in the Keychain:

```bash
./build/set_apikey virustotal YOUR_API_KEY
./build/set_apikey abuseipdb YOUR_API_KEY
```

### Map Provider

Default: `ipinfo.io`. Configure via UserDefaults:

```bash
defaults write com.sniffnetbar.app MapProvider "ip-api.com"
```

Custom provider:

```bash
defaults write com.sniffnetbar.app MapProvider "custom"
defaults write com.sniffnetbar.app MapProviderURLTemplate "https://example.com/geo/%@"
```

## Architecture

```text
SniffNetBar.app
├── Main App (AppCoordinator, MenuBuilder, UI)
├── Privileged Helper (packet capture, process lookup)
├── Modeling XPC Service (behavior analysis)
└── SQLite stores (events, trust, anomalies)
```

The privileged helper runs as a LaunchDaemon and communicates via XPC. It handles:

- Packet capture via libpcap
- Socket-to-PID mapping
- Network interface enumeration

## Limitations

- Menubar UI only (no windowed interface)
- IPv6 extension headers not fully parsed
- Requires privileged helper for packet capture

## License

MIT OR Apache-2.0 (inspired by Sniffnet)

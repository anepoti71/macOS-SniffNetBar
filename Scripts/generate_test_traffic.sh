#!/bin/bash
#
# generate_test_traffic.sh
# Generate test network traffic to various IPs for testing SniffNetBar's threat intelligence
#

set -e

echo "=== SniffNetBar Test Traffic Generator ==="
echo ""
echo "This script generates test network traffic to various IPs."
echo "Make sure SniffNetBar is running to capture this traffic."
echo ""

# Known test IPs (using TEST-NET ranges from RFC 5737 - safe for testing)
TEST_IPS=(
    "192.0.2.1"      # TEST-NET-1
    "198.51.100.1"   # TEST-NET-2
    "203.0.113.1"    # TEST-NET-3
)

# Known malicious IPs (publicly documented malicious IPs - use with caution)
# These are well-known bad IPs that should appear in threat feeds
KNOWN_BAD_IPS=(
    "185.220.101.1"  # Known Tor exit node
    "45.155.205.233" # Known in abuse databases
)

echo "Choose test mode:"
echo "1) Safe test IPs only (TEST-NET ranges - no actual connections)"
echo "2) Generate DNS queries only (safe)"
echo "3) Attempt connections to known bad IPs (CAUTION: may trigger alerts)"
echo ""
read -p "Select mode [1-3]: " mode

case $mode in
    1)
        echo ""
        echo "Generating test traffic to TEST-NET IPs..."
        for ip in "${TEST_IPS[@]}"; do
            echo "Testing $ip (will timeout - this is expected)"
            # Use nc with short timeout - these IPs are non-routable
            timeout 1 nc -zv "$ip" 80 2>&1 || true
            sleep 0.5
        done
        ;;
    2)
        echo ""
        echo "Generating DNS queries..."
        # Some domains known to be in threat feeds
        test_domains=(
            "example.com"
            "test.local"
        )
        for domain in "${test_domains[@]}"; do
            echo "Querying: $domain"
            dig +short "$domain" > /dev/null 2>&1 || true
            sleep 0.5
        done
        ;;
    3)
        echo ""
        echo "⚠️  WARNING: This will attempt connections to known malicious IPs"
        echo "This may:"
        echo "  - Trigger security alerts"
        echo "  - Be logged by your network"
        echo "  - Violate your organization's policies"
        echo ""
        read -p "Are you sure? Type 'yes' to continue: " confirm
        if [ "$confirm" != "yes" ]; then
            echo "Cancelled."
            exit 0
        fi

        echo ""
        echo "Attempting connections to known bad IPs..."
        for ip in "${KNOWN_BAD_IPS[@]}"; do
            echo "Testing $ip (quick timeout)"
            # Very short timeout to just trigger the connection attempt
            timeout 1 nc -zv "$ip" 80 2>&1 || true
            sleep 1
        done
        ;;
    *)
        echo "Invalid selection"
        exit 1
        ;;
esac

echo ""
echo "=== Test traffic generation complete ==="
echo "Check SniffNetBar menu to see captured connections and threat intel results."

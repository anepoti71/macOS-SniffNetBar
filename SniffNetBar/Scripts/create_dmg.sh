#!/bin/bash
set -e

APP_NAME="SniffNetBar"
VERSION="1.0"
DMG_NAME="${APP_NAME}-${VERSION}"
BUILD_DIR="build"
APP_BUNDLE="${BUILD_DIR}/${APP_NAME}.app"
DMG_DIR="${BUILD_DIR}/dmg"
OUTPUT_DMG="${BUILD_DIR}/${DMG_NAME}.dmg"

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}Creating DMG installer for ${APP_NAME}...${NC}"

# Verify app bundle exists
if [ ! -d "$APP_BUNDLE" ]; then
    echo "Error: App bundle not found at $APP_BUNDLE"
    echo "Please run 'make' first to build the application"
    exit 1
fi

# Clean up any existing DMG files
echo "Cleaning up previous DMG files..."
rm -f "$OUTPUT_DMG"
rm -rf "$DMG_DIR"

# Create temporary directory for DMG contents
echo "Creating DMG staging directory..."
mkdir -p "$DMG_DIR"

# Copy app bundle to DMG directory
echo "Copying ${APP_NAME}.app..."
cp -R "$APP_BUNDLE" "$DMG_DIR/"

# Create symbolic link to Applications folder
echo "Creating Applications symlink..."
ln -s /Applications "$DMG_DIR/Applications"

# Create DMG
echo "Creating disk image..."
hdiutil create -volname "$APP_NAME" \
    -srcfolder "$DMG_DIR" \
    -ov -format UDZO \
    -fs HFS+ \
    "$OUTPUT_DMG"

# Clean up temporary directory
echo "Cleaning up..."
rm -rf "$DMG_DIR"

echo -e "${GREEN}✓ DMG created successfully: ${OUTPUT_DMG}${NC}"
echo ""
echo "Installation instructions:"
echo "  1. Open ${DMG_NAME}.dmg"
echo "  2. Drag ${APP_NAME}.app to the Applications folder"
echo "  3. Run the app from /Applications/${APP_NAME}.app"
echo ""
echo "Note: The application will request root privileges on startup for packet capture."

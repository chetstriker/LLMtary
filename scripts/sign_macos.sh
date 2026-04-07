#!/bin/bash
set -e

# --- CONFIGURATION ---
APP_PATH="build/macos/Build/Products/Release/LLMary.app"

# Use version from CI environment variable if available, otherwise use default name
if [ -n "$CI_COMMIT_TAG" ]; then
  VERSION="${CI_COMMIT_TAG#v}"  # Strip 'v' prefix
  DMG_OUTPUT="build/macos/Build/Products/Release/LLMary_Installer_V${VERSION}.dmg"
else
  DMG_OUTPUT="build/macos/Build/Products/Release/LLMary_Installer.dmg"
fi

VOL_NAME="LLMary Installer"

# Variables for Keychain
KEYCHAIN_PATH=$RUNNER_TEMP_PROJECT_DIR/build.keychain
KEYCHAIN_PASSWORD="temporary-password"

# ==========================================
# PART 1: KEYCHAIN SETUP & IMPORT
# ==========================================

if [ -z "$MACOS_CERTIFICATE" ]; then
  echo "❌ Error: MACOS_CERTIFICATE variable is empty."
  exit 1
fi

echo "$MACOS_CERTIFICATE" | base64 -D -o certificate.p12

if [ ! -s certificate.p12 ]; then
  echo "❌ Error: certificate.p12 is empty."
  exit 1
fi

if [ -f "$KEYCHAIN_PATH" ]; then
    echo "⚠️ Keychain exists. Deleting..."
    security delete-keychain "$KEYCHAIN_PATH" || rm -f "$KEYCHAIN_PATH"
fi

security create-keychain -p "$KEYCHAIN_PASSWORD" $KEYCHAIN_PATH
security set-keychain-settings -lut 21600 $KEYCHAIN_PATH
security unlock-keychain -p "$KEYCHAIN_PASSWORD" $KEYCHAIN_PATH

echo "🔑 Importing certificate..."
security import certificate.p12 -k $KEYCHAIN_PATH -P "$MACOS_CERTIFICATE_PWD" -T /usr/bin/codesign

security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$KEYCHAIN_PASSWORD" $KEYCHAIN_PATH
security list-keychains -d user -s $KEYCHAIN_PATH

# ==========================================
# PART 2: CODE SIGNING
# ==========================================

ENTITLEMENTS="macos/Runner/Release.entitlements"
if [ ! -f "$ENTITLEMENTS" ]; then
    ENTITLEMENTS="macos/Runner/Runner.entitlements"
fi

echo "🔏 Signing $APP_PATH..."
codesign --force --deep --options runtime --verbose --sign "$MACOS_IDENTITY_ID" --entitlements "$ENTITLEMENTS" "$APP_PATH"

echo "✅ Successfully signed."

# ==========================================
# PART 3: CREATE DMG (Robust Method)
# ==========================================

echo "📦 Packaging into DMG (using hdiutil)..."

# 1. Prepare a staging folder
STAGING_DIR="build/macos/dmg_staging"
rm -rf "$STAGING_DIR"
mkdir -p "$STAGING_DIR"

# 2. Copy the signed App to staging
cp -R "$APP_PATH" "$STAGING_DIR/"

# 3. Create the symlink to /Applications
#    This allows the user to drag the app to Applications inside the DMG
ln -s /Applications "$STAGING_DIR/Applications"

# 4. Create the DMG using hdiutil
#    -srcfolder: The folder containing our app and the link
#    -format UDZO: Compressed image format
#    -ov: Overwrite existing file
if [ -f "$DMG_OUTPUT" ]; then
    rm "$DMG_OUTPUT"
fi

hdiutil create -volname "$VOL_NAME" -srcfolder "$STAGING_DIR" -ov -format UDZO "$DMG_OUTPUT"

# 5. Cleanup
rm -rf "$STAGING_DIR"

echo "✅ DMG Created at: $DMG_OUTPUT"

# ==========================================
# PART 3.5: SIGN DMG
# ==========================================

echo "🔏 Signing DMG..."

codesign --force --sign "$MACOS_IDENTITY_ID" "$DMG_OUTPUT"

echo "✅ DMG signed."


# ==========================================
# PART 4: NOTARIZATION
# ==========================================

if [ -z "$APPLE_ID" ] || [ -z "$APPLE_TEAM_ID" ] || [ -z "$APPLE_APP_PASSWORD" ]; then
  echo "❌ Apple notarization variables are missing."
  exit 1
fi

echo "🚀 Submitting DMG for notarization..."

xcrun notarytool submit "$DMG_OUTPUT" \
  --apple-id "$APPLE_ID" \
  --team-id "$APPLE_TEAM_ID" \
  --password "$APPLE_APP_PASSWORD" \
  --wait

echo "📎 Stapling notarization ticket..."

# Add a small delay to ensure the ticket is available
echo "⏳ Waiting 10 seconds for notarization ticket to be available..."
sleep 10

# Retry stapling up to 3 times with delays
MAX_STAPLE_RETRIES=3
STAPLE_RETRY_COUNT=0
STAPLE_SUCCESS=false

while [ $STAPLE_RETRY_COUNT -lt $MAX_STAPLE_RETRIES ]; do
  echo "Stapling attempt $((STAPLE_RETRY_COUNT + 1))/$MAX_STAPLE_RETRIES..."

  if xcrun stapler staple "$DMG_OUTPUT"; then
    echo "✅ Stapling successful!"
    STAPLE_SUCCESS=true
    break
  else
    STAPLE_RETRY_COUNT=$((STAPLE_RETRY_COUNT + 1))
    if [ $STAPLE_RETRY_COUNT -lt $MAX_STAPLE_RETRIES ]; then
      echo "⚠️ Stapling failed, waiting 15 seconds before retry..."
      sleep 15
    fi
  fi
done

if [ "$STAPLE_SUCCESS" = false ]; then
  echo "❌ Stapling failed after $MAX_STAPLE_RETRIES attempts."
  echo "⚠️ The DMG is notarized but the ticket is not stapled."
  echo "⚠️ Users will need an internet connection to verify the notarization."
  # Don't exit - the DMG is still notarized, just not stapled
fi

echo "🔍 Verifying Gatekeeper status..."
if spctl -a -vv "$DMG_OUTPUT" 2>&1; then
  echo "✅ Gatekeeper verification passed."
else
  echo "⚠️ Gatekeeper verification had warnings (this may be normal for notarized-only files)."
fi

echo "✅ Notarization complete."

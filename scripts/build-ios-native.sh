#!/usr/bin/env bash
# Build ios/EnigmCryptoNative.xcframework (dynamic) from native/ for device and simulator.
# A dynamic framework keeps its Rust runtime private, so it coexists with any other Rust
# static library linked into the host app. Requires macOS, Xcode and the pinned toolchain.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TOOLCHAIN="${ENIGM_RUST_TOOLCHAIN:-1.99.0}"
CARGO=(cargo "+${TOOLCHAIN}")
export IPHONEOS_DEPLOYMENT_TARGET=15.1
TARGETS=(aarch64-apple-ios aarch64-apple-ios-sim)
NAME=EnigmCryptoNative
VERSION="$(node -p "require('${ROOT}/package.json').version")"
WORK="${ROOT}/native/target/ios-frameworks"
OUT="${ROOT}/ios/${NAME}.xcframework"

rm -rf "${WORK}" "${OUT}"
mkdir -p "${WORK}"
args=()
for target in "${TARGETS[@]}"; do
  "${CARGO[@]}" build --manifest-path "${ROOT}/native/Cargo.toml" --release --locked --lib --target "${target}"
  framework="${WORK}/${target}/${NAME}.framework"
  mkdir -p "${framework}"
  cp "${ROOT}/native/target/${target}/release/libenigm_crypto_native.dylib" "${framework}/${NAME}"
  install_name_tool -id "@rpath/${NAME}.framework/${NAME}" "${framework}/${NAME}"
  cat > "${framework}/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key><string>en</string>
  <key>CFBundleExecutable</key><string>${NAME}</string>
  <key>CFBundleIdentifier</key><string>io.enigm.crypto.native</string>
  <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
  <key>CFBundleName</key><string>${NAME}</string>
  <key>CFBundlePackageType</key><string>FMWK</string>
  <key>CFBundleShortVersionString</key><string>${VERSION}</string>
  <key>CFBundleVersion</key><string>${VERSION}</string>
  <key>MinimumOSVersion</key><string>${IPHONEOS_DEPLOYMENT_TARGET}</string>
</dict>
</plist>
PLIST
  args+=(-framework "${framework}")
done
xcodebuild -create-xcframework "${args[@]}" -output "${OUT}" >/dev/null
echo "Built ${OUT}"

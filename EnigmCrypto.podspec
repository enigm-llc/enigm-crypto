require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

# Native primitive engine for @enigm/crypto (React Native, iOS). Autolinked; the JS library
# selects it automatically and falls back to its JavaScript engine when it is not linked.
Pod::Spec.new do |s|
  s.name         = "EnigmCrypto"
  s.version      = package["version"]
  s.summary      = "Native ML-DSA-65 / ML-KEM-768 / Ed25519 engine for @enigm/crypto"
  s.homepage     = package["homepage"]
  s.license      = package["license"]
  s.authors      = "Enigm"
  s.platforms    = { :ios => "15.1" }
  s.source       = { :git => package["repository"]["url"], :tag => "v#{s.version}" }

  s.source_files = "ios/**/*.{h,mm}", "native/include/*.h"
  s.public_header_files = []
  # Dynamic framework built from native/ (scripts/build-ios-native.sh): its Rust runtime is
  # private to it, so it never collides with another Rust static library in the host app.
  s.vendored_frameworks = "ios/EnigmCryptoNative.xcframework"
  s.pod_target_xcconfig = {
    "HEADER_SEARCH_PATHS" => "\"$(PODS_TARGET_SRCROOT)/native/include\"",
    "CLANG_CXX_LANGUAGE_STANDARD" => "c++20",
  }

  install_modules_dependencies(s)
end

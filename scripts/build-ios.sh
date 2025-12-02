#!/usr/bin/env bash
# Build logos-capability-module for iOS (Simulator and/or Device)
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/build-ios.sh [options]

Options:
  --target <sim|device|all>   Build target (default: all)
  --clean                     Clean build directories before building
  -h, --help                  Show this help text

Environment:
  LOGOS_CPP_SDK_SRC           Path to logos-cpp-sdk source (required)
  LOGOS_LIBLOGOS_SRC          Path to logos-liblogos source (required)
  QT_IOS_PATH                 Path to Qt iOS installation (default: ~/Qt6/6.8.2/ios)
  QT_HOST_PATH                Path to Qt host (macOS) installation (default: ~/Qt6/6.8.2/macos)

Examples:
  ./scripts/build-ios.sh --target sim        # Build for iOS Simulator only
  ./scripts/build-ios.sh --target device     # Build for iOS Device only
  ./scripts/build-ios.sh --target all        # Build for both (default)
USAGE
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Defaults
TARGET="all"
QT_IOS_PATH="${QT_IOS_PATH:-${HOME}/Qt6/6.8.2/ios}"
QT_HOST_PATH="${QT_HOST_PATH:-${HOME}/Qt6/6.8.2/macos}"
CLEAN=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)
      [[ $# -lt 2 ]] && { echo "Missing value for $1" >&2; exit 1; }
      TARGET="$2"
      shift 2
      ;;
    --clean)
      CLEAN=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

# Validate required environment variables (use _SRC for source paths)
# Fall back to _ROOT if _SRC not set (for backwards compatibility)
LOGOS_CPP_SDK="${LOGOS_CPP_SDK_SRC:-${LOGOS_CPP_SDK_ROOT:-}}"
LOGOS_LIBLOGOS="${LOGOS_LIBLOGOS_SRC:-${LOGOS_LIBLOGOS_ROOT:-}}"

if [[ -z "${LOGOS_CPP_SDK}" ]]; then
  echo "Error: LOGOS_CPP_SDK_SRC (or LOGOS_CPP_SDK_ROOT) is not set." >&2
  echo "Please run this script from within 'nix develop' or set the variable manually." >&2
  exit 1
fi

if [[ -z "${LOGOS_LIBLOGOS}" ]]; then
  echo "Error: LOGOS_LIBLOGOS_SRC (or LOGOS_LIBLOGOS_ROOT) is not set." >&2
  echo "Please run this script from within 'nix develop' or set the variable manually." >&2
  exit 1
fi

# Validate target
if [[ "$TARGET" != "sim" && "$TARGET" != "device" && "$TARGET" != "all" ]]; then
  echo "Error: Invalid target '$TARGET'. Must be 'sim', 'device', or 'all'." >&2
  exit 1
fi

# Validate paths
if [[ ! -d "$LOGOS_CPP_SDK" ]]; then
  echo "Error: logos-cpp-sdk not found at $LOGOS_CPP_SDK" >&2
  exit 1
fi

if [[ ! -d "$LOGOS_LIBLOGOS" ]]; then
  echo "Error: logos-liblogos not found at $LOGOS_LIBLOGOS" >&2
  exit 1
fi

if [[ ! -d "$QT_IOS_PATH" ]]; then
  echo "Error: Qt iOS installation not found at $QT_IOS_PATH" >&2
  echo "Please set QT_IOS_PATH environment variable" >&2
  exit 1
fi

if [[ ! -d "$QT_HOST_PATH" ]]; then
  echo "Error: Qt host (macOS) installation not found at $QT_HOST_PATH" >&2
  echo "Please set QT_HOST_PATH environment variable" >&2
  exit 1
fi

QT_CMAKE="${QT_IOS_PATH}/bin/qt-cmake"
if [[ ! -x "$QT_CMAKE" ]]; then
  echo "Error: qt-cmake not found at $QT_CMAKE" >&2
  exit 1
fi

echo "=== logos-capability-module iOS Build Script ==="
echo "Root Dir: ${ROOT_DIR}"
echo "SDK: ${LOGOS_CPP_SDK}"
echo "liblogos: ${LOGOS_LIBLOGOS}"
echo "Qt iOS Path: ${QT_IOS_PATH}"
echo "Qt Host Path: ${QT_HOST_PATH}"
echo "Target: ${TARGET}"
echo ""

build_for_platform() {
  local platform="$1"
  local build_dir=""
  local sdk_name=""
  local arch=""

  if [[ "$platform" == "sim" ]]; then
    build_dir="${ROOT_DIR}/build-ios-sim"
    sdk_name="iphonesimulator"
    arch="x86_64"
    echo "=== Building for iOS Simulator (${arch}) ==="
  else
    build_dir="${ROOT_DIR}/build-ios-device"
    sdk_name="iphoneos"
    arch="arm64"
    echo "=== Building for iOS Device (${arch}) ==="
  fi

  # Override nix environment completely for iOS builds
  export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
  
  # Use Qt's bundled CMake
  local QT_CMAKE_BIN="${HOME}/Qt6/Tools/CMake/CMake.app/Contents/bin"
  export PATH="${QT_CMAKE_BIN}:/usr/bin:/bin:/usr/sbin:/sbin:$DEVELOPER_DIR/usr/bin"
  
  # Unset ALL nix-related environment variables
  unset CC CXX AR LD NM RANLIB STRIP
  unset NIX_CC NIX_CXX NIX_CFLAGS_COMPILE NIX_LDFLAGS
  unset CMAKE_PREFIX_PATH CMAKE_MODULE_PATH CMAKE_FIND_ROOT_PATH CMAKE_SYSTEM_PREFIX_PATH
  unset CMAKE_INCLUDE_PATH CMAKE_LIBRARY_PATH NIXPKGS_CMAKE_PREFIX_PATH
  unset QT_ADDITIONAL_PACKAGES_PREFIX_PATH Qt6_DIR Qt6_ROOT QT_PLUGIN_PATH QT_DIR QTDIR
  unset QMAKE QMAKEPATH PKG_CONFIG_PATH
  
  local sdk_path
  sdk_path=$(/usr/bin/xcrun --sdk "${sdk_name}" --show-sdk-path)
  echo "SDK Path: ${sdk_path}"

  # Clean if requested
  if [[ $CLEAN -eq 1 && -d "$build_dir" ]]; then
    echo "Cleaning ${build_dir}..."
    rm -rf "$build_dir"
  fi

  mkdir -p "$build_dir"
  cd "$build_dir"

  # Configure with qt-cmake using Xcode generator
  echo "Configuring CMake..."
  "${QT_CMAKE}" "${ROOT_DIR}" \
    -G Xcode \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_OSX_SYSROOT="${sdk_path}" \
    -DCMAKE_OSX_ARCHITECTURES="${arch}" \
    -DLOGOS_CPP_SDK_ROOT="${LOGOS_CPP_SDK}" \
    -DLOGOS_LIBLOGOS_ROOT="${LOGOS_LIBLOGOS}" \
    -DQT_HOST_PATH="${QT_HOST_PATH}"

  # Build for the specific SDK/arch using xcodebuild flags
  echo "Building..."
  cmake --build . --config Debug -- -sdk "${sdk_name}" -arch "${arch}"

  echo "Installing to ${build_dir}/install..."
  cmake --install . --prefix "${build_dir}/install" --config Debug

  echo ""
  echo "=== ${platform} build complete ==="
  echo "Static library: ${build_dir}/modules/libcapability_module_plugin.a"
  echo ""
}

# Build requested targets
if [[ "$TARGET" == "sim" || "$TARGET" == "all" ]]; then
  build_for_platform "sim"
fi

if [[ "$TARGET" == "device" || "$TARGET" == "all" ]]; then
  build_for_platform "device"
fi

echo "=== All builds complete ==="

#!/usr/bin/env bash
set -euo pipefail

# Build the example against Qt6 (Homebrew default on Apple Silicon)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build-qt6"

# Override with QT_PREFIX_OVERRIDE if your Qt6 lives elsewhere
QT_PREFIX="${QT_PREFIX_OVERRIDE:-/opt/homebrew/opt/qt}"

if [ ! -d "${QT_PREFIX}" ]; then
  echo "Qt6 prefix not found at: ${QT_PREFIX}" >&2
  echo "Set QT_PREFIX_OVERRIDE to your Qt6 install prefix (e.g., /usr/local/opt/qt)." >&2
  exit 1
fi

cmake -S "${SCRIPT_DIR}" -B "${BUILD_DIR}" \
  -DQT_VERSION_MAJOR=6 \
  -DCMAKE_PREFIX_PATH="${QT_PREFIX}" \
  -DQt6_DIR="${QT_PREFIX}/lib/cmake/Qt6"

cmake --build "${BUILD_DIR}" -j "${JOBS:-8}"

echo "Build complete: ${BUILD_DIR}/plugin_loader"



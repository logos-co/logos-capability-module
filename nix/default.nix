# Common build configuration shared across all packages
{ pkgs, logosSdk, logosModule }:

{
  pname = "logos-capability-module";
  version = "1.0.0";

  # Common native build inputs
  nativeBuildInputs = [
    pkgs.cmake
    pkgs.ninja
    pkgs.pkg-config
    pkgs.qt6.wrapQtAppsNoGuiHook
  ];

  # Common runtime dependencies
  buildInputs = [
    pkgs.qt6.qtbase
    pkgs.qt6.qtremoteobjects
    pkgs.zstd
  ];

  # Common CMake flags
  cmakeFlags = [
    "-GNinja"
    "-DLOGOS_CPP_SDK_ROOT=${logosSdk}"
    "-DLOGOS_MODULE_ROOT=${logosModule}"
    "-DLOGOS_CAPABILITY_MODULE_USE_VENDOR=OFF"
  ];

  # Environment variables
  env = {
    LOGOS_CPP_SDK_ROOT = "${logosSdk}";
    LOGOS_MODULE_ROOT = "${logosModule}";
  };
  
  # Metadata
  meta = with pkgs.lib; {
    description = "Logos Capability Module - Coordinates permissions between modules";
    platforms = platforms.unix;
  };
}


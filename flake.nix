{
  description = "Logos Capability Module - Coordinates permissions between modules";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    logos-cpp-sdk.url = "github:logos-co/logos-cpp-sdk";
    logos-liblogos.url = "github:logos-co/logos-liblogos";
  };

  outputs = { self, nixpkgs, logos-cpp-sdk, logos-liblogos }:
    let
      systems = [ "aarch64-darwin" "x86_64-darwin" "aarch64-linux" "x86_64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f {
        pkgs = import nixpkgs { inherit system; };
        logosSdk = logos-cpp-sdk.packages.${system}.default;
        logosLiblogos = logos-liblogos.packages.${system}.default;
      });
    in
    {
      packages = forAllSystems ({ pkgs, logosSdk, logosLiblogos }: {
        default = pkgs.stdenv.mkDerivation rec {
          pname = "logos-capability-module";
          version = "1.0.0";
          
          src = ./.;
          
          nativeBuildInputs = [ 
            pkgs.cmake 
            pkgs.ninja 
            pkgs.pkg-config
            pkgs.qt6.wrapQtAppsNoGuiHook
          ];
          
          buildInputs = [ 
            pkgs.qt6.qtbase 
            pkgs.qt6.qtremoteobjects 
            logosSdk
            logosLiblogos
          ];
          
          cmakeFlags = [ 
            "-GNinja"
            "-DLOGOS_CPP_SDK_ROOT=${logosSdk}"
            "-DLOGOS_LIBLOGOS_ROOT=${logosLiblogos}"
            "-DLOGOS_CAPABILITY_MODULE_USE_VENDOR=OFF"
            "-DCMAKE_BUILD_TYPE=Release"
          ];
          
          # Set environment variables for CMake to find the dependencies
          LOGOS_CPP_SDK_ROOT = "${logosSdk}";
          LOGOS_LIBLOGOS_ROOT = "${logosLiblogos}";
          
          # Post-install phase to ensure correct file extensions and cross-platform compatibility
          postInstall = ''
            # Find the plugin file and create appropriate symlinks
            PLUGIN_DIR="$out/lib/logos/modules"
            if [ -d "$PLUGIN_DIR" ]; then
              # Find the actual plugin file (could be .so, .dylib, or .dll)
              for plugin_file in "$PLUGIN_DIR"/*; do
                if [ -f "$plugin_file" ]; then
                  plugin_name=$(basename "$plugin_file")
                  plugin_base=$(echo "$plugin_name" | sed 's/\.[^.]*$//')
                  
                  # Create symlinks for cross-platform compatibility
                  case "$plugin_name" in
                    *.so)
                      # Linux .so file - create .dylib symlink for macOS compatibility
                      ln -sf "$plugin_name" "$PLUGIN_DIR/''${plugin_base}.dylib"
                      ;;
                    *.dylib)
                      # macOS .dylib file - create .so symlink for Linux compatibility  
                      ln -sf "$plugin_name" "$PLUGIN_DIR/''${plugin_base}.so"
                      ;;
                    *.dll)
                      # Windows .dll file - create both .so and .dylib symlinks
                      ln -sf "$plugin_name" "$PLUGIN_DIR/''${plugin_base}.so"
                      ln -sf "$plugin_name" "$PLUGIN_DIR/''${plugin_base}.dylib"
                      ;;
                  esac
                fi
              done
            fi
          '';
          
          meta = with pkgs.lib; {
            description = "Logos Capability Module - Coordinates permissions between modules";
            platforms = platforms.unix;
          };
        };
      });

      devShells = forAllSystems ({ pkgs, logosSdk, logosLiblogos }: {
        default = pkgs.mkShell {
          nativeBuildInputs = [
            pkgs.cmake
            pkgs.ninja
            pkgs.pkg-config
          ];
          buildInputs = [
            pkgs.qt6.qtbase
            pkgs.qt6.qtremoteobjects
            logosSdk
            logosLiblogos
          ];
          
          shellHook = ''
            export LOGOS_CPP_SDK_ROOT="${logosSdk}"
            export LOGOS_LIBLOGOS_ROOT="${logosLiblogos}"
            echo "Logos Capability Module development environment"
            echo "LOGOS_CPP_SDK_ROOT: $LOGOS_CPP_SDK_ROOT"
            echo "LOGOS_LIBLOGOS_ROOT: $LOGOS_LIBLOGOS_ROOT"
          '';
        };
      });
    };
}


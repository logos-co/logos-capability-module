{
  description = "Capability Module plugin_loader example";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      systems = [ "aarch64-darwin" "x86_64-darwin" "aarch64-linux" "x86_64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f {
        pkgs = import nixpkgs { inherit system; };
      });
    in
    {
      packages = forAllSystems ({ pkgs }: {
        default = pkgs.stdenv.mkDerivation rec {
          pname = "plugin_loader";
          version = "1.0.0";

          src = ./.;

          nativeBuildInputs = [
            pkgs.cmake
            pkgs.ninja
            pkgs.pkg-config
            pkgs.qt6.wrapQtAppsNoGuiHook
            pkgs.patchelf
          ];

          buildInputs = [
            pkgs.qt6.qtbase
            pkgs.qt6.qtremoteobjects
          ];

          cmakeFlags = [
            "-GNinja"
          ];

          # CMakeLists.txt doesn't define an install() rule, so install manually
          installPhase = ''
            mkdir -p "$out/bin"
            cp -v plugin_loader "$out/bin/"
            # Ship example plugins alongside for easy loading
            if [ -d "${src}/modules" ]; then
              mkdir -p "$out/modules"
              cp -av "${src}/modules/." "$out/modules/"
            fi
          '';

          # Make the binary portable by patching library paths
          postInstall = ''
            # Patch the binary to use system libraries instead of nix store paths
            patchelf --set-interpreter /lib64/ld-linux-x86-64.so.2 "$out/bin/plugin_loader" || \
            patchelf --set-interpreter /lib/ld-linux-aarch64.so.1 "$out/bin/plugin_loader" || true
            
            # Remove nix store rpath and set to use system libraries
            patchelf --remove-rpath "$out/bin/plugin_loader"
            patchelf --set-rpath /lib:/lib64:/usr/lib:/usr/lib64 "$out/bin/plugin_loader"
          '';

          meta = with pkgs.lib; {
            description = "Example Qt-based plugin loader for Logos Capability Module";
            platforms = platforms.unix;
          };
        };
      });

      devShells = forAllSystems ({ pkgs }: {
        default = pkgs.mkShell {
          nativeBuildInputs = [
            pkgs.cmake
            pkgs.ninja
            pkgs.pkg-config
          ];
          buildInputs = [
            pkgs.qt6.qtbase
            pkgs.qt6.qtremoteobjects
          ];
          shellHook = ''
            echo "Capability Module plugin_loader development shell"
          '';
        };
      });
    };
}

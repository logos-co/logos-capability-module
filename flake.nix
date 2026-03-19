{
  description = "Logos Capability Module - Coordinates permissions between modules";

  inputs = {
    logos-nix.url = "github:logos-co/logos-nix";
    nixpkgs.follows = "logos-nix/nixpkgs";
    logos-cpp-sdk.url = "github:logos-co/logos-cpp-sdk";
    logos-module.url = "github:logos-co/logos-module";
  };

  outputs = { self, nixpkgs, logos-nix, logos-cpp-sdk, logos-module }:
    let
      systems = [ "aarch64-darwin" "x86_64-darwin" "aarch64-linux" "x86_64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f {
        pkgs = import nixpkgs { inherit system; };
        logosSdk = logos-cpp-sdk.packages.${system}.default;
        logosModule = logos-module.packages.${system}.default;
      });
    in
    {
      packages = forAllSystems ({ pkgs, logosSdk, logosModule }:
        let
          # Common configuration
          common = import ./nix/default.nix { inherit pkgs logosSdk logosModule; };
          src = ./.;
          
          # Library package
          lib = import ./nix/lib.nix { inherit pkgs common src; };
        in
        {
          # Individual output
          logos-capability-module-lib = lib;
          lib = lib;

          # Default package
          default = lib;
        }
      );

      devShells = forAllSystems ({ pkgs, logosSdk, logosModule }: {
        default = pkgs.mkShell {
          nativeBuildInputs = [
            pkgs.cmake
            pkgs.ninja
            pkgs.pkg-config
          ];
          buildInputs = [
            pkgs.qt6.qtbase
            pkgs.qt6.qtremoteobjects
            pkgs.zstd
          ];
          
          shellHook = ''
            export LOGOS_CPP_SDK_ROOT="${logosSdk}"
            export LOGOS_MODULE_ROOT="${logosModule}"
            echo "Logos Capability Module development environment"
            echo "LOGOS_CPP_SDK_ROOT: $LOGOS_CPP_SDK_ROOT"
            echo "LOGOS_MODULE_ROOT: $LOGOS_MODULE_ROOT"
          '';
        };
      });
    };
}


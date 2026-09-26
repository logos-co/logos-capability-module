{
  description = "Logos Capability Module - Coordinates permissions between modules";

  inputs = {
    # On the in-process builder (logos-module-builder#261) until it and the chain under it merge.
    logos-module-builder.url = "github:logos-co/logos-module-builder/feat/standalone-apps";

    # Cut the builder's logos-standalone-app input, and with it a dependency
    # cycle that this module sits inside:
    #
    #   logos-capability-module -> logos-module-builder -> logos-standalone-app
    #     -> logos-liblogos -> logos-capability-module -> ...
    #
    # flake.lock cannot express a cycle, so Nix unrolls it until the refs reach
    # a fixed point -- 5 repetitions, 23 levels deep -- duplicating the whole
    # subtree at every level. That is what makes the locks in this org enormous:
    # this repo's own lock is 3,391 nodes / 2.4 MB, of which 3,261 are copies.
    #
    # Dropping the input here breaks the loop at its origin: 3,391 -> 130 nodes
    # (0.07 MB), logos-liblogos 3,472 -> 211, logos-basecamp 22,575 -> ~2,300.
    #
    # Safe for THIS module and unsafe to copy blindly: an empty follows path
    # resolves to the root flake, so the builder receives this flake as its
    # `logos-standalone-app`. mkLogosModule only forces that value when
    # `metadata.json#type == "ui"` (lib/mkLogosModule.nix, `resolvedStandalone`),
    # and this is a core module, so it is never touched. Do NOT add this line to
    # a ui/ui_qml module -- mkLogosQmlModule uses `resolvedStandalone`
    # unconditionally and would silently hand the module itself to `nix run`.
    logos-module-builder.inputs.logos-standalone-app.follows = "";
  };

  outputs = inputs@{ logos-module-builder, ... }:
    let
      module = logos-module-builder.lib.mkLogosModule {
        src = ./.;
        configFile = ./metadata.json;
        flakeInputs = inputs;
        tests = {
          dir = ./tests;
        };
      };
      # The same module built as a Qt plugin, for hosts whose tests need a real
      # one (liblogos' Qt-plugin discovery and logos_host_qt load tests).
      qtModule = logos-module-builder.lib.mkLogosModule {
        src = ./.;
        configFile = builtins.toFile "capability-module-qt.json" (builtins.toJSON
          (builtins.removeAttrs (builtins.fromJSON (builtins.readFile ./metadata.json)) [ "transport" ]));
        flakeInputs = inputs;
      };
    in module // {
      checks = module.checks or {};
      packages = builtins.mapAttrs
        (system: packages: packages // { qt-lib = qtModule.packages.${system}.lib; })
        module.packages;
    };
}

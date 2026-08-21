{
  description = "Logos Capability Module - Coordinates permissions between modules";

  inputs = {
    # Plain master, no rev. This module is `interface: "universal"` and declares
    # metadata.json#host_services (token_registry, token_delivery). Both of the
    # things that used to require a branch pin are now on module-builder master:
    #
    #   * parsing and validating metadata.json#host_services — lib/parseMetadata.nix
    #     (its allowlist even names capability_module as the sole module permitted
    #     to ask for the trust-root services), covered by tests/test-parse-metadata.nix
    #   * emitting the cdylib glue with logos-plugin-qt's logos-qt-host-generator
    #     rather than logos-qt-sdk's stale copy — lib/modulePreConfigure.nix,
    #     asserted by tests/test-module-pre-configure.nix
    #
    # module-builder master (8cd62c7) also unpins all four SDK inputs, so this
    # module now resolves the whole B3/B4 closure at master. Those PRs were
    # SQUASH-merged, so the retired rev is correctly NOT an ancestor of master —
    # the files above are the test, not ancestry.
    logos-module-builder.url = "github:logos-co/logos-module-builder";

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
    in module // {
      checks = module.checks or {};
    };
}

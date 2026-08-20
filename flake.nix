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

{
  description = "Logos Capability Module - Coordinates permissions between modules";

  inputs = {
    # Rev-pinned, not branch-head. This module is `interface: "universal"` and
    # declares metadata.json#host_services (token_registry, token_delivery);
    # parsing and validating that key landed in module-builder 85dfb34, and the
    # cdylib glue it needs is only emitted from the maintained generator in
    # logos-plugin-qt since ed50731 — the out-of-repo fix this repo's own C4
    # commit names as its prerequisite. Neither commit is on module-builder's
    # master, so an unpinned url makes `nix flake update` relock onto a builder
    # that cannot build this module at all.
    #
    # c60d4a9 is the tip of feat/sdk-codegen-b4-qt-host-repoint and a
    # fast-forward from master (9ac3a15 is an ancestor of it), so nothing on
    # master is given up. Drop the rev once that branch merges.
    logos-module-builder.url = "github:logos-co/logos-module-builder/c60d4a9cf32cb5281909e53159c9c4cfeb993847";
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

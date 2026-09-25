# Logos Capability Module

The runtime's token authority. liblogos loads it in-process, from its bundled modules,
and admits every module, shell and UI plugin through its engine interface
(`src/logos_capability_engine.h`). It mints and records their credentials, and hands out
the per-pair tokens modules call each other with (`requestModule`).

Built with [`logos-module-builder`](https://github.com/logos-co/logos-module-builder). The implementation is a plain **Qt-free** C++ class deriving `LogosModuleContext` — no `Q_OBJECT` / `Q_INVOKABLE` boilerplate, and no dispatch marker either: its public methods *are* its API. `metadata.json` declares `interface: "universal"`, so the builder derives the contract from the impl header named by `codegen.impl_header` and generates every piece of framework plumbing — the LIDL contract, the Qt plugin glue, the C-ABI exports, packaging.

This README used to describe two earlier shapes, so for orientation: the module was
`interface: "provider"` (a `LogosProviderBase` subclass whose API methods carried a
`LOGOS_METHOD` marker — neither the base class nor the marker exists any more) up to 22e54ff,
then a handcrafted `interface: "legacy"` Qt plugin with `Q_OBJECT` / `Q_INVOKABLE` methods,
and finally `universal` as of fc39b1b. See `docs/docs.md` for the current three-step pipeline.

## Build

```bash
nix build              # produces result/lib/capability_module_plugin.{dylib,so}
nix build .#lgx        # builds the .lgx package
nix build .#unit-tests # builds the test binary
nix build .#qt-lib     # the same source as a Qt plugin (see below)
```

`qt-lib` exists as a real Qt plugin for hosts' tests (liblogos' `TEST_PLUGIN`). A hosted
capability_module is never the token authority: liblogos runs capability only in-process, and
a hosted one refuses every `requestModule`, since the runtime admits nothing through it.

To enter a development shell:

```bash
nix develop
```

## Test

```bash
nix flake check                                                 # runs all checks
nix build .#checks.<system>.unit-tests -L                       # builds + runs tests
./result/bin/capability_module_tests                            # run the binary directly
./result/bin/capability_module_tests --filter requestModule     # filter by name
```

## Layout

```
src/
├── capability_module_impl.{h,cpp}   # CapabilityModuleImpl : LogosModuleContext — the one
│                                    # dispatchable method, requestModule
├── capability_authority.{h,cpp}     # the store of record: admissions, pair tokens,
│                                    # restrictions, revocation pushes
└── logos_capability_engine.h        # the engine interface liblogos calls in-process
tests/
├── CMakeLists.txt
├── main.cpp
├── test_capability_authority.cpp    # the engine interface
└── test_capability_module.cpp       # requestModule
docs/docs.md                         # module specification
doctests/                            # end-to-end composition doc-test
metadata.json                        # interface: universal; codegen.{impl_class,impl_header};
                                     # host_services; nix.* build config
flake.nix                            # logos-module-builder, calls mkLogosModule (twice: qt-lib)
CMakeLists.txt                       # calls logos_module()
```

There is no hand-written plugin loader and no committed contract: the builder derives the
LIDL from the impl header, and the plugin entry point is generated into `generated_code/`,
which is not checked in.

## Dependencies

- [logos-module-builder](https://github.com/logos-co/logos-module-builder) — pulls in `logos-cpp-sdk`, `logos-module`, `logos-test-framework`, and Qt6 (Core + RemoteObjects).

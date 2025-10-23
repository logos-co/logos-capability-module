# Logos Capability Module

Coordinates permissions and capabilities between Logos modules.

## Building with Nix (Recommended)

### Build the module
```bash
nix build
```

This will create a `result` symlink with the following structure:
```
result/
└── lib/
    └── capability_module_plugin.dylib  (or .so on Linux)
```

### Enter development shell
```bash
nix develop
```

### Build manually in development shell
```bash
nix develop
mkdir build && cd build
cmake -GNinja ..
ninja
```

## Building with CMake

If you don't want to use Nix, you can build directly with CMake:

```bash
mkdir build && cd build
cmake -GNinja \
  -DLOGOS_CPP_SDK_ROOT=/path/to/logos-cpp-sdk \
  -DLOGOS_LIBLOGOS_ROOT=/path/to/logos-liblogos \
  ..
ninja
```

## Dependencies

- [logos-cpp-sdk](https://github.com/logos-co/logos-cpp-sdk) - Logos C++ SDK and code generator
- [logos-liblogos](https://github.com/logos-co/logos-liblogos) - Logos core library
- Qt6 (Core and RemoteObjects)

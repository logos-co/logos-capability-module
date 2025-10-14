# Docker/Podman Support for Logos Capability Module Example

This directory contains a Dockerfile that allows you to run the logos-capability-module example in a container using Docker or Podman.

## Prerequisites

- Docker or Podman installed
- The nix build system (for building the container)

## Building the Container

### Using Podman (recommended)
```bash
podman build -t logos-capability-example .
```

### Using Docker
```bash
docker build -t logos-capability-example .
```

## Running the Container

### Basic usage (show help)
```bash
podman run --rm logos-capability-example
```

### Run with a plugin
```bash
# Mount your plugin directory and specify the plugin path
podman run --rm -v /path/to/your/plugins:/plugins logos-capability-example --path /plugins/your_plugin.dylib
```

### Interactive mode
```bash
podman run --rm -it logos-capability-example /bin/bash
```

## Container Details

- **Base Image**: Ubuntu 22.04 (runtime), NixOS/nix (builder)
- **User**: Non-root user `logos` for security
- **Application**: `/usr/local/bin/plugin_loader`
- **Plugin Directory**: `/usr/local/lib/logos/modules/`
- **Working Directory**: `/home/logos`

## Environment Variables

- `PATH`: Includes `/usr/local/bin`
- `QT_PLUGIN_PATH`: Points to `/usr/local/lib/logos/modules`

## Security Notes

- The container runs as a non-root user (`logos`)
- Minimal runtime dependencies are installed
- Source code is not included in the final image

## Troubleshooting

If you encounter issues:

1. **Permission errors**: Ensure the container has access to mounted plugin directories
2. **Plugin loading issues**: Check that the plugin architecture matches the container (Linux x86_64)
3. **Missing dependencies**: The container includes minimal Qt runtime dependencies

## Development

To modify the Dockerfile:

1. Edit `Dockerfile` in this directory
2. Rebuild the container: `podman build -t logos-capability-example .`
3. Test your changes: `podman run --rm logos-capability-example --help`

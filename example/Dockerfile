# Multi-stage Dockerfile for logos-capability-module example
# This Dockerfile builds the nix package and creates a minimal runtime image

# Stage 1: Build with Nix
FROM nixos/nix:2.18.1 AS builder

# Install git and other build dependencies
RUN nix-env -iA nixpkgs.git nixpkgs.cacert

# Set up nix configuration for flakes
RUN mkdir -p /etc/nix && \
    echo "experimental-features = nix-command flakes" >> /etc/nix/nix.conf

# Copy the source code
WORKDIR /build
COPY . .

# Build the nix package
RUN nix build .#default --out-link result

# Stage 2: Runtime image - use Ubuntu to test portability
FROM ubuntu:22.04 AS runtime

# Install minimal runtime dependencies including Qt libraries
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libc6 \
        libstdc++6 \
        libgcc-s1 \
        libqt6core6 \
        libqt6network6 \
        libqt6remoteobjects6 \
        ca-certificates \
        && \
    rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN useradd -m -s /bin/bash logos

# Copy the built application from the builder stage
COPY --from=builder /build/result/bin/plugin_loader /usr/local/bin/plugin_loader
COPY --from=builder /build/result/modules/ /usr/local/lib/logos/modules/

# Set proper permissions
RUN chmod +x /usr/local/bin/plugin_loader && \
    chown -R logos:logos /usr/local/lib/logos/

# Switch to non-root user
USER logos
WORKDIR /home/logos

# Set environment variables
ENV PATH="/usr/local/bin:${PATH}"
ENV QT_PLUGIN_PATH="/usr/local/lib/logos/modules"

# Default command - show help
CMD ["plugin_loader", "--help"]

# Example usage:
# Build: podman build -t logos-capability-example .
# Run: podman run --rm logos-capability-example
# Run with plugin: podman run --rm -v /path/to/plugin:/plugin logos-capability-example --path /plugin/your_plugin.dylib

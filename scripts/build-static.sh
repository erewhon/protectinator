#!/bin/bash
# Build statically linked binary for protectinator
#
# Usage:
#   ./scripts/build-static.sh              # Build for current platform
#   ./scripts/build-static.sh linux-x64    # Build for Linux x86_64
#   ./scripts/build-static.sh linux-arm64  # Build for Linux aarch64
#   ./scripts/build-static.sh macos-x64    # Build for macOS x86_64
#   ./scripts/build-static.sh macos-arm64  # Build for macOS aarch64

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_ROOT"

# Detect current platform
detect_platform() {
    local os=$(uname -s)
    local arch=$(uname -m)

    case "$os" in
        Linux)
            case "$arch" in
                x86_64) echo "linux-x64" ;;
                aarch64) echo "linux-arm64" ;;
                *) echo "unsupported" ;;
            esac
            ;;
        Darwin)
            case "$arch" in
                x86_64) echo "macos-x64" ;;
                arm64) echo "macos-arm64" ;;
                *) echo "unsupported" ;;
            esac
            ;;
        *)
            echo "unsupported"
            ;;
    esac
}

# Get target triple for platform
get_target() {
    case "$1" in
        linux-x64)   echo "x86_64-unknown-linux-musl" ;;
        linux-arm64) echo "aarch64-unknown-linux-musl" ;;
        macos-x64)   echo "x86_64-apple-darwin" ;;
        macos-arm64) echo "aarch64-apple-darwin" ;;
        *)           echo "" ;;
    esac
}

# Ensure target is installed
ensure_target() {
    local target="$1"
    if ! rustup target list --installed | grep -q "^$target\$"; then
        echo "Installing target: $target"
        rustup target add "$target"
    fi
}

# Build the binary
build() {
    local platform="$1"
    local target=$(get_target "$platform")

    if [ -z "$target" ]; then
        echo "Error: Unsupported platform: $platform"
        echo "Supported platforms: linux-x64, linux-arm64, macos-x64, macos-arm64"
        exit 1
    fi

    echo "Building protectinator for $platform ($target)"
    echo "================================================"

    ensure_target "$target"

    # Build with release profile
    cargo build --release --target "$target" -p protectinator

    # Get output path
    local binary_name="protectinator"
    local output_dir="$PROJECT_ROOT/target/$target/release"
    local output_path="$output_dir/$binary_name"

    if [ ! -f "$output_path" ]; then
        echo "Error: Build failed - binary not found at $output_path"
        exit 1
    fi

    # Show binary info
    echo ""
    echo "Build successful!"
    echo "Binary: $output_path"
    echo "Size: $(du -h "$output_path" | cut -f1)"

    # Check if statically linked (Linux only)
    if [[ "$platform" == linux-* ]]; then
        echo ""
        echo "Checking linking:"
        if ldd "$output_path" 2>&1 | grep -q "not a dynamic executable\|statically linked"; then
            echo "  Statically linked"
        else
            echo "  Dynamic dependencies:"
            ldd "$output_path" 2>&1 | sed 's/^/    /'
        fi
    fi

    # Copy to dist directory
    local dist_dir="$PROJECT_ROOT/dist"
    mkdir -p "$dist_dir"

    local dist_name="protectinator-$platform"
    cp "$output_path" "$dist_dir/$dist_name"

    echo ""
    echo "Copied to: $dist_dir/$dist_name"
}

# Main
PLATFORM="${1:-$(detect_platform)}"

if [ "$PLATFORM" = "unsupported" ]; then
    echo "Error: Could not detect platform. Please specify one of:"
    echo "  linux-x64, linux-arm64, macos-x64, macos-arm64"
    exit 1
fi

build "$PLATFORM"

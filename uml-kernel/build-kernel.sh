#!/bin/bash
# UML Kernel Build Script for Pinchy Integration Tests
#
# This script clones and builds a User Mode Linux kernel with eBPF support
# for use in rootless, parallel integration testing.
#
# The kernel source is from the ARM64 UML port at:
#   https://github.com/kov/linux/tree/arm64-uml
#
# Usage: ./build-kernel.sh [arch]
#   arch: x86_64 or aarch64 (default: auto-detect from uname -m)

set -euo pipefail

# Configuration
KERNEL_GIT_URL="https://github.com/kov/linux.git"
KERNEL_GIT_BRANCH="arm64-uml"
KERNEL_GIT_COMMIT="f391975cd33f19c3da5cc58c217818af41ee3ec9"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CACHE_DIR="${SCRIPT_DIR}/cache"
KERNEL_SRC_DIR="${CACHE_DIR}/linux"

# Detect architecture
ARCH="${1:-$(uname -m)}"

# Map architecture names
case "${ARCH}" in
    x86_64|amd64)
        ARCH="x86_64"
        UML_SUBARCH="x86_64"
        ;;
    aarch64|arm64)
        ARCH="aarch64"
        UML_SUBARCH="arm64"
        ;;
    *)
        echo "Error: Unsupported architecture: ${ARCH}" >&2
        echo "Supported: x86_64, aarch64" >&2
        exit 1
        ;;
esac

CONFIG_FILE="${SCRIPT_DIR}/config-${ARCH}"
OUTPUT_KERNEL="${CACHE_DIR}/linux-${ARCH}"

echo "========================================"
echo "UML Kernel Build Script"
echo "========================================"
echo "Git repository: ${KERNEL_GIT_URL}"
echo "Git branch:     ${KERNEL_GIT_BRANCH}"
echo "Architecture:   ${ARCH} (SUBARCH=${UML_SUBARCH})"
echo "Config file:    ${CONFIG_FILE}"
echo "Output:         ${OUTPUT_KERNEL}"
echo "========================================"
echo

# Check prerequisites
check_prerequisites() {
    local missing=()

    for cmd in make gcc bc bison flex git; do
        if ! command -v "${cmd}" &> /dev/null; then
            missing+=("${cmd}")
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        echo "Error: Missing required tools: ${missing[*]}" >&2
        echo "" >&2
        echo "Please install them with:" >&2
        echo "  Ubuntu/Debian: sudo apt-get install build-essential bc bison flex git" >&2
        echo "  Fedora:        sudo dnf install gcc make bc bison flex git" >&2
        echo "  Arch:          sudo pacman -S base-devel bc bison flex git" >&2
        exit 1
    fi

    if [ ! -f "${CONFIG_FILE}" ]; then
        echo "Error: Kernel config not found: ${CONFIG_FILE}" >&2
        exit 1
    fi
}

# Clone or update kernel source
clone_kernel() {
    mkdir -p "${CACHE_DIR}"

    if [ -d "${KERNEL_SRC_DIR}/.git" ]; then
        local current_commit
        current_commit="$(git -C "${KERNEL_SRC_DIR}" rev-parse HEAD)"

        if [ "${current_commit}" = "${KERNEL_GIT_COMMIT}" ]; then
            echo "[✓] Repository already at pinned commit ${KERNEL_GIT_COMMIT}"
            return 0
        fi

        echo "[→] Updating existing kernel repository..."
        git -C "${KERNEL_SRC_DIR}" fetch origin "${KERNEL_GIT_BRANCH}"
        git -C "${KERNEL_SRC_DIR}" checkout "${KERNEL_GIT_COMMIT}"

        echo "[✓] Repository updated"
        return 0
    fi

    echo "[→] Cloning Linux kernel with ARM64 UML support..."
    echo "    Repository: ${KERNEL_GIT_URL}"
    echo "    Branch:     ${KERNEL_GIT_BRANCH}"
    echo "    Commit:     ${KERNEL_GIT_COMMIT}"

    git clone --branch "${KERNEL_GIT_BRANCH}" "${KERNEL_GIT_URL}" "${KERNEL_SRC_DIR}"
    git -C "${KERNEL_SRC_DIR}" checkout "${KERNEL_GIT_COMMIT}"

    echo "[✓] Clone complete"
}

# Configure kernel
configure_kernel() {
    echo "[→] Configuring kernel with pinchy config..."
    cp "${CONFIG_FILE}" "${KERNEL_SRC_DIR}/.config"

    make -C "${KERNEL_SRC_DIR}" ARCH=um SUBARCH="${UML_SUBARCH}" olddefconfig

    echo "[✓] Kernel configured"
}

# Build kernel
build_kernel() {
    local num_cores
    num_cores="$(nproc)"

    echo "[→] Building UML kernel..."
    echo "    Using ${num_cores} parallel jobs"
    echo

    local start_time
    start_time="$(date +%s)"

    make -C "${KERNEL_SRC_DIR}" ARCH=um SUBARCH="${UML_SUBARCH}" -j"${num_cores}"

    local end_time
    end_time="$(date +%s)"
    local duration=$((end_time - start_time))

    echo
    echo "[✓] Kernel built successfully in ${duration} seconds"
}

# Install kernel
install_kernel() {
    echo "[→] Installing kernel to ${OUTPUT_KERNEL}..."

    mkdir -p "${CACHE_DIR}"

    # The UML kernel binary is in the root of the source tree
    if [ -f "${KERNEL_SRC_DIR}/linux" ]; then
        cp "${KERNEL_SRC_DIR}/linux" "${OUTPUT_KERNEL}"
        chmod +x "${OUTPUT_KERNEL}"
    else
        echo "Error: Kernel binary not found at ${KERNEL_SRC_DIR}/linux" >&2
        exit 1
    fi

    local kernel_size
    kernel_size="$(du -h "${OUTPUT_KERNEL}" | cut -f1)"

    echo "[✓] Kernel installed successfully"
    echo "    Size: ${kernel_size}"
    echo "    Location: ${OUTPUT_KERNEL}"
}

# Main execution
main() {
    check_prerequisites
    clone_kernel
    configure_kernel
    build_kernel
    install_kernel

    local kernel_version
    kernel_version="$(strings "${OUTPUT_KERNEL}" | grep -m1 "Linux version" || echo "unknown")"

    echo
    echo "========================================"
    echo "[✓] Build complete!"
    echo "========================================"
    echo
    echo "Kernel location: ${OUTPUT_KERNEL}"
    echo "Kernel version:  ${kernel_version}"
    echo
    echo "To test the kernel manually:"
    echo "  ${OUTPUT_KERNEL} mem=512M root=/dev/root rootfstype=hostfs hostfs=/ init=/bin/sh"
    echo
}

main "$@"

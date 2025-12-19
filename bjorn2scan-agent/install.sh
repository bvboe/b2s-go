#!/bin/sh
set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Constants
BINARY_NAME="bjorn2scan-agent"
SERVICE_NAME="bjorn2scan-agent.service"
INSTALL_DIR="/usr/local/bin"
SERVICE_DIR="/etc/systemd/system"
CONFIG_DIR="/etc/bjorn2scan"
CONFIG_FILE="${CONFIG_DIR}/agent.conf"
CONFIG_EXAMPLE="${CONFIG_DIR}/agent.conf.example"
USER_NAME="bjorn2scan"
GROUP_NAME="bjorn2scan"
GITHUB_REPO="bvboe/b2s-go"

# Helper functions
log_info() { printf "${BLUE}[INFO]${NC} %s\n" "$1" >&2; }
log_success() { printf "${GREEN}[SUCCESS]${NC} %s\n" "$1" >&2; }
log_error() { printf "${RED}[ERROR]${NC} %s\n" "$1" >&2; }
log_warning() { printf "${YELLOW}[WARNING]${NC} %s\n" "$1" >&2; }

# Show help
show_help() {
    cat << EOF
bjorn2scan-agent installer

DESCRIPTION:
    Installs bjorn2scan-agent, a lightweight host-level security scanning agent
    for the Bjorn2Scan v2 platform.

USAGE:
    # Install
    curl -sSfL https://raw.githubusercontent.com/${GITHUB_REPO}/main/bjorn2scan-agent/install.sh | sudo sh

    # Uninstall
    curl -sSfL https://raw.githubusercontent.com/${GITHUB_REPO}/main/bjorn2scan-agent/install.sh | sudo sh -s uninstall

    # Show help (download first)
    curl -sSfL https://raw.githubusercontent.com/${GITHUB_REPO}/main/bjorn2scan-agent/install.sh -o install.sh
    sh install.sh --help

WHAT IT DOES:
    - Detects your OS and architecture (Linux amd64/arm64 only)
    - Downloads the latest release binary from GitHub
    - Verifies checksum for security
    - Installs binary to ${INSTALL_DIR}
    - Creates systemd service for auto-start
    - Starts the agent on port 9999

DIRECTORIES USED:
    ${INSTALL_DIR}             - Binary installation location
    /etc/systemd/system        - Systemd service file
    /etc/bjorn2scan            - Configuration files
    /var/lib/bjorn2scan        - Data directory (database)
    /var/log/bjorn2scan        - Log files
    /etc/logrotate.d           - Logrotate configuration
    /tmp/bjorn2scan-*          - Temporary download directory (auto-cleaned)

REQUIREMENTS:
    - Linux operating system (Ubuntu, Debian, RHEL, etc.)
    - systemd (for service management)
    - curl or wget
    - Root/sudo access

ENDPOINTS:
    Once installed, the agent exposes:
    - http://localhost:9999/health  - Health check
    - http://localhost:9999/info    - System information

USEFUL COMMANDS:
    systemctl status ${SERVICE_NAME}   - Check status
    systemctl restart ${SERVICE_NAME}  - Restart service
    journalctl -u ${SERVICE_NAME} -f   - View logs

MORE INFO:
    https://github.com/${GITHUB_REPO}

EOF
    exit 0
}

# Check if running as root
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_error "This script must be run as root"
        log_info "Try: curl -sSfL https://raw.githubusercontent.com/${GITHUB_REPO}/main/bjorn2scan-agent/install.sh | sudo sh"
        exit 1
    fi
}

# Detect OS
detect_os() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    case "$OS" in
        linux) OS="linux" ;;
        *) log_error "Unsupported OS: $OS (only Linux is supported)"; exit 1 ;;
    esac
    log_info "Detected OS: $OS"
}

# Detect architecture
detect_arch() {
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        *) log_error "Unsupported architecture: $ARCH"; exit 1 ;;
    esac
    log_info "Detected architecture: $ARCH"
}

# Detect Linux distribution (for systemd check)
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO="$ID"
        DISTRO_VERSION="$VERSION_ID"
        log_info "Detected distribution: $DISTRO $DISTRO_VERSION"
    else
        log_warning "Could not detect Linux distribution"
    fi
}

# Check for systemd
check_systemd() {
    if ! command -v systemctl >/dev/null 2>&1; then
        log_warning "Systemd not found - service will not be installed"
        return 1
    fi
    return 0
}

# Get latest version from GitHub
get_latest_version() {
    log_info "Fetching latest version..."

    if command -v curl >/dev/null 2>&1; then
        VERSION=$(curl -sSfL "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/')
    elif command -v wget >/dev/null 2>&1; then
        VERSION=$(wget -qO- "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/')
    else
        log_error "Neither curl nor wget found. Please install one of them."
        exit 1
    fi

    if [ -z "$VERSION" ]; then
        log_error "Failed to get latest version"
        exit 1
    fi

    log_success "Latest version: $VERSION"
}

# Download binary
download_binary() {
    DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/download/v${VERSION}/${BINARY_NAME}-${OS}-${ARCH}.tar.gz"
    CHECKSUM_URL="${DOWNLOAD_URL}.sha256"

    log_info "Downloading from: $DOWNLOAD_URL"

    TMP_DIR=$(mktemp -d)
    cd "$TMP_DIR"

    if command -v curl >/dev/null 2>&1; then
        curl -sSfL "$DOWNLOAD_URL" -o "${BINARY_NAME}-${OS}-${ARCH}.tar.gz"
        curl -sSfL "$CHECKSUM_URL" -o "${BINARY_NAME}-${OS}-${ARCH}.tar.gz.sha256"
    else
        wget -q "$DOWNLOAD_URL" -O "${BINARY_NAME}-${OS}-${ARCH}.tar.gz"
        wget -q "$CHECKSUM_URL" -O "${BINARY_NAME}-${OS}-${ARCH}.tar.gz.sha256"
    fi

    log_success "Download complete"
}

# Verify checksum
verify_checksum() {
    log_info "Verifying checksum..."

    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum -c "${BINARY_NAME}-${OS}-${ARCH}.tar.gz.sha256"
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 -c "${BINARY_NAME}-${OS}-${ARCH}.tar.gz.sha256"
    else
        log_warning "No checksum tool found, skipping verification"
        return
    fi

    log_success "Checksum verified"
}

# Extract binary
extract_binary() {
    log_info "Extracting binary..."
    tar -xzf "${BINARY_NAME}-${OS}-${ARCH}.tar.gz"
    log_success "Extraction complete"
}

# Stop existing service
stop_service() {
    if check_systemd && systemctl is-active --quiet "$SERVICE_NAME"; then
        log_info "Stopping existing service..."
        systemctl stop "$SERVICE_NAME"
        log_success "Service stopped"
    fi
}

# Create user and group
create_user() {
    if ! getent group "$GROUP_NAME" >/dev/null 2>&1; then
        log_info "Creating group: $GROUP_NAME"
        groupadd --system "$GROUP_NAME"
    fi

    if ! getent passwd "$USER_NAME" >/dev/null 2>&1; then
        log_info "Creating user: $USER_NAME"
        useradd --system --gid "$GROUP_NAME" --no-create-home --shell /bin/false "$USER_NAME"
    fi
}

# Install binary
install_binary() {
    log_info "Installing binary to $INSTALL_DIR..."

    install -m 755 "${BINARY_NAME}-${OS}-${ARCH}" "${INSTALL_DIR}/${BINARY_NAME}"

    log_success "Binary installed"
}

# Install configuration file
install_config() {
    log_info "Installing configuration file..."

    # Create config directory
    mkdir -p "$CONFIG_DIR"

    # Always install/update the example config
    CONFIG_EXAMPLE_URL="https://raw.githubusercontent.com/${GITHUB_REPO}/main/bjorn2scan-agent/agent.conf.example"

    if command -v curl >/dev/null 2>&1; then
        curl -sSfL "$CONFIG_EXAMPLE_URL" -o "$CONFIG_EXAMPLE" 2>/dev/null || \
            log_warning "Could not download example config (will use defaults)"
    else
        wget -q "$CONFIG_EXAMPLE_URL" -O "$CONFIG_EXAMPLE" 2>/dev/null || \
            log_warning "Could not download example config (will use defaults)"
    fi

    # Check if user config already exists
    if [ -f "$CONFIG_FILE" ]; then
        log_warning "Configuration file exists at $CONFIG_FILE"
        log_info "Preserving existing configuration"
        log_info "See $CONFIG_EXAMPLE for new configuration options"

        # Show what's different (if diff exists)
        if command -v diff >/dev/null 2>&1 && [ -f "$CONFIG_EXAMPLE" ]; then
            echo ""
            log_info "Configuration changes in this version:"
            if diff -u "$CONFIG_FILE" "$CONFIG_EXAMPLE" 2>/dev/null | grep '^[+-]' | grep -v '^[+-][+-][+-]' | head -20; then
                :
            else
                log_info "No new configuration options detected"
            fi
            echo ""
        fi
    else
        # Fresh install - copy example to active config
        if [ -f "$CONFIG_EXAMPLE" ]; then
            cp "$CONFIG_EXAMPLE" "$CONFIG_FILE"
            log_success "Configuration file created at $CONFIG_FILE"
            log_info "Edit this file to customize settings (port, paths, debug mode, etc.)"
        else
            log_warning "Using built-in defaults (no config file created)"
        fi
    fi

    # Set permissions
    if [ -f "$CONFIG_FILE" ]; then
        chmod 644 "$CONFIG_FILE"
    fi
    if [ -f "$CONFIG_EXAMPLE" ]; then
        chmod 644 "$CONFIG_EXAMPLE"
    fi
}

# Get systemd version
get_systemd_version() {
    systemctl --version | head -n 1 | awk '{print $2}'
}

# Install systemd service
install_service() {
    if ! check_systemd; then
        log_warning "Skipping service installation"
        return
    fi

    log_info "Installing systemd service..."

    # Check systemd version and choose appropriate service file
    SYSTEMD_VERSION=$(get_systemd_version)
    SERVICE_FILE="bjorn2scan-agent.service"

    if [ "$SYSTEMD_VERSION" -lt 232 ]; then
        log_warning "Old systemd detected (v$SYSTEMD_VERSION), using compatibility mode"
        SERVICE_FILE="bjorn2scan-agent-compat.service"
    fi

    # Download service file
    SERVICE_URL="https://raw.githubusercontent.com/${GITHUB_REPO}/main/bjorn2scan-agent/${SERVICE_FILE}"

    if command -v curl >/dev/null 2>&1; then
        curl -sSfL "$SERVICE_URL" -o "${SERVICE_DIR}/${SERVICE_NAME}"
    else
        wget -q "$SERVICE_URL" -O "${SERVICE_DIR}/${SERVICE_NAME}"
    fi

    # Create required directories for the service
    # Note: Service runs as root, but these directories need to exist for systemd mount namespacing
    mkdir -p /var/lib/bjorn2scan
    mkdir -p /var/log/bjorn2scan
    chmod 755 /var/lib/bjorn2scan /var/log/bjorn2scan

    # Install logrotate configuration
    LOGROTATE_URL="https://raw.githubusercontent.com/${GITHUB_REPO}/main/bjorn2scan-agent/logrotate.conf"
    if command -v curl >/dev/null 2>&1; then
        curl -sSfL "$LOGROTATE_URL" -o /etc/logrotate.d/bjorn2scan-agent 2>/dev/null || log_warning "Could not install logrotate config"
    else
        wget -q "$LOGROTATE_URL" -O /etc/logrotate.d/bjorn2scan-agent 2>/dev/null || log_warning "Could not install logrotate config"
    fi

    # Reload systemd
    systemctl daemon-reload

    log_success "Service installed"
}

# Enable and start service
enable_service() {
    if ! check_systemd; then
        return
    fi

    log_info "Enabling service..."
    systemctl enable "$SERVICE_NAME"

    log_info "Starting service..."
    systemctl start "$SERVICE_NAME"

    sleep 2

    if systemctl is-active --quiet "$SERVICE_NAME"; then
        log_success "Service is running"
    else
        log_error "Service failed to start"
        log_info "Check logs: journalctl -u $SERVICE_NAME"
        exit 1
    fi
}

# Show installation summary
show_summary() {
    echo ""
    echo "======================================"
    echo "Installation Summary"
    echo "======================================"
    log_success "bjorn2scan-agent v${VERSION} installed successfully!"
    echo ""
    echo "Installed files and directories:"
    echo "  Binary:    ${INSTALL_DIR}/${BINARY_NAME}"
    echo "  Config:    ${CONFIG_FILE}"
    echo "  Example:   ${CONFIG_EXAMPLE}"
    echo "  Data:      /var/lib/bjorn2scan"
    echo "  Logs:      /var/log/bjorn2scan"

    if check_systemd; then
        echo "  Service:   ${SERVICE_DIR}/${SERVICE_NAME}"
        echo "  Logrotate: /etc/logrotate.d/bjorn2scan-agent"
        echo ""
        echo "Useful commands:"
        echo "  Status:  systemctl status $SERVICE_NAME"
        echo "  Logs:    journalctl -u $SERVICE_NAME -f"
        echo "  Stop:    systemctl stop $SERVICE_NAME"
        echo "  Start:   systemctl start $SERVICE_NAME"
        echo "  Restart: systemctl restart $SERVICE_NAME"
    else
        echo ""
        echo "Run manually: ${BINARY_NAME}"
    fi

    echo ""
    echo "Test endpoints:"
    echo "  curl http://localhost:9999/health"
    echo "  curl http://localhost:9999/info"
    echo "======================================"
}

# Show directories that will be used
show_directories() {
    log_info "Directories that will be used:"
    echo "  Binary:         ${INSTALL_DIR}/${BINARY_NAME}"
    echo "  Config:         ${CONFIG_FILE}"
    echo "  Config example: ${CONFIG_EXAMPLE}"
    echo "  Systemd:        ${SERVICE_DIR}/${SERVICE_NAME}"
    echo "  Data:           /var/lib/bjorn2scan"
    echo "  Logs:           /var/log/bjorn2scan"
    echo "  Logrotate:      /etc/logrotate.d/bjorn2scan-agent"
    echo "  Temp download:  \$TMPDIR (auto-cleaned)"
    echo ""
}

# Main installation flow
main() {
    log_info "Starting bjorn2scan-agent installation..."
    echo ""

    check_root
    detect_os
    detect_arch
    detect_distro
    show_directories
    get_latest_version
    download_binary
    verify_checksum
    extract_binary
    stop_service
    create_user
    install_binary
    install_config
    install_service
    enable_service

    # Cleanup
    cd /
    rm -rf "$TMP_DIR"

    show_summary
}

# Handle uninstall
uninstall() {
    log_info "Uninstalling bjorn2scan-agent..."

    check_root

    if check_systemd && systemctl is-active --quiet "$SERVICE_NAME"; then
        systemctl stop "$SERVICE_NAME"
        systemctl disable "$SERVICE_NAME"
        rm -f "${SERVICE_DIR}/${SERVICE_NAME}"
        systemctl daemon-reload
    fi

    rm -f "${INSTALL_DIR}/${BINARY_NAME}"
    rm -f /etc/logrotate.d/bjorn2scan-agent

    log_success "Uninstall complete"
}

# Parse arguments
case "$1" in
    --help|-h|help)
        show_help
        ;;
    uninstall)
        uninstall
        ;;
    *)
        main
        ;;
esac

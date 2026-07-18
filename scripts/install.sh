#!/bin/bash
# ==============================================================================
# NovaSec installation script for Kali Linux.
# Installs core external dependencies and configures poetry virtualenv.
# ==============================================================================

set -e

echo "🛡️  NovaSec Installer for Kali Linux"
echo "-----------------------------------"

# 1. Update packages and install system requirements
echo "[*] Installing Kali Linux system packages..."
sudo apt update
sudo apt install -y python3.12 python3-pip pipx nmap nikto ffuf nuclei git build-essential

# 2. Check if poetry is installed
if ! command -v poetry &> /dev/null; then
    echo "[*] Installing Poetry..."
    curl -sSL https://install.python-poetry.org | python3 -
    export PATH="$HOME/.local/bin:$PATH"
fi

# 3. Setup Virtual Environment and Poetry dependencies
echo "[*] Installing NovaSec project dependencies via Poetry..."
poetry install

echo "[*] Setting up default configuration workspace..."
mkdir -p ~/.novasec/logs
mkdir -p ~/.novasec/plugins
mkdir -p ~/.novasec/profiles

cp -r config/* ~/.novasec/

echo "-----------------------------------"
echo "✅ NovaSec framework successfully installed!"
echo "Run using: poetry run novasec --help"

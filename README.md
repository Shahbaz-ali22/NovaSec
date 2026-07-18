# NovaSec 🛡️

<div align="center">

![NovaSec Banner](https://img.shields.io/badge/NovaSec-v1.0.0-blue?style=for-the-badge&logo=shield)
![Python](https://img.shields.io/badge/Python-3.12+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Kali Linux](https://img.shields.io/badge/Kali_Linux-Compatible-557C94?style=for-the-badge&logo=kali-linux&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Tests](https://img.shields.io/badge/Tests-Passing-brightgreen?style=for-the-badge)

**A modular, production-grade cybersecurity CLI framework for Security Engineers, SOC Analysts, Penetration Testers, and Bug Bounty Hunters.**

[Documentation](https://docs.novasec.dev) · [Plugin Registry](https://plugins.novasec.dev) · [Report Bug](https://github.com/novasec/novasec/issues) · [Request Feature](https://github.com/novasec/novasec/issues)

</div>

---

## ✨ Features

- 🔍 **Reconnaissance** — DNS enumeration, subdomain brute-forcing, WHOIS, OSINT
- 🔬 **Vulnerability Scanning** — Web, network, SSL/TLS, service detection
- 🧩 **Plugin Architecture** — Drop-in plugins, community marketplace
- 📊 **Reporting** — JSON, HTML, PDF, Markdown, CSV outputs
- 🎯 **Threat Intelligence** — CVE enrichment, IOC extraction, NVD integration
- ⚙️ **Scan Profiles** — Stealth, aggressive, bug bounty presets
- 📋 **Structured Logging** — JSON logs + Rich terminal UI + audit trail
- 🔌 **API Integrations** — Shodan, VirusTotal, Censys, NVD

---

## 🚀 Quick Start

### Prerequisites (Kali Linux)

```bash
sudo apt update && sudo apt install -y nmap nikto ffuf nuclei python3.12 python3-pip pipx
```

### Installation

```bash
# Via pipx (recommended)
pipx install novasec

# Via pip
pip install novasec

# From source
git clone https://github.com/novasec/novasec.git
cd novasec
poetry install
poetry run novasec --help
```

### First Run

```bash
# Show all commands
novasec --help

# DNS reconnaissance
novasec recon dns --target example.com

# Subdomain enumeration
novasec recon subdomain --domain example.com --wordlist /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Port scan via nmap plugin
novasec scan nmap --target 192.168.1.0/24 --ports 1-1000

# Web vulnerability scan
novasec scan web --target https://example.com

# SSL/TLS analysis
novasec scan ssl --target example.com

# Generate HTML report
novasec report generate --format html --output ./report.html

# List installed plugins
novasec plugin list

# Show current config
novasec config show
```

---

## 📁 Project Structure

```
novasec/
├── cli/            # Typer CLI commands (presentation layer only)
├── core/           # Framework kernel: registry, DI, events, interfaces
├── domain/         # Security business logic: recon, scan, threat
├── infrastructure/ # External adapters: HTTP, DNS, APIs, storage
├── plugins/        # Plugin engine + bundled plugins
├── config/         # Pydantic settings + YAML loader
├── reporting/      # Report formatters: JSON, HTML, PDF, Markdown
├── logging/        # Structured logging + audit trail
└── utils/          # Shared utilities
```

---

## 🧩 Plugin Development

Create a new plugin in 3 steps:

**1. Create plugin directory**
```bash
mkdir -p ~/.novasec/plugins/my_scanner
```

**2. Create `plugin.yaml` manifest**
```yaml
manifest_version: "1"
name: "my_scanner"
display_name: "My Custom Scanner"
version: "1.0.0"
author: "Your Name"
category: "scanner"
entrypoint: "scanner.MyScanner"
kali_dependencies: []
python_dependencies: []
permissions:
  - network_access
```

**3. Implement `scanner.py`**
```python
from novasec.plugins.base import PluginBase, PluginManifest
from novasec.core.context import ExecutionContext
from novasec.reporting.models import FindingSet

class MyScanner(PluginBase):
    async def run(self, target: str, **options) -> FindingSet:
        # Your scan logic here
        return FindingSet(findings=[])
```

---

## ⚙️ Configuration

NovaSec uses a 6-level configuration hierarchy (highest → lowest priority):

```
CLI flags → Environment variables → ./novasec.yaml → ~/.novasec/config.yaml → /etc/novasec/config.yaml → Defaults
```

Set API keys via environment variables:
```bash
export NOVASEC_APIS__SHODAN_KEY="your-shodan-key"
export NOVASEC_APIS__VIRUSTOTAL_KEY="your-vt-key"
```

Or in `~/.novasec/config.yaml`:
```yaml
apis:
  shodan_key: "your-shodan-key"
  virustotal_key: "your-vt-key"
```

---

## 📊 Output Formats

```bash
# JSON output (pipe-friendly)
novasec recon dns --target example.com --output json

# Rich terminal table (default)
novasec recon dns --target example.com

# Save to file
novasec report generate --format pdf --output ./pentest-report.pdf
```

---

## 🧪 Development

```bash
git clone https://github.com/novasec/novasec.git
cd novasec
poetry install
poetry run pytest tests/ -v
poetry run ruff check novasec/
poetry run mypy novasec/
```

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

---

## ⚠️ Legal Disclaimer

NovaSec is designed for **authorized security testing only**. Always ensure you have explicit written permission before scanning any target. The authors are not responsible for misuse of this tool.

---

<div align="center">
Built with ❤️ by the NovaSec Team
</div>

# NovaSec 🛡️

<div align="center">

# 🛡️ NovaSec

**A Modular Cybersecurity CLI Framework for Reconnaissance, Vulnerability Assessment, and Security Automation.**

![Python](https://img.shields.io/badge/Python-3.12+-3776AB?style=flat-square&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-blue?style=flat-square&logo=kalilinux)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-success?style=flat-square)

</div>

---

## 📖 Overview

NovaSec is an extensible command-line cybersecurity framework written in Python.

It is designed to help Security Engineers, SOC Analysts, Penetration Testers, and students perform reconnaissance, vulnerability assessment, and plugin-based security testing from a single CLI.

The project follows a modular architecture so new scanners and integrations can be added without modifying the core framework.

---

# ✨ Current Features

### 🔍 Reconnaissance

- DNS Enumeration
- WHOIS Lookup
- Subdomain Enumeration

### 🔎 Scanning

- Port Scanner
- Web Scanner
- SSL Scanner

### 🔌 Plugin System

- Dynamic Plugin Loader
- Nmap Wrapper
- Nikto Wrapper
- Nuclei Wrapper
- FFUF Wrapper

### 📄 Reporting

- Rich Terminal Output
- Structured Findings
- Severity Classification

### ⚙ Configuration

- YAML Configuration
- Environment Variables
- CLI Configuration

---

# 🚀 Installation

Clone the repository

```bash
git clone https://github.com/Shahbaz-ali22/NovaSec.git
cd NovaSec
```

Create virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies

```bash
pip install -e .
```

Verify installation

```bash
novasec --help
```

---

# 📌 Usage

Show available commands

```bash
novasec --help
```

DNS Enumeration

```bash
novasec recon dns example.com
```

WHOIS Lookup

```bash
novasec recon whois example.com
```

Port Scan

```bash
novasec scan port scanme.nmap.org
```

Web Scan

```bash
novasec scan web http://example.com
```

List Plugins

```bash
novasec plugin list
```

Configuration

```bash
novasec config show
```

---

# 🧩 Built-in Plugins

| Plugin | Purpose |
|---------|---------|
| Nmap | Network Port Scanning |
| Nikto | Web Server Scanning |
| Nuclei | Template-based Vulnerability Scanning |
| FFUF | Web Content Discovery |

---

# 📂 Project Structure

```text
novasec/
├── cli/
├── core/
├── config/
├── domain/
├── infrastructure/
├── plugins/
├── reporting/
└── utils/
```

---

# 🚧 Roadmap

- [x] DNS Enumeration
- [x] WHOIS Lookup
- [x] Port Scanner
- [x] Plugin Framework
- [x] Rich CLI Output
- [ ] Better Web Scanner
- [ ] HTML Reports
- [ ] PDF Reports
- [ ] JSON Export
- [ ] CVE Integration
- [ ] VirusTotal Integration
- [ ] Shodan Integration
- [ ] AI-assisted Finding Analysis

---

# 🤝 Contributing

Contributions are welcome.

Feel free to submit issues, feature requests, or pull requests to improve NovaSec.

---

# ⚠ Legal Disclaimer

NovaSec is intended **only for authorized security testing**.

Do not scan systems without explicit permission.

The author is not responsible for misuse of this software.

---

# 📜 License

MIT License

---

<div align="center">

Developed with ❤️ by **Shahbaz Ali**

⭐ If you like this project, consider giving it a Star.

</div>

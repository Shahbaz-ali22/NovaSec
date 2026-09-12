# 🛡️ NovaSec

> Modular Python CLI framework for authorized reconnaissance, security scanning, and security automation.

[![Python](https://img.shields.io/badge/Python-3.12%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/) [![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-557C94?logo=kalilinux)](https://www.kali.org/)

## Overview

NovaSec brings common reconnaissance and assessment workflows into a modular command-line interface. It is designed for cybersecurity learning, controlled lab environments, and authorized security testing.

## Features

- 🔎 DNS and WHOIS reconnaissance
- 🌐 Subdomain enumeration
- 🔌 Port, web, and SSL scanning
- 🧩 Plugin-based architecture
- ⚙️ YAML/environment configuration
- 📄 Structured findings and severity classification
- 🛠️ Wrappers for Nmap, Nikto, Nuclei, and FFUF

## Architecture

```text
CLI → Core → Security Modules → Plugins → Findings → Reports
```

## Stack

`Python 3.12+` `Kali Linux` `Nmap` `Nikto` `Nuclei` `FFUF` `YAML`

## Quick Start

```bash
git clone https://github.com/Shahbaz-ali22/NovaSec.git
cd NovaSec
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
novasec --help
```

## Example Commands

```bash
novasec recon dns example.com
novasec recon whois example.com
novasec scan port scanme.nmap.org
novasec scan web http://example.com
novasec plugin list
```

## Roadmap

- [x] Modular CLI
- [x] Recon modules
- [x] Plugin framework
- [ ] HTML / PDF reporting
- [ ] JSON export
- [ ] CVE intelligence integration
- [ ] Additional automated security checks

## ⚠️ Responsible Use

Use NovaSec only against systems you own or where you have explicit authorization to perform security testing.

## Author

**Shahbaz Ali** — Cybersecurity student

"""NovaSec built-in configuration defaults.

These values are the last resort in the configuration hierarchy.
All values here must be safe, conservative, and Kali Linux compatible.
"""

from __future__ import annotations

DEFAULT_CONFIG: dict = {
    "general": {
        "output_dir": "./novasec_workspace",
        "workspace_name": "default",
        "max_threads": 10,
        "max_concurrent_tasks": 20,
        "banner": True,
    },
    "network": {
        "timeout": 30,
        "connect_timeout": 10,
        "retries": 3,
        "retry_delay": 1.0,
        "rate_limit": 10,
        "proxy": None,
        "verify_ssl": True,
        "follow_redirects": True,
        "user_agent": "NovaSec/1.0.0 (+https://github.com/novasec/novasec)",
        "max_connections": 100,
    },
    "dns": {
        "nameservers": ["8.8.8.8", "8.8.4.4", "1.1.1.1"],
        "timeout": 5.0,
        "lifetime": 10.0,
        "use_tcp": False,
        "doh_url": None,
    },
    "scan": {
        "default_ports": [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080, 8443],
        "aggressive": False,
        "stealth_mode": False,
        "randomize_ports": False,
        "skip_host_discovery": False,
        "max_hosts": 256,
        "scan_timeout": 300,
    },
    "exploit": {
        "enabled": False,
        "safe_mode": True,
        "require_confirmation": True,
        "max_payload_size": 4096,
    },
    "apis": {
        "shodan_key": None,
        "virustotal_key": None,
        "censys_id": None,
        "censys_secret": None,
        "nvd_api_key": None,
    },
    "reporting": {
        "default_format": "html",
        "output_dir": "./novasec_workspace/reports",
        "include_evidence": True,
        "include_remediation": True,
        "include_raw_output": False,
        "company_name": "",
        "report_title": "NovaSec Security Assessment Report",
        "logo_path": None,
    },
    "logging": {
        "level": "INFO",
        "format": "rich",
        "log_file": None,
        "audit_log": "~/.novasec/logs/audit.jsonl",
        "rotate_max_bytes": 10485760,
        "rotate_backup_count": 5,
        "include_caller_info": False,
    },
    "plugins": {
        "enabled": True,
        "extra_plugin_dirs": [],
        "disabled_plugins": [],
        "auto_install_python_deps": False,
    },
}

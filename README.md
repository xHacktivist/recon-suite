# Recon Suite

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-blue.svg">
  <img src="https://img.shields.io/badge/Platform-Linux-green.svg">
  <img src="https://img.shields.io/badge/License-MIT-orange.svg">
  <img src="https://img.shields.io/badge/Version-4.0-purple.svg">
</p>

<p align="center">
  <b>Advanced Menu-Driven Reconnaissance Framework</b>
</p>

Recon Suite is a powerful Python-based reconnaissance framework designed for security researchers, penetration testers, bug bounty hunters, and cybersecurity students.

The framework provides a fast and interactive terminal interface for performing information gathering and target discovery tasks including:

- Subdomain Enumeration
- Port Scanning
- Service Fingerprinting
- HTTP Probing
- Web Content Discovery
- Directory Fuzzing
- Report Generation

All functionality is accessible through an interactive menu-driven interface, eliminating the need to remember complex command-line arguments.

---

# Features

## Subdomain Enumeration

Discover active subdomains using:

- DNS Resolution
- HTTP Probing
- HTTPS Detection
- Server Fingerprinting
- Title Extraction

Example Output:

```text
api.example.com      104.21.x.x      200
dev.example.com      172.67.x.x      403
admin.example.com    104.21.x.x      301
```

---

## Port Scanning

Fast multithreaded TCP port scanner with:

- Service Detection
- Banner Grabbing
- TLS Identification
- Custom Port Ranges
- Full Range Scanning (1-65535)

Supported services include:

- SSH
- FTP
- SMTP
- HTTP
- HTTPS
- MySQL
- PostgreSQL
- Redis
- MongoDB
- Docker API
- Kubernetes API
- And many more

---

## Directory & File Discovery

Perform web content discovery using built-in or custom wordlists.

Examples:

```text
/admin
/login
/api/v1
/.env
/.git/config
/backup.zip
/swagger-ui
/robots.txt
```

Features:

- HTTP Status Detection
- Content-Type Detection
- Redirect Analysis
- Page Title Extraction
- Response Size Tracking

---

## Interactive Menu Interface

Unlike traditional tools that require complex arguments, Recon Suite provides:

- Easy Navigation
- Configuration Menus
- Session Management
- Scan History
- Report Export

Example:

```text
[1] Configure Target
[2] Select Scan Mode
[3] Subdomain Settings
[4] Port Scan Settings
[5] Fuzz Settings
[6] Output Settings

[R] Start Scan
[H] History
[0] Exit
```

---

# Installation

## Clone Repository

```bash
git clone https://github.com/USERNAME/recon-suite.git
cd recon-suite
```

## Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

## Install Dependencies

```bash
pip install -r requirements.txt
```

Required packages:

```text
requests
rich
colorama
urllib3
```

---

# Usage

Start Recon Suite:

```bash
python3 recon_suite.py
```

The application will launch an interactive terminal interface.

---

# Scan Modes

## Subdomain Scan

Performs:

- DNS Resolution
- HTTP/HTTPS Detection
- Web Server Identification
- Page Title Extraction

---

## Port Scan

Performs:

- TCP Connect Scan
- Banner Grabbing
- TLS Detection
- Service Mapping

---

## Path Fuzzing

Performs:

- Directory Enumeration
- File Discovery
- Response Analysis
- Redirect Detection

---

## Full Recon

Runs:

```text
Subdomain Enumeration
        ↓
Port Scanning
        ↓
Directory Fuzzing
```

Automatically in sequence.

---

# Report Generation

Recon Suite supports exporting results in:

## JSON

```json
{
  "target": "example.com",
  "mode": "subdomain",
  "found": 15
}
```

## TXT

```text
Target: example.com
Mode: Subdomain
Results Found: 15
```

---

# Project Structure

```text
recon-suite/
│
├── recon_suite.py
├── requirements.txt
├── README.md
│
├── wordlists/
│   ├── subdomains.txt
│   └── paths.txt
│
├── reports/
│   ├── json/
│   └── txt/
│
└── screenshots/
```

---

# Performance

Recommended Settings:

| Scan Type | Threads |
|------------|----------|
| Subdomain | 50 |
| Port Scan | 150 |
| Fuzzing | 50 |

Average Performance:

- 500+ ports/sec
- 100+ HTTP requests/sec
- Multithreaded Architecture
- Low Memory Usage

---

# Security Notice

This tool is intended for:

- Security Research
- Authorized Penetration Testing
- Educational Purposes
- Internal Security Assessments

Always obtain proper authorization before scanning systems you do not own or manage.

---

# Roadmap

Future Features:

- WHOIS Enumeration
- DNS Record Discovery
- ASN Lookup
- SSL Certificate Analysis
- Screenshot Capture
- Technology Detection
- HTML Reports
- PDF Reports
- Plugin System
- API Integration
- TUI Dashboard
- Multi-Target Scanning

---

# Contributing

Contributions are welcome.

To contribute:

```bash
git checkout -b feature/new-feature
git commit -m "Add new feature"
git push origin feature/new-feature
```

Then open a Pull Request.

---

# License

MIT License

---

# Author

Created by xHacktivist

If you find this project useful, consider giving it a ⭐ on GitHub.

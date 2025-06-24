<img src="https://raw.githubusercontent.com/issamjr/SubTitan/refs/heads/main/img.jpg" />
<p align="center">
  <img src="https://img.shields.io/badge/Subdomain-Enumeration-blue?style=for-the-badge" alt="SubTitan"/>
  <img src="https://img.shields.io/badge/Python-3.10%2B-yellow?style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge"/>
</p>

<h1 align="center">SubTitan 🛡️</h1>
<p align="center">
  <strong>Advanced Subdomain Enumeration Tool</strong><br>
  Code by <a href="https://github.com/issamjr">Issam Junior</a>
</p>

---

### ⚡ Overview

**SubTitan** is a powerful and intelligent subdomain enumeration tool built with Python.  
It utilizes a multi-technique scanning mechanism to discover hidden and publicly known subdomains using:

- 🔍 DNS brute force
- 🔐 Certificate Transparency logs
- 🌐 Web scraping (Google, Archive.org, DNSDumpster)
- 🔁 Passive DNS lookups (VirusTotal, SecurityTrails)
- 🔁 Reverse DNS
- 📡 DNS zone transfers
- 🛠️ Port-based SSL banner scraping

---

### 📥 Installation

```bash
git clone https://github.com/issamjr/SubTitan.git
cd SubTitan
pip install -r requirements.txt
```

> Required Python version: **3.10+**

---

### 🧪 Usage

```bash
python subtitan.py -d example.com
```

#### 🛠 Options

| Flag        | Description                                |
|-------------|--------------------------------------------|
| `-d`        | Target domain or URL (required)            |
| `-t`        | Number of threads (default: 50)            |
| `--timeout` | Request timeout in seconds (default: 5)    |
| `-o`        | Output file to save results                |
| `--silent`  | Silent mode (no banners or logs)           |

---

### 💡 Examples

```bash
python subtitan.py -d example.com
python subtitan.py -d https://example.com -t 100 --timeout 3
python subtitan.py -d example.com -o subdomains.txt
```

---



### 📦 Download as ZIP

You can download the tool directly as a ZIP:
[![Download](https://img.shields.io/badge/Download-ZIP-blue?style=for-the-badge&logo=github)](https://github.com/issamjr/SubTitan/archive/refs/heads/main.zip)

---

### ⚠️ Disclaimer

This tool is for **educational and authorized testing purposes only**.  
The author is not responsible for any misuse.

---

### 🙋‍♂️ Author

- 👨‍💻 Issam Junior  
- 🌐 [GitHub](https://github.com/issamjr)  
- 💬 Telegram: [@issamiso](https://t.me/issamiso)  
- 🐦 Twitter: [@issam_juniorx](https://twitter.com/issam_juniorx)

---

### ⭐ Give a Star!

If you like the tool or use it, don’t forget to **⭐ star this repo** on GitHub to show your support!

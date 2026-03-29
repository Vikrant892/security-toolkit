# Security & Data Toolkit

A growing collection of **practical cybersecurity, data engineering, and ML tools** — with a new tool added every day via automated GitHub Actions.

## What's Inside

| Category | Tools | Focus Areas |
|----------|-------|-------------|
| **Cybersecurity** | Password analyzer, hash identifier, log anomaly detector, subdomain enumerator, port scanner, CVE tracker, JWT decoder, file integrity monitor | OWASP, NIST, threat detection, forensics |
| **Data Engineering** | CSV profiler, SQL builder, JSON ETL transformer | Data quality, pipelines, SQL optimization |
| **ML / AI** | Anomaly detector, text classifier (NLP) | Statistical analysis, classification |
| **Automation** | API health monitor, git repo analyzer | DevOps, monitoring, analytics |

## Quick Start

```bash
# Clone the repo
git clone https://github.com/Vikrant892/security-toolkit.git
cd security-toolkit

# Run any tool
python tools/cybersecurity/password_strength_analyzer/password_strength_analyzer.py

# Check latest CVEs
python tools/cybersecurity/cve_tracker/cve_tracker.py python

# Profile a CSV dataset
python tools/data_engineering/csv_data_profiler/csv_data_profiler.py your_data.csv

# Scan ports
python tools/cybersecurity/network_port_scanner/network_port_scanner.py target.com
```

## How It Works

A GitHub Actions workflow runs daily and generates a unique, practical tool:

1. The **tool registry** contains 15+ categories of real-world tools
2. Each day, a different tool is selected and committed
3. Every tool is a **standalone Python script** — no dependencies required
4. Tools solve **real problems** in security, data, and automation

## Tool Categories

### Cybersecurity
- **Password Strength Analyzer** — Entropy calculation + breach checking via Have I Been Pwned
- **Hash Identifier** — Detect MD5, SHA-1/256/512, bcrypt + dictionary cracking
- **Log Anomaly Detector** — Brute force detection, web attack pattern matching
- **Subdomain Enumerator** — DNS-based subdomain discovery
- **TCP Port Scanner** — Multi-threaded scanning with service fingerprinting
- **CVE Tracker** — Real-time vulnerability feeds from NIST NVD
- **JWT Decoder** — Token analysis and security vulnerability detection
- **File Integrity Monitor** — SHA-256 based tampering detection

### Data Engineering
- **CSV Data Profiler** — Automated type detection, null analysis, quality scoring
- **SQL Query Builder** — Fluent builder with optimization suggestions
- **JSON ETL Transformer** — Flatten, transform, filter, and export data

### ML / AI
- **Anomaly Detector** — Z-score, IQR, and MAD methods with consensus scoring
- **Text Classifier** — TF-IDF + Naive Bayes (spam detection, sentiment analysis)

### Automation
- **API Health Monitor** — Uptime, latency, SSL certificate checking
- **Git Repo Analyzer** — Commit patterns, contributor stats, code hotspots

## Built With

- Python 3.12 (zero external dependencies)
- GitHub Actions for daily automation
- Real-world APIs (NVD, Have I Been Pwned)

## Author

**Vikrant Sharma** — Data Engineer & Cybersecurity Analyst
- Masters of IT @ University of Sunshine Coast, Adelaide
- NASA Space Challenge App Winner

## License

MIT License — use these tools freely in your projects.

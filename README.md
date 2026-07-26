# All Your Logs Are Belong To Us

*A lightweight Python project for analyzing Linux authentication logs and learning Security Operations fundamentals.*

---

## Motivation

I built this project to better understand how security analysts work with authentication logs in practice.

Instead of focusing on complex security frameworks, I wanted to start with the fundamentals:

- reading log files
- extracting useful information
- identifying suspicious authentication events
- building a simple analysis workflow step by step

---

## Demo

Run the analyzer from the project directory:

```bash
python3 src/log-analyzer.py
```

The analyzer prints a security report in the terminal and saves the same report to [reports/analysis-report.txt](reports/analysis-report.txt).

---

## Current Features

- Read Linux auth.log files
- Detect failed SSH logins
- Detect successful SSH logins
- Count source IP addresses
- Generate login statistics
- Detect brute-force attempts
- Detect password spraying attempts
- Detect invalid user attacks
- Generate TXT reports

## Planned Features

- Export results to CSV
- Generate HTML reports
- Build a Streamlit interface

---

## Built With

Python 3.10+

---

## Getting Started

Requirements: Python 3.10 or newer.

```bash
git clone https://github.com/schibbe/log-analyzer.git
cd log-analyzer
python3 src/log-analyzer.py
```

The sample log file is located at `data/auth.log`. After the analysis, the TXT report is available at `reports/analysis-report.txt`.

---

## Project Structure

```text
log-analyzer/
├── data/
│   └── auth.log
├── reports/
│   └── analysis-report.txt
├── src/
│   └── log-analyzer.py
└── README.md
```

---

## Output Sample

```text
Failed Login Attempts : 169
Successful Logins    : 81
Unique Attacker IPs  : 19
Possible Compromises : 4

Report saved to: reports/analysis-report.txt
```

The complete sample output is available in [analysis-report.txt](reports/analysis-report.txt).

---

## What I Learned

The goal is to gradually learn:

- Linux authentication logs
- Python file handling
- Log parsing
- Regular expressions
- Basic SOC workflows

---

## Roadmap

This project is intentionally developed in small, incremental steps to better understand how log analysis works in practice.

- [x] Create project
- [x] Write initial documentation
- [x] Read Linux authentication logs
- [x] Parse log entries
- [x] Detect failed SSH logins
- [x] Detect successful SSH logins
- [x] Count source IP addresses
- [x] Generate login statistics
- [x] Detect brute-force attempts
- [x] Generate TXT reports
- [ ] Export results to CSV
- [ ] Generate HTML reports
- [ ] Build a Streamlit web interface

---

## Disclaimer

This project is intended for educational purposes only.

---

## About

Developed by Simon as part of a series of small projects exploring networking and cybersecurity fundamentals.
 

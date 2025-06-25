# 🕵️ Suspicious Log Analyzer

A Python-based tool for analyzing server log files in CSV format.  
It detects:
- 📌 IP addresses with **2 or more failed login attempts** within a 5-minute window  
- 🌙 User activity during **unusual hours (00:00–05:00)**

Ideal for learning backend logic, basic log analysis, and security event detection.

---

## 📂 Project Structure

```
├── main.py                  # Core script
├── logs.csv                 # Sample input log file
├── suspicious_report.txt    # Generated output report
├── requirements.txt         # Python dependencies
└── README.md                # Project documentation
```

---

## 🚀 How to Run

### 1. Clone the repository
```bash
git clone https://github.com/yourusername/suspicious-log-analyzer.git
cd suspicious-log-analyzer
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the analyzer
```bash
python main.py
```

> Output will be saved to `suspicious_report.txt`

---

## 🧾 Example Report Output

```
Suspicious IPs (2+ failed logins in <5 min):
- 194.67.82.4 | Attempts: 3 | Range: 0 days 00:00:58

Suspicious log entries during unusual hours (00:00–05:00):
2025-06-25 02:15:32 | john | login_failed | 194.67.82.4
2025-06-25 02:15:40 | john | login_failed | 194.67.82.4
...
```

---

## 💡 Future Improvements

- Export results to JSON format  
- Visual charts (bar/line) for activity patterns  
- Real-time log streaming support  
- Web-based frontend for visualization

---

## 🧠 Skills Demonstrated

- Python scripting & logic  
- DataFrame manipulation with `pandas`  
- Time-based analysis using `datetime`  
- Report generation & file handling  
- Basic cybersecurity event detection logic

---

## 📬 Contact

**Lidor Sanker**  
📧 lidor.email@example.com  
🔗 [https://linkedin.com/in/lidorsanker](https://linkedin.com/in/lidorsanker) | [https://github.com/lidor7776](https://github.com/lidor7776)

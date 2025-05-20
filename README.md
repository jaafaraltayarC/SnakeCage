# SnakeCage 🐍🧪

An isolated sandbox to safely test Python-based malware behavior, track its system actions, and generate behavioral logs.

## 🔐 Why?

Cybersecurity researchers and students often need to test scripts without risking their system. SnakeCage creates a secure, observable environment to do that.

## 🚀 Features

- Run Python code in isolation
- Monitor CPU, memory, and network activity
- Log file system changes and I/O
- Auto timeout and process kill
- Log suspicious actions (file deletion, system commands)
- Web interface to test code
- Risk assessment and behavior scoring
- Comprehensive visual reports

## 📋 Requirements

- Python 3.11+
- Flask
- psutil
- Chart.js (included via CDN)

## 🔧 Setup & Installation

1. Clone this repository:
```bash
git clone https://github.com/jaafaraltayarC/snakecage.git
cd snakecage
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
gunicorn --bind 0.0.0.0:5000 main:app
```

4. Open your browser and navigate to `http://localhost:5000`

## 🖥️ Usage

1. Enter Python code in the text area or use one of the sample code examples
2. Set execution timeout (default: 30 seconds)
3. Click "Run in Sandbox"
4. View detailed analysis results including:
   - Risk assessment
   - Suspicious activity detection
   - Resource usage charts (CPU, memory, network)
   - Execution output

## 🔒 Security Notes

This sandbox implements several isolation techniques:
- Process isolation
- Resource limits
- Filesystem restrictions
- Network activity monitoring

For additional security, consider running the sandbox in a virtual machine or container.

## 📊 Screenshots

- Homepage with code input
- Analysis results with charts
- History page for past executions

## ⚠️ Disclaimer

This tool is for educational and research purposes only. Always handle potentially malicious code with caution.

## 📜 License

Copyright © 2023-2025 jaafaraltayarC. All rights reserved.

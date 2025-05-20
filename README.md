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

![image](https://github.com/user-attachments/assets/8d44f598-be8b-4934-b5e0-84069dcee435)

![image](https://github.com/user-attachments/assets/081a70ba-e665-4d28-b07a-430758b1f26b)
![image](https://github.com/user-attachments/assets/43ab5254-c5a3-4194-a5ab-bf2e5ca770c0)
![image](https://github.com/user-attachments/assets/c7e8a691-c200-4c4a-8bd4-b3f25819d6c0)
![image](https://github.com/user-attachments/assets/f9c2025b-488e-4ffb-9910-d3e445e2340c)
![image](https://github.com/user-attachments/assets/d2eec851-9803-480e-b551-699f77bd788f)


## ⚠️ Disclaimer

This tool is for educational and research purposes only. Always handle potentially malicious code with caution.

## 📜 License

Copyright © 2023-2025 jaafaraltayarC. All rights reserved.

import re
import logging
import json
from collections import Counter

logger = logging.getLogger(__name__)

# Suspicious patterns to look for in code and execution
SUSPICIOUS_IMPORTS = [
    "os", "subprocess", "sys", "socket", "requests", "urllib", 
    "ftplib", "paramiko", "telnetlib", "smtplib",
    "ctypes", "winreg", "shutil", "tempfile"
]

SUSPICIOUS_FUNCTIONS = [
    r"os\.(system|popen|exec|spawn|remove|unlink|rmdir|rename)",
    r"subprocess\.(Popen|call|run|check_output)",
    r"shutil\.(rmtree|copyfile)",
    r"__import__\(",
    r"exec\(",
    r"eval\(",
    r"socket\.(socket|connect)",
    r"open\([^)]*,(.*w.*)\)",  # File opening with write permissions
    r"sys\._getframe",
    r"importlib",
    r"globals\(\)",
    r"locals\(\)"
]

SUSPICIOUS_KEYWORDS = [
    "decrypt", "encrypt", "backdoor", "malware", "virus", 
    "exploit", "hack", "crack", "steal", "crash", "shell", 
    "password", "credit", "bitcoin", "ransom", "payload"
]

def analyze_results(sandbox_results, system_monitor):
    """
    Analyze the sandbox execution results and system monitoring data.
    
    Args:
        sandbox_results (dict): Results from sandbox execution
        system_monitor: System monitoring object
    
    Returns:
        dict: Analysis results including risk assessment and suspicious activities
    """
    logger.info(f"Analyzing results for execution: {sandbox_results['execution_id']}")
    
    # Stop monitoring and get results
    monitoring_results = system_monitor.stop()
    
    # Extract code and execution data
    code = sandbox_results.get("code", "")
    imported_modules = sandbox_results.get("imported_modules", [])
    stdout = sandbox_results.get("stdout", "")
    stderr = sandbox_results.get("stderr", "")
    
    # Initialize analysis results
    analysis = {
        "execution_id": sandbox_results["execution_id"],
        "success": sandbox_results["success"],
        "timed_out": sandbox_results["timed_out"],
        "execution_time": sandbox_results.get("execution_time", 0),
        "total_time": sandbox_results.get("total_time", 0),
        "suspicious_activities": [],
        "risk_score": 0,
        "sandbox_results": sandbox_results,
        "monitoring_results": monitoring_results
    }
    
    # Check for timeout (could indicate infinite loop or resource exhaustion)
    if sandbox_results["timed_out"]:
        analysis["suspicious_activities"].append({
            "type": "timeout",
            "severity": "medium",
            "description": f"Execution timed out after {sandbox_results['timeout']} seconds"
        })
        analysis["risk_score"] += 30
    
    # Analyze code for suspicious patterns
    analyze_code(code, analysis)
    
    # Analyze imported modules
    analyze_imports(imported_modules, analysis)
    
    # Analyze system resource usage
    analyze_system_usage(monitoring_results, analysis)
    
    # Analyze file system activity
    analyze_filesystem_activity(sandbox_results.get("filesystem_activity", {}), analysis)
    
    # Analyze stdout/stderr for suspicious output
    analyze_output(stdout, stderr, analysis)
    
    # Calculate final risk score (cap at 100)
    analysis["risk_score"] = min(analysis["risk_score"], 100)
    
    # Determine risk level
    if analysis["risk_score"] >= 75:
        analysis["risk_level"] = "high"
    elif analysis["risk_score"] >= 40:
        analysis["risk_level"] = "medium"
    else:
        analysis["risk_level"] = "low"
    
    # Generate summary
    analysis["summary"] = generate_summary(analysis)
    
    logger.info(f"Analysis completed with risk score: {analysis['risk_score']}")
    return analysis

def analyze_code(code, analysis):
    """Analyze the code for suspicious patterns"""
    # Check for suspicious imports
    for module in SUSPICIOUS_IMPORTS:
        pattern = fr"import\s+{module}|from\s+{module}\s+import"
        if re.search(pattern, code, re.IGNORECASE):
            analysis["suspicious_activities"].append({
                "type": "suspicious_import",
                "severity": "medium",
                "module": module,
                "description": f"Suspicious module import: {module}"
            })
            analysis["risk_score"] += 10
    
    # Check for suspicious function calls
    for pattern in SUSPICIOUS_FUNCTIONS:
        matches = re.findall(pattern, code)
        if matches:
            analysis["suspicious_activities"].append({
                "type": "suspicious_function",
                "severity": "high",
                "function": pattern,
                "matches": matches,
                "description": f"Potentially dangerous function call: {pattern}"
            })
            analysis["risk_score"] += 15
    
    # Check for suspicious keywords
    for keyword in SUSPICIOUS_KEYWORDS:
        if re.search(r"\b" + keyword + r"\b", code, re.IGNORECASE):
            analysis["suspicious_activities"].append({
                "type": "suspicious_keyword",
                "severity": "low",
                "keyword": keyword,
                "description": f"Suspicious keyword found: {keyword}"
            })
            analysis["risk_score"] += 5
    
    # Check for obfuscation techniques
    if "base64" in code.lower() or "__" in code:
        analysis["suspicious_activities"].append({
            "type": "potential_obfuscation",
            "severity": "medium",
            "description": "Potential code obfuscation detected"
        })
        analysis["risk_score"] += 20

def analyze_imports(imported_modules, analysis):
    """Analyze the modules that were imported during execution"""
    suspicious_count = 0
    for module in imported_modules:
        if module in SUSPICIOUS_IMPORTS:
            suspicious_count += 1
            analysis["suspicious_activities"].append({
                "type": "imported_suspicious_module",
                "severity": "medium",
                "module": module,
                "description": f"Suspicious module was imported during execution: {module}"
            })
    
    # Add to risk score based on number of suspicious imports
    analysis["risk_score"] += suspicious_count * 15

def analyze_system_usage(monitoring_results, analysis):
    """Analyze system resource usage during execution"""
    summary = monitoring_results.get("summary", {})
    
    # Check for high CPU usage
    if "cpu" in summary and summary["cpu"]["peak_delta"] > 50:
        analysis["suspicious_activities"].append({
            "type": "high_cpu_usage",
            "severity": "medium",
            "usage": summary["cpu"]["peak_delta"],
            "description": f"High CPU usage spike detected: {summary['cpu']['peak_delta']}%"
        })
        analysis["risk_score"] += 15
    
    # Check for high memory usage
    if "memory" in summary and summary["memory"]["peak_delta"] > 30:
        analysis["suspicious_activities"].append({
            "type": "high_memory_usage",
            "severity": "medium",
            "usage": summary["memory"]["peak_delta"],
            "description": f"High memory usage spike detected: {summary['memory']['peak_delta']}%"
        })
        analysis["risk_score"] += 15
    
    # Check for network activity
    if "network" in summary:
        network = summary["network"]
        if network["total_sent"] > 1000 or network["total_recv"] > 1000:
            analysis["suspicious_activities"].append({
                "type": "network_activity",
                "severity": "high",
                "sent": network["total_sent"],
                "received": network["total_recv"],
                "description": f"Network activity detected: {network['total_sent']} bytes sent, {network['total_recv']} bytes received"
            })
            analysis["risk_score"] += 25
    
    # Check for process creation
    if "processes" in summary and summary["processes"]["peak_delta"] > 3:
        analysis["suspicious_activities"].append({
            "type": "process_creation",
            "severity": "high",
            "count": summary["processes"]["peak_delta"],
            "description": f"Multiple new processes created: {summary['processes']['peak_delta']}"
        })
        analysis["risk_score"] += 30

def analyze_filesystem_activity(filesystem_activity, analysis):
    """Analyze file system activity during execution"""
    created_files = filesystem_activity.get("created", [])
    modified_files = filesystem_activity.get("modified", [])
    accessed_files = filesystem_activity.get("accessed", [])
    
    # Check for file creation
    if created_files:
        analysis["suspicious_activities"].append({
            "type": "file_creation",
            "severity": "medium",
            "files": created_files,
            "count": len(created_files),
            "description": f"Created {len(created_files)} files"
        })
        analysis["risk_score"] += min(len(created_files) * 10, 30)
    
    # Check for file modification
    if modified_files:
        analysis["suspicious_activities"].append({
            "type": "file_modification",
            "severity": "high",
            "files": modified_files,
            "count": len(modified_files),
            "description": f"Modified {len(modified_files)} files"
        })
        analysis["risk_score"] += min(len(modified_files) * 15, 30)

def analyze_output(stdout, stderr, analysis):
    """Analyze program output for suspicious content"""
    # Check for error messages that might indicate malicious behavior
    error_patterns = [
        "permission denied", "access is denied", "operation not permitted",
        "couldn't connect", "connection refused", "timeout"
    ]
    
    for pattern in error_patterns:
        if pattern in stderr.lower() or pattern in stdout.lower():
            analysis["suspicious_activities"].append({
                "type": "suspicious_error",
                "severity": "medium",
                "pattern": pattern,
                "description": f"Suspicious error pattern in output: '{pattern}'"
            })
            analysis["risk_score"] += 10
            break

def generate_summary(analysis):
    """Generate a human-readable summary of the analysis results"""
    activities = Counter([activity["type"] for activity in analysis["suspicious_activities"]])
    severity_counts = Counter([activity["severity"] for activity in analysis["suspicious_activities"]])
    
    summary = f"Risk Score: {analysis['risk_score']}/100 ({analysis['risk_level'].upper()})\n"
    
    if analysis["timed_out"]:
        summary += "- Execution timed out\n"
    
    if activities:
        summary += "- Detected suspicious activities:\n"
        for activity_type, count in activities.items():
            summary += f"  - {count}x {activity_type.replace('_', ' ').title()}\n"
    else:
        summary += "- No suspicious activities detected\n"
    
    return summary

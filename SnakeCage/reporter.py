import os
import json
import logging
import time
from datetime import datetime

logger = logging.getLogger(__name__)

def generate_report(analysis_results, code, execution_id, timestamp):
    """
    Generate a comprehensive report from analysis results.
    
    Args:
        analysis_results (dict): Results from analyzer
        code (str): The original code that was executed
        execution_id (str): Unique ID for this execution
        timestamp (str): Timestamp for the execution
    
    Returns:
        dict: Complete report with all analysis data
    """
    logger.info(f"Generating report for execution: {execution_id}")
    
    # Create the report structure
    report = {
        "execution_id": execution_id,
        "timestamp": timestamp,
        "code": code,
        "risk_score": analysis_results["risk_score"],
        "risk_level": analysis_results["risk_level"],
        "summary": analysis_results["summary"],
        "execution": {
            "success": analysis_results["success"],
            "timed_out": analysis_results["timed_out"],
            "execution_time": analysis_results["execution_time"],
            "total_time": analysis_results["total_time"]
        },
        "suspicious_activities": analysis_results["suspicious_activities"],
        "monitoring": {
            "cpu": summarize_metric(analysis_results["monitoring_results"]["metrics"]["cpu"]),
            "memory": summarize_metric(analysis_results["monitoring_results"]["metrics"]["memory"]),
            "network": summarize_metric(analysis_results["monitoring_results"]["metrics"]["network"]),
            "processes": summarize_metric(analysis_results["monitoring_results"]["metrics"]["processes"])
        },
        "sandbox_results": {
            "stdout": analysis_results["sandbox_results"]["stdout"],
            "stderr": analysis_results["sandbox_results"]["stderr"],
            "imported_modules": analysis_results["sandbox_results"].get("imported_modules", []),
            "filesystem_activity": analysis_results["sandbox_results"].get("filesystem_activity", {})
        },
        "recommendations": generate_recommendations(analysis_results)
    }
    
    return report

def summarize_metric(metric_data, max_points=50):
    """
    Summarize a time-series metric to a reasonable number of data points.
    
    Args:
        metric_data (list): List of metric measurements
        max_points (int): Maximum number of data points to return
    
    Returns:
        list: Summarized metric data
    """
    if not metric_data or len(metric_data) <= max_points:
        return metric_data
    
    # Simple sampling to reduce data points
    step = len(metric_data) // max_points
    return metric_data[::step][:max_points]

def generate_recommendations(analysis_results):
    """
    Generate recommendations based on analysis results.
    
    Args:
        analysis_results (dict): Results from analyzer
    
    Returns:
        list: Recommendations for handling the analyzed code
    """
    recommendations = []
    risk_level = analysis_results["risk_level"]
    activities = [act["type"] for act in analysis_results["suspicious_activities"]]
    
    # Base recommendations on risk level
    if risk_level == "high":
        recommendations.append({
            "title": "Isolate and Investigate",
            "description": "This code exhibits highly suspicious behavior and should be considered potentially malicious. Do not run in production environments."
        })
    elif risk_level == "medium":
        recommendations.append({
            "title": "Review Carefully",
            "description": "This code shows some suspicious patterns that warrant further review before execution in sensitive environments."
        })
    else:
        recommendations.append({
            "title": "Low Risk",
            "description": "This code appears to be low risk but should still be reviewed according to your security policies."
        })
    
    # Add specific recommendations based on activities
    if "network_activity" in activities:
        recommendations.append({
            "title": "Network Activity",
            "description": "The code attempted network communications. Verify the destination and purpose of these connections."
        })
    
    if "file_creation" in activities or "file_modification" in activities:
        recommendations.append({
            "title": "File System Activity",
            "description": "The code performs file operations which could potentially be destructive or used for persistence. Review all file activities."
        })
    
    if "high_cpu_usage" in activities or "high_memory_usage" in activities:
        recommendations.append({
            "title": "Resource Usage",
            "description": "The code has high resource utilization which could indicate cryptocurrency mining, DoS attempts, or inefficient code."
        })
    
    if "process_creation" in activities:
        recommendations.append({
            "title": "Process Creation",
            "description": "The code spawns new processes which may indicate attempts to bypass security controls or execute additional malicious code."
        })
    
    if "potential_obfuscation" in activities:
        recommendations.append({
            "title": "Code Obfuscation",
            "description": "The code appears to use obfuscation techniques which may be attempting to hide malicious functionality."
        })
    
    # Add a general recommendation
    recommendations.append({
        "title": "Security Best Practices",
        "description": "Always run untrusted code in isolated environments and verify behavior before moving to production."
    })
    
    return recommendations

def save_report(report, execution_id, timestamp):
    """
    Save the report to disk in JSON and HTML formats.
    
    Args:
        report (dict): Generated report
        execution_id (str): Unique ID for this execution
        timestamp (str): Timestamp for the execution
    
    Returns:
        str: Path to the saved JSON report
    """
    # Ensure reports directory exists
    os.makedirs("reports", exist_ok=True)
    
    # Save JSON report
    json_path = f"reports/{execution_id}.json"
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2)
    
    logger.info(f"Report saved to {json_path}")
    return json_path

import os
import tempfile
import subprocess
import time
import logging
import signal
import shutil
import json
from pathlib import Path

logger = logging.getLogger(__name__)

def execute_in_sandbox(code, execution_id, timeout=30):
    """
    Execute potentially malicious Python code in a sandbox environment.
    
    Args:
        code (str): Python code to execute
        execution_id (str): Unique ID for this execution
        timeout (int): Maximum execution time in seconds
    
    Returns:
        dict: Results of the execution including stdout, stderr, and metadata
    """
    logger.info(f"Starting sandbox execution: {execution_id}")
    
    # Create a temporary directory for this execution
    sandbox_dir = Path(tempfile.mkdtemp(prefix=f"sandbox_{execution_id}_"))
    logger.debug(f"Created sandbox directory: {sandbox_dir}")
    
    # Create a script file with the code
    script_path = sandbox_dir / "malware_sample.py"
    with open(script_path, "w") as f:
        f.write(code)
    
    # Create a wrapper script that will monitor and execute the code
    wrapper_path = sandbox_dir / "wrapper.py"
    with open(wrapper_path, "w") as f:
        f.write("""
import sys
import os
import time
import traceback
import json
from io import StringIO

# Redirect stdout and stderr
original_stdout = sys.stdout
original_stderr = sys.stderr
stdout_capture = StringIO()
stderr_capture = StringIO()
sys.stdout = stdout_capture
sys.stderr = stderr_capture

start_time = time.time()

result = {
    "success": False,
    "stdout": "",
    "stderr": "",
    "exception": None,
    "execution_time": 0,
    "imported_modules": []
}

# Track imported modules
original_import = __builtins__.__import__
def import_hook(name, *args, **kwargs):
    result["imported_modules"].append(name)
    return original_import(name, *args, **kwargs)
__builtins__.__import__ = import_hook

try:
    # Execute the malware sample
    with open("malware_sample.py", "r") as f:
        code = compile(f.read(), "malware_sample.py", "exec")
        exec(code, {})
    result["success"] = True
except Exception as e:
    result["exception"] = {
        "type": type(e).__name__,
        "message": str(e),
        "traceback": traceback.format_exc()
    }

# Restore stdout and stderr
sys.stdout = original_stdout
sys.stderr = original_stderr

# Collect output
result["stdout"] = stdout_capture.getvalue()
result["stderr"] = stderr_capture.getvalue()
result["execution_time"] = time.time() - start_time

# Write results to file
with open("result.json", "w") as f:
    json.dump(result, f)
""")
    
    # Prepare the execution environment
    sandbox_env = os.environ.copy()
    sandbox_env["PYTHONPATH"] = ""  # Don't inherit PYTHONPATH
    
    # Create directories to monitor file operations
    monitor_dirs = ["created_files", "accessed_files", "modified_files"]
    for dir_name in monitor_dirs:
        os.makedirs(sandbox_dir / dir_name, exist_ok=True)
    
    results = {
        "execution_id": execution_id,
        "start_time": time.time(),
        "timeout": timeout,
        "sandbox_path": str(sandbox_dir),
        "code": code,
        "success": False,
        "timed_out": False,
        "stdout": "",
        "stderr": "",
        "exception": None,
        "execution_time": 0,
        "imported_modules": [],
        "filesystem_activity": {
            "created": [],
            "modified": [],
            "accessed": []
        },
        "process_info": {
            "pid": None,
            "exit_code": None
        }
    }
    
    try:
        # Use firejail if available, otherwise fallback to basic isolation
        if shutil.which("firejail"):
            cmd = [
                "firejail",
                "--quiet",
                "--private=" + str(sandbox_dir),
                "--disable-mnt",
                "--hostname=sandbox",
                "--nosound",
                "--x11=none",
                "--no3d",
                "--nodvd",
                "--nodbus",
                "--nonewprivs",
                "--noroot",
                "--seccomp",
                "python3", str(wrapper_path)
            ]
        else:
            logger.warning("Firejail not available, using basic isolation")
            cmd = ["python3", str(wrapper_path)]
        
        # Execute the command with timeout
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(sandbox_dir),
            env=sandbox_env,
            preexec_fn=os.setsid  # Create a new process group
        )
        
        results["process_info"]["pid"] = process.pid
        
        try:
            stdout, stderr = process.communicate(timeout=timeout)
            results["stdout"] = stdout.decode('utf-8', errors='replace')
            results["stderr"] = stderr.decode('utf-8', errors='replace')
            results["process_info"]["exit_code"] = process.returncode
        except subprocess.TimeoutExpired:
            # Kill the process group
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            stdout, stderr = process.communicate()
            results["stdout"] = stdout.decode('utf-8', errors='replace')
            results["stderr"] = stderr.decode('utf-8', errors='replace')
            results["timed_out"] = True
            results["process_info"]["exit_code"] = -1
        
        # Read execution result if available
        result_path = sandbox_dir / "result.json"
        if result_path.exists():
            with open(result_path, "r") as f:
                execution_result = json.load(f)
                results["success"] = execution_result.get("success", False)
                results["exception"] = execution_result.get("exception", None)
                results["execution_time"] = execution_result.get("execution_time", 0)
                results["imported_modules"] = execution_result.get("imported_modules", [])
        
        # Record end time
        results["end_time"] = time.time()
        results["total_time"] = results["end_time"] - results["start_time"]
        
        # Collect file system activity (simplified for now)
        for filename in os.listdir(sandbox_dir):
            if filename not in ["malware_sample.py", "wrapper.py", "result.json"] + monitor_dirs:
                results["filesystem_activity"]["created"].append(filename)
        
    except Exception as e:
        logger.exception(f"Error executing code in sandbox: {e}")
        results["exception"] = {
            "type": type(e).__name__,
            "message": str(e),
            "traceback": None
        }
    
    finally:
        # Clean up the sandbox directory
        try:
            shutil.rmtree(sandbox_dir)
        except Exception as e:
            logger.error(f"Error cleaning up sandbox directory: {e}")
    
    return results

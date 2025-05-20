import os
import psutil
import socket
import time
import logging
import threading
import queue
from datetime import datetime

logger = logging.getLogger(__name__)

class SystemMonitor:
    def __init__(self, interval=1.0):
        """
        Initialize system monitoring with the specified interval.
        
        Args:
            interval (float): Polling interval in seconds
        """
        self.interval = interval
        self.running = False
        self.data_queue = queue.Queue()
        self.monitor_thread = None
        self.start_time = None
        self.end_time = None
        self.baseline = {}
        self.data = {
            "cpu": [],
            "memory": [],
            "network": [],
            "processes": [],
            "filesystem": []
        }
    
    def capture_baseline(self):
        """Capture baseline system metrics before execution"""
        logger.debug("Capturing baseline system metrics")
        self.baseline = {
            "cpu": psutil.cpu_percent(interval=0.1),
            "memory": psutil.virtual_memory().percent,
            "network": {
                "bytes_sent": psutil.net_io_counters().bytes_sent,
                "bytes_recv": psutil.net_io_counters().bytes_recv
            },
            "connections": len(psutil.net_connections()),
            "process_count": len(psutil.pids())
        }
    
    def start(self):
        """Start the monitoring thread"""
        if self.running:
            return
        
        self.capture_baseline()
        self.start_time = datetime.now()
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        logger.info("System monitoring started")
    
    def stop(self):
        """Stop the monitoring thread and collect final data"""
        if not self.running:
            return
        
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2.0)
        
        self.end_time = datetime.now()
        
        # Process all remaining data in queue
        while not self.data_queue.empty():
            data_type, data = self.data_queue.get()
            self.data[data_type].append(data)
            self.data_queue.task_done()
        
        logger.info("System monitoring stopped")
        return self.get_results()
    
    def _monitor_loop(self):
        """Main monitoring loop that collects system metrics"""
        while self.running:
            try:
                # Monitor CPU usage
                cpu_percent = psutil.cpu_percent(interval=0)
                self.data_queue.put(("cpu", {
                    "timestamp": time.time(),
                    "percent": cpu_percent,
                    "delta": cpu_percent - self.baseline["cpu"]
                }))
                
                # Monitor memory usage
                memory = psutil.virtual_memory()
                self.data_queue.put(("memory", {
                    "timestamp": time.time(),
                    "percent": memory.percent,
                    "used": memory.used,
                    "available": memory.available,
                    "delta": memory.percent - self.baseline["memory"]
                }))
                
                # Monitor network activity
                net_io = psutil.net_io_counters()
                self.data_queue.put(("network", {
                    "timestamp": time.time(),
                    "bytes_sent": net_io.bytes_sent,
                    "bytes_recv": net_io.bytes_recv,
                    "bytes_sent_delta": net_io.bytes_sent - self.baseline["network"]["bytes_sent"],
                    "bytes_recv_delta": net_io.bytes_recv - self.baseline["network"]["bytes_recv"],
                    "connections": len(psutil.net_connections())
                }))
                
                # Monitor process count (high-level)
                self.data_queue.put(("processes", {
                    "timestamp": time.time(),
                    "count": len(psutil.pids()),
                    "delta": len(psutil.pids()) - self.baseline["process_count"]
                }))
                
                # Sleep for the specified interval
                time.sleep(self.interval)
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(self.interval)
    
    def get_results(self):
        """Get the collected monitoring results"""
        duration = None
        if self.start_time and self.end_time:
            duration = (self.end_time - self.start_time).total_seconds()
        
        results = {
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration": duration,
            "baseline": self.baseline,
            "metrics": self.data,
            "summary": self._generate_summary()
        }
        return results
    
    def _generate_summary(self):
        """Generate a summary of the monitoring data"""
        summary = {}
        
        # CPU summary
        if self.data["cpu"]:
            cpu_values = [entry["percent"] for entry in self.data["cpu"]]
            summary["cpu"] = {
                "min": min(cpu_values),
                "max": max(cpu_values),
                "avg": sum(cpu_values) / len(cpu_values),
                "peak_delta": max([entry["delta"] for entry in self.data["cpu"]])
            }
        
        # Memory summary
        if self.data["memory"]:
            memory_values = [entry["percent"] for entry in self.data["memory"]]
            summary["memory"] = {
                "min": min(memory_values),
                "max": max(memory_values),
                "avg": sum(memory_values) / len(memory_values),
                "peak_delta": max([entry["delta"] for entry in self.data["memory"]])
            }
        
        # Network summary
        if self.data["network"]:
            summary["network"] = {
                "total_sent": max([entry["bytes_sent_delta"] for entry in self.data["network"]]),
                "total_recv": max([entry["bytes_recv_delta"] for entry in self.data["network"]]),
                "max_connections": max([entry["connections"] for entry in self.data["network"]])
            }
        
        # Process summary
        if self.data["processes"]:
            process_counts = [entry["count"] for entry in self.data["processes"]]
            summary["processes"] = {
                "min": min(process_counts),
                "max": max(process_counts),
                "peak_delta": max([entry["delta"] for entry in self.data["processes"]])
            }
        
        return summary


def initialize_monitoring():
    """Initialize and return a system monitor"""
    monitor = SystemMonitor(interval=0.5)
    monitor.start()
    return monitor

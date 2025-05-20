// Dashboard.js - Handles dynamic charts and UI interactions for the Python Malware Sandbox

// Global chart instances for updating
let cpuChart, memoryChart, networkChart, timelineChart;

// Initialize charts and UI when the page loads
document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Initialize dashboard if we're on the results page
    if (document.getElementById('cpuChart')) {
        initCharts();
    }

    // Set up code editor if we're on the submit page
    if (document.getElementById('code-editor')) {
        setupCodeEditor();
    }

    // Set up automatic form validation
    const forms = document.querySelectorAll('.needs-validation');
    Array.from(forms).forEach(form => {
        form.addEventListener('submit', event => {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }
            form.classList.add('was-validated');
        }, false);
    });
});

function setupCodeEditor() {
    // For simplicity, we're using a textarea. In a real implementation,
    // you might want to use CodeMirror or Monaco Editor for a better experience.
    const textarea = document.getElementById('code-editor');
    
    // Add tab support
    textarea.addEventListener('keydown', function(e) {
        if (e.key === 'Tab') {
            e.preventDefault();
            
            // Insert tab at cursor position
            const start = this.selectionStart;
            const end = this.selectionEnd;
            
            this.value = this.value.substring(0, start) + '    ' + this.value.substring(end);
            
            // Move cursor position
            this.selectionStart = this.selectionEnd = start + 4;
        }
    });
    
    // Sample code button
    const sampleButtons = document.querySelectorAll('.sample-code-btn');
    sampleButtons.forEach(button => {
        button.addEventListener('click', function() {
            const sampleType = this.getAttribute('data-sample');
            textarea.value = getSampleCode(sampleType);
        });
    });
}

function getSampleCode(type) {
    // Return different sample code based on type
    switch(type) {
        case 'harmless':
            return `# Harmless sample code
# This code calculates and prints the Fibonacci sequence

def fibonacci(n):
    """Generate fibonacci sequence up to n"""
    a, b = 0, 1
    while a < n:
        yield a
        a, b = b, a + b

# Generate first 20 Fibonacci numbers
print("Fibonacci sequence:")
for number in fibonacci(100):
    print(number, end=' ')
`;
        case 'suspicious':
            return `# Suspicious sample code - for testing purposes only!
# This code attempts to access system information

import os
import platform
import socket

# Get system info
print("Operating system:", platform.system())
print("Machine:", platform.machine())
print("Node:", platform.node())

# Try to list files in current directory
print("\\nFiles in current directory:")
for file in os.listdir('.'):
    print(f"- {file}")

# Try to get network info
hostname = socket.gethostname()
ip = socket.gethostbyname(hostname)
print(f"\\nHostname: {hostname}")
print(f"IP Address: {ip}")
`;
        case 'malicious':
            return `# Potentially malicious sample code - for testing purposes only!
# This code tries to perform actions that might be considered malicious

import os
import sys
import socket
import subprocess
import base64

# Try to create a file
try:
    with open('test_malware_file.txt', 'w') as f:
        f.write('This is a test file created by the sample code')
    print("Created test file")
except:
    print("Failed to create file")

# Try to execute a system command
try:
    result = subprocess.check_output('whoami', shell=True)
    print(f"Executed command: {result.decode().strip()}")
except:
    print("Failed to execute command")

# Try to establish a network connection (will fail in sandbox)
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('example.com', 80))
    s.send(b"GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n")
    print("Established network connection")
    s.close()
except:
    print("Failed to establish network connection")

# Base64 encoded string (often used in malware for obfuscation)
encoded = base64.b64encode(b'This is a test of obfuscation techniques').decode()
print(f"Encoded string: {encoded}")
`;
        default:
            return '';
    }
}

function initCharts() {
    // Get report data from the data attribute
    const dataElement = document.getElementById('report-data');
    if (!dataElement) return;
    
    let reportData;
    try {
        reportData = JSON.parse(dataElement.getAttribute('data-report'));
    } catch (e) {
        console.error('Error parsing report data:', e);
        return;
    }
    
    // Initialize charts with the data
    createCpuChart(reportData);
    createMemoryChart(reportData);
    createNetworkChart(reportData);
    createActivityTimeline(reportData);
    
    // Update overview metrics
    updateOverviewMetrics(reportData);
}

function createCpuChart(reportData) {
    const ctx = document.getElementById('cpuChart').getContext('2d');
    
    // Extract CPU data
    const cpuData = reportData.monitoring.cpu || [];
    const timestamps = cpuData.map(entry => new Date(entry.timestamp * 1000).toLocaleTimeString());
    const values = cpuData.map(entry => entry.percent);
    
    cpuChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: timestamps,
            datasets: [{
                label: 'CPU Usage (%)',
                data: values,
                borderColor: '#dc3545',
                backgroundColor: 'rgba(220, 53, 69, 0.1)',
                borderWidth: 2,
                tension: 0.1,
                fill: true
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    mode: 'index',
                    intersect: false
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    max: 100,
                    title: {
                        display: true,
                        text: 'CPU Usage (%)'
                    }
                }
            }
        }
    });
}

function createMemoryChart(reportData) {
    const ctx = document.getElementById('memoryChart').getContext('2d');
    
    // Extract memory data
    const memData = reportData.monitoring.memory || [];
    const timestamps = memData.map(entry => new Date(entry.timestamp * 1000).toLocaleTimeString());
    const values = memData.map(entry => entry.percent);
    
    memoryChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: timestamps,
            datasets: [{
                label: 'Memory Usage (%)',
                data: values,
                borderColor: '#fd7e14',
                backgroundColor: 'rgba(253, 126, 20, 0.1)',
                borderWidth: 2,
                tension: 0.1,
                fill: true
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    mode: 'index',
                    intersect: false
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    max: 100,
                    title: {
                        display: true,
                        text: 'Memory Usage (%)'
                    }
                }
            }
        }
    });
}

function createNetworkChart(reportData) {
    const ctx = document.getElementById('networkChart').getContext('2d');
    
    // Extract network data
    const netData = reportData.monitoring.network || [];
    const timestamps = netData.map(entry => new Date(entry.timestamp * 1000).toLocaleTimeString());
    const sentData = netData.map(entry => entry.bytes_sent_delta);
    const recvData = netData.map(entry => entry.bytes_recv_delta);
    
    networkChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: timestamps,
            datasets: [
                {
                    label: 'Bytes Sent',
                    data: sentData,
                    borderColor: '#0dcaf0',
                    backgroundColor: 'rgba(13, 202, 240, 0.1)',
                    borderWidth: 2,
                    tension: 0.1
                },
                {
                    label: 'Bytes Received',
                    data: recvData,
                    borderColor: '#6610f2',
                    backgroundColor: 'rgba(102, 16, 242, 0.1)',
                    borderWidth: 2,
                    tension: 0.1
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                tooltip: {
                    mode: 'index',
                    intersect: false
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Bytes'
                    }
                }
            }
        }
    });
}

function createActivityTimeline(reportData) {
    // Extract suspicious activities
    const activities = reportData.suspicious_activities || [];
    
    // Sort activities by severity (high to low)
    const severityOrder = { "high": 0, "medium": 1, "low": 2 };
    activities.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
    
    // Update the timeline container
    const timelineContainer = document.getElementById('activityTimeline');
    if (!timelineContainer) return;
    
    if (activities.length === 0) {
        timelineContainer.innerHTML = '<div class="alert alert-info">No suspicious activities detected</div>';
        return;
    }
    
    let timelineHTML = '';
    activities.forEach(activity => {
        const severityClass = `severity-${activity.severity}`;
        timelineHTML += `
        <div class="timeline-item">
            <div class="d-flex align-items-center mb-2">
                <span class="badge ${severityClass} me-2">${activity.severity.toUpperCase()}</span>
                <h5 class="mb-0">${activity.type.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}</h5>
            </div>
            <p>${activity.description}</p>
            ${activity.module ? `<small class="text-muted">Module: ${activity.module}</small>` : ''}
            ${activity.function ? `<small class="text-muted">Function: ${activity.function}</small>` : ''}
        </div>`;
    });
    
    timelineContainer.innerHTML = timelineHTML;
}

function updateOverviewMetrics(reportData) {
    // Update risk score
    const riskScoreElement = document.getElementById('riskScore');
    if (riskScoreElement) {
        const score = reportData.risk_score;
        const levelClass = `risk-${reportData.risk_level}`;
        riskScoreElement.innerHTML = `
            <h2 class="${levelClass}">${score}/100</h2>
            <p class="mb-0">Risk Level: <span class="${levelClass} fw-bold">${reportData.risk_level.toUpperCase()}</span></p>
        `;
    }
    
    // Update execution metrics
    const executionTimeElement = document.getElementById('executionTime');
    if (executionTimeElement) {
        executionTimeElement.innerHTML = `
            <h4>${reportData.execution.execution_time.toFixed(2)}s</h4>
            <p class="mb-0">Execution Time</p>
        `;
    }
    
    // Update suspicious activities count
    const activitiesElement = document.getElementById('suspiciousActivities');
    if (activitiesElement) {
        const count = reportData.suspicious_activities.length;
        activitiesElement.innerHTML = `
            <h4>${count}</h4>
            <p class="mb-0">Suspicious Activities</p>
        `;
    }
    
    // Update imported modules
    const modulesElement = document.getElementById('importedModules');
    if (modulesElement) {
        const count = reportData.sandbox_results.imported_modules.length;
        modulesElement.innerHTML = `
            <h4>${count}</h4>
            <p class="mb-0">Imported Modules</p>
        `;
    }
    
    // Update stdout/stderr
    const stdoutElement = document.getElementById('stdout');
    if (stdoutElement) {
        stdoutElement.textContent = reportData.sandbox_results.stdout || 'No output';
    }
    
    const stderrElement = document.getElementById('stderr');
    if (stderrElement) {
        stderrElement.textContent = reportData.sandbox_results.stderr || 'No errors';
    }
    
    // Update recommendations
    const recommendationsElement = document.getElementById('recommendations');
    if (recommendationsElement && reportData.recommendations) {
        let recommendationsHTML = '';
        reportData.recommendations.forEach(rec => {
            recommendationsHTML += `
            <div class="card mb-3">
                <div class="card-body">
                    <h5 class="card-title">${rec.title}</h5>
                    <p class="card-text">${rec.description}</p>
                </div>
            </div>`;
        });
        recommendationsElement.innerHTML = recommendationsHTML;
    }
}

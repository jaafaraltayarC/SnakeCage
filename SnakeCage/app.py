import os
import logging
import uuid
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from werkzeug.middleware.proxy_fix import ProxyFix
import json

from sandbox import execute_in_sandbox
from monitor import initialize_monitoring
from analyzer import analyze_results
from reporter import generate_report, save_report

# Configure logging
logging.basicConfig(level=logging.DEBUG, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "default_secret_key_for_development")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Ensure reports directory exists
os.makedirs('reports', exist_ok=True)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/submit', methods=['POST'])
def submit_code():
    """Handle submission of Python code for sandbox testing"""
    code = request.form.get('code', '')
    timeout = int(request.form.get('timeout', 30))
    
    if not code:
        flash('No code provided', 'error')
        return redirect(url_for('index'))
    
    # Generate a unique ID for this execution
    execution_id = str(uuid.uuid4())
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    
    try:
        # Initialize monitoring
        monitoring = initialize_monitoring()
        
        # Execute the code in the sandbox
        sandbox_results = execute_in_sandbox(code, execution_id, timeout)
        
        # Analyze the execution results
        analysis_results = analyze_results(sandbox_results, monitoring)
        
        # Generate and save the report
        report = generate_report(analysis_results, code, execution_id, timestamp)
        report_path = save_report(report, execution_id, timestamp)
        
        # Store execution ID in session for redirect
        session['last_execution_id'] = execution_id
        
        return redirect(url_for('view_results', execution_id=execution_id))
    
    except Exception as e:
        logger.exception("Error executing code in sandbox")
        flash(f'Error executing code: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/results/<execution_id>')
def view_results(execution_id):
    """Display results for a specific execution"""
    try:
        # Load the report for this execution
        with open(f'reports/{execution_id}.json', 'r') as f:
            report = json.load(f)
        return render_template('results.html', report=report)
    except FileNotFoundError:
        flash('Report not found', 'error')
        return redirect(url_for('index'))

@app.route('/history')
def history():
    """Show history of all executions"""
    reports = []
    if os.path.exists('reports'):
        for filename in os.listdir('reports'):
            if filename.endswith('.json'):
                try:
                    with open(os.path.join('reports', filename), 'r') as f:
                        report = json.load(f)
                        reports.append({
                            'execution_id': report['execution_id'],
                            'timestamp': report['timestamp'],
                            'risk_score': report['risk_score'],
                            'summary': report['summary']
                        })
                except Exception as e:
                    logger.error(f"Error loading report {filename}: {str(e)}")
    
    # Sort reports by timestamp, newest first
    reports.sort(key=lambda x: x['timestamp'], reverse=True)
    return render_template('history.html', reports=reports)

@app.route('/api/report/<execution_id>')
def api_get_report(execution_id):
    """API endpoint to get report data in JSON format"""
    try:
        with open(f'reports/{execution_id}.json', 'r') as f:
            report = json.load(f)
        return jsonify(report)
    except FileNotFoundError:
        return jsonify({"error": "Report not found"}), 404

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

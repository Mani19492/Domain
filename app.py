import os
import json
import logging
from flask import Flask, render_template, request, jsonify, send_file, session
from flask_socketio import SocketIO, emit
from dotenv import load_dotenv
from recon import get_recon_data
from auth_check import check_authenticity, get_official_link
from pdf_generator import generate_pdf_report
from ai_threat_predictor import threat_predictor
from graph_mapper import graph_mapper
from web3_scanner import web3_scanner
from workflow_automation import workflow_automation
from monitoring_system import monitoring_system
import tempfile
import uuid
import re
from functools import wraps
from datetime import datetime, timedelta
import threading
import time

# Configure logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your-secret-key-here')
socketio = SocketIO(app, cors_allowed_origins="*")

# Store scan results temporarily (in production, use Redis or database)
scan_results = {}
workflow_executions = {}

# Simple rate limiting: track requests per IP
request_times = {}

def rate_limit(max_requests=5, window=300):  # 5 requests per 5 minutes
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            client_ip = request.remote_addr
            now = datetime.now()
            if client_ip not in request_times:
                request_times[client_ip] = []
            
            # Remove old requests
            request_times[client_ip] = [t for t in request_times[client_ip] if now - t < timedelta(seconds=window)]
            
            if len(request_times[client_ip]) >= max_requests:
                return jsonify({'error': 'Rate limit exceeded'}), 429
            
            request_times[client_ip].append(now)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def validate_domain(domain):
    """Validate domain format to prevent injection/SSRF."""
    domain_pattern = re.compile(
        r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.([a-zA-Z]{2,})$'
    )
    return domain_pattern.match(domain) is not None

@app.route('/')
def index():
    """Main page."""
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
@rate_limit()
def scan_domain():
    """API endpoint to scan a domain."""
    try:
        data = request.get_json()
        domain = data.get('domain', '').strip()
        scan_type = 'comprehensive'  # Always comprehensive - execute everything
        
        if not domain:
            return jsonify({'error': 'Domain is required'}), 400
        
        if not validate_domain(domain):
            return jsonify({'error': 'Invalid domain format'}), 400
        
        # Generate unique scan ID
        scan_id = str(uuid.uuid4())
        
        # Store initial status
        scan_results[scan_id] = {
            'status': 'processing',
            'domain': domain,
            'scan_type': scan_type,
            'progress': 0
        }
        
        # Start background processing (in production, use Celery)
        # Start background scan
        threading.Thread(target=perform_background_scan, args=(scan_id, domain, scan_type)).start()
        
        return jsonify({'scan_id': scan_id})
        
    except Exception as e:
        logger.error(f"Error in scan endpoint: {str(e)}")
        return jsonify({'error': str(e)}), 500

def perform_background_scan(scan_id: str, domain: str, scan_type: str):
    """Perform background scanning with real-time updates."""
    try:
        # Update progress
        update_scan_progress(scan_id, 5, "Starting comprehensive analysis...")
        
        # Get authenticity check
        auth_result = check_authenticity(f'https://{domain}')
        update_scan_progress(scan_id, 15, "Performing reconnaissance...")
        
        # Get reconnaissance data
        recon_data = get_recon_data(domain)
        update_scan_progress(scan_id, 35, "Analyzing threats with AI...")
        
        # AI threat prediction
        threat_analysis = threat_predictor.predict_threat_level(recon_data)
        update_scan_progress(scan_id, 50, "Creating relationship graph...")
        
        # Graph analysis
        graph_data = graph_mapper.create_domain_graph(recon_data)
        update_scan_progress(scan_id, 65, "Scanning Web3 domains...")
        
        # Always perform Web3 analysis
        web3_analysis = web3_scanner.scan_web3_domain(domain)
        update_scan_progress(scan_id, 75, "Running workflow automation...")
        
        # Execute all workflows automatically
        workflow_results = execute_all_workflows(domain, recon_data, threat_analysis)
        update_scan_progress(scan_id, 90, "Finalizing comprehensive report...")
        
        result = {
            'domain': domain,
            'authenticity': auth_result,
            'reconnaissance': recon_data,
            'threat_analysis': threat_analysis,
            'graph_data': graph_data,
            'web3_analysis': web3_analysis,
            'workflow_results': workflow_results,
            'official_link': get_official_link(domain) if not auth_result['is_genuine'] else None
        }
        
        update_scan_progress(scan_id, 95, "Generating comprehensive report...")
        
        scan_results[scan_id] = {
            'status': 'completed',
            'domain': domain,
            'scan_type': scan_type,
            'progress': 100,
            'result': result
        }
        
        update_scan_progress(scan_id, 100, "Comprehensive analysis completed!")
        
    except Exception as e:
        logger.error(f"Error scanning domain {domain}: {str(e)}")
        scan_results[scan_id] = {
            'status': 'error',
            'domain': domain,
            'progress': 0,
            'error': str(e)
        }
        socketio.emit('scan_error', {'scan_id': scan_id, 'error': str(e)})

def execute_all_workflows(domain: str, recon_data: dict, threat_analysis: dict) -> dict:
    """Execute all workflows automatically."""
    try:
        results = {}
        
        # Comprehensive Security Scan (already done above)
        results['comprehensive'] = {
            'status': 'completed',
            'description': 'Full domain reconnaissance with threat analysis'
        }
        
        # Threat Hunter Workflow
        results['threat_hunter'] = {
            'status': 'completed',
            'description': 'Focused threat detection and analysis',
            'high_risk_indicators': threat_analysis.get('rule_based_flags', []),
            'risk_score': threat_analysis.get('risk_score', 0)
        }
        
        # Compliance Audit
        sec_headers = recon_data.get('security_headers', {})
        owasp_checks = recon_data.get('owasp_checks', [])
        
        compliance_score = 100
        compliance_issues = []
        
        # Check security headers
        critical_headers = ['Content-Security-Policy', 'X-Frame-Options', 'Strict-Transport-Security']
        for header in critical_headers:
            if sec_headers.get(header) == 'Not set':
                compliance_score -= 15
                compliance_issues.append(f"Missing {header}")
        
        # Check OWASP issues
        high_risk_owasp = [check for check in owasp_checks if check.get('status') == 'High Risk']
        compliance_score -= len(high_risk_owasp) * 10
        
        results['compliance_audit'] = {
            'status': 'completed',
            'description': 'Security compliance and header analysis',
            'compliance_score': max(0, compliance_score),
            'issues': compliance_issues,
            'owasp_high_risk': len(high_risk_owasp)
        }
        
        return results
        
    except Exception as e:
        logger.error(f"Error executing workflows: {str(e)}")
        return {'error': str(e)}

def update_scan_progress(scan_id: str, progress: int, message: str):
    """Update scan progress and emit to frontend."""
    if scan_id in scan_results:
        scan_results[scan_id]['progress'] = progress
        scan_results[scan_id]['status_message'] = message
        
        # Emit progress update via WebSocket
        socketio.emit('scan_progress', {
            'scan_id': scan_id,
            'progress': progress,
            'message': message
        })
@app.route('/api/scan/<scan_id>/status')
def get_scan_status(scan_id):
    """Get scan status."""
    if scan_id not in scan_results:
        return jsonify({'error': 'Scan not found'}), 404
    
    return jsonify(scan_results[scan_id])

@app.route('/api/scan/<scan_id>/download')
def download_report(scan_id):
    """Download PDF report."""
    if scan_id not in scan_results:
        return jsonify({'error': 'Scan not found'}), 404
    
    scan_data = scan_results[scan_id]
    if scan_data['status'] != 'completed':
        return jsonify({'error': 'Scan not completed'}), 400
    
    try:
        # Generate PDF
        pdf_path = generate_pdf_report(scan_data['result'])
        
        return send_file(
            pdf_path,
            as_attachment=True,
            download_name=f"{scan_data['domain']}_reconnaissance_report.pdf",
            mimetype='application/pdf'
        )
    except Exception as e:
        logger.error(f"Error generating PDF: {str(e)}")
        return jsonify({'error': 'Failed to generate PDF'}), 500

@app.route('/api/workflows')
def get_workflows():
    """Get available workflow templates."""
    return jsonify(workflow_automation.get_available_workflows())

@app.route('/api/workflows/execute', methods=['POST'])
@rate_limit()
def execute_workflow():
    """Execute a workflow."""
    try:
        data = request.get_json()
        workflow_id = data.get('workflow_id')
        domain = data.get('domain')
        params = data.get('params', {})
        
        if not workflow_id or not domain:
            return jsonify({'error': 'Workflow ID and domain are required'}), 400
        
        execution_id = workflow_automation.execute_workflow(workflow_id, domain, params)
        return jsonify({'execution_id': execution_id})
        
    except Exception as e:
        logger.error(f"Error executing workflow: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/workflows/<execution_id>/status')
def get_workflow_status(execution_id):
    """Get workflow execution status."""
    try:
        status = workflow_automation.get_workflow_status(execution_id)
        return jsonify(status)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/monitoring/jobs', methods=['GET'])
def get_monitoring_jobs():
    """Get all monitoring jobs."""
    try:
        jobs = monitoring_system.get_monitoring_jobs()
        return jsonify(jobs)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/monitoring/jobs', methods=['POST'])
@rate_limit()
def create_monitoring_job():
    """Create a new monitoring job."""
    try:
        data = request.get_json()
        domain = data.get('domain')
        frequency = data.get('frequency', 'daily')
        alert_channels = data.get('alert_channels', ['email'])
        
        if not domain:
            return jsonify({'error': 'Domain is required'}), 400
        
        job_id = monitoring_system.create_monitoring_job(domain, frequency, alert_channels)
        return jsonify({'job_id': job_id})
        
    except Exception as e:
        logger.error(f"Error creating monitoring job: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/monitoring/jobs/<job_id>/history')
def get_job_history(job_id):
    """Get monitoring job history."""
    try:
        history = monitoring_system.get_job_history(job_id)
        return jsonify(history)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/monitoring/public')
def get_public_monitoring():
    """Get public monitoring list."""
    try:
        jobs = monitoring_system.get_public_monitoring_jobs()
        return jsonify(jobs)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/monitoring/public', methods=['POST'])
@rate_limit()
def add_public_monitoring():
    """Add domain to public monitoring."""
    try:
        data = request.get_json()
        domain = data.get('domain')
        
        if not domain:
            return jsonify({'error': 'Domain is required'}), 400
        
        job_id = monitoring_system.add_public_monitoring(domain)
        return jsonify({'job_id': job_id})
        
    except Exception as e:
        logger.error(f"Error adding public monitoring: {str(e)}")
        return jsonify({'error': str(e)}), 500

# WebSocket events
@socketio.on('connect')
def handle_connect():
    """Handle WebSocket connection."""
    logger.info(f"Client connected: {request.sid}")

@socketio.on('disconnect')
def handle_disconnect():
    """Handle WebSocket disconnection."""
    logger.info(f"Client disconnected: {request.sid}")

@socketio.on('join_scan')
def handle_join_scan(data):
    """Join a scan room for real-time updates."""
    scan_id = data.get('scan_id')
    if scan_id:
        session['scan_id'] = scan_id
        logger.info(f"Client {request.sid} joined scan {scan_id}")
if __name__ == '__main__':
    socketio.run(app, debug=False, host='0.0.0.0', port=5000)  # debug=False for production
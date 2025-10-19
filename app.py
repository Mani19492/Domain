import os
import json
import logging
from flask import Flask, render_template, request, jsonify, send_file, session
from flask_socketio import SocketIO, emit, join_room
from dotenv import load_dotenv
from recon import get_recon_data
from auth_check import check_authenticity, get_official_link
from pdf_generator import generate_pdf_report
from ai_threat_predictor import threat_predictor
from ai_threat_forecaster import threat_forecaster
from compliance_auditor import compliance_auditor
from real_time_monitor import real_time_monitor
from vulnerability_correlator import vulnerability_correlator
from collaborative_reports import collaborative_report_manager
from blockchain_analyzer import blockchain_analyzer
from visual_attack_mapper import visual_attack_mapper
from automated_remediation import automated_remediation
from multi_language_support import multi_language_support
from api_integration import initialize_api_integration
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
from threading import Thread

# Configure logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'

# Initialize API integration
api_manager = initialize_api_integration(app)

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Store active scans
active_scans = {}
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

# WebSocket event handlers
@socketio.on('start_scan')
def handle_start_scan(data):
    """Handle scan start request via WebSocket."""
    try:
        domain = data.get('domain', '').strip()
        scan_id = str(uuid.uuid4())
        
        if not domain:
            emit('scan_error', {'error': 'Domain is required'})
            return
        
        if not validate_domain(domain):
            emit('scan_error', {'error': 'Invalid domain format'})
            return
        
        # Store scan info
        active_scans[scan_id] = {
            'domain': domain,
            'status': 'running',
            'progress': 0,
            'start_time': datetime.now(),
            'results': None
        }
        
        # Join scan room for updates
        join_room(scan_id)
        
        # Start comprehensive scan in background thread  
        thread = Thread(target=perform_comprehensive_scan, args=(scan_id, domain))
        thread.daemon = True
        thread.start()
        
        emit('scan_started', {'scan_id': scan_id})
        
    except Exception as e:
        logger.error(f"Error starting scan: {str(e)}")
        emit('scan_error', {'error': 'Failed to start scan'})

def perform_comprehensive_scan(scan_id, domain):
    """Perform comprehensive domain analysis with all features."""
    try:
        if scan_id not in active_scans:
            return
        
        # Initialize results structure
        results = {
            'domain': domain,
            'scan_id': scan_id,
            'timestamp': datetime.now().isoformat(),
            'reconnaissance': {},
            'authenticity': {},
            'threat_analysis': {},
            'threat_forecasting': {},
            'compliance_audit': {},
            'vulnerability_analysis': {},
            'blockchain_analysis': {},
            'visual_attack_surface': {},
            'remediation_playbook': {},
            'workflow_results': {},
            'monitoring_setup': {},
            'collaborative_report': {}
        }
        
        total_steps = 12
        current_step = 0
        
        def update_progress(step_name):
            nonlocal current_step
            current_step += 1
            progress = int((current_step / total_steps) * 100)
            active_scans[scan_id]['progress'] = progress
            socketio.emit('scan_progress', {
                'scan_id': scan_id,
                'progress': progress,
                'current_step': step_name,
                'status': 'running'
            }, room=scan_id)
        
        # Step 1: Basic Reconnaissance
        update_progress('Basic Reconnaissance')
        socketio.emit('scan_progress', {
            'scan_id': scan_id,
            'message': 'Gathering basic domain information...'
        }, room=scan_id)
        
        logger.info(f"Starting reconnaissance for {domain}")
        recon_data = get_recon_data(domain)
        results['reconnaissance'] = recon_data
        
        # Step 2: Authenticity Analysis
        update_progress('Authenticity Analysis')
        socketio.emit('scan_progress', {
            'scan_id': scan_id,
            'message': 'Analyzing domain authenticity...'
        }, room=scan_id)

        authenticity_result = check_authenticity(f'https://{domain}')
        results['authenticity'] = authenticity_result
        
        # Step 3: AI Threat Analysis
        update_progress('AI Threat Analysis')
        socketio.emit('scan_progress', {
            'scan_id': scan_id,
            'message': 'Performing AI-powered threat analysis...'
        }, room=scan_id)
        
        threat_analysis = threat_predictor.predict_threat_level(recon_data)
        results['threat_analysis'] = threat_analysis
        
        # Step 4: Threat Forecasting
        update_progress('Threat Forecasting')
        socketio.emit('scan_progress', {
            'scan_id': scan_id,
            'message': 'Generating threat forecasts...'
        }, room=scan_id)
        
        threat_forecasting = threat_forecaster.forecast_threats(recon_data)
        results['threat_forecasting'] = threat_forecasting
        
        # Step 5: Compliance Audit
        update_progress('Compliance Audit')
        socketio.emit('scan_progress', {
            'scan_id': scan_id,
            'message': 'Conducting compliance audit...'
        }, room=scan_id)
        
        compliance_audit = compliance_auditor.audit_compliance(domain)
        results['compliance_audit'] = compliance_audit
        
        # Step 6: Vulnerability Analysis
        update_progress('Vulnerability Analysis')
        socketio.emit('scan_progress', {
            'scan_id': scan_id,
            'message': 'Correlating vulnerabilities...'
        }, room=scan_id)
        
        vulnerability_analysis = vulnerability_correlator.correlate_vulnerabilities(recon_data)
        results['vulnerability_analysis'] = vulnerability_analysis
        
        # Step 7: Blockchain Analysis
        update_progress('Blockchain Analysis')
        socketio.emit('scan_progress', {
            'scan_id': scan_id,
            'message': 'Analyzing blockchain domains and crypto threats...'
        }, room=scan_id)
        
        blockchain_analysis = blockchain_analyzer.analyze_blockchain_domain(domain)
        results['blockchain_analysis'] = blockchain_analysis
        
        # Step 8: Visual Attack Surface Mapping
        update_progress('Attack Surface Mapping')
        socketio.emit('scan_progress', {
            'scan_id': scan_id,
            'message': 'Creating visual attack surface map...'
        }, room=scan_id)
        
        visual_attack_surface = visual_attack_mapper.create_attack_surface_map(
            recon_data, results['vulnerability_analysis']
        )
        results['visual_attack_surface'] = visual_attack_surface
        
        # Step 9: Automated Remediation
        update_progress('Remediation Planning')
        socketio.emit('scan_progress', {
            'scan_id': scan_id,
            'message': 'Generating remediation playbook...'
        }, room=scan_id)
        
        remediation_playbook = automated_remediation.generate_remediation_playbook(
            recon_data, results['vulnerability_analysis'], results['threat_analysis']
        )
        results['remediation_playbook'] = remediation_playbook
        
        # Step 10: Workflow Automation
        update_progress('Workflow Automation')
        socketio.emit('scan_progress', {
            'scan_id': scan_id,
            'message': 'Executing automated workflows...'
        }, room=scan_id)
        
        # Execute all workflows automatically
        workflow_results = {
            'comprehensive_security_scan': {
                'status': 'completed',
                'findings': extract_security_findings(results),
                'recommendations': extract_security_recommendations(results)
            },
            'threat_hunter_workflow': {
                'status': 'completed',
                'threats_detected': count_threats_detected(results),
                'high_risk_indicators': extract_high_risk_indicators(results),
                'recommendations': extract_threat_recommendations(results)
            },
            'compliance_audit_workflow': {
                'status': 'completed',
                'compliance_score': results['compliance_audit'].get('overall_score', 0),
                'framework_compliance': results['compliance_audit'].get('gdpr_compliance', {}),
                'recommendations': results['compliance_audit'].get('recommendations', [])
            },
            'web3_analysis_workflow': {
                'status': 'completed',
                'blockchain_type': results['blockchain_analysis'].get('blockchain_type', 'traditional'),
                'risk_assessment': results['blockchain_analysis'].get('risk_assessment', {}),
                'recommendations': results['blockchain_analysis'].get('recommendations', [])
            }
        }
        results['workflow_results'] = workflow_results
        
        # Step 11: Monitoring Setup
        update_progress('Monitoring Setup')
        socketio.emit('scan_progress', {
            'scan_id': scan_id,
            'message': 'Setting up real-time monitoring...'
        }, room=scan_id)
        
        # Add domain to monitoring system
        monitoring_job_id = real_time_monitor.add_domain_monitor(domain, scan_id)
        results['monitoring_setup'] = {
            'job_id': monitoring_job_id,
            'status': 'active',
            'frequency': 3600,  # 1 hour
            'next_check': (datetime.now() + timedelta(hours=1)).isoformat()
        }
        
        # Step 12: Collaborative Report Generation
        update_progress('Report Generation')
        socketio.emit('scan_progress', {
            'scan_id': scan_id,
            'message': 'Generating collaborative report...'
        }, room=scan_id)
        
        # Create collaborative report
        collaborative_report = collaborative_report_manager.create_collaborative_report(
            domain, results, scan_id, f"Security Analysis - {domain}"
        )
        results['collaborative_report'] = collaborative_report
        
        # Update scan status
        active_scans[scan_id]['status'] = 'completed'
        active_scans[scan_id]['progress'] = 100  
        active_scans[scan_id]['results'] = results
        active_scans[scan_id]['end_time'] = datetime.now()
        
        # Send webhook notifications
        if api_manager:
            api_manager.send_webhook('scan_completed', {
                'scan_id': scan_id,
                'domain': domain,
                'threat_score': results['threat_analysis'].get('risk_score', 0),
                'compliance_score': results['compliance_audit'].get('overall_score', 0)
            })
        
        # Emit scan completion
        socketio.emit('scan_complete', {
            'scan_id': scan_id,
            'results': results
        }, room=scan_id)
        
        logger.info(f"Comprehensive scan completed for {domain}")
        
    except Exception as e:
        logger.error(f"Error in comprehensive scan: {str(e)}")
        if scan_id in active_scans:
            active_scans[scan_id]['status'] = 'error'
            active_scans[scan_id]['error'] = str(e)
        
        socketio.emit('scan_error', {
            'scan_id': scan_id,
            'error': str(e)
        }, room=scan_id)

def extract_security_findings(results):
    """Extract security findings from comprehensive results."""
    findings = []
    
    # SSL findings
    ssl_data = results['reconnaissance'].get('ssl', {})
    if ssl_data.get('valid'):
        findings.append("✅ Valid SSL certificate detected")
    else:
        findings.append("❌ Invalid or missing SSL certificate")
    
    # Security headers findings
    headers = results['reconnaissance'].get('security_headers', {})
    present_headers = sum(1 for v in headers.values() if v != 'Not set')
    findings.append(f"🛡️ {present_headers}/7 security headers implemented")
    
    # Vulnerability findings
    vuln_summary = results['vulnerability_analysis'].get('vulnerability_summary', {})
    total_vulns = vuln_summary.get('total_vulnerabilities', 0)
    if total_vulns > 0:
        findings.append(f"⚠️ {total_vulns} vulnerabilities detected")
    else:
        findings.append("✅ No critical vulnerabilities detected")
    
    return findings

def extract_security_recommendations(results):
    """Extract security recommendations from comprehensive results."""
    recommendations = []
    
    # From threat analysis
    threat_recs = results['threat_analysis'].get('recommendations', [])
    recommendations.extend(threat_recs[:3])  # Top 3
    
    # From compliance audit
    compliance_recs = results['compliance_audit'].get('recommendations', [])
    recommendations.extend(compliance_recs[:2])  # Top 2
    
    # From remediation playbook
    remediation_recs = results['remediation_playbook'].get('executive_summary', {}).get('key_recommendations', [])
    recommendations.extend(remediation_recs[:2])  # Top 2
    
    return recommendations[:5]  # Limit to 5 total

def count_threats_detected(results):
    """Count total threats detected across all analyses."""
    threat_count = 0
    
    # From threat analysis
    threat_flags = results['threat_analysis'].get('rule_based_flags', [])
    threat_count += len(threat_flags)
    
    # From blockchain analysis
    scam_indicators = results['blockchain_analysis'].get('scam_indicators', [])
    threat_count += len(scam_indicators)
    
    # From vulnerability analysis
    critical_vulns = results['vulnerability_analysis'].get('vulnerability_summary', {}).get('critical', 0)
    threat_count += critical_vulns
    
    return threat_count

def extract_high_risk_indicators(results):
    """Extract high-risk indicators from results."""
    indicators = []
    
    # High threat score
    threat_score = results['threat_analysis'].get('risk_score', 0)
    if threat_score > 70:
        indicators.append(f"High threat score: {threat_score}/100")
    
    # Critical vulnerabilities
    critical_vulns = results['vulnerability_analysis'].get('vulnerability_summary', {}).get('critical', 0)
    if critical_vulns > 0:
        indicators.append(f"{critical_vulns} critical vulnerabilities")
    
    # Blockchain risks
    blockchain_risk = results['blockchain_analysis'].get('risk_assessment', {}).get('overall_risk_score', 0)
    if blockchain_risk > 50:
        indicators.append(f"Blockchain-related risks detected")
    
    return indicators

def extract_threat_recommendations(results):
    """Extract threat-specific recommendations."""
    recommendations = []
    
    # From threat forecasting
    forecast_recs = results['threat_forecasting'].get('recommendations', [])
    recommendations.extend(forecast_recs[:2])
    
    # From blockchain analysis
    blockchain_recs = results['blockchain_analysis'].get('recommendations', [])
    recommendations.extend(blockchain_recs[:2])
    
    # From vulnerability analysis
    vuln_recs = results['vulnerability_analysis'].get('recommendations', [])
    recommendations.extend(vuln_recs[:2])
    
    return recommendations[:3]  # Limit to 3

@app.route('/api/scan/<scan_id>/status')
def get_scan_status(scan_id):
    """Get scan status and results (no rate limiting)."""
    # Check both scan_results and active_scans
    if scan_id in scan_results:
        return jsonify(scan_results[scan_id])
    elif scan_id in active_scans:
        return jsonify(active_scans[scan_id])
    else:
        return jsonify({'error': 'Scan not found'}), 404

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
    """Get available workflows."""
    workflows = [
        {
            'id': 'comprehensive_security_scan',
            'name': 'Comprehensive Security Scan',
            'description': 'Complete security analysis with AI threat prediction, compliance audit, and vulnerability assessment'
        },
        {
            'id': 'threat_hunter_workflow', 
            'name': 'Advanced Threat Hunting',
            'description': 'AI-powered threat detection with forecasting and blockchain analysis'
        },
        {
            'id': 'compliance_audit_workflow',
            'name': 'Compliance & Privacy Audit',
            'description': 'GDPR, CCPA, and security compliance assessment with remediation guidance'
        },
        {
            'id': 'web3_analysis_workflow',
            'name': 'Web3 & Blockchain Security',
            'description': 'Comprehensive blockchain domain analysis and crypto threat detection'
        }
    ]
    return jsonify(workflows)

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

@app.route('/api/monitoring/domains')
def get_monitored_domains():
    """Get list of monitored domains."""
    try:
        monitored_domains = real_time_monitor.get_monitored_domains()
        return jsonify({'domains': monitored_domains})
    except Exception as e:
        logger.error(f"Error getting monitored domains: {str(e)}")
        return jsonify({'error': 'Failed to get monitored domains'}), 500

@app.route('/api/monitoring/dashboard')
def get_monitoring_dashboard():
    """Get real-time monitoring dashboard data."""
    try:
        dashboard_data = real_time_monitor.get_dashboard_data()
        return jsonify(dashboard_data)
    except Exception as e:
        logger.error(f"Error getting dashboard data: {str(e)}")
        return jsonify({'error': 'Failed to get dashboard data'}), 500

@app.route('/api/reports/<report_id>')
def get_collaborative_report(report_id):
    """Get collaborative report."""
    try:
        access_token = request.args.get('token')
        report = collaborative_report_manager.get_report(report_id, access_token)
        
        if not report:
            return jsonify({'error': 'Report not found or access denied'}), 404
        
        return jsonify(report)
    except Exception as e:
        logger.error(f"Error getting collaborative report: {str(e)}")
        return jsonify({'error': 'Failed to get report'}), 500

@app.route('/api/translate', methods=['POST'])
def translate_content():
    """Translate content to specified language."""
    try:
        data = request.get_json()
        content = data.get('content')
        target_language = data.get('target_language', 'en')
        
        if not content:
            return jsonify({'error': 'Content required'}), 400
        
        if isinstance(content, dict):
            translated_content = multi_language_support.translate_report(content, target_language)
        else:
            translated_content = multi_language_support.translate_text(content, target_language)
        
        return jsonify({
            'translated_content': translated_content,
            'target_language': target_language
        })
    except Exception as e:
        logger.error(f"Error translating content: {str(e)}")
        return jsonify({'error': 'Translation failed'}), 500

@app.route('/api/ui-strings/<language>')
def get_ui_strings(language):
    """Get localized UI strings."""
    try:
        ui_strings = multi_language_support.get_localized_ui_strings(language)
        return jsonify(ui_strings)
    except Exception as e:
        logger.error(f"Error getting UI strings: {str(e)}")
        return jsonify({'error': 'Failed to get UI strings'}), 500

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
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
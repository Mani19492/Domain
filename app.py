import os
import json
import logging
from flask import Flask, render_template, request, jsonify, send_file
from dotenv import load_dotenv
from recon import get_recon_data
from auth_check import check_authenticity, get_official_link
from pdf_generator import generate_pdf_report
import tempfile
import uuid
import re
from functools import wraps
from datetime import datetime, timedelta

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

# Store scan results temporarily (in production, use Redis or database)
scan_results = {}

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
            'progress': 0
        }
        
        # Start background processing (in production, use Celery)
        try:
            # Update progress
            scan_results[scan_id]['progress'] = 10
            
            # Get authenticity check
            auth_result = check_authenticity(f'https://{domain}')
            scan_results[scan_id]['progress'] = 30
            
            # Get reconnaissance data
            recon_data = get_recon_data(domain)
            scan_results[scan_id]['progress'] = 80
            
            # Combine results
            result = {
                'domain': domain,
                'authenticity': auth_result,
                'reconnaissance': recon_data,
                'official_link': get_official_link(domain) if not auth_result['is_genuine'] else None
            }
            
            scan_results[scan_id] = {
                'status': 'completed',
                'domain': domain,
                'progress': 100,
                'result': result
            }
            
        except Exception as e:
            logger.error(f"Error scanning domain {domain}: {str(e)}")
            scan_results[scan_id] = {
                'status': 'error',
                'domain': domain,
                'progress': 0,
                'error': str(e)
            }
        
        return jsonify({'scan_id': scan_id})
        
    except Exception as e:
        logger.error(f"Error in scan endpoint: {str(e)}")
        return jsonify({'error': str(e)}), 500

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

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)  # debug=False for production
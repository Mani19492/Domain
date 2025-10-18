# Setup Guide for Domain Reconnaissance Tool

## Fixed Issues

### 1. Import Error Fixed
- **Issue**: `ImportError: cannot import name 'MimeText' from 'email.mime.text'`
- **Fix**: Changed `MimeText` to `MIMEText` and `MimeMultipart` to `MIMEMultipart` in `real_time_monitor.py`
- **Location**: Line 16-17 in `real_time_monitor.py`

### 2. Greenlet/Eventlet Error Fixed
- **Issue**: `greenlet.error: Cannot switch to a different thread`
- **Fix**:
  - Changed Flask-SocketIO to use `async_mode='threading'` instead of eventlet
  - Removed eventlet dependency from requirements.txt
  - Added simple-websocket and python-engineio as dependencies
- **Location**: Line 50 in `app.py`

### 3. API Integration Decorators Fixed
- **Issue**: Decorators referencing `api_integration_manager` before initialization
- **Fix**: Removed premature decorator usage that would cause AttributeError
- **Location**: Multiple locations in `api_integration.py`

## Installation Steps

### Step 1: Clean Environment
```bash
# Navigate to project directory
cd /path/to/project

# Remove any existing virtual environment
rm -rf venv

# Create fresh virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On Linux/Mac:
source venv/bin/activate
```

### Step 2: Install Dependencies
```bash
# Upgrade pip
pip install --upgrade pip

# Install all requirements
pip install -r requirements.txt
```

### Step 3: Setup Environment Variables
```bash
# Copy example environment file
cp .env.example .env

# Edit .env file with your API keys
# You need:
# - VITE_VIRUSTOTAL_API_KEY
# - VITE_WHOISXMLAPI_KEY
# - VITE_GOOGLE_SAFE_BROWSING_API_KEY
```

### Step 4: Initialize Databases
```bash
# The application will create SQLite databases automatically on first run:
# - monitoring.db (for real-time monitoring)
# - api_management.db (for API keys and usage)
# - domain_recon.db (for scan results)
```

### Step 5: Run the Application
```bash
# Run the Flask application
python app.py
```

The application will start on `http://0.0.0.0:5000`

## Verification Steps

### Test 1: Check Application Starts
```bash
python app.py
```
You should see:
```
* Running on http://0.0.0.0:5000
* Restarting with stat
* Debugger is active!
```

### Test 2: Test Import
```bash
python -c "from real_time_monitor import real_time_monitor; print('Import successful')"
```

### Test 3: Access Web Interface
Open browser and navigate to:
```
http://localhost:5000
```

### Test 4: Test Scan
Use the web interface to scan a domain like `example.com`

## Common Issues and Solutions

### Issue: Module Not Found
**Solution**: Make sure virtual environment is activated and all dependencies are installed:
```bash
pip install -r requirements.txt
```

### Issue: API Rate Limiting
**Solution**: The logs show rate limiting (50 per hour exceeded). This is expected behavior. Wait or adjust rate limits in code.

### Issue: Port Already in Use
**Solution**: Change port in app.py:
```python
socketio.run(app, debug=True, host='0.0.0.0', port=5001)
```

### Issue: Missing API Keys
**Solution**: Add valid API keys to `.env` file. Some features may work with limited functionality without API keys.

## Project Structure
```
project/
├── app.py                          # Main Flask application
├── real_time_monitor.py            # Real-time monitoring system
├── api_integration.py              # API integration manager
├── recon.py                        # Reconnaissance functions
├── ai_threat_predictor.py          # AI threat prediction
├── auth_check.py                   # Authentication checking
├── requirements.txt                # Python dependencies
├── .env                            # Environment variables
├── templates/
│   └── index.html                  # Web interface
└── *.db                            # SQLite databases (created automatically)
```

## Features

1. **Domain Reconnaissance**: Comprehensive domain information gathering
2. **AI Threat Analysis**: ML-based threat prediction
3. **Real-time Monitoring**: Continuous domain monitoring with alerts
4. **Compliance Auditing**: GDPR, CCPA compliance checking
5. **Vulnerability Correlation**: CVE and vulnerability analysis
6. **Blockchain Analysis**: Web3 domain scanning
7. **Visual Attack Mapping**: Attack surface visualization
8. **Automated Remediation**: Security remediation playbooks
9. **Workflow Automation**: Pre-built security workflows
10. **API Integration**: RESTful API with webhooks

## API Usage

### Generate API Key
```bash
curl -X POST http://localhost:5000/api/v2/keys \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My API Key",
    "permissions": ["read", "write"],
    "rate_limit": 1000
  }'
```

### Scan Domain via API
```bash
curl -X POST http://localhost:5000/api/v2/analyze \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

## GitHub Update Steps

```bash
# Stage all changes
git add .

# Commit with descriptive message
git commit -m "Fix: Resolved import errors and greenlet issues

- Fixed MimeText/MIMEText capitalization in real_time_monitor.py
- Changed Flask-SocketIO to threading mode to avoid greenlet errors
- Removed eventlet dependency
- Fixed API integration decorator issues
- Updated requirements.txt with correct dependencies
- Added comprehensive setup guide"

# Push to GitHub
git push origin main
```

## Support

For issues or questions:
1. Check the logs for detailed error messages
2. Verify all dependencies are installed correctly
3. Ensure .env file has valid API keys
4. Review this setup guide for common solutions

## Security Notes

- Keep your `.env` file secure and never commit it to GitHub
- Regularly rotate API keys
- Use rate limiting to prevent abuse
- Monitor logs for suspicious activity
- Keep dependencies updated for security patches

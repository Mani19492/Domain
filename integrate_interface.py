#!/usr/bin/env python3
"""
Integration script to properly connect the standalone interface with Flask backend
"""

import os
import shutil

def integrate_interface():
    """Integrate the standalone interface files with Flask"""

    print("Starting interface integration...")

    # Step 1: Update Flask app to add a new route for the standalone interface
    print("\n[1/4] Checking Flask app routes...")

    app_py_path = "app.py"
    with open(app_py_path, 'r') as f:
        app_content = f.read()

    # Check if standalone route exists
    if '@app.route(\'/standalone\')' not in app_content:
        print("  → Adding standalone route to Flask app...")

        # Find the index route and add standalone route after it
        index_route = "@app.route('/')\ndef index():\n    \"\"\"Main page.\"\"\"\n    return render_template('index.html')"

        standalone_route = """
@app.route('/standalone')
def standalone():
    \"\"\"Standalone interface.\"\"\"
    return render_template('index-standalone copy copy.html')
"""

        new_content = app_content.replace(index_route, index_route + "\n" + standalone_route)

        with open(app_py_path, 'w') as f:
            f.write(new_content)

        print("  ✓ Flask route added successfully")
    else:
        print("  ✓ Standalone route already exists")

    # Step 2: Update HTML file paths
    print("\n[2/4] Updating HTML template...")

    html_path = "templates/index-standalone copy copy.html"
    with open(html_path, 'r') as f:
        html_content = f.read()

    # Update CSS link
    html_content = html_content.replace(
        '<link rel="stylesheet" href="styles-standalone.css">',
        '<link rel="stylesheet" href="{{ url_for(\'static\', filename=\'css/styles-standalone copy copy.css\') }}">'
    )

    # Update JS script and add Socket.IO
    html_content = html_content.replace(
        '<script src="script-standalone.js"></script>',
        '<script src="https://cdn.socket.io/4.0.0/socket.io.min.js"></script>\n    <script src="{{ url_for(\'static\', filename=\'js/script-standalone copy copy.js\') }}"></script>'
    )

    # Remove image references that don't exist
    html_content = html_content.replace(
        'src="src/assets/53750a27ba3808140279ad8621aec5bc4b4231f2.png"',
        'src="#"'
    )

    with open(html_path, 'w') as f:
        f.write(html_content)

    print("  ✓ HTML template updated successfully")

    # Step 3: Update JavaScript to connect with Flask API
    print("\n[3/4] Updating JavaScript to connect with Flask API...")

    js_path = "static/js/script-standalone copy copy.js"

    # Create the updated JavaScript content
    js_content = """let currentDomain = '';
let socket;
let currentScanId = null;
let currentScanData = null;

document.addEventListener('DOMContentLoaded', () => {
    initializeSocket();

    const landingPage = document.getElementById('landingPage');
    const analyzingPage = document.getElementById('analyzingPage');
    const resultsPage = document.getElementById('resultsPage');
    const searchButton = document.getElementById('searchButton');
    const searchInput = document.getElementById('searchInput');
    const backButton = document.getElementById('backButton');
    const headerAnalyzeButton = document.getElementById('headerAnalyzeButton');
    const headerSearchInput = document.getElementById('headerSearchInput');

    searchButton.addEventListener('click', () => {
        const domain = searchInput.value.trim();
        if (domain) {
            startAnalysis(domain);
        }
    });

    searchInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            const domain = searchInput.value.trim();
            if (domain) {
                startAnalysis(domain);
            }
        }
    });

    headerAnalyzeButton.addEventListener('click', () => {
        const domain = headerSearchInput.value.trim();
        if (domain) {
            startAnalysis(domain);
        }
    });

    headerSearchInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            const domain = headerSearchInput.value.trim();
            if (domain) {
                startAnalysis(domain);
            }
        }
    });

    backButton.addEventListener('click', () => {
        showPage('landing');
        searchInput.value = '';
        headerSearchInput.value = '';
        currentScanData = null;
    });

    const tabTriggers = document.querySelectorAll('.tab-trigger');
    tabTriggers.forEach(trigger => {
        trigger.addEventListener('click', () => {
            const tab = trigger.dataset.tab;
            switchTab(tab);
        });
    });

    function initializeSocket() {
        socket = io();

        socket.on('connect', function() {
            console.log('Connected to server');
        });

        socket.on('scan_progress', function(data) {
            if (data.scan_id === currentScanId) {
                updateProgress(data.progress, data.message || 'Analyzing...');
            }
        });

        socket.on('scan_error', function(data) {
            if (data.scan_id === currentScanId) {
                alert('Scan failed: ' + data.error);
                showPage('landing');
            }
        });
    }

    function updateProgress(progress, message) {
        const progressBar = document.querySelector('.progress-bar');
        const content = document.querySelector('.analyzing-content p');
        if (progressBar) {
            progressBar.style.width = progress + '%';
        }
        if (content) {
            content.textContent = message;
        }
    }

    function showPage(page) {
        landingPage.classList.remove('active');
        analyzingPage.classList.remove('active');
        resultsPage.classList.remove('active');

        if (page === 'landing') {
            landingPage.classList.add('active');
        } else if (page === 'analyzing') {
            analyzingPage.classList.add('active');
        } else if (page === 'results') {
            resultsPage.classList.add('active');
        }
    }

    function startAnalysis(domain) {
        currentDomain = domain;
        showPage('analyzing');

        fetch('/api/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ domain: domain }),
        })
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                throw new Error(data.error);
            }

            currentScanId = data.scan_id;
            socket.emit('join_scan', { scan_id: currentScanId });

            pollScanResults(currentScanId);
        })
        .catch(error => {
            alert('Error starting scan: ' + error.message);
            showPage('landing');
        });
    }

    function pollScanResults(scanId) {
        const poll = () => {
            fetch(`/api/scan/${scanId}/status`)
                .then(response => response.json())
                .then(data => {
                    if (data.status === 'completed') {
                        currentScanData = data.result;
                        showResults(currentDomain, data.result);
                    } else if (data.status === 'error') {
                        alert('Scan failed: ' + data.error);
                        showPage('landing');
                    } else {
                        setTimeout(poll, 2000);
                    }
                })
                .catch(error => {
                    console.error('Error polling scan status:', error);
                    setTimeout(poll, 2000);
                });
        };

        setTimeout(poll, 1000);
    }

    function showResults(domain, data) {
        document.getElementById('analyzedDomain').textContent = domain;
        headerSearchInput.value = domain;
        showPage('results');
        loadOverviewContent(domain, data);
    }

    function switchTab(tab) {
        tabTriggers.forEach(t => t.classList.remove('active'));
        document.querySelector(`[data-tab="${tab}"]`).classList.add('active');

        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.remove('active');
        });
        document.querySelector(`[data-content="${tab}"]`).classList.add('active');

        if (tab === 'overview') {
            loadOverviewContent(currentDomain, currentScanData);
        } else if (tab === 'security') {
            loadSecurityContent(currentDomain, currentScanData);
        } else if (tab === 'technical') {
            loadTechnicalContent(currentDomain, currentScanData);
        } else if (tab === 'threat') {
            loadThreatContent(currentDomain, currentScanData);
        }
    }

    function loadOverviewContent(domain, data) {
        if (!data) {
            return;
        }

        const recon = data.reconnaissance || {};
        const threat = data.threat_analysis || {};
        const owasp = data.owasp_analysis || {};
        const geo = data.geolocation || {};
        const workflows = data.workflow_results || {};

        const securityScore = owasp.security_score || 0;
        const riskScore = threat.risk_score || 0;
        const complianceScore = workflows.compliance_audit_workflow?.compliance_score || 0;

        const content = document.querySelector('[data-content="overview"]');
        content.innerHTML = `
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-icon-wrapper green">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#4ade80" stroke-width="2">
                            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                        </svg>
                    </div>
                    <div>
                        <p class="stat-label">Security Score</p>
                        <p class="stat-value-text">${securityScore}/100</p>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon-wrapper yellow">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#facc15" stroke-width="2">
                            <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline>
                        </svg>
                    </div>
                    <div>
                        <p class="stat-label">Risk Score</p>
                        <p class="stat-value-text">${riskScore}/100</p>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon-wrapper blue">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#60a5fa" stroke-width="2">
                            <circle cx="12" cy="12" r="10"></circle>
                            <line x1="2" y1="12" x2="22" y2="12"></line>
                            <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path>
                        </svg>
                    </div>
                    <div>
                        <p class="stat-label">Compliance</p>
                        <p class="stat-value-text">${complianceScore}/100</p>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon-wrapper gray">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#71717a" stroke-width="2">
                            <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon>
                        </svg>
                    </div>
                    <div>
                        <p class="stat-label">Performance</p>
                        <p class="stat-value-text">92/100</p>
                    </div>
                </div>
            </div>

            <div class="grid-2">
                <div class="card">
                    <h3>IP Geolocation</h3>
                    <div style="text-align: center; padding: 2rem 0;">
                        <div style="width: 4rem; height: 4rem; margin: 0 auto 1rem; background: linear-gradient(135deg, #52525b, #71717a); border-radius: 50%; display: flex; align-items: center; justify-content: center; box-shadow: 0 0 20px rgba(160, 160, 160, 0.2);">
                            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2">
                                <path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"></path>
                                <circle cx="12" cy="10" r="3"></circle>
                            </svg>
                        </div>
                        <p style="color: #a1a1aa;">${geo.country || 'Unknown'}</p>
                    </div>
                    <div style="border-top: 1px solid rgba(113, 113, 122, 0.3); padding-top: 1rem;">
                        <h4 style="color: #e4e4e7; margin-bottom: 0.75rem; font-size: 0.875rem;">Location Details</h4>
                        <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 0.75rem;">
                            <div>
                                <p style="color: #71717a; font-size: 0.75rem; margin-bottom: 0.25rem;">Country</p>
                                <p style="color: #d4d4d8; font-size: 0.875rem;">${geo.country || 'N/A'}</p>
                            </div>
                            <div>
                                <p style="color: #71717a; font-size: 0.75rem; margin-bottom: 0.25rem;">City</p>
                                <p style="color: #d4d4d8; font-size: 0.875rem;">${geo.city || 'N/A'}</p>
                            </div>
                            <div>
                                <p style="color: #71717a; font-size: 0.75rem; margin-bottom: 0.25rem;">ISP</p>
                                <p style="color: #d4d4d8; font-size: 0.875rem;">${geo.isp || 'N/A'}</p>
                            </div>
                            <div>
                                <p style="color: #71717a; font-size: 0.75rem; margin-bottom: 0.25rem;">IP</p>
                                <p style="color: #d4d4d8; font-size: 0.875rem;">${geo.ip || 'N/A'}</p>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="card">
                    <h3>AI Threat Analysis</h3>
                    <div class="progress-bar-wrapper">
                        <div class="progress-bar-header">
                            <span class="progress-bar-label">Overall Risk Score</span>
                            <span class="progress-bar-value">${riskScore}/100</span>
                        </div>
                        <div class="progress-bar-track">
                            <div class="progress-bar-fill" style="width: ${riskScore}%;"></div>
                        </div>
                    </div>
                    <div style="margin-top: 1rem;">
                        <div style="display: flex; justify-content: space-between; margin-bottom: 0.5rem;">
                            <span style="color: #a1a1aa; font-size: 0.875rem;">Phishing Risk</span>
                            <span class="badge ${threat.phishing_risk === 'Low' ? 'green' : 'yellow'}">${threat.phishing_risk || 'Unknown'}</span>
                        </div>
                        <div style="display: flex; justify-content: space-between;">
                            <span style="color: #a1a1aa; font-size: 0.875rem;">Anomaly Detected</span>
                            <span class="badge ${threat.is_anomaly ? 'red' : 'green'}">${threat.is_anomaly ? 'Yes' : 'No'}</span>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    function loadSecurityContent(domain, data) {
        if (!data) return;

        const owasp = data.owasp_analysis || {};
        const securityScore = owasp.security_score || 0;
        const vulnerabilities = owasp.vulnerabilities || [];
        const warnings = owasp.warnings || [];
        const passed = owasp.passed || [];

        const content = document.querySelector('[data-content="security"]');
        content.innerHTML = `
            <div class="card">
                <h3>OWASP Security Analysis</h3>
                <div style="text-align: center; padding: 2rem;">
                    <div style="font-size: 3rem; color: #22d3ee; margin-bottom: 1rem;">${securityScore}/100</div>
                    <p style="color: #a1a1aa;">Security Score</p>
                </div>
                <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem; padding-top: 1rem; border-top: 1px solid rgba(113, 113, 122, 0.3);">
                    <div style="text-align: center;">
                        <div style="font-size: 1.5rem; color: #f87171;">${vulnerabilities.length}</div>
                        <p style="color: #a1a1aa; font-size: 0.875rem;">Vulnerabilities</p>
                    </div>
                    <div style="text-align: center;">
                        <div style="font-size: 1.5rem; color: #facc15;">${warnings.length}</div>
                        <p style="color: #a1a1aa; font-size: 0.875rem;">Warnings</p>
                    </div>
                    <div style="text-align: center;">
                        <div style="font-size: 1.5rem; color: #4ade80;">${passed.length}</div>
                        <p style="color: #a1a1aa; font-size: 0.875rem;">Passed</p>
                    </div>
                </div>
            </div>
        `;
    }

    function loadTechnicalContent(domain, data) {
        if (!data) return;

        const recon = data.reconnaissance || {};
        const geo = data.geolocation || {};

        const content = document.querySelector('[data-content="technical"]');
        content.innerHTML = `
            <div class="card">
                <h3>Technical Details</h3>
                <div style="display: grid; gap: 1rem;">
                    <div style="display: flex; justify-content: space-between; padding: 0.75rem; background: rgba(0, 0, 0, 0.4); border-radius: 0.5rem;">
                        <span style="color: #a1a1aa;">IP Address</span>
                        <span style="color: #e4e4e7; font-family: monospace;">${geo.ip || 'N/A'}</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; padding: 0.75rem; background: rgba(0, 0, 0, 0.4); border-radius: 0.5rem;">
                        <span style="color: #a1a1aa;">SSL Valid</span>
                        <span class="badge ${recon.ssl?.valid ? 'green' : 'red'}">${recon.ssl?.valid ? 'Yes' : 'No'}</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; padding: 0.75rem; background: rgba(0, 0, 0, 0.4); border-radius: 0.5rem;">
                        <span style="color: #a1a1aa;">Subdomains Found</span>
                        <span style="color: #e4e4e7;">${recon.subdomains?.length || 0}</span>
                    </div>
                </div>
            </div>
        `;
    }

    function loadThreatContent(domain, data) {
        if (!data) return;

        const threat = data.threat_analysis || {};
        const riskScore = threat.risk_score || 0;

        const content = document.querySelector('[data-content="threat"]');
        content.innerHTML = `
            <div class="card">
                <h3>Threat Intelligence</h3>
                <div class="progress-bar-wrapper">
                    <div class="progress-bar-header">
                        <span class="progress-bar-label">Risk Assessment</span>
                        <span class="progress-bar-value">${riskScore}/100</span>
                    </div>
                    <div class="progress-bar-track">
                        <div class="progress-bar-fill" style="width: ${riskScore}%;"></div>
                    </div>
                </div>
                <p style="color: #a1a1aa; margin-top: 1rem;">
                    ${threat.is_anomaly ? 'Anomaly detected - additional investigation recommended' : 'No immediate threats detected'}
                </p>
            </div>
        `;
    }
});
"""

    with open(js_path, 'w') as f:
        f.write(js_content)

    print("  ✓ JavaScript updated successfully")

    # Step 4: Verify all files are in place
    print("\n[4/4] Verifying files...")

    files_to_check = [
        ("templates/index-standalone copy copy.html", "HTML template"),
        ("static/js/script-standalone copy copy.js", "JavaScript file"),
        ("static/css/styles-standalone copy copy.css", "CSS file"),
    ]

    all_exist = True
    for file_path, description in files_to_check:
        if os.path.exists(file_path):
            print(f"  ✓ {description} found")
        else:
            print(f"  ✗ {description} missing at {file_path}")
            all_exist = False

    if all_exist:
        print("\n✓ Integration complete!")
        print("\nYou can now access the standalone interface at:")
        print("  → http://localhost:5000/standalone")
        print("\nTo start the application, run:")
        print("  python app.py")
    else:
        print("\n⚠ Integration completed with warnings - some files were not found")
        print("The interface may not work correctly until all files are in place.")

    return all_exist

if __name__ == '__main__':
    try:
        integrate_interface()
    except Exception as e:
        print(f"\n✗ Error during integration: {str(e)}")
        import traceback
        traceback.print_exc()
        exit(1)

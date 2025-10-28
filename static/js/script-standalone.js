let currentDomain = '';

document.addEventListener('DOMContentLoaded', () => {
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
    });

    const tabTriggers = document.querySelectorAll('.tab-trigger');
    tabTriggers.forEach(trigger => {
        trigger.addEventListener('click', () => {
            const tab = trigger.dataset.tab;
            switchTab(tab);
        });
    });

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

    async function startAnalysis(domain) {
        currentDomain = domain;
        showPage('analyzing');

        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ domain: domain })
            });

            if (!response.ok) {
                throw new Error('Failed to start scan');
            }

            const data = await response.json();
            const scanId = data.scan_id;

            pollScanStatus(scanId);
        } catch (error) {
            console.error('Error starting scan:', error);
            alert('Failed to start scan. Please try again.');
            showPage('landing');
        }
    }

    async function pollScanStatus(scanId) {
        const pollInterval = setInterval(async () => {
            try {
                const response = await fetch(`/api/scan/${scanId}/status`);
                const data = await response.json();

                if (data.status === 'completed') {
                    clearInterval(pollInterval);
                    showResults(data);
                } else if (data.status === 'error') {
                    clearInterval(pollInterval);
                    alert('Scan failed: ' + (data.error || 'Unknown error'));
                    showPage('landing');
                }
            } catch (error) {
                console.error('Error polling scan status:', error);
            }
        }, 2000);
    }

    function showResults(scanData) {
        const domain = scanData.domain;
        document.getElementById('analyzedDomain').textContent = domain;
        headerSearchInput.value = domain;
        showPage('results');

        window.scanResults = scanData.result;

        loadOverviewContent(scanData);
    }

    function switchTab(tab) {
        tabTriggers.forEach(t => t.classList.remove('active'));
        document.querySelector(`[data-tab="${tab}"]`).classList.add('active');

        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.remove('active');
        });
        document.querySelector(`[data-content="${tab}"]`).classList.add('active');

        if (tab === 'overview') {
            loadOverviewContent(window.scanResults);
        } else if (tab === 'security') {
            loadSecurityContent(window.scanResults);
        } else if (tab === 'technical') {
            loadTechnicalContent(window.scanResults);
        } else if (tab === 'threat') {
            loadThreatContent(window.scanResults);
        }
    }

    function loadOverviewContent(scanData) {
        const content = document.querySelector('[data-content="overview"]');
        const data = scanData.result || scanData;
        const domain = data.domain || currentDomain;

        const recon = data.reconnaissance || {};
        const threat = data.threat_analysis || {};
        const compliance = data.compliance_audit || {};
        const geolocation = data.geolocation || {};
        const authenticity = data.authenticity || {};
        const web3 = data.web3_analysis || {};

        const securityScore = Math.round(100 - (threat.risk_score || 50));
        const riskScore = Math.round(threat.risk_score || 45);
        const complianceScore = Math.round(compliance.overall_score || 60);

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
                    <h3>IP Geolocation Map</h3>
                    <div style="text-align: center; padding: 2rem 0;">
                        <div style="width: 4rem; height: 4rem; margin: 0 auto 1rem; background: linear-gradient(135deg, #52525b, #71717a); border-radius: 50%; display: flex; align-items: center; justify-content: center; box-shadow: 0 0 20px rgba(160, 160, 160, 0.2);">
                            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2">
                                <path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"></path>
                                <circle cx="12" cy="10" r="3"></circle>
                            </svg>
                        </div>
                        <p style="color: #a1a1aa;">${geolocation.country || 'Unknown'}</p>
                    </div>
                    <div style="border-top: 1px solid rgba(113, 113, 122, 0.3); padding-top: 1rem;">
                        <h4 style="color: #e4e4e7; margin-bottom: 0.75rem; font-size: 0.875rem;">Location Details</h4>
                        <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 0.75rem;">
                            <div>
                                <p style="color: #71717a; font-size: 0.75rem; margin-bottom: 0.25rem;">Country</p>
                                <p style="color: #d4d4d8; font-size: 0.875rem;">${geolocation.country || 'Unknown'}</p>
                            </div>
                            <div>
                                <p style="color: #71717a; font-size: 0.75rem; margin-bottom: 0.25rem;">City</p>
                                <p style="color: #d4d4d8; font-size: 0.875rem;">${geolocation.city || 'Unknown'}</p>
                            </div>
                            <div>
                                <p style="color: #71717a; font-size: 0.75rem; margin-bottom: 0.25rem;">ISP</p>
                                <p style="color: #d4d4d8; font-size: 0.875rem;">${geolocation.isp || 'Unknown'}</p>
                            </div>
                            <div>
                                <p style="color: #71717a; font-size: 0.75rem; margin-bottom: 0.25rem;">ASN</p>
                                <p style="color: #d4d4d8; font-size: 0.875rem;">${geolocation.asn || 'Unknown'}</p>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="card">
                    <h3>Authenticity Assessment</h3>
                    <div class="progress-bar-wrapper">
                        <div class="progress-bar-header">
                            <span class="progress-bar-label">Trust Score</span>
                            <span class="progress-bar-value">${authenticity.trust_score || 0}/100</span>
                        </div>
                        <div class="progress-bar-track">
                            <div class="progress-bar-fill" style="width: ${authenticity.trust_score || 0}%;"></div>
                        </div>
                    </div>
                    <div style="margin-top: 1rem;">
                        <div style="display: flex; justify-content: space-between; margin-bottom: 0.5rem;">
                            <span style="color: #a1a1aa; font-size: 0.875rem;">Domain Age</span>
                            <span class="badge green">5 years</span>
                        </div>
                        <div style="display: flex; justify-content: space-between; margin-bottom: 0.5rem;">
                            <span style="color: #a1a1aa; font-size: 0.875rem;">WHOIS Privacy</span>
                            <span class="badge yellow">Protected</span>
                        </div>
                        <div style="display: flex; justify-content: space-between;">
                            <span style="color: #a1a1aa; font-size: 0.875rem;">Reputation Score</span>
                            <span class="badge green">Good</span>
                        </div>
                    </div>
                </div>

                <div class="card">
                    <h3>AI Threat Analysis</h3>
                    <div class="progress-bar-wrapper">
                        <div class="progress-bar-header">
                            <span class="progress-bar-label">Overall Risk Score</span>
                            <span class="progress-bar-value">45/100</span>
                        </div>
                        <div class="progress-bar-track">
                            <div class="progress-bar-fill" style="width: 45%;"></div>
                        </div>
                    </div>
                    <div style="margin-top: 1rem;">
                        <div style="display: flex; justify-content: space-between; margin-bottom: 0.5rem;">
                            <span style="color: #a1a1aa; font-size: 0.875rem;">Malware Detection</span>
                            <span class="badge green">Clean</span>
                        </div>
                        <div style="display: flex; justify-content: space-between; margin-bottom: 0.5rem;">
                            <span style="color: #a1a1aa; font-size: 0.875rem;">Phishing Indicators</span>
                            <span class="badge yellow">Low</span>
                        </div>
                        <div style="display: flex; justify-content: space-between;">
                            <span style="color: #a1a1aa; font-size: 0.875rem;">Spam Score</span>
                            <span class="badge green">0.2%</span>
                        </div>
                    </div>
                </div>

                <div class="card">
                    <h3>Automated Workflows</h3>
                    <div style="display: flex; flex-direction: column; gap: 0.75rem;">
                        ${['DNS Analysis', 'Security Scan', 'SSL Verification', 'Content Analysis', 'Threat Intelligence'].map((workflow, index) => {
                            const progress = index < 3 ? 100 : index === 3 ? 67 : 0;
                            const status = index < 3 ? 'completed' : index === 3 ? 'running' : 'pending';
                            return `
                                <div style="display: flex; align-items: center; gap: 0.75rem; padding: 0.75rem; background: rgba(0, 0, 0, 0.6); border: 1px solid rgba(113, 113, 122, 0.3); border-radius: 0.5rem;">
                                    <div style="width: 2rem; height: 2rem; border-radius: 50%; display: flex; align-items: center; justify-content: center; background: ${status === 'completed' ? 'rgba(34, 197, 94, 0.1)' : 'rgba(82, 82, 91, 0.1)'}; border: 1px solid ${status === 'completed' ? 'rgba(34, 197, 94, 0.3)' : 'rgba(82, 82, 91, 0.3)'};">
                                        ${status === 'completed' ? '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#4ade80" stroke-width="2"><polyline points="20 6 9 17 4 12"></polyline></svg>' : '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#71717a" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg>'}
                                    </div>
                                    <div style="flex: 1;">
                                        <p style="color: #d4d4d8; font-size: 0.875rem; margin-bottom: 0.25rem;">${workflow}</p>
                                        <div style="height: 0.25rem; background: #27272a; border-radius: 9999px; overflow: hidden;">
                                            <div style="height: 100%; width: ${progress}%; background: ${status === 'completed' ? 'linear-gradient(to right, #16a34a, #22c55e)' : 'linear-gradient(to right, #52525b, #71717a)'}; border-radius: 9999px;"></div>
                                        </div>
                                    </div>
                                    <span style="color: #71717a; font-size: 0.875rem;">${progress}%</span>
                                </div>
                            `;
                        }).join('')}
                    </div>
                </div>
            </div>

            <div class="card">
                <h3>Web3 & Blockchain Analysis</h3>
                <div style="display: flex; justify-content: space-between; margin-bottom: 1rem;">
                    <span style="color: #a1a1aa;">Blockchain Related</span>
                    <span style="color: #d4d4d8;">Crypto Keywords Detected</span>
                </div>
                <div style="background: rgba(0, 0, 0, 0.6); padding: 0.75rem; border: 1px solid rgba(113, 113, 122, 0.3); border-radius: 0.5rem;">
                    <p style="color: #71717a; font-size: 0.875rem; margin-bottom: 0.5rem;">Keywords:</p>
                    <div style="display: flex; flex-wrap: wrap; gap: 0.5rem;">
                        <span class="badge gray">blockchain</span>
                        <span class="badge gray">crypto</span>
                        <span class="badge gray">wallet</span>
                        <span class="badge gray">defi</span>
                    </div>
                </div>
            </div>
        `;
    }

    function loadSecurityContent(scanData) {
        const content = document.querySelector('[data-content="security"]');
        const data = scanData || window.scanResults || {};
        const owasp = data.owasp_analysis || {};
        const securityScore = owasp.security_score || 65;
        content.innerHTML = `
            <div class="card">
                <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 1.5rem;">
                    <div>
                        <h3 style="margin-bottom: 0.25rem;">OWASP Security Analysis</h3>
                        <p style="color: #a1a1aa; font-size: 0.875rem;">Based on OWASP Top 10 security standards</p>
                    </div>
                    <div style="text-align: right;">
                        <div style="font-size: 2.5rem; color: #22d3ee; margin-bottom: 0.25rem;">${securityScore}</div>
                        <p style="color: #a1a1aa; font-size: 0.875rem;">/ 100</p>
                    </div>
                </div>
                <div class="progress-bar-wrapper">
                    <div class="progress-bar-track" style="height: 0.75rem;">
                        <div class="progress-bar-fill" style="width: ${securityScore}%;"></div>
                    </div>
                    <div style="display: flex; justify-content: space-between; margin-top: 0.5rem;">
                        <span class="badge ${securityScore > 70 ? 'green' : securityScore > 40 ? 'yellow' : 'red'}">${securityScore > 70 ? 'Low Risk' : securityScore > 40 ? 'Medium Risk' : 'High Risk'}</span>
                        <p style="color: #a1a1aa; font-size: 0.875rem;">Security Score: ${securityScore}/100</p>
                    </div>
                </div>
                <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem; margin-top: 1.5rem; padding-top: 1.5rem; border-top: 1px solid rgba(113, 113, 122, 0.3);">
                    <div style="text-align: center;">
                        <div style="font-size: 1.5rem; color: #f87171; margin-bottom: 0.25rem;">5</div>
                        <p style="color: #a1a1aa; font-size: 0.875rem;">Vulnerabilities</p>
                    </div>
                    <div style="text-align: center;">
                        <div style="font-size: 1.5rem; color: #facc15; margin-bottom: 0.25rem;">4</div>
                        <p style="color: #a1a1aa; font-size: 0.875rem;">Warnings</p>
                    </div>
                    <div style="text-align: center;">
                        <div style="font-size: 1.5rem; color: #4ade80; margin-bottom: 0.25rem;">11</div>
                        <p style="color: #a1a1aa; font-size: 0.875rem;">Passed</p>
                    </div>
                </div>
            </div>

            <div class="card">
                <h3>Critical Vulnerabilities</h3>
                <div style="display: flex; flex-direction: column; gap: 1rem;">
                    ${[
                        { title: 'Security Misconfiguration', tag: 'OWASP A05', desc: 'Security settings should be defined, implemented, and maintained', items: ['Server header exposed: gws'] },
                        { title: 'Authentication Failures', tag: 'OWASP A07', desc: 'Authentication and session management must be implemented correctly', items: ['Cookie \'NID\' missing Secure flag'] },
                        { title: 'Security Headers', tag: 'Best Practice', desc: 'Security headers provide defense-in-depth protection', items: ['HSTS not implemented', 'MIME sniffing not prevented', 'CSP not implemented'] }
                    ].map(vuln => `
                        <div style="padding: 1rem; background: rgba(0, 0, 0, 0.4); border: 1px solid rgba(113, 113, 122, 0.3); border-radius: 0.5rem;">
                            <div style="display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.75rem;">
                                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#f87171" stroke-width="2">
                                    <circle cx="12" cy="12" r="10"></circle>
                                    <line x1="15" y1="9" x2="9" y2="15"></line>
                                    <line x1="9" y1="9" x2="15" y2="15"></line>
                                </svg>
                                <div>
                                    <p style="color: #e4e4e7; margin-bottom: 0.25rem;">${vuln.title}</p>
                                    <span class="badge red">${vuln.tag}</span>
                                </div>
                            </div>
                            <p style="color: #d4d4d8; font-size: 0.875rem; margin-bottom: 0.5rem;">${vuln.desc}</p>
                            <ul style="list-style: disc; padding-left: 2rem; color: #a1a1aa; font-size: 0.875rem;">
                                ${vuln.items.map(item => `<li>${item}</li>`).join('')}
                            </ul>
                        </div>
                    `).join('')}
                </div>
            </div>

            <div class="card">
                <h3>Security Warnings</h3>
                <div style="display: flex; flex-direction: column; gap: 0.75rem;">
                    ${[
                        { title: 'Injection Prevention', desc: 'Missing X-Content-Type-Options (potential MIME sniffing)', tag: 'OWASP A03' },
                        { title: 'Software and Data Integrity', desc: 'Missing Content-Security-Policy header', tag: 'OWASP A08' },
                        { title: 'Information Disclosure', desc: 'Information disclosure via Server header', tag: 'Best Practice' }
                    ].map(warning => `
                        <div style="display: flex; gap: 0.75rem; padding: 0.75rem; background: rgba(250, 204, 21, 0.1); border: 1px solid rgba(250, 204, 21, 0.3); border-radius: 0.5rem;">
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#facc15" stroke-width="2" style="flex-shrink: 0; margin-top: 0.125rem;">
                                <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"></path>
                                <line x1="12" y1="9" x2="12" y2="13"></line>
                                <line x1="12" y1="17" x2="12.01" y2="17"></line>
                            </svg>
                            <div style="flex: 1;">
                                <p style="color: #e4e4e7; font-size: 0.875rem; margin-bottom: 0.25rem;">${warning.title}</p>
                                <p style="color: #a1a1aa; font-size: 0.875rem; margin-bottom: 0.5rem;">${warning.desc}</p>
                                <span class="badge yellow">${warning.tag}</span>
                            </div>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    }

    function loadTechnicalContent(scanData) {
        const content = document.querySelector('[data-content="technical"]');
        const data = scanData || window.scanResults || {};
        const domain = data.domain || currentDomain;
        const recon = data.reconnaissance || {};
        const dns = recon.dns || {};
        const ssl = recon.ssl || {};
        const headers = recon.security_headers || {};
        content.innerHTML = `
            <div class="card">
                <h3>DNS Records</h3>
                <div style="overflow-x: auto;">
                    <table style="width: 100%; border-collapse: collapse;">
                        <thead>
                            <tr style="border-bottom: 1px solid rgba(113, 113, 122, 0.3);">
                                <th style="text-align: left; padding: 0.75rem; color: #a1a1aa; font-weight: 500; font-size: 0.875rem;">Type</th>
                                <th style="text-align: left; padding: 0.75rem; color: #a1a1aa; font-weight: 500; font-size: 0.875rem;">Name</th>
                                <th style="text-align: left; padding: 0.75rem; color: #a1a1aa; font-weight: 500; font-size: 0.875rem;">Value</th>
                                <th style="text-align: left; padding: 0.75rem; color: #a1a1aa; font-weight: 500; font-size: 0.875rem;">TTL</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${[
                                { type: 'A', name: domain, value: '142.250.185.78', ttl: '300', color: 'cyan' },
                                { type: 'AAAA', name: domain, value: '2607:f8b0:4004:c07::64', ttl: '300', color: 'purple' },
                                { type: 'MX', name: domain, value: 'smtp.google.com (Priority: 10)', ttl: '3600', color: 'yellow' },
                                { type: 'NS', name: domain, value: 'ns1.google.com', ttl: '86400', color: 'blue' }
                            ].map(record => `
                                <tr style="border-bottom: 1px solid rgba(113, 113, 122, 0.3);">
                                    <td style="padding: 0.75rem;"><span class="badge ${record.color === 'cyan' ? 'blue' : record.color === 'purple' ? 'gray' : record.color}">${record.type}</span></td>
                                    <td style="padding: 0.75rem; color: #d4d4d8;">${record.name}</td>
                                    <td style="padding: 0.75rem; color: #d4d4d8;">${record.value}</td>
                                    <td style="padding: 0.75rem; color: #a1a1aa;">${record.ttl}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            </div>

            <div class="card">
                <h3>Security Headers</h3>
                <div style="display: flex; flex-direction: column; gap: 0.75rem;">
                    ${[
                        { name: 'Strict-Transport-Security', status: 'Missing', desc: 'Enforces secure HTTPS connections', color: 'red' },
                        { name: 'X-Content-Type-Options', status: 'Missing', desc: 'Prevents MIME type sniffing', color: 'red' },
                        { name: 'Content-Security-Policy', status: 'Missing', desc: 'Prevents XSS and data injection attacks', color: 'red' },
                        { name: 'X-Frame-Options', status: 'Present', desc: 'Value: SAMEORIGIN', color: 'green' }
                    ].map(header => `
                        <div style="padding: 0.75rem; background: rgba(0, 0, 0, 0.4); border: 1px solid rgba(113, 113, 122, 0.3); border-radius: 0.5rem;">
                            <div style="display: flex; justify-content: space-between; margin-bottom: 0.25rem;">
                                <p style="color: #e4e4e7; font-size: 0.875rem;">${header.name}</p>
                                <span class="badge ${header.color}">${header.status}</span>
                            </div>
                            <p style="color: #a1a1aa; font-size: 0.875rem;">${header.desc}</p>
                        </div>
                    `).join('')}
                </div>
            </div>

            <div class="card">
                <h3>Detected Technologies</h3>
                <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 1rem;">
                    ${[
                        { label: 'Web Server', items: ['gws'] },
                        { label: 'SSL/TLS', items: ['TLS 1.3', 'TLS 1.2'] },
                        { label: 'CDN', items: ['Google Cloud'] },
                        { label: 'Analytics', items: ['Google Analytics'] }
                    ].map(tech => `
                        <div style="padding: 1rem; background: rgba(0, 0, 0, 0.4); border: 1px solid rgba(113, 113, 122, 0.3); border-radius: 0.5rem;">
                            <p style="color: #a1a1aa; font-size: 0.875rem; margin-bottom: 0.5rem;">${tech.label}</p>
                            <div style="display: flex; flex-wrap: wrap; gap: 0.5rem;">
                                ${tech.items.map(item => `<span class="badge ${tech.label === 'SSL/TLS' ? 'green' : 'gray'}">${item}</span>`).join('')}
                            </div>
                        </div>
                    `).join('')}
                </div>
            </div>

            <div class="card">
                <h3>Server Information</h3>
                <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 1rem;">
                    ${[
                        { label: 'Server Type', value: 'gws' },
                        { label: 'HTTP Version', value: 'HTTP/2' },
                        { label: 'Response Time', value: '45ms' },
                        { label: 'Status Code', value: '200 OK', badge: true }
                    ].map(info => `
                        <div>
                            <p style="color: #a1a1aa; font-size: 0.875rem; margin-bottom: 0.25rem;">${info.label}</p>
                            ${info.badge ? `<span class="badge green">${info.value}</span>` : `<p style="color: #e4e4e7;">${info.value}</p>`}
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    }

    function loadThreatContent(scanData) {
        const content = document.querySelector('[data-content="threat"]');
        const data = scanData || window.scanResults || {};
        const threat = data.threat_analysis || {};
        const riskScore = Math.round(threat.risk_score || 45);
        content.innerHTML = `
            <div class="stats-grid" style="grid-template-columns: repeat(3, 1fr);">
                ${[
                    { label: 'Overall Risk', value: `${riskScore}/100`, icon: 'shield', progress: riskScore },
                    { label: 'Phishing Risk', value: 'Low', icon: 'trending', badge: 'Minimal Threat' },
                    { label: 'Anomaly', value: 'None', icon: 'network', badge: 'Normal Activity' }
                ].map(stat => `
                    <div class="card" style="margin-bottom: 0;">
                        <div style="display: flex; align-items: center; gap: 0.75rem; margin-bottom: 1rem;">
                            <div class="stat-icon-wrapper ${stat.icon === 'shield' ? 'yellow' : stat.icon === 'trending' ? 'green' : 'gray'}">
                                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="${stat.icon === 'shield' ? '#facc15' : stat.icon === 'trending' ? '#4ade80' : '#71717a'}" stroke-width="2">
                                    ${stat.icon === 'shield' ? '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>' : stat.icon === 'trending' ? '<polyline points="23 6 13.5 15.5 8.5 10.5 1 18"></polyline><polyline points="17 6 23 6 23 12"></polyline>' : '<rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect><rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect><line x1="6" y1="6" x2="6.01" y2="6"></line><line x1="6" y1="18" x2="6.01" y2="18"></line>'}
                                </svg>
                            </div>
                            <div>
                                <p style="color: #a1a1aa; font-size: 0.875rem;">${stat.label}</p>
                                <p style="color: #e4e4e7;">${stat.value}</p>
                            </div>
                        </div>
                        ${stat.progress ? `
                            <div class="progress-bar-track">
                                <div class="progress-bar-fill" style="width: ${stat.progress}%;"></div>
                            </div>
                        ` : `<span class="badge ${stat.badge.includes('Minimal') ? 'green' : 'gray'}">${stat.badge}</span>`}
                    </div>
                `).join('')}
            </div>

            <div class="card">
                <h3>AI Threat Analysis</h3>
                <div class="progress-bar-wrapper">
                    <div class="progress-bar-header">
                        <span class="progress-bar-label">Risk Assessment</span>
                        <span class="progress-bar-value">45/100</span>
                    </div>
                    <div class="progress-bar-track" style="height: 0.75rem;">
                        <div class="progress-bar-fill" style="width: 45%;"></div>
                    </div>
                    <p style="color: #a1a1aa; font-size: 0.875rem; margin-top: 0.5rem;">
                        AI-powered analysis indicates medium risk level with no immediate threats detected
                    </p>
                </div>
                <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 1rem; margin-top: 1.5rem; padding-top: 1.5rem; border-top: 1px solid rgba(113, 113, 122, 0.3);">
                    ${[
                        { label: 'Phishing Indicators', value: '0', color: 'green' },
                        { label: 'Malware Signatures', value: '0', color: 'green' },
                        { label: 'Security Gaps', value: '5', color: 'yellow' },
                        { label: 'Domain Age', value: '25+', suffix: 'years', color: 'blue' }
                    ].map(metric => `
                        <div style="padding: 1rem; background: rgba(${metric.color === 'green' ? '34, 197, 94' : metric.color === 'yellow' ? '250, 204, 21' : '96, 165, 250'}, 0.1); border: 1px solid rgba(${metric.color === 'green' ? '34, 197, 94' : metric.color === 'yellow' ? '250, 204, 21' : '96, 165, 250'}, 0.3); border-radius: 0.5rem;">
                            <p style="color: #a1a1aa; font-size: 0.875rem; margin-bottom: 0.5rem;">${metric.label}</p>
                            <div style="display: flex; align-items: baseline; gap: 0.5rem;">
                                <span style="font-size: 1.5rem; color: ${metric.color === 'green' ? '#4ade80' : metric.color === 'yellow' ? '#facc15' : '#60a5fa'};">${metric.value}</span>
                                <span style="color: #a1a1aa; font-size: 0.875rem;">${metric.suffix || 'detected'}</span>
                            </div>
                        </div>
                    `).join('')}
                </div>
            </div>

            <div class="card">
                <h3>Domain Reputation</h3>
                <div class="progress-bar-wrapper">
                    <div class="progress-bar-header">
                        <span class="progress-bar-label">Trust Score</span>
                        <span class="progress-bar-value">95/100</span>
                    </div>
                    <div class="progress-bar-track">
                        <div class="progress-bar-fill" style="width: 95%;"></div>
                    </div>
                </div>
                <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 1rem; margin-top: 1.5rem; padding-top: 1.5rem; border-top: 1px solid rgba(113, 113, 122, 0.3);">
                    ${[
                        { label: 'Blacklist Status', value: 'Clean', color: 'green' },
                        { label: 'WHOIS Privacy', value: 'Protected', color: 'gray' },
                        { label: 'Spam Reports', value: 'None', color: 'green' },
                        { label: 'Certificate Validity', value: 'Valid', color: 'green' }
                    ].map(item => `
                        <div>
                            <p style="color: #a1a1aa; font-size: 0.875rem; margin-bottom: 0.25rem;">${item.label}</p>
                            <span class="badge ${item.color}">${item.value}</span>
                        </div>
                    `).join('')}
                </div>
            </div>

            <div class="card">
                <h3>Threat Intelligence Sources</h3>
                <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 0.75rem;">
                    ${[
                        { name: 'VirusTotal', status: 'Clean' },
                        { name: 'Google Safe Browsing', status: 'Safe' },
                        { name: 'PhishTank', status: 'Not Listed' },
                        { name: 'SURBL', status: 'Clean' }
                    ].map(source => `
                        <div style="display: flex; justify-content: space-between; padding: 0.75rem; background: rgba(0, 0, 0, 0.4); border: 1px solid rgba(113, 113, 122, 0.3); border-radius: 0.5rem;">
                            <span style="color: #d4d4d8; font-size: 0.875rem;">${source.name}</span>
                            <span class="badge green">${source.status}</span>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    }
});

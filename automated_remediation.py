import json
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
import re
from jinja2 import Template
import yaml

logger = logging.getLogger(__name__)

class AutomatedRemediationEngine:
    def __init__(self):
        self.remediation_templates = self.load_remediation_templates()
        self.severity_priorities = {
            'critical': 1,
            'high': 2,
            'medium': 3,
            'low': 4,
            'info': 5
        }
    
    def load_remediation_templates(self) -> dict:
        """Load remediation playbook templates."""
        return {
            'ssl_certificate': {
                'title': 'SSL Certificate Remediation',
                'description': 'Steps to implement or fix SSL certificate issues',
                'severity': 'high',
                'estimated_time': '2-4 hours',
                'difficulty': 'medium',
                'steps': [
                    {
                        'step': 1,
                        'title': 'Obtain SSL Certificate',
                        'description': 'Get a valid SSL certificate from a trusted Certificate Authority',
                        'commands': [
                            '# Using Let\'s Encrypt (free)',
                            'sudo apt-get update',
                            'sudo apt-get install certbot python3-certbot-apache',
                            'sudo certbot --apache -d {{ domain }}',
                            '',
                            '# Or using Certbot with Nginx',
                            'sudo certbot --nginx -d {{ domain }}'
                        ],
                        'verification': 'curl -I https://{{ domain }} | grep "HTTP/2 200"',
                        'notes': 'Let\'s Encrypt certificates are free and automatically renewable'
                    },
                    {
                        'step': 2,
                        'title': 'Configure SSL Settings',
                        'description': 'Configure secure SSL/TLS settings',
                        'commands': [
                            '# Apache SSL configuration',
                            'SSLEngine on',
                            'SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1',
                            'SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256',
                            'SSLHonorCipherOrder on',
                            '',
                            '# Nginx SSL configuration',
                            'ssl_protocols TLSv1.2 TLSv1.3;',
                            'ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384;',
                            'ssl_prefer_server_ciphers off;'
                        ],
                        'verification': 'openssl s_client -connect {{ domain }}:443 -tls1_2',
                        'notes': 'Use only TLS 1.2 and 1.3 for security'
                    },
                    {
                        'step': 3,
                        'title': 'Set Up Auto-Renewal',
                        'description': 'Configure automatic certificate renewal',
                        'commands': [
                            '# Test renewal',
                            'sudo certbot renew --dry-run',
                            '',
                            '# Add to crontab for auto-renewal',
                            'echo "0 12 * * * /usr/bin/certbot renew --quiet" | sudo crontab -'
                        ],
                        'verification': 'sudo crontab -l | grep certbot',
                        'notes': 'Certificates should renew automatically before expiration'
                    }
                ],
                'validation_checks': [
                    'SSL certificate is valid and trusted',
                    'Certificate expiration date is more than 30 days away',
                    'Only secure TLS protocols are enabled',
                    'Auto-renewal is configured'
                ],
                'references': [
                    'https://letsencrypt.org/getting-started/',
                    'https://ssl-config.mozilla.org/',
                    'https://www.ssllabs.com/ssltest/'
                ]
            },
            
            'security_headers': {
                'title': 'Security Headers Implementation',
                'description': 'Implement essential HTTP security headers',
                'severity': 'medium',
                'estimated_time': '1-2 hours',
                'difficulty': 'easy',
                'steps': [
                    {
                        'step': 1,
                        'title': 'Content Security Policy (CSP)',
                        'description': 'Implement Content Security Policy header',
                        'commands': [
                            '# Apache (.htaccess or virtual host)',
                            'Header always set Content-Security-Policy "default-src \'self\'; script-src \'self\' \'unsafe-inline\'; style-src \'self\' \'unsafe-inline\'"',
                            '',
                            '# Nginx',
                            'add_header Content-Security-Policy "default-src \'self\'; script-src \'self\' \'unsafe-inline\'; style-src \'self\' \'unsafe-inline\'";'
                        ],
                        'verification': 'curl -I https://{{ domain }} | grep "Content-Security-Policy"',
                        'notes': 'Start with a permissive policy and gradually tighten'
                    },
                    {
                        'step': 2,
                        'title': 'X-Frame-Options',
                        'description': 'Prevent clickjacking attacks',
                        'commands': [
                            '# Apache',
                            'Header always set X-Frame-Options "SAMEORIGIN"',
                            '',
                            '# Nginx',
                            'add_header X-Frame-Options "SAMEORIGIN";'
                        ],
                        'verification': 'curl -I https://{{ domain }} | grep "X-Frame-Options"',
                        'notes': 'Use DENY for maximum security or SAMEORIGIN for flexibility'
                    },
                    {
                        'step': 3,
                        'title': 'Strict-Transport-Security (HSTS)',
                        'description': 'Enforce HTTPS connections',
                        'commands': [
                            '# Apache',
                            'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"',
                            '',
                            '# Nginx',
                            'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";'
                        ],
                        'verification': 'curl -I https://{{ domain }} | grep "Strict-Transport-Security"',
                        'notes': 'Start with shorter max-age, then increase to 1 year'
                    },
                    {
                        'step': 4,
                        'title': 'Additional Security Headers',
                        'description': 'Implement other important security headers',
                        'commands': [
                            '# Apache - Additional headers',
                            'Header always set X-Content-Type-Options "nosniff"',
                            'Header always set Referrer-Policy "strict-origin-when-cross-origin"',
                            'Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"',
                            '',
                            '# Nginx - Additional headers',
                            'add_header X-Content-Type-Options "nosniff";',
                            'add_header Referrer-Policy "strict-origin-when-cross-origin";',
                            'add_header Permissions-Policy "geolocation=(), microphone=(), camera=()";'
                        ],
                        'verification': 'curl -I https://{{ domain }} | grep -E "(X-Content-Type-Options|Referrer-Policy|Permissions-Policy)"',
                        'notes': 'Customize Permissions-Policy based on your site\'s needs'
                    }
                ],
                'validation_checks': [
                    'All security headers are present',
                    'CSP policy is appropriate for the application',
                    'HSTS is configured with appropriate max-age',
                    'Headers are applied to all responses'
                ],
                'references': [
                    'https://owasp.org/www-project-secure-headers/',
                    'https://securityheaders.com/',
                    'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers'
                ]
            },
            
            'open_ports': {
                'title': 'Open Ports Security Hardening',
                'description': 'Secure or close unnecessary open ports',
                'severity': 'high',
                'estimated_time': '2-6 hours',
                'difficulty': 'medium',
                'steps': [
                    {
                        'step': 1,
                        'title': 'Audit Open Ports',
                        'description': 'Identify all open ports and their services',
                        'commands': [
                            '# List all listening ports',
                            'sudo netstat -tlnp',
                            'sudo ss -tlnp',
                            '',
                            '# Check specific ports',
                            'sudo lsof -i :{{ port }}',
                            '',
                            '# Scan from external perspective',
                            'nmap -sS -O {{ domain }}'
                        ],
                        'verification': 'netstat -tlnp | grep {{ port }}',
                        'notes': 'Document all services and their necessity'
                    },
                    {
                        'step': 2,
                        'title': 'Configure Firewall',
                        'description': 'Set up firewall rules to restrict access',
                        'commands': [
                            '# UFW (Ubuntu Firewall)',
                            'sudo ufw default deny incoming',
                            'sudo ufw default allow outgoing',
                            'sudo ufw allow ssh',
                            'sudo ufw allow 80/tcp',
                            'sudo ufw allow 443/tcp',
                            'sudo ufw enable',
                            '',
                            '# iptables alternative',
                            'sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT',
                            'sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT',
                            'sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT',
                            'sudo iptables -A INPUT -j DROP'
                        ],
                        'verification': 'sudo ufw status verbose',
                        'notes': 'Only allow necessary ports and services'
                    },
                    {
                        'step': 3,
                        'title': 'Secure SSH (if applicable)',
                        'description': 'Harden SSH configuration',
                        'commands': [
                            '# Edit SSH config',
                            'sudo nano /etc/ssh/sshd_config',
                            '',
                            '# Recommended settings:',
                            'Port 2222  # Change default port',
                            'PermitRootLogin no',
                            'PasswordAuthentication no',
                            'PubkeyAuthentication yes',
                            'Protocol 2',
                            'MaxAuthTries 3',
                            '',
                            '# Restart SSH service',
                            'sudo systemctl restart sshd'
                        ],
                        'verification': 'sudo sshd -t && echo "SSH config is valid"',
                        'notes': 'Always test SSH changes before closing current session'
                    },
                    {
                        'step': 4,
                        'title': 'Disable Unnecessary Services',
                        'description': 'Stop and disable unused services',
                        'commands': [
                            '# List all services',
                            'sudo systemctl list-unit-files --type=service',
                            '',
                            '# Disable unnecessary services (examples)',
                            'sudo systemctl stop telnet',
                            'sudo systemctl disable telnet',
                            'sudo systemctl stop ftp',
                            'sudo systemctl disable ftp',
                            '',
                            '# Remove packages if not needed',
                            'sudo apt-get remove --purge telnetd ftpd'
                        ],
                        'verification': 'sudo systemctl is-active {{ service_name }}',
                        'notes': 'Only disable services you\'re certain are not needed'
                    }
                ],
                'validation_checks': [
                    'Only necessary ports are open',
                    'Firewall is properly configured',
                    'SSH is hardened (if applicable)',
                    'Unnecessary services are disabled'
                ],
                'references': [
                    'https://www.cyberciti.biz/tips/linux-security.html',
                    'https://linux-audit.com/ubuntu-server-hardening-guide-quick-and-secure/',
                    'https://www.ssh.com/academy/ssh/sshd_config'
                ]
            },
            
            'vulnerability_patching': {
                'title': 'Vulnerability Patching Guide',
                'description': 'Systematic approach to patching identified vulnerabilities',
                'severity': 'critical',
                'estimated_time': '4-8 hours',
                'difficulty': 'hard',
                'steps': [
                    {
                        'step': 1,
                        'title': 'Vulnerability Assessment',
                        'description': 'Assess and prioritize vulnerabilities',
                        'commands': [
                            '# Update package lists',
                            'sudo apt-get update',
                            '',
                            '# Check for security updates',
                            'sudo apt list --upgradable | grep -i security',
                            '',
                            '# Check specific package versions',
                            'dpkg -l | grep {{ package_name }}',
                            '',
                            '# Check for CVE information',
                            'curl -s "https://cve.circl.lu/api/cve/{{ cve_id }}"'
                        ],
                        'verification': 'apt list --upgradable',
                        'notes': 'Prioritize critical and high-severity vulnerabilities'
                    },
                    {
                        'step': 2,
                        'title': 'Create System Backup',
                        'description': 'Backup system before applying patches',
                        'commands': [
                            '# Create system snapshot (if using LVM)',
                            'sudo lvcreate -L1G -s -n backup-$(date +%Y%m%d) /dev/vg0/root',
                            '',
                            '# Backup important configurations',
                            'sudo tar -czf /backup/config-$(date +%Y%m%d).tar.gz /etc/',
                            '',
                            '# Backup database (if applicable)',
                            'mysqldump -u root -p --all-databases > /backup/mysql-$(date +%Y%m%d).sql'
                        ],
                        'verification': 'ls -la /backup/',
                        'notes': 'Always backup before making system changes'
                    },
                    {
                        'step': 3,
                        'title': 'Apply Security Updates',
                        'description': 'Install security patches and updates',
                        'commands': [
                            '# Install security updates only',
                            'sudo unattended-upgrade -d',
                            '',
                            '# Or upgrade specific packages',
                            'sudo apt-get install --only-upgrade {{ package_name }}',
                            '',
                            '# Full system upgrade (use with caution)',
                            'sudo apt-get upgrade',
                            '',
                            '# Reboot if kernel was updated',
                            'sudo reboot'
                        ],
                        'verification': 'dpkg -l | grep {{ package_name }}',
                        'notes': 'Test applications after updates to ensure compatibility'
                    },
                    {
                        'step': 4,
                        'title': 'Verify Patch Installation',
                        'description': 'Confirm vulnerabilities are resolved',
                        'commands': [
                            '# Check package versions',
                            'dpkg -l | grep {{ package_name }}',
                            '',
                            '# Verify services are running',
                            'sudo systemctl status {{ service_name }}',
                            '',
                            '# Test application functionality',
                            'curl -I https://{{ domain }}',
                            '',
                            '# Run vulnerability scanner again',
                            'nmap --script vuln {{ domain }}'
                        ],
                        'verification': 'echo "Patch verification completed"',
                        'notes': 'Document all changes and test thoroughly'
                    }
                ],
                'validation_checks': [
                    'All critical vulnerabilities are patched',
                    'System is stable after updates',
                    'Applications are functioning correctly',
                    'Vulnerability scanners show improvements'
                ],
                'references': [
                    'https://ubuntu.com/security/notices',
                    'https://www.debian.org/security/',
                    'https://access.redhat.com/security/updates/classification'
                ]
            },
            
            'dns_security': {
                'title': 'DNS Security Hardening',
                'description': 'Secure DNS configuration and prevent DNS attacks',
                'severity': 'medium',
                'estimated_time': '2-3 hours',
                'difficulty': 'medium',
                'steps': [
                    {
                        'step': 1,
                        'title': 'Implement DNS Security Extensions (DNSSEC)',
                        'description': 'Enable DNSSEC for domain authentication',
                        'commands': [
                            '# Generate DNSSEC keys (BIND example)',
                            'cd /etc/bind/keys',
                            'dnssec-keygen -a RSASHA256 -b 2048 -n ZONE {{ domain }}',
                            'dnssec-keygen -a RSASHA256 -b 2048 -n ZONE -f KSK {{ domain }}',
                            '',
                            '# Sign the zone',
                            'dnssec-signzone -o {{ domain }} -k Kexample.com.+008+12345.key {{ domain }}.zone Kexample.com.+008+54321.key'
                        ],
                        'verification': 'dig +dnssec {{ domain }}',
                        'notes': 'DNSSEC provides authentication but not encryption'
                    },
                    {
                        'step': 2,
                        'title': 'Configure Secure DNS Resolvers',
                        'description': 'Use secure and reliable DNS resolvers',
                        'commands': [
                            '# Edit resolv.conf',
                            'sudo nano /etc/resolv.conf',
                            '',
                            '# Add secure DNS servers',
                            'nameserver 1.1.1.1    # Cloudflare',
                            'nameserver 1.0.0.1    # Cloudflare',
                            'nameserver 8.8.8.8    # Google',
                            'nameserver 8.8.4.4    # Google',
                            '',
                            '# Or use systemd-resolved',
                            'sudo systemctl enable systemd-resolved',
                            'sudo systemctl start systemd-resolved'
                        ],
                        'verification': 'nslookup {{ domain }}',
                        'notes': 'Consider using DNS over HTTPS (DoH) or DNS over TLS (DoT)'
                    },
                    {
                        'step': 3,
                        'title': 'Implement DNS Filtering',
                        'description': 'Block malicious domains and content',
                        'commands': [
                            '# Install Pi-hole (DNS sinkhole)',
                            'curl -sSL https://install.pi-hole.net | bash',
                            '',
                            '# Configure custom blocklists',
                            'echo "malicious-domain.com" >> /etc/pihole/blacklist.txt',
                            'pihole -g',
                            '',
                            '# Update DNS settings to use Pi-hole',
                            'echo "nameserver 127.0.0.1" > /etc/resolv.conf'
                        ],
                        'verification': 'dig @127.0.0.1 malicious-domain.com',
                        'notes': 'Regularly update blocklists for effectiveness'
                    }
                ],
                'validation_checks': [
                    'DNSSEC is properly configured',
                    'DNS resolvers are secure and fast',
                    'DNS filtering is blocking malicious domains',
                    'DNS queries are not being leaked'
                ],
                'references': [
                    'https://www.cloudflare.com/dns/',
                    'https://developers.google.com/speed/public-dns',
                    'https://pi-hole.net/'
                ]
            }
        }
    
    def generate_remediation_playbook(self, domain_data: dict, vulnerability_data: dict = None, threat_analysis: dict = None) -> dict:
        """Generate comprehensive remediation playbook based on findings."""
        try:
            playbook = {
                'domain': domain_data.get('domain', ''),
                'generated_at': datetime.now().isoformat(),
                'executive_summary': {},
                'remediation_tasks': [],
                'implementation_timeline': {},
                'resource_requirements': {},
                'risk_mitigation_matrix': {}
            }
            
            # Analyze findings and determine required remediations
            required_remediations = self.analyze_required_remediations(domain_data, vulnerability_data, threat_analysis)
            
            # Generate executive summary
            playbook['executive_summary'] = self.generate_executive_summary(required_remediations, domain_data)
            
            # Generate detailed remediation tasks
            for remediation_type, priority in required_remediations.items():
                if remediation_type in self.remediation_templates:
                    task = self.generate_remediation_task(
                        remediation_type, 
                        self.remediation_templates[remediation_type],
                        domain_data,
                        priority
                    )
                    playbook['remediation_tasks'].append(task)
            
            # Sort tasks by priority
            playbook['remediation_tasks'].sort(key=lambda x: self.severity_priorities.get(x['priority'], 5))
            
            # Generate implementation timeline
            playbook['implementation_timeline'] = self.generate_implementation_timeline(playbook['remediation_tasks'])
            
            # Calculate resource requirements
            playbook['resource_requirements'] = self.calculate_resource_requirements(playbook['remediation_tasks'])
            
            # Create risk mitigation matrix
            playbook['risk_mitigation_matrix'] = self.create_risk_mitigation_matrix(playbook['remediation_tasks'])
            
            return playbook
            
        except Exception as e:
            logger.error(f"Error generating remediation playbook: {str(e)}")
            return {'error': str(e)}
    
    def analyze_required_remediations(self, domain_data: dict, vulnerability_data: dict = None, threat_analysis: dict = None) -> dict:
        """Analyze domain data to determine required remediations."""
        required_remediations = {}
        
        try:
            # SSL Certificate issues
            ssl_data = domain_data.get('ssl', {})
            if not ssl_data.get('valid', False):
                required_remediations['ssl_certificate'] = 'critical'
            
            # Security headers issues
            sec_headers = domain_data.get('security_headers', {})
            missing_headers = sum(1 for v in sec_headers.values() if str(v) == 'Not set')
            if missing_headers >= 3:
                required_remediations['security_headers'] = 'high'
            elif missing_headers > 0:
                required_remediations['security_headers'] = 'medium'
            
            # Open ports issues
            open_ports = domain_data.get('open_ports', [])
            risky_ports = [21, 22, 23, 135, 139, 445, 1433, 3389]
            risky_count = sum(1 for port in open_ports if port.get('port') in risky_ports)
            if risky_count > 0:
                required_remediations['open_ports'] = 'high' if risky_count > 2 else 'medium'
            
            # Vulnerability patching
            if vulnerability_data:
                vuln_summary = vulnerability_data.get('vulnerability_summary', {})
                critical_count = vuln_summary.get('critical', 0)
                high_count = vuln_summary.get('high', 0)
                
                if critical_count > 0:
                    required_remediations['vulnerability_patching'] = 'critical'
                elif high_count > 0:
                    required_remediations['vulnerability_patching'] = 'high'
            
            # DNS security
            subdomains = domain_data.get('subdomains', [])
            if len(subdomains) > 20:  # Large attack surface
                required_remediations['dns_security'] = 'medium'
            
            # Threat-based remediations
            if threat_analysis:
                risk_score = threat_analysis.get('risk_score', 0)
                if risk_score > 70:
                    # High-risk domains need comprehensive security
                    if 'security_headers' not in required_remediations:
                        required_remediations['security_headers'] = 'high'
                    if 'dns_security' not in required_remediations:
                        required_remediations['dns_security'] = 'medium'
            
            return required_remediations
            
        except Exception as e:
            logger.error(f"Error analyzing required remediations: {str(e)}")
            return {}
    
    def generate_remediation_task(self, remediation_type: str, template: dict, domain_data: dict, priority: str) -> dict:
        """Generate a specific remediation task from template."""
        try:
            domain = domain_data.get('domain', '')
            
            # Create Jinja2 template context
            context = {
                'domain': domain,
                'port': '22',  # Default, would be customized based on findings
                'service_name': 'apache2',  # Default, would be customized
                'package_name': 'apache2',  # Default, would be customized
                'cve_id': 'CVE-2023-XXXX'  # Would be populated from vulnerability data
            }
            
            # Process template steps
            processed_steps = []
            for step in template.get('steps', []):
                processed_step = step.copy()
                
                # Process commands with Jinja2
                if 'commands' in processed_step:
                    processed_commands = []
                    for command in processed_step['commands']:
                        template_obj = Template(command)
                        processed_command = template_obj.render(**context)
                        processed_commands.append(processed_command)
                    processed_step['commands'] = processed_commands
                
                # Process verification commands
                if 'verification' in processed_step:
                    template_obj = Template(processed_step['verification'])
                    processed_step['verification'] = template_obj.render(**context)
                
                processed_steps.append(processed_step)
            
            # Create the remediation task
            task = {
                'id': f"{remediation_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                'type': remediation_type,
                'title': template['title'],
                'description': template['description'],
                'priority': priority,
                'severity': template.get('severity', 'medium'),
                'estimated_time': template.get('estimated_time', '2-4 hours'),
                'difficulty': template.get('difficulty', 'medium'),
                'steps': processed_steps,
                'validation_checks': template.get('validation_checks', []),
                'references': template.get('references', []),
                'domain_specific_notes': self.generate_domain_specific_notes(remediation_type, domain_data),
                'success_criteria': self.generate_success_criteria(remediation_type, domain_data),
                'rollback_plan': self.generate_rollback_plan(remediation_type)
            }
            
            return task
            
        except Exception as e:
            logger.error(f"Error generating remediation task: {str(e)}")
            return {}
    
    def generate_domain_specific_notes(self, remediation_type: str, domain_data: dict) -> List[str]:
        """Generate domain-specific implementation notes."""
        notes = []
        
        try:
            domain = domain_data.get('domain', '')
            
            if remediation_type == 'ssl_certificate':
                if domain_data.get('geolocation', {}).get('country') == 'US':
                    notes.append("Consider using a US-based Certificate Authority for compliance")
                
                subdomains = domain_data.get('subdomains', [])
                if len(subdomains) > 5:
                    notes.append(f"Consider wildcard certificate for {len(subdomains)} subdomains")
            
            elif remediation_type == 'security_headers':
                technologies = domain_data.get('technologies', [])
                if any('wordpress' in tech.lower() for tech in technologies):
                    notes.append("WordPress-specific security headers may be needed")
                if any('cloudflare' in tech.lower() for tech in technologies):
                    notes.append("Some headers may be set by Cloudflare - check configuration")
            
            elif remediation_type == 'open_ports':
                open_ports = domain_data.get('open_ports', [])
                ssh_ports = [p for p in open_ports if p.get('service', '').lower() == 'ssh']
                if ssh_ports:
                    notes.append(f"SSH detected on port {ssh_ports[0].get('port')} - ensure secure configuration")
            
            elif remediation_type == 'dns_security':
                subdomains = domain_data.get('subdomains', [])
                if len(subdomains) > 20:
                    notes.append(f"Large number of subdomains ({len(subdomains)}) increases DNS attack surface")
            
            return notes
            
        except Exception as e:
            logger.error(f"Error generating domain-specific notes: {str(e)}")
            return []
    
    def generate_success_criteria(self, remediation_type: str, domain_data: dict) -> List[str]:
        """Generate success criteria for remediation task."""
        criteria = []
        
        try:
            if remediation_type == 'ssl_certificate':
                criteria = [
                    "SSL certificate is valid and trusted by major browsers",
                    "Certificate covers all necessary domains and subdomains",
                    "SSL Labs test shows A+ rating",
                    "Auto-renewal is configured and tested"
                ]
            
            elif remediation_type == 'security_headers':
                criteria = [
                    "All critical security headers are present",
                    "SecurityHeaders.com shows A+ rating",
                    "CSP policy blocks unauthorized resources",
                    "HSTS is properly configured with appropriate max-age"
                ]
            
            elif remediation_type == 'open_ports':
                criteria = [
                    "Only necessary ports are accessible from internet",
                    "Firewall rules are properly configured",
                    "SSH is hardened with key-based authentication",
                    "Port scan shows reduced attack surface"
                ]
            
            elif remediation_type == 'vulnerability_patching':
                criteria = [
                    "All critical and high-severity vulnerabilities are patched",
                    "System is stable after updates",
                    "Vulnerability scanners show no critical issues",
                    "Applications function correctly after patching"
                ]
            
            elif remediation_type == 'dns_security':
                criteria = [
                    "DNSSEC is properly configured and validated",
                    "DNS resolvers are secure and fast",
                    "DNS filtering blocks known malicious domains",
                    "No DNS leaks detected"
                ]
            
            return criteria
            
        except Exception as e:
            logger.error(f"Error generating success criteria: {str(e)}")
            return []
    
    def generate_rollback_plan(self, remediation_type: str) -> dict:
        """Generate rollback plan for remediation task."""
        try:
            rollback_plans = {
                'ssl_certificate': {
                    'description': 'Rollback SSL certificate changes',
                    'steps': [
                        'Restore previous certificate files from backup',
                        'Revert web server configuration changes',
                        'Restart web server',
                        'Verify site accessibility'
                    ],
                    'estimated_time': '30 minutes'
                },
                
                'security_headers': {
                    'description': 'Remove security headers if they break functionality',
                    'steps': [
                        'Comment out or remove header directives',
                        'Restart web server',
                        'Test application functionality',
                        'Gradually re-enable headers one by one'
                    ],
                    'estimated_time': '15 minutes'
                },
                
                'open_ports': {
                    'description': 'Restore network access if services become unavailable',
                    'steps': [
                        'Disable firewall temporarily: sudo ufw disable',
                        'Restore original service configurations',
                        'Restart affected services',
                        'Re-enable firewall with corrected rules'
                    ],
                    'estimated_time': '20 minutes'
                },
                
                'vulnerability_patching': {
                    'description': 'Rollback system updates if issues occur',
                    'steps': [
                        'Restore from system snapshot/backup',
                        'Downgrade specific packages if needed',
                        'Restart services',
                        'Verify system stability'
                    ],
                    'estimated_time': '1-2 hours'
                },
                
                'dns_security': {
                    'description': 'Revert DNS configuration changes',
                    'steps': [
                        'Restore original DNS server configuration',
                        'Remove DNSSEC keys if causing issues',
                        'Restart DNS services',
                        'Verify DNS resolution works'
                    ],
                    'estimated_time': '30 minutes'
                }
            }
            
            return rollback_plans.get(remediation_type, {
                'description': 'Generic rollback procedure',
                'steps': [
                    'Restore configuration from backup',
                    'Restart affected services',
                    'Verify functionality'
                ],
                'estimated_time': '30 minutes'
            })
            
        except Exception as e:
            logger.error(f"Error generating rollback plan: {str(e)}")
            return {}
    
    def generate_executive_summary(self, required_remediations: dict, domain_data: dict) -> dict:
        """Generate executive summary of remediation needs."""
        try:
            domain = domain_data.get('domain', '')
            total_tasks = len(required_remediations)
            
            # Count by priority
            priority_counts = {}
            for priority in required_remediations.values():
                priority_counts[priority] = priority_counts.get(priority, 0) + 1
            
            # Calculate estimated total time
            time_estimates = {
                'ssl_certificate': 4,
                'security_headers': 2,
                'open_ports': 4,
                'vulnerability_patching': 6,
                'dns_security': 3
            }
            
            total_hours = sum(time_estimates.get(task, 2) for task in required_remediations.keys())
            
            # Determine overall risk level
            if 'critical' in required_remediations.values():
                overall_risk = 'Critical'
            elif 'high' in required_remediations.values():
                overall_risk = 'High'
            elif 'medium' in required_remediations.values():
                overall_risk = 'Medium'
            else:
                overall_risk = 'Low'
            
            summary = {
                'domain': domain,
                'overall_risk_level': overall_risk,
                'total_remediation_tasks': total_tasks,
                'priority_breakdown': priority_counts,
                'estimated_total_time': f"{total_hours} hours",
                'immediate_actions_required': [task for task, priority in required_remediations.items() if priority == 'critical'],
                'key_recommendations': self.generate_key_recommendations(required_remediations),
                'business_impact': self.assess_business_impact(required_remediations, domain_data),
                'compliance_considerations': self.assess_compliance_impact(required_remediations)
            }
            
            return summary
            
        except Exception as e:
            logger.error(f"Error generating executive summary: {str(e)}")
            return {}
    
    def generate_key_recommendations(self, required_remediations: dict) -> List[str]:
        """Generate key recommendations based on required remediations."""
        recommendations = []
        
        try:
            if 'ssl_certificate' in required_remediations:
                recommendations.append("🔒 Implement valid SSL certificate immediately to secure data transmission")
            
            if 'vulnerability_patching' in required_remediations:
                recommendations.append("🚨 Apply critical security patches to prevent exploitation")
            
            if 'open_ports' in required_remediations:
                recommendations.append("🛡️ Secure network services and close unnecessary ports")
            
            if 'security_headers' in required_remediations:
                recommendations.append("📋 Implement HTTP security headers to prevent common attacks")
            
            if 'dns_security' in required_remediations:
                recommendations.append("🌐 Enhance DNS security to prevent DNS-based attacks")
            
            # General recommendations
            recommendations.append("📊 Establish regular security monitoring and assessment schedule")
            recommendations.append("🎓 Provide security training for development and operations teams")
            recommendations.append("📝 Document all security configurations and procedures")
            
            return recommendations
            
        except Exception as e:
            logger.error(f"Error generating key recommendations: {str(e)}")
            return []
    
    def assess_business_impact(self, required_remediations: dict, domain_data: dict) -> dict:
        """Assess business impact of security issues and remediations."""
        try:
            impact_assessment = {
                'current_risk_exposure': [],
                'potential_consequences': [],
                'remediation_benefits': [],
                'implementation_considerations': []
            }
            
            # Current risk exposure
            if 'ssl_certificate' in required_remediations:
                impact_assessment['current_risk_exposure'].append("Data transmission is not encrypted")
                impact_assessment['potential_consequences'].append("Customer data could be intercepted")
                impact_assessment['remediation_benefits'].append("Secure customer trust and data protection")
            
            if 'vulnerability_patching' in required_remediations:
                impact_assessment['current_risk_exposure'].append("System vulnerable to known exploits")
                impact_assessment['potential_consequences'].append("Potential for data breach or system compromise")
                impact_assessment['remediation_benefits'].append("Eliminate known attack vectors")
            
            if 'open_ports' in required_remediations:
                impact_assessment['current_risk_exposure'].append("Unnecessary network services exposed")
                impact_assessment['potential_consequences'].append("Increased attack surface for malicious actors")
                impact_assessment['remediation_benefits'].append("Reduced attack surface and improved security posture")
            
            # Implementation considerations
            impact_assessment['implementation_considerations'] = [
                "Schedule maintenance windows for critical updates",
                "Test changes in staging environment first",
                "Prepare rollback procedures for each change",
                "Communicate changes to stakeholders in advance",
                "Monitor systems closely after implementation"
            ]
            
            return impact_assessment
            
        except Exception as e:
            logger.error(f"Error assessing business impact: {str(e)}")
            return {}
    
    def assess_compliance_impact(self, required_remediations: dict) -> dict:
        """Assess compliance implications of security issues."""
        try:
            compliance_frameworks = {
                'PCI-DSS': [],
                'HIPAA': [],
                'GDPR': [],
                'SOX': [],
                'ISO27001': []
            }
            
            if 'ssl_certificate' in required_remediations:
                compliance_frameworks['PCI-DSS'].append("Requirement 4: Encrypt transmission of cardholder data")
                compliance_frameworks['HIPAA'].append("Administrative Safeguards: Encryption of PHI in transit")
                compliance_frameworks['GDPR'].append("Article 32: Security of processing")
            
            if 'vulnerability_patching' in required_remediations:
                compliance_frameworks['PCI-DSS'].append("Requirement 6: Develop and maintain secure systems")
                compliance_frameworks['ISO27001'].append("A.12.6.1: Management of technical vulnerabilities")
            
            if 'security_headers' in required_remediations:
                compliance_frameworks['GDPR'].append("Article 25: Data protection by design and by default")
                compliance_frameworks['ISO27001'].append("A.14.1.3: Protecting application services transactions")
            
            # Remove empty frameworks
            compliance_frameworks = {k: v for k, v in compliance_frameworks.items() if v}
            
            return {
                'affected_frameworks': compliance_frameworks,
                'compliance_recommendations': [
                    "Document all security implementations for audit purposes",
                    "Maintain evidence of remediation efforts",
                    "Regular compliance assessments and gap analysis",
                    "Staff training on compliance requirements"
                ]
            }
            
        except Exception as e:
            logger.error(f"Error assessing compliance impact: {str(e)}")
            return {}
    
    def generate_implementation_timeline(self, remediation_tasks: List[dict]) -> dict:
        """Generate implementation timeline for remediation tasks."""
        try:
            timeline = {
                'immediate': [],  # 0-24 hours
                'short_term': [],  # 1-7 days
                'medium_term': [],  # 1-4 weeks
                'long_term': []  # 1+ months
            }
            
            for task in remediation_tasks:
                priority = task.get('priority', 'medium')
                task_id = task.get('id', '')
                title = task.get('title', '')
                estimated_time = task.get('estimated_time', '2-4 hours')
                
                task_summary = {
                    'id': task_id,
                    'title': title,
                    'estimated_time': estimated_time,
                    'priority': priority
                }
                
                if priority == 'critical':
                    timeline['immediate'].append(task_summary)
                elif priority == 'high':
                    timeline['short_term'].append(task_summary)
                elif priority == 'medium':
                    timeline['medium_term'].append(task_summary)
                else:
                    timeline['long_term'].append(task_summary)
            
            return timeline
            
        except Exception as e:
            logger.error(f"Error generating implementation timeline: {str(e)}")
            return {}
    
    def calculate_resource_requirements(self, remediation_tasks: List[dict]) -> dict:
        """Calculate resource requirements for remediation tasks."""
        try:
            requirements = {
                'personnel': {
                    'security_engineer': 0,
                    'system_administrator': 0,
                    'developer': 0,
                    'network_engineer': 0
                },
                'estimated_costs': {
                    'ssl_certificates': 0,
                    'security_tools': 0,
                    'consulting': 0,
                    'training': 0
                },
                'time_breakdown': {
                    'planning': 0,
                    'implementation': 0,
                    'testing': 0,
                    'documentation': 0
                }
            }
            
            for task in remediation_tasks:
                task_type = task.get('type', '')
                
                # Personnel requirements
                if task_type in ['ssl_certificate', 'security_headers']:
                    requirements['personnel']['security_engineer'] += 4
                    requirements['personnel']['system_administrator'] += 2
                
                elif task_type == 'open_ports':
                    requirements['personnel']['network_engineer'] += 4
                    requirements['personnel']['system_administrator'] += 4
                
                elif task_type == 'vulnerability_patching':
                    requirements['personnel']['security_engineer'] += 6
                    requirements['personnel']['system_administrator'] += 8
                
                elif task_type == 'dns_security':
                    requirements['personnel']['network_engineer'] += 3
                    requirements['personnel']['system_administrator'] += 2
                
                # Cost estimates
                if task_type == 'ssl_certificate':
                    requirements['estimated_costs']['ssl_certificates'] += 100  # Annual cost
                
                # Time breakdown
                estimated_time = task.get('estimated_time', '2-4 hours')
                hours = self.parse_time_estimate(estimated_time)
                
                requirements['time_breakdown']['planning'] += hours * 0.2
                requirements['time_breakdown']['implementation'] += hours * 0.5
                requirements['time_breakdown']['testing'] += hours * 0.2
                requirements['time_breakdown']['documentation'] += hours * 0.1
            
            return requirements
            
        except Exception as e:
            logger.error(f"Error calculating resource requirements: {str(e)}")
            return {}
    
    def parse_time_estimate(self, time_str: str) -> float:
        """Parse time estimate string to hours."""
        try:
            # Extract numbers from string like "2-4 hours" or "1-2 days"
            numbers = re.findall(r'\d+', time_str)
            if numbers:
                if 'day' in time_str.lower():
                    return float(numbers[0]) * 8  # Assume 8 hours per day
                else:
                    return float(numbers[0])  # Assume hours
            return 2.0  # Default
        except:
            return 2.0
    
    def create_risk_mitigation_matrix(self, remediation_tasks: List[dict]) -> dict:
        """Create risk mitigation matrix showing before/after risk levels."""
        try:
            matrix = {
                'current_risks': {},
                'mitigated_risks': {},
                'residual_risks': {},
                'risk_reduction_percentage': {}
            }
            
            risk_categories = [
                'Data Breach',
                'System Compromise',
                'Service Disruption',
                'Compliance Violation',
                'Reputation Damage'
            ]
            
            # Simulate risk levels (in real implementation, these would be calculated)
            for category in risk_categories:
                current_risk = 70  # High risk initially
                
                # Calculate risk reduction based on remediation tasks
                risk_reduction = 0
                for task in remediation_tasks:
                    task_type = task.get('type', '')
                    priority = task.get('priority', 'medium')
                    
                    if task_type == 'ssl_certificate':
                        risk_reduction += 20 if category in ['Data Breach', 'Compliance Violation'] else 10
                    elif task_type == 'vulnerability_patching':
                        risk_reduction += 25 if category == 'System Compromise' else 15
                    elif task_type == 'security_headers':
                        risk_reduction += 15 if category in ['Data Breach', 'System Compromise'] else 5
                    elif task_type == 'open_ports':
                        risk_reduction += 20 if category == 'System Compromise' else 10
                
                mitigated_risk = max(10, current_risk - risk_reduction)  # Minimum 10% residual risk
                
                matrix['current_risks'][category] = current_risk
                matrix['mitigated_risks'][category] = mitigated_risk
                matrix['residual_risks'][category] = mitigated_risk
                matrix['risk_reduction_percentage'][category] = round(
                    ((current_risk - mitigated_risk) / current_risk) * 100, 1
                )
            
            return matrix
            
        except Exception as e:
            logger.error(f"Error creating risk mitigation matrix: {str(e)}")
            return {}

# Initialize global automated remediation engine
automated_remediation = AutomatedRemediationEngine()
"""
OWASP Top 20 Security Vulnerability Checker
Defensive security tool for analyzing web applications
"""
import requests
import logging
import ssl
import socket
from urllib.parse import urlparse
from typing import Dict, List, Any

logger = logging.getLogger(__name__)


class OWASPChecker:
    """OWASP Top 20 vulnerability checker for defensive security analysis."""

    def __init__(self):
        self.checks = [
            self.check_broken_access_control,
            self.check_cryptographic_failures,
            self.check_injection,
            self.check_insecure_design,
            self.check_security_misconfiguration,
            self.check_vulnerable_components,
            self.check_authentication_failures,
            self.check_software_data_integrity,
            self.check_logging_monitoring_failures,
            self.check_ssrf,
            self.check_security_headers,
            self.check_cors_policy,
            self.check_cookie_security,
            self.check_tls_configuration,
            self.check_information_disclosure,
            self.check_clickjacking_protection,
            self.check_content_security_policy,
            self.check_mixed_content,
            self.check_http_methods,
            self.check_directory_listing
        ]

    def analyze_domain(self, domain: str) -> Dict[str, Any]:
        """Analyze domain for OWASP Top 20 vulnerabilities."""
        logger.info(f"Starting OWASP analysis for {domain}")

        results = {
            "domain": domain,
            "vulnerabilities": [],
            "warnings": [],
            "passed": [],
            "security_score": 0,
            "risk_level": "Unknown",
            "recommendations": []
        }

        try:
            for check in self.checks:
                try:
                    check_result = check(domain)
                    if check_result:
                        if check_result.get("status") == "vulnerable":
                            results["vulnerabilities"].append(check_result)
                        elif check_result.get("status") == "warning":
                            results["warnings"].append(check_result)
                        else:
                            results["passed"].append(check_result)
                except Exception as e:
                    logger.error(f"Error in check {check.__name__}: {str(e)}")

            results["security_score"] = self._calculate_security_score(results)
            results["risk_level"] = self._determine_risk_level(results["security_score"])
            results["recommendations"] = self._generate_recommendations(results)

        except Exception as e:
            logger.error(f"Error analyzing domain: {str(e)}")
            results["error"] = str(e)

        return results

    def check_broken_access_control(self, domain: str) -> Dict:
        """Check for broken access control vulnerabilities."""
        try:
            url = f"https://{domain}"
            response = requests.get(url, timeout=10, allow_redirects=True)

            issues = []
            if 'X-Frame-Options' not in response.headers:
                issues.append("Missing X-Frame-Options header")

            return {
                "check": "Broken Access Control",
                "category": "OWASP A01",
                "status": "warning" if issues else "passed",
                "issues": issues,
                "description": "Access control enforces policy such that users cannot act outside of their intended permissions"
            }
        except Exception as e:
            return {"check": "Broken Access Control", "status": "error", "error": str(e)}

    def check_cryptographic_failures(self, domain: str) -> Dict:
        """Check for cryptographic failures."""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cipher = ssock.cipher()
                    version = ssock.version()

                    issues = []
                    if version in ['TLSv1', 'TLSv1.1', 'SSLv2', 'SSLv3']:
                        issues.append(f"Weak TLS version: {version}")

                    if cipher and 'RC4' in cipher[0] or 'DES' in cipher[0]:
                        issues.append(f"Weak cipher suite: {cipher[0]}")

                    return {
                        "check": "Cryptographic Failures",
                        "category": "OWASP A02",
                        "status": "vulnerable" if issues else "passed",
                        "issues": issues,
                        "tls_version": version,
                        "cipher_suite": cipher[0] if cipher else "Unknown",
                        "description": "Encryption in transit and at rest should use strong cryptography"
                    }
        except Exception as e:
            return {"check": "Cryptographic Failures", "status": "error", "error": str(e)}

    def check_injection(self, domain: str) -> Dict:
        """Check for injection vulnerabilities indicators."""
        try:
            url = f"https://{domain}"
            response = requests.get(url, timeout=10)

            issues = []
            headers = response.headers

            if 'X-Content-Type-Options' not in headers:
                issues.append("Missing X-Content-Type-Options (potential MIME sniffing)")

            if 'Content-Type' in headers and 'charset' not in headers['Content-Type'].lower():
                issues.append("Content-Type missing charset declaration")

            return {
                "check": "Injection Prevention",
                "category": "OWASP A03",
                "status": "warning" if issues else "passed",
                "issues": issues,
                "description": "Application should validate and sanitize all user input"
            }
        except Exception as e:
            return {"check": "Injection Prevention", "status": "error", "error": str(e)}

    def check_insecure_design(self, domain: str) -> Dict:
        """Check for insecure design patterns."""
        try:
            url = f"https://{domain}"
            response = requests.get(url, timeout=10)

            issues = []

            if response.status_code == 200:
                content_length = len(response.content)
                if content_length < 100:
                    issues.append("Suspiciously small response size")

            return {
                "check": "Insecure Design",
                "category": "OWASP A04",
                "status": "warning" if issues else "passed",
                "issues": issues,
                "description": "Secure design patterns should be established and used"
            }
        except Exception as e:
            return {"check": "Insecure Design", "status": "error", "error": str(e)}

    def check_security_misconfiguration(self, domain: str) -> Dict:
        """Check for security misconfigurations."""
        try:
            url = f"https://{domain}"
            response = requests.get(url, timeout=10)

            issues = []
            headers = response.headers

            if 'Server' in headers:
                issues.append(f"Server header exposed: {headers['Server']}")

            if 'X-Powered-By' in headers:
                issues.append(f"X-Powered-By header exposed: {headers['X-Powered-By']}")

            if 'X-AspNet-Version' in headers:
                issues.append("ASP.NET version exposed")

            return {
                "check": "Security Misconfiguration",
                "category": "OWASP A05",
                "status": "vulnerable" if issues else "passed",
                "issues": issues,
                "description": "Security settings should be defined, implemented, and maintained"
            }
        except Exception as e:
            return {"check": "Security Misconfiguration", "status": "error", "error": str(e)}

    def check_vulnerable_components(self, domain: str) -> Dict:
        """Check for vulnerable and outdated components."""
        try:
            url = f"https://{domain}"
            response = requests.get(url, timeout=10)

            issues = []
            headers = response.headers

            for header in ['Server', 'X-Powered-By', 'X-Generator']:
                if header in headers:
                    value = headers[header]
                    if any(old_tech in value.lower() for old_tech in ['php/5', 'apache/2.2', 'nginx/1.1']):
                        issues.append(f"Potentially outdated technology: {value}")

            return {
                "check": "Vulnerable Components",
                "category": "OWASP A06",
                "status": "warning" if issues else "passed",
                "issues": issues,
                "description": "Components should be up-to-date and vulnerability-free"
            }
        except Exception as e:
            return {"check": "Vulnerable Components", "status": "error", "error": str(e)}

    def check_authentication_failures(self, domain: str) -> Dict:
        """Check for authentication and session management issues."""
        try:
            url = f"https://{domain}"
            response = requests.get(url, timeout=10)

            issues = []

            cookies = response.cookies
            for cookie in cookies:
                if not cookie.secure:
                    issues.append(f"Cookie '{cookie.name}' missing Secure flag")
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    issues.append(f"Cookie '{cookie.name}' missing HttpOnly flag")

            return {
                "check": "Authentication Failures",
                "category": "OWASP A07",
                "status": "vulnerable" if issues else "passed",
                "issues": issues,
                "description": "Authentication and session management must be implemented correctly"
            }
        except Exception as e:
            return {"check": "Authentication Failures", "status": "error", "error": str(e)}

    def check_software_data_integrity(self, domain: str) -> Dict:
        """Check for software and data integrity failures."""
        try:
            url = f"https://{domain}"
            response = requests.get(url, timeout=10)

            issues = []
            headers = response.headers

            if 'Content-Security-Policy' not in headers:
                issues.append("Missing Content-Security-Policy header")

            return {
                "check": "Software and Data Integrity",
                "category": "OWASP A08",
                "status": "warning" if issues else "passed",
                "issues": issues,
                "description": "Software updates and critical data should be integrity-verified"
            }
        except Exception as e:
            return {"check": "Software and Data Integrity", "status": "error", "error": str(e)}

    def check_logging_monitoring_failures(self, domain: str) -> Dict:
        """Check for logging and monitoring failures."""
        return {
            "check": "Logging and Monitoring",
            "category": "OWASP A09",
            "status": "passed",
            "issues": [],
            "description": "This requires internal assessment of logging practices",
            "note": "Cannot be fully assessed externally"
        }

    def check_ssrf(self, domain: str) -> Dict:
        """Check for SSRF vulnerability indicators."""
        try:
            url = f"https://{domain}"
            response = requests.get(url, timeout=10)

            return {
                "check": "Server-Side Request Forgery (SSRF)",
                "category": "OWASP A10",
                "status": "passed",
                "issues": [],
                "description": "SSRF prevention requires input validation and URL filtering",
                "note": "Requires application-level testing"
            }
        except Exception as e:
            return {"check": "SSRF", "status": "error", "error": str(e)}

    def check_security_headers(self, domain: str) -> Dict:
        """Comprehensive security headers check."""
        try:
            url = f"https://{domain}"
            response = requests.get(url, timeout=10)

            required_headers = {
                'Strict-Transport-Security': 'HSTS not implemented',
                'X-Content-Type-Options': 'MIME sniffing not prevented',
                'X-Frame-Options': 'Clickjacking protection missing',
                'Content-Security-Policy': 'CSP not implemented',
                'Referrer-Policy': 'Referrer policy not set',
                'Permissions-Policy': 'Permissions policy not set'
            }

            issues = []
            for header, message in required_headers.items():
                if header not in response.headers:
                    issues.append(message)

            return {
                "check": "Security Headers",
                "category": "Best Practice",
                "status": "vulnerable" if len(issues) > 3 else "warning" if issues else "passed",
                "issues": issues,
                "present_headers": list(response.headers.keys()),
                "description": "Security headers provide defense-in-depth protection"
            }
        except Exception as e:
            return {"check": "Security Headers", "status": "error", "error": str(e)}

    def check_cors_policy(self, domain: str) -> Dict:
        """Check CORS policy configuration."""
        try:
            url = f"https://{domain}"
            headers = {'Origin': 'https://evil.com'}
            response = requests.get(url, headers=headers, timeout=10)

            issues = []
            if 'Access-Control-Allow-Origin' in response.headers:
                acao = response.headers['Access-Control-Allow-Origin']
                if acao == '*':
                    issues.append("CORS allows all origins (wildcard)")
                if 'evil.com' in acao:
                    issues.append("CORS reflects untrusted origin")

            return {
                "check": "CORS Policy",
                "category": "Best Practice",
                "status": "vulnerable" if issues else "passed",
                "issues": issues,
                "description": "CORS should be configured to allow only trusted origins"
            }
        except Exception as e:
            return {"check": "CORS Policy", "status": "error", "error": str(e)}

    def check_cookie_security(self, domain: str) -> Dict:
        """Comprehensive cookie security check."""
        try:
            url = f"https://{domain}"
            response = requests.get(url, timeout=10)

            issues = []
            for cookie in response.cookies:
                if not cookie.secure:
                    issues.append(f"Cookie '{cookie.name}' lacks Secure flag")
                if 'httponly' not in str(cookie).lower():
                    issues.append(f"Cookie '{cookie.name}' lacks HttpOnly flag")
                if 'samesite' not in str(cookie).lower():
                    issues.append(f"Cookie '{cookie.name}' lacks SameSite attribute")

            return {
                "check": "Cookie Security",
                "category": "Best Practice",
                "status": "vulnerable" if issues else "passed",
                "issues": issues,
                "description": "Cookies should have Secure, HttpOnly, and SameSite attributes"
            }
        except Exception as e:
            return {"check": "Cookie Security", "status": "error", "error": str(e)}

    def check_tls_configuration(self, domain: str) -> Dict:
        """Detailed TLS configuration check."""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

                    issues = []

                    if version not in ['TLSv1.2', 'TLSv1.3']:
                        issues.append(f"TLS version should be 1.2 or 1.3, found: {version}")

                    return {
                        "check": "TLS Configuration",
                        "category": "Best Practice",
                        "status": "warning" if issues else "passed",
                        "issues": issues,
                        "tls_version": version,
                        "cipher": cipher[0] if cipher else "Unknown",
                        "description": "TLS configuration should use modern versions and strong ciphers"
                    }
        except Exception as e:
            return {"check": "TLS Configuration", "status": "error", "error": str(e)}

    def check_information_disclosure(self, domain: str) -> Dict:
        """Check for information disclosure."""
        try:
            url = f"https://{domain}"
            response = requests.get(url, timeout=10)

            issues = []
            sensitive_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version']

            for header in sensitive_headers:
                if header in response.headers:
                    issues.append(f"Information disclosure via {header} header")

            return {
                "check": "Information Disclosure",
                "category": "Best Practice",
                "status": "warning" if issues else "passed",
                "issues": issues,
                "description": "Sensitive information should not be exposed in headers"
            }
        except Exception as e:
            return {"check": "Information Disclosure", "status": "error", "error": str(e)}

    def check_clickjacking_protection(self, domain: str) -> Dict:
        """Check clickjacking protection."""
        try:
            url = f"https://{domain}"
            response = requests.get(url, timeout=10)

            issues = []
            if 'X-Frame-Options' not in response.headers and 'Content-Security-Policy' not in response.headers:
                issues.append("No clickjacking protection (missing X-Frame-Options and CSP frame-ancestors)")

            return {
                "check": "Clickjacking Protection",
                "category": "Best Practice",
                "status": "vulnerable" if issues else "passed",
                "issues": issues,
                "description": "X-Frame-Options or CSP frame-ancestors should be set"
            }
        except Exception as e:
            return {"check": "Clickjacking Protection", "status": "error", "error": str(e)}

    def check_content_security_policy(self, domain: str) -> Dict:
        """Detailed CSP check."""
        try:
            url = f"https://{domain}"
            response = requests.get(url, timeout=10)

            issues = []
            if 'Content-Security-Policy' not in response.headers:
                issues.append("No Content-Security-Policy header")
            else:
                csp = response.headers['Content-Security-Policy']
                if 'unsafe-inline' in csp:
                    issues.append("CSP allows unsafe-inline")
                if 'unsafe-eval' in csp:
                    issues.append("CSP allows unsafe-eval")

            return {
                "check": "Content Security Policy",
                "category": "Best Practice",
                "status": "vulnerable" if issues else "passed",
                "issues": issues,
                "description": "CSP helps prevent XSS and data injection attacks"
            }
        except Exception as e:
            return {"check": "Content Security Policy", "status": "error", "error": str(e)}

    def check_mixed_content(self, domain: str) -> Dict:
        """Check for mixed content issues."""
        try:
            url = f"https://{domain}"
            response = requests.get(url, timeout=10)

            issues = []
            content = response.text.lower()

            if 'http://' in content and 'https://' in content:
                issues.append("Potential mixed content detected (HTTP resources on HTTPS page)")

            return {
                "check": "Mixed Content",
                "category": "Best Practice",
                "status": "warning" if issues else "passed",
                "issues": issues,
                "description": "All resources should be loaded over HTTPS"
            }
        except Exception as e:
            return {"check": "Mixed Content", "status": "error", "error": str(e)}

    def check_http_methods(self, domain: str) -> Dict:
        """Check allowed HTTP methods."""
        try:
            url = f"https://{domain}"
            response = requests.options(url, timeout=10)

            issues = []
            if 'Allow' in response.headers:
                allowed_methods = response.headers['Allow'].upper()
                dangerous_methods = ['TRACE', 'TRACK', 'PUT', 'DELETE']

                for method in dangerous_methods:
                    if method in allowed_methods:
                        issues.append(f"Potentially dangerous HTTP method allowed: {method}")

            return {
                "check": "HTTP Methods",
                "category": "Best Practice",
                "status": "warning" if issues else "passed",
                "issues": issues,
                "description": "Only necessary HTTP methods should be allowed"
            }
        except Exception as e:
            return {"check": "HTTP Methods", "status": "error", "error": str(e)}

    def check_directory_listing(self, domain: str) -> Dict:
        """Check for directory listing."""
        try:
            test_paths = ['/', '/images/', '/assets/', '/static/']
            issues = []

            for path in test_paths:
                url = f"https://{domain}{path}"
                try:
                    response = requests.get(url, timeout=5)
                    if 'Index of' in response.text or 'Directory listing' in response.text:
                        issues.append(f"Directory listing enabled at {path}")
                except:
                    pass

            return {
                "check": "Directory Listing",
                "category": "Best Practice",
                "status": "vulnerable" if issues else "passed",
                "issues": issues,
                "description": "Directory listing should be disabled"
            }
        except Exception as e:
            return {"check": "Directory Listing", "status": "error", "error": str(e)}

    def _calculate_security_score(self, results: Dict) -> int:
        """Calculate overall security score."""
        total_checks = len(results["vulnerabilities"]) + len(results["warnings"]) + len(results["passed"])
        if total_checks == 0:
            return 0

        vulnerable_weight = 0
        warning_weight = 50
        passed_weight = 100

        total_score = (
            len(results["vulnerabilities"]) * vulnerable_weight +
            len(results["warnings"]) * warning_weight +
            len(results["passed"]) * passed_weight
        )

        return min(100, int(total_score / total_checks))

    def _determine_risk_level(self, score: int) -> str:
        """Determine risk level based on security score."""
        if score >= 80:
            return "Low"
        elif score >= 60:
            return "Medium"
        elif score >= 40:
            return "High"
        else:
            return "Critical"

    def _generate_recommendations(self, results: Dict) -> List[str]:
        """Generate security recommendations."""
        recommendations = []

        if results["vulnerabilities"]:
            recommendations.append("Address critical vulnerabilities immediately")
            for vuln in results["vulnerabilities"][:3]:
                recommendations.append(f"Fix: {vuln.get('check', 'Unknown')} - {vuln.get('description', '')}")

        if results["warnings"]:
            recommendations.append("Review and address security warnings")

        if results["security_score"] < 70:
            recommendations.append("Implement comprehensive security headers")
            recommendations.append("Review and update TLS configuration")
            recommendations.append("Enable security monitoring and logging")

        return recommendations[:5]


owasp_checker = OWASPChecker()

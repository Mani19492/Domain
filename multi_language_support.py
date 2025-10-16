import json
import logging
from typing import Dict, List, Any, Optional
from googletrans import Translator
import os
from datetime import datetime

logger = logging.getLogger(__name__)

class MultiLanguageSupport:
    def __init__(self):
        self.translator = Translator()
        self.supported_languages = {
            'en': 'English',
            'es': 'Spanish',
            'fr': 'French',
            'de': 'German',
            'it': 'Italian',
            'pt': 'Portuguese',
            'ru': 'Russian',
            'zh': 'Chinese (Simplified)',
            'ja': 'Japanese',
            'ko': 'Korean',
            'ar': 'Arabic',
            'hi': 'Hindi',
            'nl': 'Dutch',
            'sv': 'Swedish',
            'no': 'Norwegian',
            'da': 'Danish',
            'fi': 'Finnish',
            'pl': 'Polish',
            'tr': 'Turkish',
            'th': 'Thai'
        }
        
        # Load pre-translated common terms
        self.common_translations = self.load_common_translations()
        
        # Accessibility features
        self.accessibility_features = {
            'screen_reader_support': True,
            'high_contrast_mode': True,
            'large_text_support': True,
            'keyboard_navigation': True,
            'voice_commands': False  # Future feature
        }
    
    def load_common_translations(self) -> dict:
        """Load pre-translated common cybersecurity terms."""
        return {
            'en': {
                'domain': 'Domain',
                'security': 'Security',
                'threat': 'Threat',
                'vulnerability': 'Vulnerability',
                'risk': 'Risk',
                'analysis': 'Analysis',
                'report': 'Report',
                'scan': 'Scan',
                'ssl_certificate': 'SSL Certificate',
                'dns_records': 'DNS Records',
                'open_ports': 'Open Ports',
                'subdomains': 'Subdomains',
                'ip_address': 'IP Address',
                'geolocation': 'Geolocation',
                'whois_data': 'WHOIS Data',
                'security_headers': 'Security Headers',
                'threat_analysis': 'Threat Analysis',
                'recommendations': 'Recommendations',
                'critical': 'Critical',
                'high': 'High',
                'medium': 'Medium',
                'low': 'Low',
                'safe': 'Safe',
                'malicious': 'Malicious',
                'suspicious': 'Suspicious',
                'phishing': 'Phishing',
                'malware': 'Malware',
                'compliance': 'Compliance',
                'remediation': 'Remediation'
            },
            'es': {
                'domain': 'Dominio',
                'security': 'Seguridad',
                'threat': 'Amenaza',
                'vulnerability': 'Vulnerabilidad',
                'risk': 'Riesgo',
                'analysis': 'Análisis',
                'report': 'Informe',
                'scan': 'Escaneo',
                'ssl_certificate': 'Certificado SSL',
                'dns_records': 'Registros DNS',
                'open_ports': 'Puertos Abiertos',
                'subdomains': 'Subdominios',
                'ip_address': 'Dirección IP',
                'geolocation': 'Geolocalización',
                'whois_data': 'Datos WHOIS',
                'security_headers': 'Cabeceras de Seguridad',
                'threat_analysis': 'Análisis de Amenazas',
                'recommendations': 'Recomendaciones',
                'critical': 'Crítico',
                'high': 'Alto',
                'medium': 'Medio',
                'low': 'Bajo',
                'safe': 'Seguro',
                'malicious': 'Malicioso',
                'suspicious': 'Sospechoso',
                'phishing': 'Phishing',
                'malware': 'Malware',
                'compliance': 'Cumplimiento',
                'remediation': 'Remediación'
            },
            'fr': {
                'domain': 'Domaine',
                'security': 'Sécurité',
                'threat': 'Menace',
                'vulnerability': 'Vulnérabilité',
                'risk': 'Risque',
                'analysis': 'Analyse',
                'report': 'Rapport',
                'scan': 'Analyse',
                'ssl_certificate': 'Certificat SSL',
                'dns_records': 'Enregistrements DNS',
                'open_ports': 'Ports Ouverts',
                'subdomains': 'Sous-domaines',
                'ip_address': 'Adresse IP',
                'geolocation': 'Géolocalisation',
                'whois_data': 'Données WHOIS',
                'security_headers': 'En-têtes de Sécurité',
                'threat_analysis': 'Analyse des Menaces',
                'recommendations': 'Recommandations',
                'critical': 'Critique',
                'high': 'Élevé',
                'medium': 'Moyen',
                'low': 'Faible',
                'safe': 'Sûr',
                'malicious': 'Malveillant',
                'suspicious': 'Suspect',
                'phishing': 'Hameçonnage',
                'malware': 'Logiciel Malveillant',
                'compliance': 'Conformité',
                'remediation': 'Remédiation'
            },
            'de': {
                'domain': 'Domain',
                'security': 'Sicherheit',
                'threat': 'Bedrohung',
                'vulnerability': 'Schwachstelle',
                'risk': 'Risiko',
                'analysis': 'Analyse',
                'report': 'Bericht',
                'scan': 'Scan',
                'ssl_certificate': 'SSL-Zertifikat',
                'dns_records': 'DNS-Einträge',
                'open_ports': 'Offene Ports',
                'subdomains': 'Subdomains',
                'ip_address': 'IP-Adresse',
                'geolocation': 'Geolokalisierung',
                'whois_data': 'WHOIS-Daten',
                'security_headers': 'Sicherheits-Header',
                'threat_analysis': 'Bedrohungsanalyse',
                'recommendations': 'Empfehlungen',
                'critical': 'Kritisch',
                'high': 'Hoch',
                'medium': 'Mittel',
                'low': 'Niedrig',
                'safe': 'Sicher',
                'malicious': 'Bösartig',
                'suspicious': 'Verdächtig',
                'phishing': 'Phishing',
                'malware': 'Malware',
                'compliance': 'Compliance',
                'remediation': 'Behebung'
            },
            'zh': {
                'domain': '域名',
                'security': '安全',
                'threat': '威胁',
                'vulnerability': '漏洞',
                'risk': '风险',
                'analysis': '分析',
                'report': '报告',
                'scan': '扫描',
                'ssl_certificate': 'SSL证书',
                'dns_records': 'DNS记录',
                'open_ports': '开放端口',
                'subdomains': '子域名',
                'ip_address': 'IP地址',
                'geolocation': '地理位置',
                'whois_data': 'WHOIS数据',
                'security_headers': '安全头',
                'threat_analysis': '威胁分析',
                'recommendations': '建议',
                'critical': '严重',
                'high': '高',
                'medium': '中',
                'low': '低',
                'safe': '安全',
                'malicious': '恶意',
                'suspicious': '可疑',
                'phishing': '钓鱼',
                'malware': '恶意软件',
                'compliance': '合规',
                'remediation': '修复'
            }
        }
    
    def detect_language(self, text: str) -> str:
        """Detect the language of input text."""
        try:
            detection = self.translator.detect(text)
            detected_lang = detection.lang
            
            # Return detected language if supported, otherwise default to English
            return detected_lang if detected_lang in self.supported_languages else 'en'
            
        except Exception as e:
            logger.error(f"Error detecting language: {str(e)}")
            return 'en'  # Default to English
    
    def translate_text(self, text: str, target_language: str, source_language: str = 'auto') -> str:
        """Translate text to target language."""
        try:
            if target_language == 'en' and source_language == 'auto':
                return text  # No translation needed
            
            # Check if it's a common term with pre-translation
            text_lower = text.lower().replace(' ', '_')
            if target_language in self.common_translations:
                common_terms = self.common_translations[target_language]
                if text_lower in self.common_translations.get('en', {}):
                    # Find the English key and get translation
                    for en_key, en_value in self.common_translations['en'].items():
                        if en_value.lower() == text.lower():
                            return common_terms.get(en_key, text)
            
            # Use Google Translate for other text
            translation = self.translator.translate(
                text, 
                src=source_language, 
                dest=target_language
            )
            
            return translation.text
            
        except Exception as e:
            logger.error(f"Error translating text: {str(e)}")
            return text  # Return original text if translation fails
    
    def translate_report(self, report_data: dict, target_language: str) -> dict:
        """Translate entire report to target language."""
        try:
            if target_language == 'en':
                return report_data  # No translation needed
            
            translated_report = self.deep_translate_dict(report_data, target_language)
            
            # Add translation metadata
            translated_report['translation_info'] = {
                'target_language': target_language,
                'language_name': self.supported_languages.get(target_language, 'Unknown'),
                'translated_at': datetime.now().isoformat(),
                'translator': 'Google Translate API'
            }
            
            return translated_report
            
        except Exception as e:
            logger.error(f"Error translating report: {str(e)}")
            return report_data
    
    def deep_translate_dict(self, data: Any, target_language: str) -> Any:
        """Recursively translate dictionary values."""
        try:
            if isinstance(data, dict):
                translated_dict = {}
                for key, value in data.items():
                    # Translate key if it's a user-facing field
                    translated_key = self.translate_if_user_facing(key, target_language)
                    translated_dict[translated_key] = self.deep_translate_dict(value, target_language)
                return translated_dict
            
            elif isinstance(data, list):
                return [self.deep_translate_dict(item, target_language) for item in data]
            
            elif isinstance(data, str):
                # Skip translation for certain technical fields
                if self.should_skip_translation(data):
                    return data
                return self.translate_text(data, target_language)
            
            else:
                return data  # Return as-is for numbers, booleans, etc.
                
        except Exception as e:
            logger.error(f"Error in deep translation: {str(e)}")
            return data
    
    def translate_if_user_facing(self, key: str, target_language: str) -> str:
        """Translate key if it's user-facing, otherwise keep original."""
        user_facing_keys = [
            'title', 'description', 'message', 'recommendation', 'summary',
            'finding', 'note', 'warning', 'error', 'success', 'info'
        ]
        
        if any(uf_key in key.lower() for uf_key in user_facing_keys):
            return self.translate_text(key.replace('_', ' ').title(), target_language)
        
        return key  # Keep technical keys untranslated
    
    def should_skip_translation(self, text: str) -> bool:
        """Determine if text should be skipped from translation."""
        skip_patterns = [
            # Technical identifiers
            r'^[A-Z0-9\-_]+$',  # All caps with numbers/hyphens
            r'^\d+\.\d+\.\d+\.\d+$',  # IP addresses
            r'^[a-f0-9]{32,}$',  # Hashes
            r'^https?://',  # URLs
            r'^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$',  # Domain names
            r'^CVE-\d{4}-\d+$',  # CVE identifiers
            r'^\w+://\w+',  # Protocol strings
            r'^[A-Z]{2,10}-[A-Z0-9\-]+$',  # Technical codes
        ]
        
        import re
        for pattern in skip_patterns:
            if re.match(pattern, text):
                return True
        
        # Skip very short strings (likely technical)
        if len(text) <= 3:
            return True
        
        # Skip if mostly numbers
        if sum(c.isdigit() for c in text) / len(text) > 0.7:
            return True
        
        return False
    
    def get_localized_ui_strings(self, language: str) -> dict:
        """Get localized UI strings for the interface."""
        ui_strings = {
            'en': {
                'page_title': 'Advanced Domain Reconnaissance Platform',
                'scan_button': 'Start Comprehensive Scan',
                'domain_placeholder': 'Enter domain name (e.g., example.com)',
                'scanning_progress': 'Scanning in progress...',
                'results_title': 'Scan Results',
                'threat_analysis': 'Threat Analysis',
                'recommendations': 'Security Recommendations',
                'technical_details': 'Technical Details',
                'download_report': 'Download Report',
                'share_report': 'Share Report',
                'monitoring_tab': 'Real-time Monitoring',
                'compliance_tab': 'Compliance Audit',
                'vulnerabilities_tab': 'Vulnerabilities',
                'blockchain_tab': 'Blockchain Analysis',
                'attack_surface_tab': 'Attack Surface',
                'remediation_tab': 'Remediation Guide',
                'error_invalid_domain': 'Please enter a valid domain name',
                'error_scan_failed': 'Scan failed. Please try again.',
                'success_scan_complete': 'Scan completed successfully',
                'loading': 'Loading...',
                'no_data': 'No data available',
                'high_risk': 'High Risk',
                'medium_risk': 'Medium Risk',
                'low_risk': 'Low Risk',
                'safe': 'Safe'
            },
            'es': {
                'page_title': 'Plataforma Avanzada de Reconocimiento de Dominios',
                'scan_button': 'Iniciar Escaneo Completo',
                'domain_placeholder': 'Ingrese nombre de dominio (ej: ejemplo.com)',
                'scanning_progress': 'Escaneo en progreso...',
                'results_title': 'Resultados del Escaneo',
                'threat_analysis': 'Análisis de Amenazas',
                'recommendations': 'Recomendaciones de Seguridad',
                'technical_details': 'Detalles Técnicos',
                'download_report': 'Descargar Informe',
                'share_report': 'Compartir Informe',
                'monitoring_tab': 'Monitoreo en Tiempo Real',
                'compliance_tab': 'Auditoría de Cumplimiento',
                'vulnerabilities_tab': 'Vulnerabilidades',
                'blockchain_tab': 'Análisis Blockchain',
                'attack_surface_tab': 'Superficie de Ataque',
                'remediation_tab': 'Guía de Remediación',
                'error_invalid_domain': 'Por favor ingrese un nombre de dominio válido',
                'error_scan_failed': 'El escaneo falló. Inténtelo de nuevo.',
                'success_scan_complete': 'Escaneo completado exitosamente',
                'loading': 'Cargando...',
                'no_data': 'No hay datos disponibles',
                'high_risk': 'Alto Riesgo',
                'medium_risk': 'Riesgo Medio',
                'low_risk': 'Bajo Riesgo',
                'safe': 'Seguro'
            },
            'fr': {
                'page_title': 'Plateforme Avancée de Reconnaissance de Domaines',
                'scan_button': 'Démarrer l\'Analyse Complète',
                'domain_placeholder': 'Entrez le nom de domaine (ex: exemple.com)',
                'scanning_progress': 'Analyse en cours...',
                'results_title': 'Résultats de l\'Analyse',
                'threat_analysis': 'Analyse des Menaces',
                'recommendations': 'Recommandations de Sécurité',
                'technical_details': 'Détails Techniques',
                'download_report': 'Télécharger le Rapport',
                'share_report': 'Partager le Rapport',
                'monitoring_tab': 'Surveillance en Temps Réel',
                'compliance_tab': 'Audit de Conformité',
                'vulnerabilities_tab': 'Vulnérabilités',
                'blockchain_tab': 'Analyse Blockchain',
                'attack_surface_tab': 'Surface d\'Attaque',
                'remediation_tab': 'Guide de Remédiation',
                'error_invalid_domain': 'Veuillez entrer un nom de domaine valide',
                'error_scan_failed': 'L\'analyse a échoué. Veuillez réessayer.',
                'success_scan_complete': 'Analyse terminée avec succès',
                'loading': 'Chargement...',
                'no_data': 'Aucune donnée disponible',
                'high_risk': 'Risque Élevé',
                'medium_risk': 'Risque Moyen',
                'low_risk': 'Faible Risque',
                'safe': 'Sûr'
            },
            'de': {
                'page_title': 'Erweiterte Domain-Aufklärungs-Plattform',
                'scan_button': 'Umfassenden Scan Starten',
                'domain_placeholder': 'Domain-Namen eingeben (z.B. beispiel.com)',
                'scanning_progress': 'Scan läuft...',
                'results_title': 'Scan-Ergebnisse',
                'threat_analysis': 'Bedrohungsanalyse',
                'recommendations': 'Sicherheitsempfehlungen',
                'technical_details': 'Technische Details',
                'download_report': 'Bericht Herunterladen',
                'share_report': 'Bericht Teilen',
                'monitoring_tab': 'Echtzeit-Überwachung',
                'compliance_tab': 'Compliance-Audit',
                'vulnerabilities_tab': 'Schwachstellen',
                'blockchain_tab': 'Blockchain-Analyse',
                'attack_surface_tab': 'Angriffsfläche',
                'remediation_tab': 'Behebungsleitfaden',
                'error_invalid_domain': 'Bitte geben Sie einen gültigen Domain-Namen ein',
                'error_scan_failed': 'Scan fehlgeschlagen. Bitte versuchen Sie es erneut.',
                'success_scan_complete': 'Scan erfolgreich abgeschlossen',
                'loading': 'Laden...',
                'no_data': 'Keine Daten verfügbar',
                'high_risk': 'Hohes Risiko',
                'medium_risk': 'Mittleres Risiko',
                'low_risk': 'Geringes Risiko',
                'safe': 'Sicher'
            },
            'zh': {
                'page_title': '高级域名侦察平台',
                'scan_button': '开始综合扫描',
                'domain_placeholder': '输入域名 (例如: example.com)',
                'scanning_progress': '扫描进行中...',
                'results_title': '扫描结果',
                'threat_analysis': '威胁分析',
                'recommendations': '安全建议',
                'technical_details': '技术详情',
                'download_report': '下载报告',
                'share_report': '分享报告',
                'monitoring_tab': '实时监控',
                'compliance_tab': '合规审计',
                'vulnerabilities_tab': '漏洞',
                'blockchain_tab': '区块链分析',
                'attack_surface_tab': '攻击面',
                'remediation_tab': '修复指南',
                'error_invalid_domain': '请输入有效的域名',
                'error_scan_failed': '扫描失败，请重试',
                'success_scan_complete': '扫描成功完成',
                'loading': '加载中...',
                'no_data': '无可用数据',
                'high_risk': '高风险',
                'medium_risk': '中等风险',
                'low_risk': '低风险',
                'safe': '安全'
            }
        }
        
        return ui_strings.get(language, ui_strings['en'])
    
    def generate_accessibility_features(self, content: dict, language: str = 'en') -> dict:
        """Generate accessibility features for content."""
        try:
            accessibility_content = {
                'aria_labels': {},
                'alt_texts': {},
                'screen_reader_descriptions': {},
                'keyboard_shortcuts': {},
                'high_contrast_styles': {},
                'large_text_styles': {}
            }
            
            # Generate ARIA labels
            accessibility_content['aria_labels'] = {
                'scan_button': self.translate_text('Start security scan for domain', language),
                'domain_input': self.translate_text('Enter domain name to analyze', language),
                'results_section': self.translate_text('Security analysis results', language),
                'threat_gauge': self.translate_text('Threat level indicator', language),
                'recommendations_list': self.translate_text('Security recommendations list', language)
            }
            
            # Generate alt texts for visual elements
            accessibility_content['alt_texts'] = {
                'threat_gauge': self.translate_text('Circular gauge showing threat level', language),
                'network_graph': self.translate_text('Network diagram showing domain relationships', language),
                'risk_chart': self.translate_text('Bar chart displaying risk levels', language),
                'world_map': self.translate_text('World map showing domain geographic location', language)
            }
            
            # Screen reader descriptions
            accessibility_content['screen_reader_descriptions'] = {
                'scan_progress': self.translate_text('Scan in progress, please wait', language),
                'high_risk_alert': self.translate_text('High risk detected, immediate attention required', language),
                'scan_complete': self.translate_text('Security scan completed successfully', language),
                'no_threats': self.translate_text('No significant threats detected', language)
            }
            
            # Keyboard shortcuts
            accessibility_content['keyboard_shortcuts'] = {
                'start_scan': 'Ctrl+Enter',
                'download_report': 'Ctrl+D',
                'share_report': 'Ctrl+S',
                'next_tab': 'Tab',
                'previous_tab': 'Shift+Tab',
                'close_modal': 'Escape'
            }
            
            # High contrast styles
            accessibility_content['high_contrast_styles'] = {
                'background_color': '#000000',
                'text_color': '#FFFFFF',
                'link_color': '#FFFF00',
                'button_color': '#FFFFFF',
                'button_background': '#000000',
                'border_color': '#FFFFFF',
                'focus_color': '#FFFF00'
            }
            
            # Large text styles
            accessibility_content['large_text_styles'] = {
                'base_font_size': '18px',
                'heading_font_size': '24px',
                'button_font_size': '16px',
                'line_height': '1.6',
                'letter_spacing': '0.05em'
            }
            
            return accessibility_content
            
        except Exception as e:
            logger.error(f"Error generating accessibility features: {str(e)}")
            return {}
    
    def create_voice_commands_config(self, language: str = 'en') -> dict:
        """Create voice commands configuration for the interface."""
        try:
            voice_commands = {
                'en': {
                    'start_scan': ['start scan', 'begin analysis', 'analyze domain'],
                    'stop_scan': ['stop scan', 'cancel analysis', 'abort'],
                    'download_report': ['download report', 'save report', 'export results'],
                    'share_report': ['share report', 'send report', 'collaborate'],
                    'next_tab': ['next tab', 'next section', 'move forward'],
                    'previous_tab': ['previous tab', 'back', 'go back'],
                    'show_help': ['help', 'show help', 'assistance'],
                    'repeat_last': ['repeat', 'say again', 'repeat last']
                },
                'es': {
                    'start_scan': ['iniciar escaneo', 'comenzar análisis', 'analizar dominio'],
                    'stop_scan': ['detener escaneo', 'cancelar análisis', 'abortar'],
                    'download_report': ['descargar informe', 'guardar informe', 'exportar resultados'],
                    'share_report': ['compartir informe', 'enviar informe', 'colaborar'],
                    'next_tab': ['siguiente pestaña', 'siguiente sección', 'avanzar'],
                    'previous_tab': ['pestaña anterior', 'atrás', 'regresar'],
                    'show_help': ['ayuda', 'mostrar ayuda', 'asistencia'],
                    'repeat_last': ['repetir', 'decir de nuevo', 'repetir último']
                },
                'fr': {
                    'start_scan': ['démarrer analyse', 'commencer analyse', 'analyser domaine'],
                    'stop_scan': ['arrêter analyse', 'annuler analyse', 'abandonner'],
                    'download_report': ['télécharger rapport', 'sauvegarder rapport', 'exporter résultats'],
                    'share_report': ['partager rapport', 'envoyer rapport', 'collaborer'],
                    'next_tab': ['onglet suivant', 'section suivante', 'avancer'],
                    'previous_tab': ['onglet précédent', 'retour', 'revenir'],
                    'show_help': ['aide', 'afficher aide', 'assistance'],
                    'repeat_last': ['répéter', 'redire', 'répéter dernier']
                }
            }
            
            return voice_commands.get(language, voice_commands['en'])
            
        except Exception as e:
            logger.error(f"Error creating voice commands config: {str(e)}")
            return {}
    
    def generate_rtl_support(self, language: str) -> dict:
        """Generate right-to-left language support configuration."""
        rtl_languages = ['ar', 'he', 'fa', 'ur']
        
        if language in rtl_languages:
            return {
                'direction': 'rtl',
                'text_align': 'right',
                'margin_adjustments': {
                    'margin_left': 'margin_right',
                    'padding_left': 'padding_right',
                    'border_left': 'border_right'
                },
                'icon_adjustments': {
                    'arrow_left': 'arrow_right',
                    'chevron_left': 'chevron_right'
                },
                'layout_adjustments': {
                    'flex_direction': 'row-reverse',
                    'float': 'right'
                }
            }
        else:
            return {
                'direction': 'ltr',
                'text_align': 'left',
                'margin_adjustments': {},
                'icon_adjustments': {},
                'layout_adjustments': {}
            }
    
    def get_language_specific_formatting(self, language: str) -> dict:
        """Get language-specific formatting rules."""
        formatting_rules = {
            'en': {
                'date_format': 'MM/DD/YYYY',
                'time_format': '12h',
                'number_format': '1,234.56',
                'currency_symbol': '$',
                'decimal_separator': '.',
                'thousands_separator': ','
            },
            'es': {
                'date_format': 'DD/MM/YYYY',
                'time_format': '24h',
                'number_format': '1.234,56',
                'currency_symbol': '€',
                'decimal_separator': ',',
                'thousands_separator': '.'
            },
            'fr': {
                'date_format': 'DD/MM/YYYY',
                'time_format': '24h',
                'number_format': '1 234,56',
                'currency_symbol': '€',
                'decimal_separator': ',',
                'thousands_separator': ' '
            },
            'de': {
                'date_format': 'DD.MM.YYYY',
                'time_format': '24h',
                'number_format': '1.234,56',
                'currency_symbol': '€',
                'decimal_separator': ',',
                'thousands_separator': '.'
            },
            'zh': {
                'date_format': 'YYYY/MM/DD',
                'time_format': '24h',
                'number_format': '1,234.56',
                'currency_symbol': '¥',
                'decimal_separator': '.',
                'thousands_separator': ','
            }
        }
        
        return formatting_rules.get(language, formatting_rules['en'])
    
    def create_localized_error_messages(self, language: str) -> dict:
        """Create localized error messages."""
        error_messages = {
            'en': {
                'invalid_domain': 'Please enter a valid domain name',
                'network_error': 'Network error occurred. Please check your connection.',
                'scan_timeout': 'Scan timed out. Please try again.',
                'server_error': 'Server error occurred. Please try again later.',
                'rate_limit': 'Too many requests. Please wait before trying again.',
                'invalid_input': 'Invalid input provided',
                'permission_denied': 'Permission denied',
                'resource_not_found': 'Requested resource not found',
                'service_unavailable': 'Service temporarily unavailable'
            },
            'es': {
                'invalid_domain': 'Por favor ingrese un nombre de dominio válido',
                'network_error': 'Error de red. Por favor verifique su conexión.',
                'scan_timeout': 'El escaneo expiró. Por favor inténtelo de nuevo.',
                'server_error': 'Error del servidor. Por favor inténtelo más tarde.',
                'rate_limit': 'Demasiadas solicitudes. Por favor espere antes de intentar de nuevo.',
                'invalid_input': 'Entrada inválida proporcionada',
                'permission_denied': 'Permiso denegado',
                'resource_not_found': 'Recurso solicitado no encontrado',
                'service_unavailable': 'Servicio temporalmente no disponible'
            },
            'fr': {
                'invalid_domain': 'Veuillez entrer un nom de domaine valide',
                'network_error': 'Erreur réseau. Veuillez vérifier votre connexion.',
                'scan_timeout': 'L\'analyse a expiré. Veuillez réessayer.',
                'server_error': 'Erreur serveur. Veuillez réessayer plus tard.',
                'rate_limit': 'Trop de requêtes. Veuillez attendre avant de réessayer.',
                'invalid_input': 'Entrée invalide fournie',
                'permission_denied': 'Permission refusée',
                'resource_not_found': 'Ressource demandée non trouvée',
                'service_unavailable': 'Service temporairement indisponible'
            }
        }
        
        return error_messages.get(language, error_messages['en'])

# Initialize global multi-language support
multi_language_support = MultiLanguageSupport()
import os
import tempfile
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.pdfgen import canvas
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from datetime import datetime
import logging
from io import BytesIO

logger = logging.getLogger(__name__)

# Removed custom font registration to avoid path errors; using default Helvetica

def generate_pdf_report(scan_data: dict) -> str:
    """Generate a comprehensive, stylish PDF report."""
    try:
        # Create temporary file
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
        temp_file.close()
        
        # Create PDF document
        doc = SimpleDocTemplate(
            temp_file.name,
            pagesize=A4,
            rightMargin=0.75*inch,
            leftMargin=0.75*inch,
            topMargin=1*inch,
            bottomMargin=0.5*inch
        )
        
        # Get styles
        styles = getSampleStyleSheet()
        
        # Enhanced custom styles for professionalism
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=28,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=colors.HexColor('#1e40af'),
            backColor=colors.HexColor('#eff6ff')
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontName='Helvetica-Bold',
            fontSize=18,
            spaceAfter=12,
            spaceBefore=24,
            textColor=colors.HexColor('#1e40af'),
            leftIndent=0.5*inch
        )
        
        subheading_style = ParagraphStyle(
            'CustomSubHeading',
            parent=styles['Heading3'],
            fontName='Helvetica',
            fontSize=14,
            spaceAfter=8,
            spaceBefore=12,
            textColor=colors.HexColor('#059669'),
            leftIndent=0.5*inch
        )
        
        normal_style = ParagraphStyle(
            'CustomNormal',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=11,
            spaceAfter=6,
            leftIndent=0.5*inch,
            textColor=colors.HexColor('#374151')
        )
        
        # Build story
        story = []
        
        # Cover Page
        story.append(Paragraph("Domain Reconnaissance Report", title_style))
        story.append(Spacer(1, 20))
        domain = scan_data.get('domain', 'Unknown')
        story.append(Paragraph(f"<b><font size=24 color='#1e40af'>{domain}</font></b>", styles['Title']))
        story.append(Spacer(1, 40))
        story.append(Paragraph(f"Generated on: {datetime.now().strftime('%B %d, %Y at %I:%M %p')}", normal_style))
        story.append(Spacer(1, 60))
        story.append(Paragraph("Professional Security Analysis & Threat Intelligence", ParagraphStyle(
            'CoverSub',
            parent=styles['Normal'],
            fontSize=14,
            alignment=TA_CENTER,
            textColor=colors.HexColor('#6b7280'),
            spaceAfter=200
        )))
        story.append(PageBreak())
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", heading_style))
        auth_data = scan_data.get('authenticity', {})
        confidence = auth_data.get('confidence_score', 100)
        status_icon = "✅" if auth_data.get('is_genuine', True) else "⚠️"
        story.append(Paragraph(f"{status_icon} <b>Authenticity Status:</b> {'Genuine' if auth_data.get('is_genuine', True) else 'Potential Risk'} (Confidence: {confidence}/100)", normal_style))
        if not auth_data.get('is_genuine', True) and scan_data.get('official_link'):
            story.append(Paragraph(f"<b>Recommended Official Link:</b> {scan_data['official_link']}", normal_style))
        story.append(Spacer(1, 20))
        
        # Key Metrics Table
        key_metrics = [
            ['Metric', 'Value'],
            ['Domain Age', 'Recent' if 'created' in scan_data.get('reconnaissance', {}).get('whois', {}) and 'N/A' not in scan_data.get('reconnaissance', {}).get('whois', {}).get('created', 'N/A') else 'Unknown'],
            ['Subdomains Found', str(len(scan_data.get('reconnaissance', {}).get('subdomains', [])))],
            ['Open Ports', str(len(scan_data.get('reconnaissance', {}).get('open_ports', [])))],
            ['Threat Score', f"{confidence}/100"],
            ['SSL Valid', 'Yes' if scan_data.get('reconnaissance', {}).get('ssl', {}).get('valid', False) else 'No']
        ]
        metrics_table = Table(key_metrics, colWidths=[2.5*inch, 3.5*inch])
        metrics_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#dbeafe')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#1e40af')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8fafc')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
        ]))
        story.append(metrics_table)
        story.append(Spacer(1, 30))
        
        # Authenticity Check Section
        story.append(Paragraph("🔒 Authenticity Assessment", heading_style))
        
        if auth_data.get('is_genuine', True):
            story.append(Paragraph("✅ <b>Status:</b> Domain verified as genuine", normal_style))
        else:
            story.append(Paragraph("⚠️ <b>Status:</b> Potential security risk detected", normal_style))
            if scan_data.get('official_link'):
                story.append(Paragraph(f"<b>Official Link:</b> {scan_data['official_link']}", normal_style))
        
        # VirusTotal results with styled badge
        vt_result = auth_data.get('vt_result', {})
        vt_status = f"<font color='#059669'>Safe</font>" if vt_result.get('malicious', 0) == 0 else f"<font color='#dc2626'>Risky</font>"
        story.append(Paragraph(f"<b>VirusTotal Analysis:</b> {vt_result.get('malicious', 0)} malicious, {vt_result.get('suspicious', 0)} suspicious ({vt_status})", normal_style))
        
        # Google Safe Browsing results
        gs_result = auth_data.get('gs_result', {})
        if gs_result and not gs_result.get('error'):
            threat_type = gs_result.get('threat_type', 'Safe')
            gs_color = colors.HexColor('#059669') if threat_type == 'Safe' else colors.HexColor('#dc2626')
            story.append(Paragraph(f"<b>Google Safe Browsing:</b> <font color='{gs_color.name}'>{threat_type}</font>", normal_style))
        
        # Confidence score with progress-like bar simulation
        story.append(Paragraph(f"<b>Overall Confidence Score:</b> {confidence}/100", normal_style))
        story.append(Spacer(1, 30))
        
        # Reconnaissance Sections (similar enhancements for all)
        recon_data = scan_data.get('reconnaissance', {})
        
        # WHOIS Information
        story.append(Paragraph("📋 WHOIS Information", heading_style))
        whois_data = recon_data.get('whois', {})
        whois_table_data = [
            ['Field', 'Value'],
            ['Registrar', whois_data.get('registrar', 'N/A')],
            ['Registrant', whois_data.get('registrant', 'N/A')],
            ['Created', whois_data.get('created', 'N/A')],
            ['Updated', whois_data.get('updated', 'N/A')],
            ['Expires', whois_data.get('expires', 'N/A')],
            ['Status', whois_data.get('status', 'N/A')],
            ['Source', whois_data.get('source', 'N/A')]
        ]
        
        whois_table = Table(whois_table_data, colWidths=[2*inch, 4*inch])
        whois_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#dbeafe')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#1e40af')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8fafc')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
        ]))
        story.append(whois_table)
        story.append(Spacer(1, 30))
        
        # DNS Records (limit and style)
        story.append(Paragraph("🌐 DNS Records", heading_style))
        dns_records = recon_data.get('dns', [])
        if dns_records:
            dns_table_data = [['Type', 'Value']]
            for record in dns_records[:10]:
                value = record.get('value', '')[:60] + '...' if len(record.get('value', '')) > 60 else record.get('value', '')
                dns_table_data.append([record.get('type', ''), value])
            
            dns_table = Table(dns_table_data, colWidths=[1*inch, 5*inch])
            dns_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#dbeafe')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#1e40af')),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 11),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8fafc')),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1'))
            ]))
            story.append(dns_table)
        else:
            story.append(Paragraph("No DNS records found.", normal_style))
        story.append(Spacer(1, 30))
        
        # SSL Certificate
        story.append(Paragraph("🔐 SSL Certificate Analysis", heading_style))
        ssl_data = recon_data.get('ssl', {})
        ssl_table_data = [
            ['Field', 'Value'],
            ['Issuer', ssl_data.get('issuer', 'N/A')],
            ['Subject', ssl_data.get('subject', 'N/A')],
            ['Expiry Date', ssl_data.get('expiry', 'N/A')],
            ['Certificate Valid', 'Yes' if ssl_data.get('valid', False) else 'No'],
            ['Serial Number', ssl_data.get('serial_number', 'N/A')]
        ]
        
        ssl_table = Table(ssl_table_data, colWidths=[2*inch, 4*inch])
        ssl_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#dbeafe')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#1e40af')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8fafc')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1'))
        ]))
        story.append(ssl_table)
        story.append(Spacer(1, 30))
        
        # Geolocation
        story.append(Paragraph("🌍 Geolocation & Network Details", heading_style))
        geo_data = recon_data.get('geolocation', {})
        if not geo_data.get('error'):
            geo_table_data = [
                ['Field', 'Value'],
                ['IP Address', geo_data.get('ip', 'N/A')],
                ['Country', geo_data.get('country', 'N/A')],
                ['City', geo_data.get('city', 'N/A')],
                ['Region', geo_data.get('region', 'N/A')],
                ['ISP', geo_data.get('isp', 'N/A')],
                ['Organization', geo_data.get('org', 'N/A')],
                ['Timezone', geo_data.get('timezone', 'N/A')],
                ['Coordinates', f"{geo_data.get('latitude', 0)}, {geo_data.get('longitude', 0)}"]
            ]
            
            geo_table = Table(geo_table_data, colWidths=[2*inch, 4*inch])
            geo_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#dbeafe')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#1e40af')),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 11),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8fafc')),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1'))
            ]))
            story.append(geo_table)
        else:
            story.append(Paragraph(f"Geolocation unavailable: {geo_data.get('error', 'Unknown error')}", normal_style))
        story.append(Spacer(1, 30))
        
        # Threat Intelligence
        story.append(Paragraph("🛡️ Advanced Threat Intelligence", heading_style))
        vt_data = recon_data.get('virustotal', {})
        threat_table_data = [
            ['Metric', 'Value'],
            ['Reputation Score', str(vt_data.get('reputation', 'N/A'))],
            ['Last Analysis Date', vt_data.get('last_analysis', 'N/A')],
            ['Malicious Detections', str(vt_data.get('malicious', 0))],
            ['Suspicious Detections', str(vt_data.get('suspicious', 0))],
            ['Categories', ', '.join(vt_data.get('categories', [])[:3]) if vt_data.get('categories') else 'None']
        ]
        
        threat_table = Table(threat_table_data, colWidths=[2*inch, 4*inch])
        threat_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#dbeafe')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#1e40af')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8fafc')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1'))
        ]))
        story.append(threat_table)
        story.append(Spacer(1, 30))
        
        # Traceroute
        story.append(Paragraph("🛤️ Traceroute", heading_style))
        traceroute_data = recon_data.get('traceroute', {})
        if not traceroute_data.get('error'):
            traceroute_table_data = [['Hop']]
            for hop in traceroute_data.get('hops', []):
                traceroute_table_data.append([hop])
            
            traceroute_table = Table(traceroute_table_data, colWidths=[6*inch])
            traceroute_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#dbeafe')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#1e40af')),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 11),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8fafc')),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1'))
            ]))
            story.append(traceroute_table)
        else:
            story.append(Paragraph(f"Traceroute unavailable: {traceroute_data.get('error', 'Unknown error')}", normal_style))
        story.append(Spacer(1, 30))
        
        # Reverse IP Lookup
        story.append(Paragraph("🔄 Reverse IP Lookup", heading_style))
        reverse_ip = recon_data.get('reverse_ip', [])
        if reverse_ip:
            reverse_table_data = [['Domain']]
            for dom in reverse_ip[:20]:
                reverse_table_data.append([dom])
            
            reverse_table = Table(reverse_table_data, colWidths=[6*inch])
            reverse_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#dbeafe')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#1e40af')),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 11),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8fafc')),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1'))
            ]))
            story.append(reverse_table)
            if len(reverse_ip) > 20:
                story.append(Paragraph(f"... and {len(reverse_ip) - 20} more", normal_style))
        else:
            story.append(Paragraph("No domains found on the same IP.", normal_style))
        story.append(Spacer(1, 30))
        
        # Subdomains
        subdomains = recon_data.get('subdomains', [])
        if subdomains:
            story.append(Paragraph(f"🔍 Discovered Subdomains ({len(subdomains)} total)", heading_style))
            subdomain_text = ', '.join(subdomains[:20])
            if len(subdomains) > 20:
                subdomain_text += f" ... and {len(subdomains) - 20} more"
            story.append(Paragraph(subdomain_text, normal_style))
            story.append(Spacer(1, 30))
        
        # Open Ports
        open_ports = recon_data.get('open_ports', [])
        if open_ports:
            story.append(Paragraph("🔓 Open Ports Scan", heading_style))
            port_table_data = [['Port', 'Service']]
            for port_info in open_ports:
                port_table_data.append([str(port_info.get('port', '')), port_info.get('service', '')])
            
            port_table = Table(port_table_data, colWidths=[1*inch, 2*inch])
            port_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#dbeafe')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#1e40af')),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 11),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8fafc')),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1'))
            ]))
            story.append(port_table)
            story.append(Spacer(1, 30))
        
        # Technologies
        technologies = recon_data.get('technologies', [])
        if technologies:
            story.append(Paragraph("⚙️ Detected Technologies", heading_style))
            tech_text = ', '.join(technologies)
            story.append(Paragraph(tech_text, normal_style))
            story.append(Spacer(1, 30))
        
        # Security Headers
        story.append(Paragraph("🔒 Security Headers Evaluation", heading_style))
        sec_headers = recon_data.get('security_headers', {})
        if not sec_headers.get('error'):
            sec_table_data = [['Header', 'Status']]
            for header, value in sec_headers.items():
                if header != 'error':
                    status = 'Present' if value != 'Not set' else 'Missing'
                    sec_table_data.append([header, status])
            
            sec_table = Table(sec_table_data, colWidths=[2.5*inch, 3.5*inch])
            sec_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#dbeafe')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#1e40af')),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 11),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8fafc')),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1'))
            ]))
            story.append(sec_table)
        else:
            story.append(Paragraph(f"Security headers unavailable: {sec_headers.get('error', 'Unknown error')}", normal_style))
        story.append(Spacer(1, 30))
        
        # OWASP Vulnerability Checklist
        story.append(Paragraph("🛡️ OWASP Top 10 Vulnerability Checklist (2025)", heading_style))
        owasp_checks = recon_data.get('owasp_checks', [])
        if owasp_checks:
            owasp_table_data = [['Vulnerability', 'Status', 'Details']]
            for check in owasp_checks:
                status_color = '#059669' if check['status'] == 'Low Risk' else '#dc2626' if check['status'] == 'High Risk' else '#d97706' if check['status'] == 'Potential Risk' else '#6b7280'
                owasp_table_data.append([check['name'], f"<font color='{status_color}'>{check['status']}</font>", check['details']])
            
            owasp_table = Table(owasp_table_data, colWidths=[2*inch, 1.5*inch, 2.5*inch])
            owasp_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#dbeafe')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#1e40af')),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 11),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8fafc')),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
            ]))
            story.append(owasp_table)
        else:
            story.append(Paragraph("No OWASP checks performed.", normal_style))
        story.append(Spacer(1, 30))
        
        # Wayback Machine Historical Snapshots
        wayback_snapshots = recon_data.get('wayback_snapshots', [])
        if wayback_snapshots:
            story.append(Paragraph("📸 Historical Snapshots (Wayback Machine)", heading_style))
            wayback_table_data = [['Timestamp', 'Snapshot URL']]
            for snapshot in wayback_snapshots[:5]:  # Limit to 5
                wayback_table_data.append([snapshot.get('timestamp', 'N/A'), snapshot.get('url', 'N/A')])
            
            wayback_table = Table(wayback_table_data, colWidths=[1.5*inch, 4.5*inch])
            wayback_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#dbeafe')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#1e40af')),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8fafc')),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1'))
            ]))
            story.append(wayback_table)
            story.append(Paragraph(f"Total historical snapshots: {len(wayback_snapshots)}", normal_style))
        else:
            story.append(Paragraph("No historical snapshots found in Wayback Machine.", normal_style))
        story.append(Spacer(1, 30))
        
        # Pro Tip
        pro_tip = recon_data.get('pro_tip', '')
        if pro_tip:
            story.append(Paragraph("💡 Professional Recommendation", heading_style))
            story.append(Paragraph(pro_tip, normal_style))
            story.append(Spacer(1, 40))
        
        # Footer Section
        story.append(Paragraph("Report Footer", subheading_style))
        story.append(Paragraph("This report was generated using advanced reconnaissance tools and threat intelligence APIs.", normal_style))
        story.append(Paragraph("For more details, visit: https://github.com/yourusername/domain-recon-web", normal_style))
        story.append(Paragraph("Confidential - For Security Analysis Only", ParagraphStyle(
            'Footer',
            parent=styles['Normal'],
            alignment=TA_CENTER,
            fontSize=10,
            textColor=colors.HexColor('#9ca3af'),
            spaceBefore=20
        )))
        
        # Build PDF with custom canvas for custom headers/footers if needed
        def add_page_number(canvas, doc):
            canvas.setFont("Helvetica", 9)
            canvas.drawString(0.75*inch, 0.5*inch, f"Page {doc.page}")
        
        doc.build(story, onFirstPage=add_page_number, onLaterPages=add_page_number)
        
        return temp_file.name
        
    except Exception as e:
        logger.error(f"Error generating PDF: {str(e)}")
        raise e
import os
import tempfile
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

def generate_pdf_report(scan_data: dict) -> str:
    """Generate a comprehensive PDF report."""
    try:
        # Create temporary file
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
        temp_file.close()
        
        # Create PDF document
        doc = SimpleDocTemplate(
            temp_file.name,
            pagesize=A4,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18
        )
        
        # Get styles
        styles = getSampleStyleSheet()
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=colors.darkblue
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            spaceAfter=12,
            spaceBefore=20,
            textColor=colors.darkblue
        )
        
        subheading_style = ParagraphStyle(
            'CustomSubHeading',
            parent=styles['Heading3'],
            fontSize=14,
            spaceAfter=8,
            spaceBefore=12,
            textColor=colors.darkgreen
        )
        
        # Build story
        story = []
        
        # Title
        domain = scan_data.get('domain', 'Unknown')
        story.append(Paragraph(f"Domain Reconnaissance Report", title_style))
        story.append(Paragraph(f"<b>{domain}</b>", styles['Title']))
        story.append(Spacer(1, 12))
        
        # Report info
        story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Authenticity Check
        auth_data = scan_data.get('authenticity', {})
        story.append(Paragraph("🔒 Authenticity Assessment", heading_style))
        
        if auth_data.get('is_genuine', True):
            story.append(Paragraph("✅ <b>Status:</b> Domain verified as genuine", styles['Normal']))
        else:
            story.append(Paragraph("⚠️ <b>Status:</b> Potential security risk detected", styles['Normal']))
            if scan_data.get('official_link'):
                story.append(Paragraph(f"<b>Official Link:</b> {scan_data['official_link']}", styles['Normal']))
        
        # VirusTotal results
        vt_result = auth_data.get('vt_result', {})
        story.append(Paragraph(f"<b>VirusTotal:</b> {vt_result.get('malicious', 0)} malicious, {vt_result.get('suspicious', 0)} suspicious detections", styles['Normal']))
        
        # Google Safe Browsing results
        gs_result = auth_data.get('gs_result', {})
        if gs_result and not gs_result.get('error'):
            threat_type = gs_result.get('threat_type', 'Safe')
            story.append(Paragraph(f"<b>Google Safe Browsing:</b> {threat_type}", styles['Normal']))
        
        # Confidence score
        confidence = auth_data.get('confidence_score', 100)
        story.append(Paragraph(f"<b>Confidence Score:</b> {confidence}/100", styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Reconnaissance data
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
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(whois_table)
        story.append(Spacer(1, 20))
        
        # DNS Records
        story.append(Paragraph("🌐 DNS Records", heading_style))
        dns_records = recon_data.get('dns', [])
        if dns_records:
            dns_table_data = [['Type', 'Value']]
            for record in dns_records[:10]:  # Limit to 10 records
                dns_table_data.append([record.get('type', ''), record.get('value', '')[:60] + '...' if len(record.get('value', '')) > 60 else record.get('value', '')])
            
            dns_table = Table(dns_table_data, colWidths=[1*inch, 5*inch])
            dns_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(dns_table)
        else:
            story.append(Paragraph("No DNS records found", styles['Normal']))
        story.append(Spacer(1, 20))
        
        # SSL Certificate
        story.append(Paragraph("🔐 SSL Certificate", heading_style))
        ssl_data = recon_data.get('ssl', {})
        ssl_table_data = [
            ['Field', 'Value'],
            ['Issuer', ssl_data.get('issuer', 'N/A')],
            ['Subject', ssl_data.get('subject', 'N/A')],
            ['Expiry', ssl_data.get('expiry', 'N/A')],
            ['Valid', 'Yes' if ssl_data.get('valid', False) else 'No'],
            ['Serial Number', ssl_data.get('serial_number', 'N/A')]
        ]
        
        ssl_table = Table(ssl_table_data, colWidths=[2*inch, 4*inch])
        ssl_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(ssl_table)
        story.append(Spacer(1, 20))
        
        # Geolocation
        story.append(Paragraph("🌍 Geolocation", heading_style))
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
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(geo_table)
        else:
            story.append(Paragraph(f"Geolocation unavailable: {geo_data.get('error', 'Unknown error')}", styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Threat Intelligence
        story.append(Paragraph("🛡️ Threat Intelligence", heading_style))
        vt_data = recon_data.get('virustotal', {})
        threat_table_data = [
            ['Metric', 'Value'],
            ['Reputation', str(vt_data.get('reputation', 'N/A'))],
            ['Last Analysis', vt_data.get('last_analysis', 'N/A')],
            ['Malicious Detections', str(vt_data.get('malicious', 0))],
            ['Suspicious Detections', str(vt_data.get('suspicious', 0))],
            ['Categories', ', '.join(vt_data.get('categories', [])[:3]) if vt_data.get('categories') else 'None']
        ]
        
        threat_table = Table(threat_table_data, colWidths=[2*inch, 4*inch])
        threat_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(threat_table)
        story.append(Spacer(1, 20))
        
        # Subdomains
        subdomains = recon_data.get('subdomains', [])
        if subdomains:
            story.append(Paragraph(f"🔍 Subdomains ({len(subdomains)} found)", heading_style))
            subdomain_text = ', '.join(subdomains[:20])  # Limit to 20
            if len(subdomains) > 20:
                subdomain_text += f" ... and {len(subdomains) - 20} more"
            story.append(Paragraph(subdomain_text, styles['Normal']))
            story.append(Spacer(1, 20))
        
        # Open Ports
        open_ports = recon_data.get('open_ports', [])
        if open_ports:
            story.append(Paragraph("🔓 Open Ports", heading_style))
            port_table_data = [['Port', 'Service']]
            for port_info in open_ports:
                port_table_data.append([str(port_info.get('port', '')), port_info.get('service', '')])
            
            port_table = Table(port_table_data, colWidths=[1*inch, 2*inch])
            port_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(port_table)
            story.append(Spacer(1, 20))
        
        # Technologies
        technologies = recon_data.get('technologies', [])
        if technologies:
            story.append(Paragraph("⚙️ Technologies", heading_style))
            tech_text = ', '.join(technologies)
            story.append(Paragraph(tech_text, styles['Normal']))
            story.append(Spacer(1, 20))
        
        # Security Headers
        story.append(Paragraph("🔒 Security Headers", heading_style))
        sec_headers = recon_data.get('security_headers', {})
        if not sec_headers.get('error'):
            sec_table_data = [['Header', 'Value']]
            for header, value in sec_headers.items():
                if header != 'error':
                    display_value = value[:50] + '...' if len(value) > 50 else value
                    sec_table_data.append([header, display_value])
            
            sec_table = Table(sec_table_data, colWidths=[2.5*inch, 3.5*inch])
            sec_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(sec_table)
        else:
            story.append(Paragraph(f"Security headers unavailable: {sec_headers.get('error', 'Unknown error')}", styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Pro Tip
        pro_tip = recon_data.get('pro_tip', '')
        if pro_tip:
            story.append(Paragraph("💡 Pro Tip", heading_style))
            story.append(Paragraph(pro_tip, styles['Normal']))
        
        # Footer
        story.append(Spacer(1, 30))
        story.append(Paragraph("Generated by Domain Reconnaissance Tool", styles['Normal']))
        story.append(Paragraph("https://github.com/yourusername/domain-recon-web", styles['Normal']))
        
        # Build PDF
        doc.build(story)
        
        return temp_file.name
        
    except Exception as e:
        logger.error(f"Error generating PDF: {str(e)}")
        raise e
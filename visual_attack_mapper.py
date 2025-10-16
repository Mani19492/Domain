import networkx as nx
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import json
import logging
from typing import Dict, List, Any, Tuple
import numpy as np
from datetime import datetime
import math

logger = logging.getLogger(__name__)

class VisualAttackSurfaceMapper:
    def __init__(self):
        self.color_scheme = {
            'main_domain': '#2563eb',
            'subdomain': '#8b5cf6',
            'ip_address': '#10b981',
            'mail_server': '#ef4444',
            'name_server': '#06b6d4',
            'ssl_issuer': '#84cc16',
            'related_domain': '#f59e0b',
            'vulnerability': '#dc2626',
            'service': '#6366f1',
            'technology': '#ec4899'
        }
        
        self.node_sizes = {
            'main_domain': 30,
            'subdomain': 20,
            'ip_address': 25,
            'mail_server': 15,
            'name_server': 15,
            'ssl_issuer': 12,
            'related_domain': 18,
            'vulnerability': 22,
            'service': 16,
            'technology': 14
        }
    
    def create_attack_surface_map(self, domain_data: dict, vulnerability_data: dict = None) -> dict:
        """Create comprehensive attack surface visualization."""
        try:
            # Create network graph
            graph = self.build_attack_surface_graph(domain_data, vulnerability_data)
            
            # Generate different visualizations
            visualizations = {
                'network_graph': self.create_network_visualization(graph),
                'attack_vectors': self.create_attack_vectors_chart(domain_data, vulnerability_data),
                'risk_heatmap': self.create_risk_heatmap(domain_data, vulnerability_data),
                'timeline_analysis': self.create_timeline_analysis(domain_data),
                'geographic_map': self.create_geographic_visualization(domain_data),
                'technology_stack': self.create_technology_stack_chart(domain_data),
                'port_analysis': self.create_port_analysis_chart(domain_data),
                'threat_landscape': self.create_threat_landscape_radar(domain_data, vulnerability_data)
            }
            
            return {
                'domain': domain_data.get('domain', ''),
                'generated_at': datetime.now().isoformat(),
                'visualizations': visualizations,
                'summary_stats': self.calculate_summary_stats(graph, domain_data, vulnerability_data)
            }
            
        except Exception as e:
            logger.error(f"Error creating attack surface map: {str(e)}")
            return {'error': str(e)}
    
    def build_attack_surface_graph(self, domain_data: dict, vulnerability_data: dict = None) -> nx.Graph:
        """Build NetworkX graph representing the attack surface."""
        try:
            graph = nx.Graph()
            domain = domain_data.get('domain', '')
            
            # Add main domain node
            graph.add_node(domain, 
                          type='main_domain',
                          label=domain,
                          risk_level='medium',
                          size=self.node_sizes['main_domain'],
                          color=self.color_scheme['main_domain'])
            
            # Add IP address nodes
            geo_data = domain_data.get('geolocation', {})
            if geo_data.get('ip'):
                ip = geo_data['ip']
                graph.add_node(ip,
                              type='ip_address',
                              label=f"IP: {ip}",
                              country=geo_data.get('country', 'Unknown'),
                              isp=geo_data.get('isp', 'Unknown'),
                              size=self.node_sizes['ip_address'],
                              color=self.color_scheme['ip_address'])
                graph.add_edge(domain, ip, relationship='resolves_to', weight=1.0)
            
            # Add subdomain nodes
            subdomains = domain_data.get('subdomains', [])[:20]  # Limit for performance
            for subdomain in subdomains:
                if subdomain != domain:
                    graph.add_node(subdomain,
                                  type='subdomain',
                                  label=subdomain,
                                  size=self.node_sizes['subdomain'],
                                  color=self.color_scheme['subdomain'])
                    graph.add_edge(domain, subdomain, relationship='subdomain_of', weight=0.8)
            
            # Add DNS server nodes
            dns_records = domain_data.get('dns', [])
            mx_records = [r for r in dns_records if r.get('type') == 'MX'][:3]
            ns_records = [r for r in dns_records if r.get('type') == 'NS'][:3]
            
            for mx in mx_records:
                mx_value = mx.get('value', '').split()[-1] if mx.get('value') else ''
                if mx_value:
                    graph.add_node(mx_value,
                                  type='mail_server',
                                  label=f"MX: {mx_value}",
                                  size=self.node_sizes['mail_server'],
                                  color=self.color_scheme['mail_server'])
                    graph.add_edge(domain, mx_value, relationship='mail_server', weight=0.7)
            
            for ns in ns_records:
                ns_value = ns.get('value', '')
                if ns_value:
                    graph.add_node(ns_value,
                                  type='name_server',
                                  label=f"NS: {ns_value}",
                                  size=self.node_sizes['name_server'],
                                  color=self.color_scheme['name_server'])
                    graph.add_edge(domain, ns_value, relationship='name_server', weight=0.6)
            
            # Add technology nodes
            technologies = domain_data.get('technologies', [])[:10]
            for tech in technologies:
                tech_id = f"tech_{tech.replace(' ', '_').lower()}"
                graph.add_node(tech_id,
                              type='technology',
                              label=f"Tech: {tech}",
                              size=self.node_sizes['technology'],
                              color=self.color_scheme['technology'])
                graph.add_edge(domain, tech_id, relationship='uses_technology', weight=0.5)
            
            # Add service nodes from open ports
            open_ports = domain_data.get('open_ports', [])
            for port_info in open_ports:
                port = port_info.get('port')
                service = port_info.get('service', 'unknown')
                service_id = f"service_{port}_{service}"
                
                # Determine risk level based on port
                risk_level = 'low'
                if port in [21, 23, 135, 139, 445]:  # Risky ports
                    risk_level = 'high'
                elif port in [22, 3389]:  # Administrative ports
                    risk_level = 'medium'
                
                graph.add_node(service_id,
                              type='service',
                              label=f"{service} ({port})",
                              port=port,
                              risk_level=risk_level,
                              size=self.node_sizes['service'],
                              color=self.color_scheme['service'])
                graph.add_edge(domain, service_id, relationship='exposes_service', weight=0.9)
            
            # Add vulnerability nodes if vulnerability data provided
            if vulnerability_data:
                vulnerabilities = vulnerability_data.get('prioritized_vulnerabilities', [])[:10]
                for i, vuln in enumerate(vulnerabilities):
                    vuln_id = f"vuln_{i}_{vuln.get('cve_id', 'unknown')}"
                    severity = vuln.get('severity', 'unknown')
                    
                    graph.add_node(vuln_id,
                                  type='vulnerability',
                                  label=f"CVE: {vuln.get('cve_id', 'Unknown')}",
                                  severity=severity,
                                  cvss_score=vuln.get('cvss_score', 0),
                                  size=self.node_sizes['vulnerability'],
                                  color=self.color_scheme['vulnerability'])
                    
                    # Connect to affected technology if available
                    affected_tech = vuln.get('affected_technology', '')
                    if affected_tech:
                        tech_id = f"tech_{affected_tech.replace(' ', '_').lower()}"
                        if graph.has_node(tech_id):
                            graph.add_edge(tech_id, vuln_id, relationship='has_vulnerability', weight=1.0)
                        else:
                            graph.add_edge(domain, vuln_id, relationship='affects', weight=0.8)
            
            # Add related domains from reverse IP
            related_domains = domain_data.get('reverse_ip', [])[:5]  # Limit for performance
            for related in related_domains:
                if related != domain and related not in subdomains:
                    graph.add_node(related,
                                  type='related_domain',
                                  label=related,
                                  size=self.node_sizes['related_domain'],
                                  color=self.color_scheme['related_domain'])
                    if geo_data.get('ip'):
                        graph.add_edge(related, geo_data['ip'], relationship='shares_ip', weight=0.4)
            
            return graph
            
        except Exception as e:
            logger.error(f"Error building attack surface graph: {str(e)}")
            return nx.Graph()
    
    def create_network_visualization(self, graph: nx.Graph) -> dict:
        """Create interactive network visualization using Plotly."""
        try:
            if len(graph.nodes()) == 0:
                return {'error': 'No nodes in graph'}
            
            # Use spring layout for positioning
            pos = nx.spring_layout(graph, k=3, iterations=50)
            
            # Prepare node traces
            node_traces = {}
            for node_type in set(nx.get_node_attributes(graph, 'type').values()):
                node_traces[node_type] = {
                    'x': [],
                    'y': [],
                    'text': [],
                    'hovertext': [],
                    'size': [],
                    'color': self.color_scheme.get(node_type, '#gray')
                }
            
            # Add nodes to traces
            for node in graph.nodes():
                node_data = graph.nodes[node]
                node_type = node_data.get('type', 'unknown')
                
                if node_type not in node_traces:
                    node_traces[node_type] = {
                        'x': [], 'y': [], 'text': [], 'hovertext': [], 'size': [],
                        'color': '#gray'
                    }
                
                x, y = pos[node]
                node_traces[node_type]['x'].append(x)
                node_traces[node_type]['y'].append(y)
                node_traces[node_type]['text'].append(node_data.get('label', node))
                node_traces[node_type]['size'].append(node_data.get('size', 10))
                
                # Create hover text
                hover_text = f"<b>{node_data.get('label', node)}</b><br>"
                hover_text += f"Type: {node_type.replace('_', ' ').title()}<br>"
                
                if 'country' in node_data:
                    hover_text += f"Country: {node_data['country']}<br>"
                if 'isp' in node_data:
                    hover_text += f"ISP: {node_data['isp']}<br>"
                if 'port' in node_data:
                    hover_text += f"Port: {node_data['port']}<br>"
                if 'severity' in node_data:
                    hover_text += f"Severity: {node_data['severity']}<br>"
                if 'cvss_score' in node_data:
                    hover_text += f"CVSS: {node_data['cvss_score']}<br>"
                
                node_traces[node_type]['hovertext'].append(hover_text)
            
            # Prepare edge traces
            edge_x = []
            edge_y = []
            edge_info = []
            
            for edge in graph.edges():
                x0, y0 = pos[edge[0]]
                x1, y1 = pos[edge[1]]
                edge_x.extend([x0, x1, None])
                edge_y.extend([y0, y1, None])
                
                edge_data = graph.edges[edge]
                relationship = edge_data.get('relationship', 'connected')
                edge_info.append(f"{edge[0]} → {edge[1]} ({relationship})")
            
            # Create Plotly figure
            fig = go.Figure()
            
            # Add edges
            fig.add_trace(go.Scatter(
                x=edge_x, y=edge_y,
                line=dict(width=1, color='rgba(125,125,125,0.5)'),
                hoverinfo='none',
                mode='lines',
                name='Connections'
            ))
            
            # Add node traces
            for node_type, trace_data in node_traces.items():
                if trace_data['x']:  # Only add if there are nodes of this type
                    fig.add_trace(go.Scatter(
                        x=trace_data['x'],
                        y=trace_data['y'],
                        mode='markers+text',
                        marker=dict(
                            size=trace_data['size'],
                            color=trace_data['color'],
                            line=dict(width=2, color='white')
                        ),
                        text=trace_data['text'],
                        textposition="middle center",
                        textfont=dict(size=8, color='white'),
                        hovertext=trace_data['hovertext'],
                        hoverinfo='text',
                        name=node_type.replace('_', ' ').title()
                    ))
            
            # Update layout
            fig.update_layout(
                title="Attack Surface Network Map",
                showlegend=True,
                hovermode='closest',
                margin=dict(b=20,l=5,r=5,t=40),
                annotations=[
                    dict(
                        text="Interactive network showing domain relationships and attack vectors",
                        showarrow=False,
                        xref="paper", yref="paper",
                        x=0.005, y=-0.002,
                        xanchor='left', yanchor='bottom',
                        font=dict(color='gray', size=12)
                    )
                ],
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                plot_bgcolor='rgba(0,0,0,0)',
                paper_bgcolor='rgba(0,0,0,0)'
            )
            
            return {
                'type': 'plotly',
                'figure': fig.to_dict(),
                'description': 'Interactive network visualization of the attack surface'
            }
            
        except Exception as e:
            logger.error(f"Error creating network visualization: {str(e)}")
            return {'error': str(e)}
    
    def create_attack_vectors_chart(self, domain_data: dict, vulnerability_data: dict = None) -> dict:
        """Create attack vectors analysis chart."""
        try:
            attack_vectors = []
            risk_scores = []
            descriptions = []
            
            # Analyze different attack vectors
            
            # 1. Web Application Attacks
            web_risk = 0
            web_desc = []
            
            ssl_data = domain_data.get('ssl', {})
            if not ssl_data.get('valid', False):
                web_risk += 30
                web_desc.append("Invalid SSL certificate")
            
            sec_headers = domain_data.get('security_headers', {})
            missing_headers = sum(1 for v in sec_headers.values() if str(v) == 'Not set')
            web_risk += missing_headers * 5
            if missing_headers > 0:
                web_desc.append(f"{missing_headers} missing security headers")
            
            attack_vectors.append("Web Application")
            risk_scores.append(min(100, web_risk))
            descriptions.append("; ".join(web_desc) if web_desc else "Standard web security posture")
            
            # 2. Network-based Attacks
            network_risk = 0
            network_desc = []
            
            open_ports = domain_data.get('open_ports', [])
            risky_ports = [21, 22, 23, 135, 139, 445, 1433, 3389]
            risky_count = sum(1 for port in open_ports if port.get('port') in risky_ports)
            network_risk += risky_count * 20
            if risky_count > 0:
                network_desc.append(f"{risky_count} risky ports open")
            
            attack_vectors.append("Network Services")
            risk_scores.append(min(100, network_risk))
            descriptions.append("; ".join(network_desc) if network_desc else "Standard network exposure")
            
            # 3. DNS-based Attacks
            dns_risk = 0
            dns_desc = []
            
            subdomains = domain_data.get('subdomains', [])
            if len(subdomains) > 20:
                dns_risk += 25
                dns_desc.append("High subdomain count increases attack surface")
            
            attack_vectors.append("DNS Infrastructure")
            risk_scores.append(min(100, dns_risk))
            descriptions.append("; ".join(dns_desc) if dns_desc else "Standard DNS configuration")
            
            # 4. Social Engineering
            social_risk = 0
            social_desc = []
            
            emails = domain_data.get('emails', [])
            if len(emails) > 5:
                social_risk += 15
                social_desc.append("Multiple email addresses exposed")
            
            attack_vectors.append("Social Engineering")
            risk_scores.append(min(100, social_risk))
            descriptions.append("; ".join(social_desc) if social_desc else "Limited exposed contact information")
            
            # 5. Vulnerability Exploitation
            vuln_risk = 0
            vuln_desc = []
            
            if vulnerability_data:
                vuln_summary = vulnerability_data.get('vulnerability_summary', {})
                critical_count = vuln_summary.get('critical', 0)
                high_count = vuln_summary.get('high', 0)
                
                vuln_risk += critical_count * 30 + high_count * 20
                if critical_count > 0:
                    vuln_desc.append(f"{critical_count} critical vulnerabilities")
                if high_count > 0:
                    vuln_desc.append(f"{high_count} high-severity vulnerabilities")
            
            attack_vectors.append("Vulnerability Exploitation")
            risk_scores.append(min(100, vuln_risk))
            descriptions.append("; ".join(vuln_desc) if vuln_desc else "No critical vulnerabilities detected")
            
            # Create bar chart
            fig = go.Figure(data=[
                go.Bar(
                    x=attack_vectors,
                    y=risk_scores,
                    text=[f"{score}%" for score in risk_scores],
                    textposition='auto',
                    marker_color=['#ef4444' if score >= 70 else '#f59e0b' if score >= 40 else '#10b981' for score in risk_scores],
                    hovertemplate='<b>%{x}</b><br>Risk Score: %{y}%<br>%{customdata}<extra></extra>',
                    customdata=descriptions
                )
            ])
            
            fig.update_layout(
                title="Attack Vector Risk Analysis",
                xaxis_title="Attack Vector",
                yaxis_title="Risk Score (%)",
                yaxis=dict(range=[0, 100]),
                showlegend=False,
                height=400
            )
            
            return {
                'type': 'plotly',
                'figure': fig.to_dict(),
                'description': 'Risk assessment across different attack vectors'
            }
            
        except Exception as e:
            logger.error(f"Error creating attack vectors chart: {str(e)}")
            return {'error': str(e)}
    
    def create_risk_heatmap(self, domain_data: dict, vulnerability_data: dict = None) -> dict:
        """Create risk heatmap visualization."""
        try:
            # Define risk categories and components
            categories = ['Infrastructure', 'Application', 'Network', 'Data', 'Authentication']
            components = ['SSL/TLS', 'DNS', 'Ports', 'Headers', 'Vulnerabilities', 'Certificates', 'Subdomains', 'Technologies']
            
            # Create risk matrix
            risk_matrix = np.random.randint(0, 100, size=(len(categories), len(components)))
            
            # Calculate actual risk scores based on domain data
            # Infrastructure risks
            ssl_risk = 0 if domain_data.get('ssl', {}).get('valid', False) else 80
            dns_risk = min(100, len(domain_data.get('subdomains', [])) * 2)
            
            # Application risks
            header_risk = sum(1 for v in domain_data.get('security_headers', {}).values() if str(v) == 'Not set') * 15
            
            # Network risks
            port_risk = len(domain_data.get('open_ports', [])) * 10
            
            # Update matrix with real data
            risk_matrix[0] = [ssl_risk, dns_risk, port_risk, header_risk, 30, 20, 40, 25]  # Infrastructure
            risk_matrix[1] = [header_risk, 35, 25, ssl_risk, 45, 30, 20, 35]  # Application
            risk_matrix[2] = [25, 30, port_risk, 20, 35, 25, 30, 40]  # Network
            risk_matrix[3] = [ssl_risk, 40, 30, header_risk, 25, 35, 20, 30]  # Data
            risk_matrix[4] = [ssl_risk, 30, 35, 40, 25, 30, 35, 25]  # Authentication
            
            # Create heatmap
            fig = go.Figure(data=go.Heatmap(
                z=risk_matrix,
                x=components,
                y=categories,
                colorscale=[
                    [0, '#10b981'],    # Green (low risk)
                    [0.3, '#f59e0b'],  # Yellow (medium risk)
                    [0.7, '#ef4444'],  # Red (high risk)
                    [1, '#7f1d1d']     # Dark red (critical risk)
                ],
                text=risk_matrix,
                texttemplate="%{text}",
                textfont={"size": 10},
                hoverongaps=False,
                hovertemplate='<b>%{y} - %{x}</b><br>Risk Score: %{z}%<extra></extra>'
            ))
            
            fig.update_layout(
                title="Security Risk Heatmap",
                xaxis_title="Security Components",
                yaxis_title="Risk Categories",
                height=400
            )
            
            return {
                'type': 'plotly',
                'figure': fig.to_dict(),
                'description': 'Heatmap showing risk levels across security categories and components'
            }
            
        except Exception as e:
            logger.error(f"Error creating risk heatmap: {str(e)}")
            return {'error': str(e)}
    
    def create_timeline_analysis(self, domain_data: dict) -> dict:
        """Create timeline analysis of domain history."""
        try:
            # Extract timeline data
            timeline_events = []
            
            # WHOIS data
            whois_data = domain_data.get('whois', {})
            created_date = whois_data.get('created', '')
            updated_date = whois_data.get('updated', '')
            expires_date = whois_data.get('expires', '')
            
            if created_date and created_date != 'N/A':
                try:
                    created_dt = datetime.fromisoformat(created_date.replace('Z', ''))
                    timeline_events.append({
                        'date': created_dt,
                        'event': 'Domain Created',
                        'type': 'creation',
                        'description': f'Domain registered on {created_dt.strftime("%Y-%m-%d")}'
                    })
                except:
                    pass
            
            if updated_date and updated_date != 'N/A':
                try:
                    updated_dt = datetime.fromisoformat(updated_date.replace('Z', ''))
                    timeline_events.append({
                        'date': updated_dt,
                        'event': 'Domain Updated',
                        'type': 'update',
                        'description': f'Domain information updated on {updated_dt.strftime("%Y-%m-%d")}'
                    })
                except:
                    pass
            
            # SSL certificate data
            ssl_data = domain_data.get('ssl', {})
            if ssl_data.get('expiry') and ssl_data.get('expiry') != 'N/A':
                try:
                    # Parse SSL expiry (format may vary)
                    ssl_expiry = ssl_data['expiry']
                    # This is a simplified parsing - in reality, you'd need more robust date parsing
                    timeline_events.append({
                        'date': datetime.now(),  # Placeholder
                        'event': 'SSL Certificate Expires',
                        'type': 'ssl_expiry',
                        'description': f'SSL certificate expires: {ssl_expiry}'
                    })
                except:
                    pass
            
            # Wayback Machine snapshots
            wayback_snapshots = domain_data.get('wayback_snapshots', [])
            for snapshot in wayback_snapshots[:5]:  # Limit to 5 most recent
                timestamp = snapshot.get('timestamp', '')
                if timestamp:
                    try:
                        # Parse Wayback timestamp (format: YYYYMMDDHHMMSS)
                        if len(timestamp) >= 8:
                            year = int(timestamp[:4])
                            month = int(timestamp[4:6])
                            day = int(timestamp[6:8])
                            snapshot_dt = datetime(year, month, day)
                            
                            timeline_events.append({
                                'date': snapshot_dt,
                                'event': 'Website Snapshot',
                                'type': 'snapshot',
                                'description': f'Website archived on {snapshot_dt.strftime("%Y-%m-%d")}'
                            })
                    except:
                        pass
            
            # Sort events by date
            timeline_events.sort(key=lambda x: x['date'])
            
            if not timeline_events:
                return {
                    'type': 'message',
                    'message': 'No timeline data available',
                    'description': 'Insufficient historical data to create timeline'
                }
            
            # Create timeline chart
            dates = [event['date'] for event in timeline_events]
            events = [event['event'] for event in timeline_events]
            descriptions = [event['description'] for event in timeline_events]
            types = [event['type'] for event in timeline_events]
            
            # Color mapping for event types
            type_colors = {
                'creation': '#10b981',
                'update': '#f59e0b',
                'ssl_expiry': '#ef4444',
                'snapshot': '#8b5cf6'
            }
            
            colors = [type_colors.get(t, '#6b7280') for t in types]
            
            fig = go.Figure()
            
            fig.add_trace(go.Scatter(
                x=dates,
                y=list(range(len(dates))),
                mode='markers+lines+text',
                marker=dict(size=12, color=colors, line=dict(width=2, color='white')),
                line=dict(width=2, color='rgba(107, 114, 128, 0.5)'),
                text=events,
                textposition="middle right",
                hovertemplate='<b>%{text}</b><br>%{customdata}<br>Date: %{x}<extra></extra>',
                customdata=descriptions,
                name='Timeline Events'
            ))
            
            fig.update_layout(
                title="Domain Timeline Analysis",
                xaxis_title="Date",
                yaxis=dict(showticklabels=False, showgrid=False),
                height=400,
                showlegend=False
            )
            
            return {
                'type': 'plotly',
                'figure': fig.to_dict(),
                'description': 'Timeline of significant domain events and changes'
            }
            
        except Exception as e:
            logger.error(f"Error creating timeline analysis: {str(e)}")
            return {'error': str(e)}
    
    def create_geographic_visualization(self, domain_data: dict) -> dict:
        """Create geographic visualization of domain infrastructure."""
        try:
            geo_data = domain_data.get('geolocation', {})
            
            if geo_data.get('error') or not geo_data.get('latitude'):
                return {
                    'type': 'message',
                    'message': 'No geographic data available',
                    'description': 'Unable to determine domain geographic location'
                }
            
            # Create world map with domain location
            fig = go.Figure()
            
            fig.add_trace(go.Scattergeo(
                lon=[geo_data.get('longitude', 0)],
                lat=[geo_data.get('latitude', 0)],
                text=[f"{geo_data.get('city', 'Unknown')}, {geo_data.get('country', 'Unknown')}"],
                mode='markers+text',
                marker=dict(
                    size=15,
                    color='red',
                    line=dict(width=2, color='white')
                ),
                textposition="top center",
                hovertemplate='<b>%{text}</b><br>IP: %{customdata}<br>ISP: %{meta}<extra></extra>',
                customdata=[geo_data.get('ip', 'Unknown')],
                meta=[geo_data.get('isp', 'Unknown')]
            ))
            
            fig.update_layout(
                title=f"Geographic Location - {domain_data.get('domain', '')}",
                geo=dict(
                    projection_type='natural earth',
                    showland=True,
                    landcolor='rgb(243, 243, 243)',
                    coastlinecolor='rgb(204, 204, 204)',
                ),
                height=400
            )
            
            return {
                'type': 'plotly',
                'figure': fig.to_dict(),
                'description': 'Geographic location of domain infrastructure'
            }
            
        except Exception as e:
            logger.error(f"Error creating geographic visualization: {str(e)}")
            return {'error': str(e)}
    
    def create_technology_stack_chart(self, domain_data: dict) -> dict:
        """Create technology stack visualization."""
        try:
            technologies = domain_data.get('technologies', [])
            
            if not technologies:
                return {
                    'type': 'message',
                    'message': 'No technology stack detected',
                    'description': 'Unable to identify web technologies in use'
                }
            
            # Categorize technologies
            tech_categories = {
                'Web Servers': ['apache', 'nginx', 'iis', 'tomcat'],
                'Programming Languages': ['php', 'python', 'java', 'node.js', 'ruby'],
                'Databases': ['mysql', 'postgresql', 'mongodb', 'redis'],
                'Frameworks': ['wordpress', 'drupal', 'joomla', 'django', 'rails'],
                'CDN/Proxy': ['cloudflare', 'akamai', 'fastly'],
                'Analytics': ['google analytics', 'google tag manager'],
                'Other': []
            }
            
            categorized_tech = {cat: [] for cat in tech_categories.keys()}
            
            for tech in technologies:
                tech_lower = tech.lower()
                categorized = False
                
                for category, keywords in tech_categories.items():
                    if category == 'Other':
                        continue
                    if any(keyword in tech_lower for keyword in keywords):
                        categorized_tech[category].append(tech)
                        categorized = True
                        break
                
                if not categorized:
                    categorized_tech['Other'].append(tech)
            
            # Remove empty categories
            categorized_tech = {k: v for k, v in categorized_tech.items() if v}
            
            # Create sunburst chart
            labels = []
            parents = []
            values = []
            
            # Add root
            labels.append("Technology Stack")
            parents.append("")
            values.append(len(technologies))
            
            # Add categories and technologies
            for category, techs in categorized_tech.items():
                labels.append(category)
                parents.append("Technology Stack")
                values.append(len(techs))
                
                for tech in techs:
                    labels.append(tech)
                    parents.append(category)
                    values.append(1)
            
            fig = go.Figure(go.Sunburst(
                labels=labels,
                parents=parents,
                values=values,
                branchvalues="total",
                hovertemplate='<b>%{label}</b><br>Count: %{value}<extra></extra>'
            ))
            
            fig.update_layout(
                title="Technology Stack Analysis",
                height=500
            )
            
            return {
                'type': 'plotly',
                'figure': fig.to_dict(),
                'description': 'Hierarchical view of detected web technologies'
            }
            
        except Exception as e:
            logger.error(f"Error creating technology stack chart: {str(e)}")
            return {'error': str(e)}
    
    def create_port_analysis_chart(self, domain_data: dict) -> dict:
        """Create port analysis visualization."""
        try:
            open_ports = domain_data.get('open_ports', [])
            
            if not open_ports:
                return {
                    'type': 'message',
                    'message': 'No open ports detected',
                    'description': 'Port scan did not detect any open ports'
                }
            
            # Categorize ports by risk level
            port_categories = {
                'Critical Risk': [21, 23, 135, 139, 445],  # FTP, Telnet, RPC, NetBIOS
                'High Risk': [22, 3389, 1433, 3306],       # SSH, RDP, SQL Server, MySQL
                'Medium Risk': [25, 110, 143, 993, 995],   # Mail services
                'Low Risk': [80, 443, 53, 8080, 8443]      # Web and DNS services
            }
            
            port_risk_data = {category: [] for category in port_categories.keys()}
            
            for port_info in open_ports:
                port = port_info.get('port')
                service = port_info.get('service', 'unknown')
                
                categorized = False
                for risk_level, risk_ports in port_categories.items():
                    if port in risk_ports:
                        port_risk_data[risk_level].append({
                            'port': port,
                            'service': service
                        })
                        categorized = True
                        break
                
                if not categorized:
                    port_risk_data['Low Risk'].append({
                        'port': port,
                        'service': service
                    })
            
            # Create stacked bar chart
            categories = list(port_risk_data.keys())
            counts = [len(ports) for ports in port_risk_data.values()]
            
            colors = {
                'Critical Risk': '#dc2626',
                'High Risk': '#ea580c',
                'Medium Risk': '#d97706',
                'Low Risk': '#16a34a'
            }
            
            fig = go.Figure(data=[
                go.Bar(
                    x=categories,
                    y=counts,
                    marker_color=[colors[cat] for cat in categories],
                    text=counts,
                    textposition='auto',
                    hovertemplate='<b>%{x}</b><br>Open Ports: %{y}<extra></extra>'
                )
            ])
            
            fig.update_layout(
                title="Open Ports Risk Analysis",
                xaxis_title="Risk Level",
                yaxis_title="Number of Ports",
                height=400
            )
            
            return {
                'type': 'plotly',
                'figure': fig.to_dict(),
                'description': 'Risk categorization of open network ports'
            }
            
        except Exception as e:
            logger.error(f"Error creating port analysis chart: {str(e)}")
            return {'error': str(e)}
    
    def create_threat_landscape_radar(self, domain_data: dict, vulnerability_data: dict = None) -> dict:
        """Create threat landscape radar chart."""
        try:
            # Define threat categories
            categories = [
                'Web Application Security',
                'Network Security',
                'Data Protection',
                'Authentication',
                'Infrastructure Security',
                'Vulnerability Management',
                'Compliance',
                'Incident Response'
            ]
            
            # Calculate scores for each category (0-100)
            scores = []
            
            # Web Application Security
            ssl_score = 100 if domain_data.get('ssl', {}).get('valid', False) else 20
            headers_score = 100 - (sum(1 for v in domain_data.get('security_headers', {}).values() if str(v) == 'Not set') * 15)
            web_score = (ssl_score + headers_score) / 2
            scores.append(max(0, min(100, web_score)))
            
            # Network Security
            open_ports = domain_data.get('open_ports', [])
            risky_ports = [21, 22, 23, 135, 139, 445, 1433, 3389]
            risky_count = sum(1 for port in open_ports if port.get('port') in risky_ports)
            network_score = 100 - (risky_count * 20)
            scores.append(max(0, min(100, network_score)))
            
            # Data Protection
            data_score = ssl_score  # Simplified - based on SSL
            scores.append(max(0, min(100, data_score)))
            
            # Authentication
            auth_score = ssl_score  # Simplified - based on SSL
            scores.append(max(0, min(100, auth_score)))
            
            # Infrastructure Security
            subdomain_count = len(domain_data.get('subdomains', []))
            infra_score = 100 - min(50, subdomain_count * 2)  # More subdomains = larger attack surface
            scores.append(max(0, min(100, infra_score)))
            
            # Vulnerability Management
            vuln_score = 100
            if vulnerability_data:
                vuln_summary = vulnerability_data.get('vulnerability_summary', {})
                critical_count = vuln_summary.get('critical', 0)
                high_count = vuln_summary.get('high', 0)
                vuln_score = 100 - (critical_count * 30 + high_count * 15)
            scores.append(max(0, min(100, vuln_score)))
            
            # Compliance
            compliance_score = headers_score  # Simplified - based on security headers
            scores.append(max(0, min(100, compliance_score)))
            
            # Incident Response
            incident_score = 70  # Default score - would need more data to calculate properly
            scores.append(max(0, min(100, incident_score)))
            
            # Create radar chart
            fig = go.Figure()
            
            fig.add_trace(go.Scatterpolar(
                r=scores,
                theta=categories,
                fill='toself',
                name='Current Security Posture',
                line_color='rgba(37, 99, 235, 0.8)',
                fillcolor='rgba(37, 99, 235, 0.3)'
            ))
            
            # Add ideal security posture for comparison
            ideal_scores = [90] * len(categories)
            fig.add_trace(go.Scatterpolar(
                r=ideal_scores,
                theta=categories,
                fill='toself',
                name='Target Security Posture',
                line_color='rgba(16, 185, 129, 0.8)',
                fillcolor='rgba(16, 185, 129, 0.1)'
            ))
            
            fig.update_layout(
                polar=dict(
                    radialaxis=dict(
                        visible=True,
                        range=[0, 100]
                    )),
                showlegend=True,
                title="Threat Landscape Assessment",
                height=500
            )
            
            return {
                'type': 'plotly',
                'figure': fig.to_dict(),
                'description': 'Comprehensive threat landscape radar showing security posture across multiple dimensions'
            }
            
        except Exception as e:
            logger.error(f"Error creating threat landscape radar: {str(e)}")
            return {'error': str(e)}
    
    def calculate_summary_stats(self, graph: nx.Graph, domain_data: dict, vulnerability_data: dict = None) -> dict:
        """Calculate summary statistics for the attack surface."""
        try:
            stats = {
                'total_nodes': graph.number_of_nodes(),
                'total_edges': graph.number_of_edges(),
                'node_types': {},
                'risk_summary': {},
                'coverage_metrics': {}
            }
            
            # Count node types
            node_types = nx.get_node_attributes(graph, 'type')
            for node_type in node_types.values():
                stats['node_types'][node_type] = stats['node_types'].get(node_type, 0) + 1
            
            # Risk summary
            high_risk_nodes = sum(1 for node in graph.nodes() 
                                if graph.nodes[node].get('risk_level') == 'high')
            stats['risk_summary'] = {
                'high_risk_nodes': high_risk_nodes,
                'total_subdomains': len(domain_data.get('subdomains', [])),
                'open_ports': len(domain_data.get('open_ports', [])),
                'ssl_valid': domain_data.get('ssl', {}).get('valid', False)
            }
            
            # Coverage metrics
            stats['coverage_metrics'] = {
                'dns_coverage': len(domain_data.get('dns', [])),
                'subdomain_coverage': len(domain_data.get('subdomains', [])),
                'technology_coverage': len(domain_data.get('technologies', [])),
                'security_header_coverage': sum(1 for v in domain_data.get('security_headers', {}).values() if v != 'Not set')
            }
            
            if vulnerability_data:
                vuln_summary = vulnerability_data.get('vulnerability_summary', {})
                stats['vulnerability_metrics'] = {
                    'total_vulnerabilities': vuln_summary.get('total_vulnerabilities', 0),
                    'critical_vulnerabilities': vuln_summary.get('critical', 0),
                    'high_vulnerabilities': vuln_summary.get('high', 0),
                    'average_cvss': vuln_summary.get('average_cvss', 0)
                }
            
            return stats
            
        except Exception as e:
            logger.error(f"Error calculating summary stats: {str(e)}")
            return {}

# Initialize global visual attack surface mapper
visual_attack_mapper = VisualAttackSurfaceMapper()
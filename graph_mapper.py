import networkx as nx
import json
from typing import Dict, List, Any
import logging
from collections import defaultdict

logger = logging.getLogger(__name__)

class DomainGraphMapper:
    def __init__(self):
        self.graph = nx.Graph()
        
    def create_domain_graph(self, domain_data: dict) -> dict:
        """Create an interactive graph of domain relationships."""
        try:
            self.graph.clear()
            domain = domain_data.get('domain', '')
            
            # Add main domain node
            self.graph.add_node(domain, 
                               type='main_domain', 
                               label=domain,
                               size=30,
                               color='#2563eb')
            
            # Add IP nodes
            geo = domain_data.get('geolocation', {})
            if not geo.get('error') and geo.get('ip'):
                ip = geo['ip']
                self.graph.add_node(ip, 
                                   type='ip', 
                                   label=f"IP: {ip}",
                                   size=20,
                                   color='#10b981',
                                   country=geo.get('country', 'Unknown'),
                                   city=geo.get('city', 'Unknown'),
                                   isp=geo.get('isp', 'Unknown'))
                self.graph.add_edge(domain, ip, relationship='resolves_to')
            
            # Add subdomain nodes
            subdomains = domain_data.get('subdomains', [])[:20]  # Limit for performance
            for subdomain in subdomains:
                if subdomain != domain:
                    self.graph.add_node(subdomain, 
                                       type='subdomain', 
                                       label=subdomain,
                                       size=15,
                                       color='#8b5cf6')
                    self.graph.add_edge(domain, subdomain, relationship='subdomain_of')
            
            # Add reverse IP domains
            reverse_domains = domain_data.get('reverse_ip', [])[:10]  # Limit for performance
            for rev_domain in reverse_domains:
                if rev_domain != domain and rev_domain not in subdomains:
                    self.graph.add_node(rev_domain, 
                                       type='related_domain', 
                                       label=rev_domain,
                                       size=12,
                                       color='#f59e0b')
                    if geo.get('ip'):
                        self.graph.add_edge(rev_domain, geo['ip'], relationship='shares_ip')
            
            # Add DNS record nodes
            dns_records = domain_data.get('dns', [])
            mx_records = [r for r in dns_records if r.get('type') == 'MX']
            ns_records = [r for r in dns_records if r.get('type') == 'NS']
            
            for mx in mx_records[:3]:  # Limit MX records
                mx_value = mx.get('value', '').split()[-1] if mx.get('value') else ''
                if mx_value:
                    self.graph.add_node(mx_value, 
                                       type='mx_server', 
                                       label=f"MX: {mx_value}",
                                       size=10,
                                       color='#ef4444')
                    self.graph.add_edge(domain, mx_value, relationship='mail_server')
            
            for ns in ns_records[:3]:  # Limit NS records
                ns_value = ns.get('value', '')
                if ns_value:
                    self.graph.add_node(ns_value, 
                                       type='name_server', 
                                       label=f"NS: {ns_value}",
                                       size=10,
                                       color='#06b6d4')
                    self.graph.add_edge(domain, ns_value, relationship='name_server')
            
            # Add SSL certificate info
            ssl = domain_data.get('ssl', {})
            if ssl.get('issuer') and ssl.get('issuer') != 'N/A':
                issuer = ssl['issuer']
                self.graph.add_node(issuer, 
                                   type='ssl_issuer', 
                                   label=f"SSL: {issuer}",
                                   size=8,
                                   color='#84cc16')
                self.graph.add_edge(domain, issuer, relationship='ssl_issued_by')
            
            # Convert to format suitable for frontend visualization
            return self._convert_to_vis_format()
            
        except Exception as e:
            logger.error(f"Error creating domain graph: {str(e)}")
            return {'nodes': [], 'edges': []}
    
    def _convert_to_vis_format(self) -> dict:
        """Convert NetworkX graph to format suitable for web visualization."""
        nodes = []
        edges = []
        
        # Convert nodes
        for node_id, node_data in self.graph.nodes(data=True):
            nodes.append({
                'id': node_id,
                'label': node_data.get('label', node_id),
                'type': node_data.get('type', 'unknown'),
                'size': node_data.get('size', 10),
                'color': node_data.get('color', '#gray'),
                'title': self._create_node_tooltip(node_id, node_data)
            })
        
        # Convert edges
        for source, target, edge_data in self.graph.edges(data=True):
            edges.append({
                'from': source,
                'to': target,
                'label': edge_data.get('relationship', ''),
                'title': edge_data.get('relationship', '').replace('_', ' ').title()
            })
        
        return {
            'nodes': nodes,
            'edges': edges,
            'stats': {
                'total_nodes': len(nodes),
                'total_edges': len(edges),
                'node_types': self._get_node_type_counts()
            }
        }
    
    def _create_node_tooltip(self, node_id: str, node_data: dict) -> str:
        """Create tooltip text for graph nodes."""
        tooltip = f"<b>{node_data.get('label', node_id)}</b><br>"
        tooltip += f"Type: {node_data.get('type', 'unknown').replace('_', ' ').title()}<br>"
        
        if node_data.get('country'):
            tooltip += f"Country: {node_data['country']}<br>"
        if node_data.get('city'):
            tooltip += f"City: {node_data['city']}<br>"
        if node_data.get('isp'):
            tooltip += f"ISP: {node_data['isp']}<br>"
            
        return tooltip
    
    def _get_node_type_counts(self) -> dict:
        """Get count of each node type."""
        type_counts = defaultdict(int)
        for _, node_data in self.graph.nodes(data=True):
            type_counts[node_data.get('type', 'unknown')] += 1
        return dict(type_counts)
    
    def find_shortest_path(self, source: str, target: str) -> List[str]:
        """Find shortest path between two nodes."""
        try:
            return nx.shortest_path(self.graph, source, target)
        except nx.NetworkXNoPath:
            return []
    
    def get_node_centrality(self) -> dict:
        """Calculate node centrality measures."""
        try:
            return {
                'betweenness': nx.betweenness_centrality(self.graph),
                'closeness': nx.closeness_centrality(self.graph),
                'degree': nx.degree_centrality(self.graph)
            }
        except Exception as e:
            logger.error(f"Error calculating centrality: {str(e)}")
            return {}
    
    def export_graph(self, format_type: str = 'graphml') -> str:
        """Export graph in various formats."""
        try:
            if format_type == 'graphml':
                nx.write_graphml(self.graph, 'domain_graph.graphml')
                return 'domain_graph.graphml'
            elif format_type == 'gexf':
                nx.write_gexf(self.graph, 'domain_graph.gexf')
                return 'domain_graph.gexf'
            elif format_type == 'json':
                data = nx.node_link_data(self.graph)
                with open('domain_graph.json', 'w') as f:
                    json.dump(data, f, indent=2)
                return 'domain_graph.json'
        except Exception as e:
            logger.error(f"Error exporting graph: {str(e)}")
            return None

# Initialize global graph mapper
graph_mapper = DomainGraphMapper()
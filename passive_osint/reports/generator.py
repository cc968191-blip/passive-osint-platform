"""Main report generator for the Passive OSINT Platform."""

import json
import csv
import os
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from jinja2 import Template

from .formatters import JSONFormatter, HTMLFormatter, CSVFormatter, TXTFormatter
from ..core.config import Config
from ..core.engine import ReconResult


class ReportGenerator:
    """Main report generator supporting multiple output formats."""
    
    def __init__(self, config: Optional[Config] = None):
        """
        Initialize report generator.
        
        Args:
            config: Configuration object
        """
        self.config = config or Config()
        
        # Initialize formatters
        self.json_formatter = JSONFormatter(config)
        self.html_formatter = HTMLFormatter(config)
        self.csv_formatter = CSVFormatter(config)
        self.txt_formatter = TXTFormatter(config)
    
    def generate_report(self, 
                       result: ReconResult, 
                       output_format: str = 'json',
                       output_file: Optional[str] = None,
                       include_raw_data: bool = False) -> str:
        """
        Generate a reconnaissance report.
        
        Args:
            result: Reconnaissance results
            output_format: Output format (json, html, csv, txt)
            output_file: Output file path (optional)
            include_raw_data: Include raw API data in report
            
        Returns:
            Report content or file path
        """
        # Process results for reporting
        processed_result = self._process_results(result, include_raw_data)
        
        # Generate report based on format
        if output_format.lower() == 'json':
            content = self.json_formatter.format(processed_result)
        elif output_format.lower() == 'html':
            content = self.html_formatter.format(processed_result)
        elif output_format.lower() == 'csv':
            content = self.csv_formatter.format(processed_result)
        elif output_format.lower() == 'txt':
            content = self.txt_formatter.format(processed_result)
        else:
            raise ValueError(f"Unsupported output format: {output_format}")
        
        # Save to file if specified
        if output_file:
            self._save_report(content, output_file)
            return output_file
        
        return content
    
    def _process_results(self, result: ReconResult, include_raw_data: bool) -> Dict[str, Any]:
        """
        Process reconnaissance results for reporting.
        
        Args:
            result: Raw reconnaissance results
            include_raw_data: Whether to include raw API data
            
        Returns:
            Processed results dictionary
        """
        processed = {
            'metadata': {
                'domain': result.domain,
                'timestamp': result.timestamp,
                'execution_time': result.metadata.get('execution_time', 0),
                'modules_run': result.metadata.get('modules_run', []),
                'report_generated': datetime.now(timezone.utc).isoformat()
            },
            'summary': self._generate_summary(result),
            'findings': {
                'subdomains': self._process_subdomains(result.subdomains, include_raw_data),
                'ports': self._process_ports(result.ports, include_raw_data),
                'technologies': self._process_technologies(result.technologies, include_raw_data),
                'vulnerabilities': self._process_vulnerabilities(result.vulnerabilities, include_raw_data),
                'credentials': self._process_credentials(result.credentials, include_raw_data)
            },
            'recommendations': self._generate_recommendations(result),
            'risk_assessment': self._generate_risk_assessment(result)
        }
        
        return processed
    
    def _generate_summary(self, result: ReconResult) -> Dict[str, Any]:
        """Generate executive summary of findings."""
        summary = {
            'total_findings': {
                'subdomains': len(result.subdomains),
                'open_ports': sum(len(item['data'].get('services', [])) for item in result.ports),
                'technologies': len(result.technologies),
                'vulnerabilities': len(result.vulnerabilities),
                'credential_leaks': len(result.credentials)
            },
            'risk_levels': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            },
            'key_findings': []
        }
        
        # Count vulnerability risk levels
        for vuln in result.vulnerabilities:
            severity = vuln['data'].get('severity', '').lower()
            if severity in summary['risk_levels']:
                summary['risk_levels'][severity] += 1
        
        # Count credential risk levels
        for cred in result.credentials:
            risk_level = cred['data'].get('risk_level', '').lower()
            if risk_level in summary['risk_levels']:
                summary['risk_levels'][risk_level] += 1
        
        # Generate key findings
        if summary['total_findings']['vulnerabilities'] > 0:
            summary['key_findings'].append(f"{summary['total_findings']['vulnerabilities']} potential vulnerabilities identified")
        
        if summary['total_findings']['credential_leaks'] > 0:
            summary['key_findings'].append(f"{summary['total_findings']['credential_leaks']} potential credential leaks detected")
        
        if summary['total_findings']['open_ports'] > 10:
            summary['key_findings'].append(f"{summary['total_findings']['open_ports']} open services detected - extensive attack surface")
        
        if summary['total_findings']['subdomains'] > 50:
            summary['key_findings'].append(f"{summary['total_findings']['subdomains']} subdomains discovered - large digital footprint")
        
        return summary
    
    def _process_subdomains(self, subdomains: List[Dict[str, Any]], include_raw_data: bool) -> Dict[str, Any]:
        """Process subdomain results for reporting."""
        processed = {
            'total_count': len(subdomains),
            'unique_subdomains': [],
            'sources_summary': {},
            'confidence_distribution': {'low': 0, 'medium': 0, 'high': 0, 'very_high': 0}
        }
        
        # Process unique subdomains
        seen_subdomains = set()
        for subdomain in subdomains:
            data = subdomain['data']
            full_host = data['full_host']
            
            if full_host not in seen_subdomains:
                seen_subdomains.add(full_host)
                
                subdomain_info = {
                    'subdomain': data['subdomain'],
                    'full_host': full_host,
                    'confidence': data.get('confidence', 'medium'),
                    'sources': data.get('sources', [subdomain['source']])
                }
                
                if include_raw_data:
                    subdomain_info['raw_data'] = data
                
                processed['unique_subdomains'].append(subdomain_info)
                
                # Update confidence distribution
                confidence = data.get('confidence', 'medium')
                if confidence in processed['confidence_distribution']:
                    processed['confidence_distribution'][confidence] += 1
        
        # Summarize sources
        for subdomain in subdomains:
            source = subdomain['source']
            processed['sources_summary'][source] = processed['sources_summary'].get(source, 0) + 1
        
        return processed
    
    def _process_ports(self, ports: List[Dict[str, Any]], include_raw_data: bool) -> Dict[str, Any]:
        """Process port detection results for reporting."""
        processed = {
            'total_hosts': len(ports),
            'total_services': 0,
            'unique_ports': set(),
            'services_by_port': {},
            'risk_assessment': {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
        }
        
        for port_result in ports:
            data = port_result['data']
            services = data.get('services', [])
            
            processed['total_services'] += len(services)
            
            for service in services:
                port_num = service.get('port')
                if port_num:
                    processed['unique_ports'].add(port_num)
                    
                    if port_num not in processed['services_by_port']:
                        processed['services_by_port'][port_num] = []
                    
                    service_info = {
                        'port': port_num,
                        'transport': service.get('transport', 'tcp'),
                        'service_name': service.get('service_name'),
                        'product': service.get('product'),
                        'version': service.get('version'),
                        'banner': service.get('banner', '')[:100] + '...' if len(service.get('banner', '')) > 100 else service.get('banner', '')
                    }
                    
                    if include_raw_data:
                        service_info['raw_data'] = service
                    
                    processed['services_by_port'][port_num].append(service_info)
            
            # Process risk assessment
            if 'risk_assessment' in data:
                for risk in data['risk_assessment']:
                    risk_level = risk.get('risk_level', 'low')
                    processed['risk_assessment'][risk_level] = processed['risk_assessment'].get(risk_level, 0) + 1
        
        processed['unique_ports'] = sorted(list(processed['unique_ports']))
        return processed
    
    def _process_technologies(self, technologies: List[Dict[str, Any]], include_raw_data: bool) -> Dict[str, Any]:
        """Process technology identification results for reporting."""
        processed = {
            'total_count': len(technologies),
            'by_category': {},
            'confidence_distribution': {'low': 0, 'medium': 0, 'high': 0, 'very_high': 0}
        }
        
        for tech in technologies:
            data = tech['data']
            category = data.get('category', 'unknown')
            confidence = data.get('confidence', 'medium')
            
            if category not in processed['by_category']:
                processed['by_category'][category] = []
            
            tech_info = {
                'name': data['technology'],
                'category': category,
                'version': data.get('version'),
                'confidence': confidence,
                'sources': data.get('sources', [tech['source']]),
                'evidence_count': len(data.get('evidence', []))
            }
            
            if include_raw_data:
                tech_info['raw_data'] = data
            
            processed['by_category'][category].append(tech_info)
            processed['confidence_distribution'][confidence] += 1
        
        return processed
    
    def _process_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]], include_raw_data: bool) -> Dict[str, Any]:
        """Process vulnerability scan results for reporting."""
        processed = {
            'total_count': len(vulnerabilities),
            'by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
            'by_type': {},
            'top_priorities': []
        }
        
        for vuln in vulnerabilities:
            data = vuln['data']
            severity = data.get('severity', 'unknown').lower()
            vuln_type = data.get('type', 'unknown')
            
            if severity not in processed['by_severity']:
                severity = 'unknown'
            
            processed['by_severity'][severity] += 1
            
            if vuln_type not in processed['by_type']:
                processed['by_type'][vuln_type] = []
            
            vuln_info = {
                'cve_id': data.get('cve_id'),
                'title': data.get('title', 'Unknown'),
                'severity': severity,
                'cvss_score': data.get('cvss_score'),
                'description': data.get('description', '')[:200] + '...' if len(data.get('description', '')) > 200 else data.get('description', ''),
                'priority_rank': data.get('priority_rank', 999),
                'risk_assessment': data.get('risk_assessment', {})
            }
            
            if include_raw_data:
                vuln_info['raw_data'] = data
            
            processed['by_type'][vuln_type].append(vuln_info)
        
        # Get top priorities (first 10 by priority rank)
        processed['top_priorities'] = sorted(
            [v for v in vulnerabilities if 'priority_rank' in v['data']],
            key=lambda x: x['data']['priority_rank']
        )[:10]
        
        return processed
    
    def _process_credentials(self, credentials: List[Dict[str, Any]], include_raw_data: bool) -> Dict[str, Any]:
        """Process credential leak detection results for reporting."""
        processed = {
            'total_count': len(credentials),
            'by_risk_level': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
            'by_source': {},
            'by_category': {}
        }
        
        for cred in credentials:
            data = cred['data']
            risk_level = data.get('risk_level', 'unknown').lower()
            source = cred['source']
            
            if risk_level not in processed['by_risk_level']:
                risk_level = 'unknown'
            
            processed['by_risk_level'][risk_level] += 1
            
            if source not in processed['by_source']:
                processed['by_source'][source] = []
            
            cred_info = {
                'source': source,
                'risk_level': risk_level,
                'description': self._summarize_credential_leak(data),
                'recommendations': data.get('recommendations', [])
            }
            
            if include_raw_data:
                cred_info['raw_data'] = data
            
            processed['by_source'][source].append(cred_info)
            
            # Process by category if matches available
            if 'matches' in data:
                for match in data['matches']:
                    category = match.get('category', 'unknown')
                    if category not in processed['by_category']:
                        processed['by_category'][category] = 0
                    processed['by_category'][category] += 1
        
        return processed
    
    def _summarize_credential_leak(self, credential_data: Dict[str, Any]) -> str:
        """Generate summary description for credential leak."""
        source = credential_data.get('source', 'unknown')
        
        if source == 'pastebin':
            return f"Credentials found in paste: {credential_data.get('title', 'Unknown')}"
        elif source == 'github_leaks':
            return f"Credentials found in GitHub repository: {credential_data.get('repository', 'Unknown')}"
        elif source == 'breach_database':
            return f"Data breach detected: {credential_data.get('breach_name', 'Unknown')}"
        else:
            return f"Credential leak detected from {source}"
    
    def _generate_recommendations(self, result: ReconResult) -> Dict[str, List[str]]:
        """Generate security recommendations based on findings."""
        recommendations = {
            'immediate': [],
            'short_term': [],
            'long_term': [],
            'general': []
        }
        
        # Vulnerability recommendations
        critical_vulns = [v for v in result.vulnerabilities if v['data'].get('severity') == 'Critical']
        if critical_vulns:
            recommendations['immediate'].append("Patch critical vulnerabilities immediately")
        
        high_vulns = [v for v in result.vulnerabilities if v['data'].get('severity') == 'High']
        if high_vulns:
            recommendations['short_term'].append("Address high-severity vulnerabilities within 7 days")
        
        # Credential leak recommendations
        critical_creds = [c for c in result.credentials if c['data'].get('risk_level') == 'Critical']
        if critical_creds:
            recommendations['immediate'].append("Rotate all critical exposed credentials immediately")
        
        # Port/service recommendations
        risky_ports = []
        for port_result in result.ports:
            if 'risk_assessment' in port_result['data']:
                for risk in port_result['data']['risk_assessment']:
                    if risk.get('risk_level') in ['high', 'critical']:
                        risky_ports.extend(risk.get('recommendations', []))
        
        if risky_ports:
            recommendations['short_term'].extend(risky_ports[:3])  # Limit to top 3
        
        # General recommendations
        recommendations['general'].extend([
            "Implement regular security monitoring and alerting",
            "Conduct periodic security assessments",
            "Maintain an up-to-date asset inventory",
            "Implement proper access control policies"
        ])
        
        return recommendations
    
    def _generate_risk_assessment(self, result: ReconResult) -> Dict[str, Any]:
        """Generate overall risk assessment."""
        risk_scores = {
            'vulnerabilities': 0,
            'credentials': 0,
            'exposure': 0,
            'overall': 0
        }
        
        # Calculate vulnerability risk score
        for vuln in result.vulnerabilities:
            severity = vuln['data'].get('severity', '').lower()
            if severity == 'critical':
                risk_scores['vulnerabilities'] += 10
            elif severity == 'high':
                risk_scores['vulnerabilities'] += 7
            elif severity == 'medium':
                risk_scores['vulnerabilities'] += 4
            elif severity == 'low':
                risk_scores['vulnerabilities'] += 1
        
        # Calculate credential risk score
        for cred in result.credentials:
            risk_level = cred['data'].get('risk_level', '').lower()
            if risk_level == 'critical':
                risk_scores['credentials'] += 10
            elif risk_level == 'high':
                risk_scores['credentials'] += 7
            elif risk_level == 'medium':
                risk_scores['credentials'] += 4
            elif risk_level == 'low':
                risk_scores['credentials'] += 1
        
        # Calculate exposure risk score
        total_services = sum(len(item['data'].get('services', [])) for item in result.ports)
        if total_services > 20:
            risk_scores['exposure'] += 5
        elif total_services > 10:
            risk_scores['exposure'] += 3
        
        if len(result.subdomains) > 100:
            risk_scores['exposure'] += 3
        elif len(result.subdomains) > 50:
            risk_scores['exposure'] += 2
        
        # Calculate overall risk
        risk_scores['overall'] = sum(risk_scores.values())
        
        # Determine risk level
        if risk_scores['overall'] >= 30:
            overall_risk = 'Critical'
        elif risk_scores['overall'] >= 20:
            overall_risk = 'High'
        elif risk_scores['overall'] >= 10:
            overall_risk = 'Medium'
        else:
            overall_risk = 'Low'
        
        return {
            'risk_scores': risk_scores,
            'overall_risk_level': overall_risk,
            'risk_factors': self._identify_risk_factors(result)
        }
    
    def _identify_risk_factors(self, result: ReconResult) -> List[str]:
        """Identify specific risk factors."""
        factors = []
        
        if any(v['data'].get('severity') == 'Critical' for v in result.vulnerabilities):
            factors.append("Critical vulnerabilities present")
        
        if any(c['data'].get('risk_level') == 'Critical' for c in result.credentials):
            factors.append("Critical credential leaks detected")
        
        total_services = sum(len(item['data'].get('services', [])) for item in result.ports)
        if total_services > 15:
            factors.append(f"Large attack surface ({total_services} exposed services)")
        
        if len(result.subdomains) > 75:
            factors.append(f"Extensive digital footprint ({len(result.subdomains)} subdomains)")
        
        return factors
    
    def _save_report(self, content: str, output_file: str) -> None:
        """
        Save report content to file.
        
        Args:
            content: Report content
            output_file: Output file path
        """
        try:
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(content)
        except Exception as e:
            raise IOError(f"Failed to save report to {output_file}: {e}")

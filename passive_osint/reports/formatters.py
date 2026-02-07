"""Output formatters for different report formats."""

import json
import csv
import io
from typing import Dict, Any
from datetime import datetime
from jinja2 import Template

from ..core.config import Config


class BaseFormatter:
    """Base class for all output formatters."""
    
    def __init__(self, config: Config):
        """Initialize formatter."""
        self.config = config
    
    def format(self, data: Dict[str, Any]) -> str:
        """Format data into specific format."""
        raise NotImplementedError


class JSONFormatter(BaseFormatter):
    """JSON output formatter."""
    
    def format(self, data: Dict[str, Any]) -> str:
        """Format data as JSON."""
        return json.dumps(data, indent=2, ensure_ascii=False)


class HTMLFormatter(BaseFormatter):
    """HTML output formatter with styling."""
    
    def format(self, data: Dict[str, Any]) -> str:
        """Format data as HTML report."""
        template_str = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OSINT Reconnaissance Report - {{ data.metadata.domain }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .critical { color: #e74c3c; font-weight: bold; }
        .high { color: #e67e22; font-weight: bold; }
        .medium { color: #f39c12; font-weight: bold; }
        .low { color: #27ae60; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 15px 0; }
        .summary-card { background: #f8f9fa; padding: 15px; border-radius: 5px; text-align: center; }
        .summary-card h3 { margin: 0 0 10px 0; color: #2c3e50; }
        .summary-card .number { font-size: 2em; font-weight: bold; color: #3498db; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f8f9fa; }
        .risk-meter { width: 100%; height: 20px; background: linear-gradient(to right, #27ae60, #f39c12, #e67e22, #e74c3c); border-radius: 10px; }
        .recommendations { background: #e8f5e8; padding: 15px; border-radius: 5px; }
        .recommendations ul { margin: 0; padding-left: 20px; }
        .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; text-align: center; }
    </style>
</head>
<body>
    <div class="header">
        <h1>OSINT Reconnaissance Report</h1>
        <p><strong>Target:</strong> {{ data.metadata.domain }}</p>
        <p><strong>Generated:</strong> {{ data.metadata.timestamp }}</p>
        <p><strong>Execution Time:</strong> {{ data.metadata.execution_time }}s</p>
    </div>

    <div class="section">
        <h2>Executive Summary</h2>
        <div class="summary-grid">
            <div class="summary-card">
                <h3>Subdomains</h3>
                <div class="number">{{ data.summary.total_findings.subdomains }}</div>
            </div>
            <div class="summary-card">
                <h3>Open Services</h3>
                <div class="number">{{ data.summary.total_findings.open_ports }}</div>
            </div>
            <div class="summary-card">
                <h3>Technologies</h3>
                <div class="number">{{ data.summary.total_findings.technologies }}</div>
            </div>
            <div class="summary-card">
                <h3>Vulnerabilities</h3>
                <div class="number">{{ data.summary.total_findings.vulnerabilities }}</div>
            </div>
            <div class="summary-card">
                <h3>Credential Leaks</h3>
                <div class="number">{{ data.summary.total_findings.credential_leaks }}</div>
            </div>
        </div>
        
        <h3>Risk Level Distribution</h3>
        <table>
            <tr><th>Risk Level</th><th>Count</th></tr>
            <tr><td class="critical">Critical</td><td>{{ data.summary.risk_levels.critical }}</td></tr>
            <tr><td class="high">High</td><td>{{ data.summary.risk_levels.high }}</td></tr>
            <tr><td class="medium">Medium</td><td>{{ data.summary.risk_levels.medium }}</td></tr>
            <tr><td class="low">Low</td><td>{{ data.summary.risk_levels.low }}</td></tr>
        </table>
        
        {% if data.summary.key_findings %}
        <h3>Key Findings</h3>
        <ul>
            {% for finding in data.summary.key_findings %}
            <li>{{ finding }}</li>
            {% endfor %}
        </ul>
        {% endif %}
    </div>

    <div class="section">
        <h2>Subdomains</h2>
        <p><strong>Total Unique Subdomains:</strong> {{ data.findings.subdomains.total_count }}</p>
        
        {% if data.findings.subdomains.unique_subdomains %}
        <table>
            <tr><th>Subdomain</th><th>Full Host</th><th>Confidence</th><th>Sources</th></tr>
            {% for subdomain in data.findings.subdomains.unique_subdomains[:20] %}
            <tr>
                <td>{{ subdomain.subdomain }}</td>
                <td>{{ subdomain.full_host }}</td>
                <td class="{{ subdomain.confidence }}">{{ subdomain.confidence|title }}</td>
                <td>{{ subdomain.sources|join(', ') }}</td>
            </tr>
            {% endfor %}
        </table>
        {% if data.findings.subdomains.unique_subdomains|length > 20 %}
        <p><em>Showing first 20 of {{ data.findings.subdomains.unique_subdomains|length }} subdomains</em></p>
        {% endif %}
        {% endif %}
    </div>

    <div class="section">
        <h2>Ports and Services</h2>
        <p><strong>Total Hosts:</strong> {{ data.findings.ports.total_hosts }}</p>
        <p><strong>Total Services:</strong> {{ data.findings.ports.total_services }}</p>
        
        {% if data.findings.ports.services_by_port %}
        <h3>Services by Port</h3>
        <table>
            <tr><th>Port</th><th>Service</th><th>Product</th><th>Version</th></tr>
            {% for port, services in data.findings.ports.services_by_port.items() %}
                {% for service in services[:5] %}
                <tr>
                    <td>{{ port }}</td>
                    <td>{{ service.service_name or 'Unknown' }}</td>
                    <td>{{ service.product or '-' }}</td>
                    <td>{{ service.version or '-' }}</td>
                </tr>
                {% endfor %}
            {% endfor %}
        </table>
        {% endif %}
    </div>

    <div class="section">
        <h2>Technologies</h2>
        <p><strong>Total Technologies:</strong> {{ data.findings.technologies.total_count }}</p>
        
        {% for category, techs in data.findings.technologies.by_category.items() %}
        <h3>{{ category|title }}</h3>
        <table>
            <tr><th>Technology</th><th>Version</th><th>Confidence</th></tr>
            {% for tech in techs %}
            <tr>
                <td>{{ tech.name }}</td>
                <td>{{ tech.version or '-' }}</td>
                <td class="{{ tech.confidence }}">{{ tech.confidence|title }}</td>
            </tr>
            {% endfor %}
        </table>
        {% endfor %}
    </div>

    <div class="section">
        <h2>Vulnerabilities</h2>
        <p><strong>Total Vulnerabilities:</strong> {{ data.findings.vulnerabilities.total_count }}</p>
        
        {% if data.findings.vulnerabilities.top_priorities %}
        <h3>Top Priority Vulnerabilities</h3>
        <table>
            <tr><th>CVE ID</th><th>Title</th><th>Severity</th><th>CVSS Score</th></tr>
            {% for vuln in data.findings.vulnerabilities.top_priorities[:10] %}
            <tr>
                <td>{{ vuln.data.cve_id or '-' }}</td>
                <td>{{ vuln.data.title }}</td>
                <td class="{{ vuln.data.severity|lower }}">{{ vuln.data.severity|title }}</td>
                <td>{{ vuln.data.cvss_score or '-' }}</td>
            </tr>
            {% endfor %}
        </table>
        {% endif %}
    </div>

    <div class="section">
        <h2>Credential Leaks</h2>
        <p><strong>Total Leaks:</strong> {{ data.findings.credentials.total_count }}</p>
        
        {% if data.findings.credentials.by_source %}
        <h3>Leaks by Source</h3>
        {% for source, leaks in data.findings.credentials.by_source.items() %}
        <h4>{{ source|title }}</h4>
        <ul>
            {% for leak in leaks[:5] %}
            <li class="{{ leak.risk_level|lower }}">{{ leak.description }}</li>
            {% endfor %}
        </ul>
        {% endfor %}
        {% endif %}
    </div>

    <div class="section recommendations">
        <h2>Recommendations</h2>
        
        {% if data.recommendations.immediate %}
        <h3 class="critical">Immediate Actions Required</h3>
        <ul>
            {% for rec in data.recommendations.immediate %}
            <li>{{ rec }}</li>
            {% endfor %}
        </ul>
        {% endif %}
        
        {% if data.recommendations.short_term %}
        <h3 class="high">Short-term Actions (Within 7 days)</h3>
        <ul>
            {% for rec in data.recommendations.short_term %}
            <li>{{ rec }}</li>
            {% endfor %}
        </ul>
        {% endif %}
        
        {% if data.recommendations.general %}
        <h3>General Security Recommendations</h3>
        <ul>
            {% for rec in data.recommendations.general %}
            <li>{{ rec }}</li>
            {% endfor %}
        </ul>
        {% endif %}
    </div>

    <div class="section">
        <h2>Overall Risk Assessment</h2>
        <p><strong>Overall Risk Level:</strong> <span class="{{ data.risk_assessment.overall_risk_level|lower }}">{{ data.risk_assessment.overall_risk_level|title }}</span></p>
        
        <h3>Risk Scores</h3>
        <table>
            <tr><th>Category</th><th>Score</th></tr>
            <tr><td>Vulnerabilities</td><td>{{ data.risk_assessment.risk_scores.vulnerabilities }}</td></tr>
            <tr><td>Credential Leaks</td><td>{{ data.risk_assessment.risk_scores.credentials }}</td></tr>
            <tr><td>Exposure</td><td>{{ data.risk_assessment.risk_scores.exposure }}</td></tr>
            <tr><td><strong>Overall</strong></td><td><strong>{{ data.risk_assessment.risk_scores.overall }}</strong></td></tr>
        </table>
        
        {% if data.risk_assessment.risk_factors %}
        <h3>Risk Factors</h3>
        <ul>
            {% for factor in data.risk_assessment.risk_factors %}
            <li>{{ factor }}</li>
            {% endfor %}
        </ul>
        {% endif %}
    </div>

    <div class="footer">
        <p>Report generated by Passive OSINT Reconnaissance Platform</p>
        <p>Generated on {{ data.metadata.report_generated }}</p>
    </div>
</body>
</html>
        """
        
        template = Template(template_str)
        return template.render(data=data)


class CSVFormatter(BaseFormatter):
    """CSV output formatter."""
    
    def format(self, data: Dict[str, Any]) -> str:
        """Format data as CSV."""
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write metadata
        writer.writerow(['Metadata'])
        writer.writerow(['Domain', data['metadata']['domain']])
        writer.writerow(['Timestamp', data['metadata']['timestamp']])
        writer.writerow(['Execution Time', data['metadata']['execution_time']])
        writer.writerow([])
        
        # Write summary
        writer.writerow(['Summary'])
        writer.writerow(['Category', 'Count'])
        for category, count in data['summary']['total_findings'].items():
            writer.writerow([category.title(), count])
        writer.writerow([])
        
        # Write subdomains
        if data['findings']['subdomains']['unique_subdomains']:
            writer.writerow(['Subdomains'])
            writer.writerow(['Subdomain', 'Full Host', 'Confidence', 'Sources'])
            for subdomain in data['findings']['subdomains']['unique_subdomains']:
                writer.writerow([
                    subdomain['subdomain'],
                    subdomain['full_host'],
                    subdomain['confidence'],
                    ', '.join(subdomain['sources'])
                ])
            writer.writerow([])
        
        # Write vulnerabilities
        if data['findings']['vulnerabilities']['top_priorities']:
            writer.writerow(['Vulnerabilities'])
            writer.writerow(['CVE ID', 'Title', 'Severity', 'CVSS Score'])
            for vuln in data['findings']['vulnerabilities']['top_priorities']:
                writer.writerow([
                    vuln['data'].get('cve_id', ''),
                    vuln['data'].get('title', ''),
                    vuln['data'].get('severity', ''),
                    vuln['data'].get('cvss_score', '')
                ])
            writer.writerow([])
        
        # Write technologies
        if data['findings']['technologies']['by_category']:
            writer.writerow(['Technologies'])
            writer.writerow(['Technology', 'Category', 'Version', 'Confidence'])
            for category, techs in data['findings']['technologies']['by_category'].items():
                for tech in techs:
                    writer.writerow([
                        tech['name'],
                        category,
                        tech.get('version', ''),
                        tech['confidence']
                    ])
        
        return output.getvalue()


class TXTFormatter(BaseFormatter):
    """Plain text output formatter."""
    
    def format(self, data: Dict[str, Any]) -> str:
        """Format data as plain text."""
        output = []
        
        # Header
        output.append("=" * 60)
        output.append("PASSIVE OSINT RECONNAISSANCE REPORT")
        output.append("=" * 60)
        output.append(f"Target Domain: {data['metadata']['domain']}")
        output.append(f"Generated: {data['metadata']['timestamp']}")
        output.append(f"Execution Time: {data['metadata']['execution_time']}s")
        output.append("")
        
        # Executive Summary
        output.append("EXECUTIVE SUMMARY")
        output.append("-" * 20)
        summary = data['summary']['total_findings']
        output.append(f"Subdomains Found: {summary['subdomains']}")
        output.append(f"Open Services: {summary['open_ports']}")
        output.append(f"Technologies Identified: {summary['technologies']}")
        output.append(f"Vulnerabilities: {summary['vulnerabilities']}")
        output.append(f"Credential Leaks: {summary['credential_leaks']}")
        output.append("")
        
        # Risk Distribution
        output.append("RISK LEVEL DISTRIBUTION")
        output.append("-" * 20)
        for level, count in data['summary']['risk_levels'].items():
            output.append(f"{level.title()}: {count}")
        output.append("")
        
        # Key Findings
        if data['summary']['key_findings']:
            output.append("KEY FINDINGS")
            output.append("-" * 20)
            for finding in data['summary']['key_findings']:
                output.append(f"• {finding}")
            output.append("")
        
        # Subdomains
        if data['findings']['subdomains']['unique_subdomains']:
            output.append("SUBDOMAINS")
            output.append("-" * 20)
            output.append(f"Total Unique Subdomains: {data['findings']['subdomains']['total_count']}")
            for subdomain in data['findings']['subdomains']['unique_subdomains'][:15]:
                output.append(f"• {subdomain['full_host']} ({subdomain['confidence']})")
            if len(data['findings']['subdomains']['unique_subdomains']) > 15:
                output.append(f"... and {len(data['findings']['subdomains']['unique_subdomains']) - 15} more")
            output.append("")
        
        # Vulnerabilities
        if data['findings']['vulnerabilities']['top_priorities']:
            output.append("TOP VULNERABILITIES")
            output.append("-" * 20)
            for vuln in data['findings']['vulnerabilities']['top_priorities'][:10]:
                cve_id = vuln['data'].get('cve_id', 'Unknown')
                title = vuln['data'].get('title', 'Unknown')
                severity = vuln['data'].get('severity', 'Unknown')
                output.append(f"• [{severity}] {cve_id}: {title}")
            output.append("")
        
        # Technologies
        if data['findings']['technologies']['by_category']:
            output.append("TECHNOLOGIES")
            output.append("-" * 20)
            for category, techs in data['findings']['technologies']['by_category'].items():
                output.append(f"{category.title()}:")
                for tech in techs[:5]:
                    version = f" ({tech['version']})" if tech.get('version') else ""
                    output.append(f"  • {tech['name']}{version}")
            output.append("")
        
        # Recommendations
        output.append("RECOMMENDATIONS")
        output.append("-" * 20)
        
        if data['recommendations']['immediate']:
            output.append("IMMEDIATE ACTIONS:")
            for rec in data['recommendations']['immediate']:
                output.append(f"• {rec}")
            output.append("")
        
        if data['recommendations']['short_term']:
            output.append("SHORT-TERM ACTIONS:")
            for rec in data['recommendations']['short_term']:
                output.append(f"• {rec}")
            output.append("")
        
        if data['recommendations']['general']:
            output.append("GENERAL RECOMMENDATIONS:")
            for rec in data['recommendations']['general']:
                output.append(f"• {rec}")
            output.append("")
        
        # Risk Assessment
        output.append("OVERALL RISK ASSESSMENT")
        output.append("-" * 20)
        output.append(f"Overall Risk Level: {data['risk_assessment']['overall_risk_level'].upper()}")
        output.append(f"Overall Risk Score: {data['risk_assessment']['risk_scores']['overall']}")
        output.append("")
        
        if data['risk_assessment']['risk_factors']:
            output.append("Risk Factors:")
            for factor in data['risk_assessment']['risk_factors']:
                output.append(f"• {factor}")
            output.append("")
        
        # Footer
        output.append("=" * 60)
        output.append("Report generated by Passive OSINT Reconnaissance Platform")
        output.append(f"Generated on {data['metadata']['report_generated']}")
        output.append("=" * 60)
        
        return "\n".join(output)

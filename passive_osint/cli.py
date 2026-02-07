"""Command Line Interface for the Passive OSINT Platform."""

import click
import asyncio
import sys
import os
from pathlib import Path
from typing import List, Optional

from .core.config import Config
from .core.engine import ReconEngine
from .core.exceptions import OSINTError, ValidationError, ConfigurationError
from .reports.generator import ReportGenerator


@click.command()
@click.option('--domain', '-d', required=True, help='Target domain for reconnaissance')
@click.option('--output', '-o', type=click.Choice(['json', 'html', 'csv', 'txt']), 
              default='json', help='Output format')
@click.option('--file', '-f', type=click.Path(), help='Output file path')
@click.option('--modules', '-m', multiple=True, 
              type=click.Choice(['subdomains', 'ports', 'technologies', 'vulnerabilities', 'credentials']),
              help='Specific modules to run (default: all enabled)')
@click.option('--config', '-c', type=click.Path(exists=True), help='Configuration file path')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.option('--include-raw', is_flag=True, help='Include raw API data in report')
@click.option('--timeout', type=int, default=300, help='Timeout in seconds (default: 300)')
@click.option('--max-results', type=int, help='Maximum results per module')
@click.pass_context
def main(ctx, domain, output, file, modules, config, verbose, include_raw, timeout, max_results):
    """
    Passive OSINT Reconnaissance Platform
    
    Perform comprehensive passive reconnaissance on a target domain using multiple OSINT sources.
    
    This tool performs PASSIVE reconnaissance only:
    - No scanning
    - No exploitation
    - No active interaction with targets
    - Authorized use only on owned assets or with explicit permission
    """
    
    # Ensure we're running with proper context
    ctx.ensure_object(dict)
    
    try:
        # Initialize configuration
        config_obj = Config(config) if config else Config()
        
        # Override config with CLI options
        if max_results:
            config_obj.set('modules.subdomains.max_results', max_results)
        
        if verbose:
            config_obj.set('logging.level', 'DEBUG')
        
        # Validate domain
        engine = ReconEngine(config_obj)
        domain = engine.validate_domain(domain)
        
        # Display banner
        if verbose:
            click.echo("=" * 60)
            click.echo("PASSIVE OSINT RECONNAISSANCE PLATFORM")
            click.echo("=" * 60)
            click.echo(f"Target Domain: {domain}")
            click.echo(f"Output Format: {output.upper()}")
            if file:
                click.echo(f"Output File: {file}")
            click.echo(f"Modules: {', '.join(modules) if modules else 'All enabled'}")
            click.echo("=" * 60)
            click.echo()
        
        # Run reconnaissance
        click.echo("Starting passive reconnaissance...")
        click.echo("This may take several minutes depending on the target...")
        click.echo()
        
        # Convert modules tuple to list if provided
        modules_list = list(modules) if modules else None
        
        # Run with timeout
        try:
            result = asyncio.run(
                asyncio.wait_for(
                    engine.run_reconnaissance(domain, modules_list),
                    timeout=timeout
                )
            )
        except asyncio.TimeoutError:
            click.echo(f"ERROR: Reconnaissance timed out after {timeout} seconds", err=True)
            sys.exit(1)
        
        # Display summary
        if verbose:
            click.echo("Reconnaissance completed!")
            click.echo(f"Execution time: {result.metadata['execution_time']}s")
            click.echo()
            click.echo("SUMMARY:")
            click.echo(f"  Subdomains: {len(result.subdomains)}")
            click.echo(f"  Open Services: {sum(len(item['data'].get('services', [])) for item in result.ports)}")
            click.echo(f"  Technologies: {len(result.technologies)}")
            click.echo(f"  Vulnerabilities: {len(result.vulnerabilities)}")
            click.echo(f"  Credential Leaks: {len(result.credentials)}")
            click.echo()
        
        # Generate report
        click.echo("Generating report...")
        report_generator = ReportGenerator(config_obj)
        
        # Generate output filename if not provided
        if not file:
            timestamp = result.timestamp.replace(':', '-').replace(' ', '_')
            file = f"osint_report_{domain}_{timestamp}.{output}"
        
        # Generate and save report
        report_path = report_generator.generate_report(
            result=result,
            output_format=output,
            output_file=file,
            include_raw_data=include_raw
        )
        
        click.echo(f"Report saved to: {report_path}")
        
        # Display quick summary
        critical_vulns = []
        high_vulns = []
        critical_creds = []
        high_creds = []
        
        if len(result.vulnerabilities) > 0:
            critical_vulns = [v for v in result.vulnerabilities if v['data'].get('severity') == 'Critical']
            high_vulns = [v for v in result.vulnerabilities if v['data'].get('severity') == 'High']
            
            if critical_vulns:
                click.echo(f"⚠️  Found {len(critical_vulns)} CRITICAL vulnerabilities")
            if high_vulns:
                click.echo(f"⚠️  Found {len(high_vulns)} HIGH severity vulnerabilities")
        
        if len(result.credentials) > 0:
            critical_creds = [c for c in result.credentials if c['data'].get('risk_level') == 'Critical']
            high_creds = [c for c in result.credentials if c['data'].get('risk_level') == 'High']
            
            if critical_creds:
                click.echo(f"🚨 Found {len(critical_creds)} CRITICAL credential leaks")
            if high_creds:
                click.echo(f"🚨 Found {len(high_creds)} HIGH risk credential leaks")
        
        # Exit with appropriate code based on findings
        if critical_vulns or critical_creds:
            sys.exit(2)  # Critical findings
        elif high_vulns or high_creds:
            sys.exit(1)  # High severity findings
        else:
            sys.exit(0)  # Success
    
    except ValidationError as e:
        click.echo(f"ERROR: Invalid input - {e}", err=True)
        sys.exit(1)
    except ConfigurationError as e:
        click.echo(f"ERROR: Configuration error - {e}", err=True)
        sys.exit(1)
    except OSINTError as e:
        click.echo(f"ERROR: {e}", err=True)
        sys.exit(1)
    except KeyboardInterrupt:
        click.echo("\nOperation cancelled by user", err=True)
        sys.exit(1)
    except Exception as e:
        if verbose:
            import traceback
            click.echo(f"ERROR: Unexpected error - {e}", err=True)
            click.echo(traceback.format_exc(), err=True)
        else:
            click.echo(f"ERROR: Unexpected error - {e}", err=True)
            click.echo("Use --verbose for more details", err=True)
        sys.exit(1)


@click.group()
def cli():
    """Passive OSINT Reconnaissance Platform CLI."""
    pass


@cli.command()
@click.option('--config', '-c', type=click.Path(), help='Configuration file path')
def init(config):
    """Initialize configuration file."""
    config_path = config or 'config.yaml'
    
    if os.path.exists(config_path):
        if not click.confirm(f"Configuration file {config_path} already exists. Overwrite?"):
            return
    
    # Create default configuration
    from .core.config import Config
    default_config = Config()
    default_config.config_file = config_path
    default_config.save()
    
    click.echo(f"Configuration file created: {config_path}")
    click.echo("Edit the file to add your API keys for full functionality.")


@cli.command()
@click.option('--config', '-c', type=click.Path(exists=True), help='Configuration file path')
def test(config):
    """Test configuration and API connections."""
    try:
        config_obj = Config(config) if config else Config()
        
        click.echo("Testing configuration...")
        
        # Test API keys
        api_services = ['virustotal', 'shodan', 'censys', 'securitytrails', 'github']
        
        for service in api_services:
            api_key = config_obj.get_api_key(service)
            if api_key:
                click.echo(f"✓ {service}: API key configured")
            else:
                click.echo(f"⚠ {service}: No API key configured")
        
        # Test modules
        modules = ['subdomains', 'ports', 'technologies', 'vulnerabilities', 'credentials']
        
        click.echo("\nTesting modules:")
        for module in modules:
            if config_obj.is_module_enabled(module):
                click.echo(f"✓ {module}: Enabled")
            else:
                click.echo(f"⚠ {module}: Disabled")
        
        click.echo("\nConfiguration test completed.")
        
    except Exception as e:
        click.echo(f"ERROR: Configuration test failed - {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('domain')
@click.option('--config', '-c', type=click.Path(exists=True), help='Configuration file path')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def validate(domain, config, verbose):
    """Validate domain input and show basic information."""
    try:
        config_obj = Config(config) if config else Config()
        engine = ReconEngine(config_obj)
        
        # Validate domain
        validated_domain = engine.validate_domain(domain)
        
        click.echo(f"Domain: {validated_domain}")
        click.echo(f"Valid: ✓")
        
        if verbose:
            click.echo(f"Original input: {domain}")
            click.echo(f"Normalized: {validated_domain}")
        
    except ValidationError as e:
        click.echo(f"Domain validation failed: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"ERROR: {e}", err=True)
        sys.exit(1)


@cli.command()
def version():
    """Show version information."""
    from . import __version__, __author__
    
    click.echo(f"Passive OSINT Reconnaissance Platform v{__version__}")
    click.echo(f"Author: {__author__}")
    click.echo("License: MIT")


# Main entry point
def entry_point():
    """Main CLI entry point."""
    # Add main command to CLI group
    cli.add_command(main)
    
    # Run CLI
    cli()


if __name__ == '__main__':
    entry_point()

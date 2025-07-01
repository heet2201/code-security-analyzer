#!/usr/bin/env python3
"""
Command Line Interface for AI Security Analyzer
"""

import os
import sys
import asyncio
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

import click
import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import print as rprint

# Add the parent directory to sys.path to enable imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from security_analyzer.core.architecture import AgenticSecurityArchitecture
from security_analyzer.models.config import AnalyzerConfig, LLMConfig, ScanMode
from security_analyzer.models.findings import SecurityReport

app = typer.Typer(
    name="ai-security-analyzer",
    help="🛡️ AI-Powered Code Security Analyzer with Multi-LLM Support",
    rich_markup_mode="rich"
)

console = Console()


def setup_logging(verbose: bool = False):
    """Setup logging configuration"""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('security_analyzer.log'),
            logging.StreamHandler()
        ]
    )


@app.command("scan")
def scan_repository(
    target: str = typer.Argument(..., help="Repository path or GitHub URL to analyze"),
    api_key: Optional[str] = typer.Option(None, "--api-key", "-k", help="OpenRouter API key"),
    output: str = typer.Option("security_report.json", "--output", "-o", help="Output file path"),
    mode: ScanMode = typer.Option(ScanMode.COMPREHENSIVE, "--mode", "-m", help="Scan mode"),
    max_files: int = typer.Option(100, "--max-files", help="Maximum number of files to analyze"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose logging"),
    quick: bool = typer.Option(False, "--quick", "-q", help="Quick scan mode"),
    no_llm: bool = typer.Option(False, "--no-llm", help="Disable LLM analysis, use only traditional tools"),
    config_file: Optional[str] = typer.Option(None, "--config", "-c", help="Configuration file path"),
):
    """
    🔍 Scan a repository or codebase for security vulnerabilities
    
    This command analyzes your code using both AI-powered agents and traditional SAST tools
    to identify security vulnerabilities, insecure patterns, and provide actionable recommendations.
    """
    
    setup_logging(verbose)
    
    # Print banner
    console.print(Panel.fit(
        "[bold blue]🛡️  AI-Powered Security Analyzer[/bold blue]\n"
        "[dim]Advanced multi-agent security analysis with LLM integration[/dim]",
        border_style="blue"
    ))
    
    try:
        # Get API key
        if not api_key:
            api_key = os.getenv("OPENROUTER_API_KEY")
            if not api_key:
                console.print("[red]❌ OpenRouter API key required. Set OPENROUTER_API_KEY environment variable or use --api-key[/red]")
                raise typer.Exit(1)
        
        # Load or create configuration
        if config_file and os.path.exists(config_file):
            config = AnalyzerConfig.from_file(config_file)
            config.llm.api_key = api_key  # Override with provided key
        else:
            config = AnalyzerConfig.create_default(api_key)
        
        # Apply CLI options
        if quick:
            config.scan.scan_mode = ScanMode.QUICK
        else:
            config.scan.scan_mode = mode
            
        if no_llm:
            config.scan.enabled_agents = []
        
        # Validate target
        if not os.path.exists(target) and 'github.com' not in target:
            console.print(f"[red]❌ Target path does not exist: {target}[/red]")
            raise typer.Exit(1)
        
        # Create analyzer
        analyzer = AgenticSecurityArchitecture(config)
        
        # Show scan configuration
        _display_scan_info(target, config, analyzer)
        
        # Run analysis with progress tracking
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            
            # Create progress tasks
            main_task = progress.add_task("🔍 Analyzing repository...", total=100)
            
            # Run the analysis
            console.print("\n[yellow]🚀 Starting security analysis...[/yellow]")
            
            try:
                # Use async analysis for better performance
                report = asyncio.run(analyzer.analyze_repository_async(target))
                
                progress.update(main_task, completed=100)
                
                # Display results
                _display_results(report, console)
                
                # Save report
                analyzer.save_report(report, output)
                console.print(f"\n[green]📁 Detailed report saved to: {output}[/green]")
                
                # Display final summary
                _display_final_summary(report, analyzer.get_analysis_stats())
                
            except Exception as e:
                console.print(f"\n[red]❌ Analysis failed: {str(e)}[/red]")
                if verbose:
                    console.print_exception()
                raise typer.Exit(1)
                
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️ Analysis interrupted by user[/yellow]")
        raise typer.Exit(1)


@app.command("config")
def create_config(
    output: str = typer.Option("analyzer_config.yaml", "--output", "-o", help="Output configuration file"),
    api_key: Optional[str] = typer.Option(None, "--api-key", "-k", help="OpenRouter API key"),
):
    """
    ⚙️ Create a configuration file template
    """
    
    console.print("[blue]📝 Creating configuration file...[/blue]")
    
    if not api_key:
        api_key = console.input("Enter your OpenRouter API key: ")
    
    config = AnalyzerConfig.create_default(api_key)
    config.save_to_file(output)
    
    console.print(f"[green]✅ Configuration saved to: {output}[/green]")
    console.print("\n[dim]Edit the configuration file to customize scan settings.[/dim]")


@app.command("test")
def test_setup(
    api_key: Optional[str] = typer.Option(None, "--api-key", "-k", help="OpenRouter API key"),
):
    """
    🧪 Test the analyzer setup and API connectivity
    """
    
    console.print("[blue]🧪 Testing analyzer setup...[/blue]")
    
    # Check API key
    if not api_key:
        api_key = os.getenv("OPENROUTER_API_KEY")
        if not api_key:
            console.print("[red]❌ No API key provided[/red]")
            raise typer.Exit(1)
    
    console.print("[green]✅ API key found[/green]")
    
    # Test configuration
    try:
        config = AnalyzerConfig.create_default(api_key)
        console.print("[green]✅ Configuration created successfully[/green]")
    except Exception as e:
        console.print(f"[red]❌ Configuration error: {e}[/red]")
        raise typer.Exit(1)
    
    # Test analyzer initialization
    try:
        analyzer = AgenticSecurityArchitecture(config)
        console.print(f"[green]✅ Analyzer initialized with {len(analyzer.agents)} agents[/green]")
    except Exception as e:
        console.print(f"[red]❌ Analyzer initialization failed: {e}[/red]")
        raise typer.Exit(1)
    
    console.print("\n[green]🎉 All tests passed! The analyzer is ready to use.[/green]")


def _display_scan_info(target: str, config: AnalyzerConfig, analyzer):
    """Display scan configuration information"""
    
    table = Table(title="🔧 Scan Configuration", border_style="cyan")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="white")
    
    table.add_row("Target", target)
    table.add_row("Scan Mode", config.scan.scan_mode.value)
    table.add_row("LLM Agents", str(len(analyzer.agents)))
    table.add_row("Traditional SAST", "✅ Enabled" if config.scan.enable_traditional_sast else "❌ Disabled")
    table.add_row("Max Concurrent Files", str(config.scan.max_concurrent_files))
    table.add_row("Max File Size", f"{config.scan.max_file_size // 1024} KB")
    
    console.print("\n")
    console.print(table)


def _display_results(report: SecurityReport, console: Console):
    """Display analysis results in a formatted table"""
    
    console.print("\n")
    console.print(Panel.fit(
        "[bold green]🔍 Analysis Results[/bold green]",
        border_style="green"
    ))
    
    # Summary table
    summary_table = Table(title="📊 Security Summary", border_style="yellow")
    summary_table.add_column("Metric", style="yellow")
    summary_table.add_column("Count", style="white")
    
    summary_table.add_row("Files Scanned", str(report.total_files_scanned))
    summary_table.add_row("Total Findings", str(report.summary.total_findings))
    summary_table.add_row("🔴 Critical", str(report.summary.critical))
    summary_table.add_row("🟠 High", str(report.summary.high))
    summary_table.add_row("🟡 Medium", str(report.summary.medium))
    summary_table.add_row("🟢 Low", str(report.summary.low))
    summary_table.add_row("ℹ️ Info", str(report.summary.info))
    
    console.print(summary_table)
    
    # Top findings
    if report.findings:
        critical_high = report.get_critical_and_high_findings()[:10]
        
        if critical_high:
            console.print("\n")
            findings_table = Table(title="🚨 Top Critical & High Severity Findings", border_style="red")
            findings_table.add_column("Severity", width=10)
            findings_table.add_column("Type", width=15)
            findings_table.add_column("File", width=30)
            findings_table.add_column("Description", width=50)
            
            for finding in critical_high:
                severity_emoji = "🔴" if finding.severity == "critical" else "🟠"
                findings_table.add_row(
                    f"{severity_emoji} {finding.severity.upper()}",
                    finding.vulnerability_type,
                    f"{finding.file_path}:{finding.line_number}",
                    finding.title[:47] + "..." if len(finding.title) > 50 else finding.title
                )
            
            console.print(findings_table)


def _display_final_summary(report: SecurityReport, stats: dict):
    """Display final analysis summary"""
    
    console.print("\n")
    
    # Security score calculation
    total_findings = report.summary.total_findings
    critical_weight = report.summary.critical * 10
    high_weight = report.summary.high * 5
    medium_weight = report.summary.medium * 2
    low_weight = report.summary.low * 1
    
    total_risk_score = critical_weight + high_weight + medium_weight + low_weight
    
    if total_risk_score == 0:
        security_score = 100
        score_color = "green"
        score_emoji = "🛡️"
    elif total_risk_score < 10:
        security_score = 90
        score_color = "green"
        score_emoji = "✅"
    elif total_risk_score < 50:
        security_score = 70
        score_color = "yellow"
        score_emoji = "⚠️"
    else:
        security_score = 30
        score_color = "red"
        score_emoji = "🚨"
    
    console.print(Panel(
        f"[bold {score_color}]{score_emoji} Security Score: {security_score}/100[/bold {score_color}]\n\n"
        f"Analysis completed in {stats.get('analysis_duration', 0):.1f} seconds\n"
        f"Files analyzed: {stats.get('files_analyzed', 0)}\n"
        f"Agents used: {stats.get('agents_used', 0)}\n"
        f"Total findings: {total_findings}",
        title="🏁 Final Results",
        border_style=score_color
    ))
    
    # Recommendations
    if report.recommendations:
        console.print("\n[bold blue]💡 Recommendations:[/bold blue]")
        for i, rec in enumerate(report.recommendations[:5], 1):
            console.print(f"  {i}. {rec}")


def main():
    """Main entry point"""
    app()


def scan_command():
    """Entry point for ai-security-scan command"""
    # This is a simplified version that defaults to scan
    if len(sys.argv) == 1:
        # If no arguments provided, show help
        app(["--help"])
    else:
        # Add 'scan' as the first argument if it's not a command
        if sys.argv[1] not in ['scan', 'config', 'test', '--help', '-h']:
            sys.argv.insert(1, 'scan')
        app()


if __name__ == "__main__":
    main() 
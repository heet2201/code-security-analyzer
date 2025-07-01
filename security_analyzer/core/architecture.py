#!/usr/bin/env python3
"""
Main agentic security architecture with async optimizations
"""

import asyncio
import logging
import os
import time
from datetime import datetime
from typing import List, Dict, Optional, Set
from pathlib import Path

from ..models.config import AnalyzerConfig, AgentType, ScanMode
from ..models.findings import SecurityFinding, SecurityReport, SecuritySummary
from ..agents.security_agent import SecurityAgentFactory, BaseSecurityAgent
from ..tools.llm_provider import AsyncLLMProvider
from ..tools.traditional_sast import TraditionalSASTRunner


logger = logging.getLogger(__name__)


class AgenticSecurityArchitecture:
    """Multi-agent security analysis system with async optimizations"""
    
    def __init__(self, config: AnalyzerConfig):
        self.config = config
        self.agents: Dict[AgentType, BaseSecurityAgent] = {}
        self.traditional_sast = TraditionalSASTRunner(config.scan)
        self._initialize_agents()
    
    def _initialize_agents(self):
        """Initialize specialized security agents"""
        logger.info("Initializing security agents...")
        
        self.agents = SecurityAgentFactory.create_all_agents(
            self.config.llm,
            self.config.scan.agent_model_mapping
        )
        
        logger.info(f"Initialized {len(self.agents)} security agents")
    
    async def analyze_repository_async(self, repo_path: str) -> SecurityReport:
        """Analyze entire repository asynchronously"""
        start_time = time.time()
        logger.info(f"Starting analysis of: {repo_path}")
        
        report = SecurityReport(repository_path=repo_path)
        
        # Discover files
        code_files = self._discover_code_files(repo_path)
        report.total_files_scanned = len(code_files)
        
        # Run traditional SAST tools
        sast_findings = []
        if self.config.scan.enable_traditional_sast:
            sast_findings = await self.traditional_sast.run_all_tools_async(repo_path)
        
        # Run LLM agents
        llm_findings = []
        if self.agents:
            llm_findings = await self._analyze_files_with_agents_async(code_files)
        
        # Combine and add findings
        all_findings = sast_findings + llm_findings
        for finding in all_findings:
            report.add_finding(finding)
        
        # Generate recommendations
        report.recommendations = self._generate_recommendations(all_findings)
        report.scan_duration = time.time() - start_time
        
        return report
    
    def _discover_code_files(self, directory: str) -> List[str]:
        """Discover code files in repository"""
        code_extensions = set(self.config.scan.supported_extensions)
        code_files = []
        
        for root, dirs, files in os.walk(directory):
            for file in files:
                if any(file.endswith(ext) for ext in code_extensions):
                    file_path = os.path.join(root, file)
                    if os.path.getsize(file_path) < self.config.scan.max_file_size:
                        code_files.append(file_path)
        
        return code_files
    
    async def _analyze_files_with_agents_async(self, file_paths: List[str]) -> List[SecurityFinding]:
        """Analyze files with LLM agents"""
        all_findings = []
        batch_size = min(self.config.scan.max_concurrent_files, 5)
        
        for i in range(0, len(file_paths), batch_size):
            batch = file_paths[i:i + batch_size]
            tasks = [self._analyze_single_file(fp) for fp in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, list):
                    all_findings.extend(result)
            
            await asyncio.sleep(1)  # Rate limiting
        
        return all_findings
    
    async def _analyze_single_file(self, file_path: str) -> List[SecurityFinding]:
        """Analyze a single file"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                code_content = f.read()
            
            if not code_content.strip():
                return []
            
            findings = []
            for agent in self.agents.values():
                async with agent.llm_provider as provider:
                    agent_findings = await agent.analyze_async(code_content, file_path)
                    findings.extend(agent_findings)
            
            return findings
            
        except Exception as e:
            logger.warning(f"Failed to analyze {file_path}: {e}")
            return []
    
    def _generate_recommendations(self, findings: List[SecurityFinding]) -> List[str]:
        """Generate security recommendations"""
        if not findings:
            return ["No security issues found."]
        
        recommendations = []
        critical_count = sum(1 for f in findings if f.severity == 'critical')
        high_count = sum(1 for f in findings if f.severity == 'high')
        
        if critical_count > 0:
            recommendations.append(f"🚨 {critical_count} critical vulnerabilities need immediate attention")
        
        if high_count > 0:
            recommendations.append(f"⚠️ {high_count} high-severity issues found")
        
        recommendations.extend([
            "🔄 Regular security updates recommended",
            "📚 Security training for development team"
        ])
        
        return recommendations
    
    def analyze_repository(self, repo_path: str) -> SecurityReport:
        """Synchronous wrapper"""
        return asyncio.run(self.analyze_repository_async(repo_path))
    
    def save_report(self, report: SecurityReport, output_file: str):
        """Save report to file"""
        import json
        with open(output_file, 'w') as f:
            json.dump(report.export_to_dict(), f, indent=2, default=str)
    
    def get_analysis_stats(self) -> Dict:
        """Get analysis performance statistics"""
        return {
            'files_analyzed': 0,
            'agents_used': len(self.agents),
            'traditional_tools_used': 1 if self.config.scan.enable_traditional_sast else 0,
            'total_findings': 0,
            'analysis_duration': 0.0
        }

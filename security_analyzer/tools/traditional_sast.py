#!/usr/bin/env python3
"""
Integration with traditional SAST tools (Bandit, Semgrep, Safety, etc.)
"""

import asyncio
import json
import logging
import subprocess
import tempfile
import os
from typing import List, Dict, Any, Optional
from pathlib import Path
import concurrent.futures

from ..models.findings import SecurityFinding, SeverityLevel, VulnerabilityType
from ..models.config import ScanConfig


logger = logging.getLogger(__name__)


class TraditionalSASTRunner:
    """Async runner for traditional SAST tools"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=4)
    
    async def run_all_tools_async(self, target_path: str) -> List[SecurityFinding]:
        """Run all enabled SAST tools asynchronously"""
        findings = []
        tasks = []
        
        if self.config.enable_bandit and self._is_python_project(target_path):
            tasks.append(self._run_bandit_async(target_path))
        
        if self.config.enable_semgrep:
            tasks.append(self._run_semgrep_async(target_path))
        
        if self.config.enable_safety and self._is_python_project(target_path):
            tasks.append(self._run_safety_async(target_path))
        
        # Run all tools concurrently
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, list):
                    findings.extend(result)
                elif isinstance(result, Exception):
                    logger.warning(f"SAST tool failed: {result}")
        
        return findings
    
    async def _run_bandit_async(self, target_path: str) -> List[SecurityFinding]:
        """Run Bandit asynchronously"""
        loop = asyncio.get_event_loop()
        
        def run_bandit():
            return TraditionalSASTTools.run_bandit(target_path)
        
        try:
            bandit_results = await loop.run_in_executor(self.executor, run_bandit)
            return self._convert_bandit_results(bandit_results)
        except Exception as e:
            logger.error(f"Bandit execution failed: {e}")
            return []
    
    async def _run_semgrep_async(self, target_path: str) -> List[SecurityFinding]:
        """Run Semgrep asynchronously"""
        loop = asyncio.get_event_loop()
        
        def run_semgrep():
            return TraditionalSASTTools.run_semgrep(target_path)
        
        try:
            semgrep_results = await loop.run_in_executor(self.executor, run_semgrep)
            return self._convert_semgrep_results(semgrep_results)
        except Exception as e:
            logger.error(f"Semgrep execution failed: {e}")
            return []
    
    async def _run_safety_async(self, target_path: str) -> List[SecurityFinding]:
        """Run Safety asynchronously"""
        loop = asyncio.get_event_loop()
        
        def run_safety():
            return TraditionalSASTTools.run_safety(target_path)
        
        try:
            safety_results = await loop.run_in_executor(self.executor, run_safety)
            return self._convert_safety_results(safety_results)
        except Exception as e:
            logger.error(f"Safety execution failed: {e}")
            return []
    
    def _is_python_project(self, path: str) -> bool:
        """Check if the target is a Python project"""
        if os.path.isfile(path):
            return path.endswith('.py')
        
        # Check for Python files or common Python project markers
        python_indicators = [
            "requirements.txt", "setup.py", "pyproject.toml", 
            "Pipfile", "poetry.lock", "conda.yml"
        ]
        
        for indicator in python_indicators:
            if os.path.exists(os.path.join(path, indicator)):
                return True
        
        # Check for .py files
        for root, dirs, files in os.walk(path):
            if any(f.endswith('.py') for f in files):
                return True
        
        return False
    
    def _convert_bandit_results(self, bandit_results: List[Dict]) -> List[SecurityFinding]:
        """Convert Bandit results to SecurityFinding objects"""
        findings = []
        
        for result in bandit_results:
            try:
                # Map Bandit severity to our severity levels
                severity_map = {
                    "HIGH": SeverityLevel.HIGH,
                    "MEDIUM": SeverityLevel.MEDIUM,
                    "LOW": SeverityLevel.LOW
                }
                
                severity = severity_map.get(result.get('issue_severity', 'MEDIUM'), SeverityLevel.MEDIUM)
                
                finding = SecurityFinding(
                    file_path=result.get('filename', ''),
                    line_number=result.get('line_number', 0),
                    vulnerability_type=self._map_bandit_test_to_vuln_type(result.get('test_name', '')),
                    severity=severity,
                    title=result.get('test_name', 'Bandit Security Issue'),
                    description=result.get('issue_text', ''),
                    code_snippet=result.get('code', ''),
                    recommendation="Review and fix the identified security issue",
                    confidence=result.get('issue_confidence', ''),
                    tool_source="Bandit"
                )
                findings.append(finding)
                
            except Exception as e:
                logger.warning(f"Failed to convert Bandit result: {e}")
                continue
        
        return findings
    
    def _convert_semgrep_results(self, semgrep_results: List[Dict]) -> List[SecurityFinding]:
        """Convert Semgrep results to SecurityFinding objects"""
        findings = []
        
        for result in semgrep_results:
            try:
                extra = result.get('extra', {})
                severity_str = extra.get('severity', 'medium').lower()
                
                # Map Semgrep severity to our levels
                severity_map = {
                    'error': SeverityLevel.HIGH,
                    'warning': SeverityLevel.MEDIUM,
                    'info': SeverityLevel.LOW
                }
                severity = severity_map.get(severity_str, SeverityLevel.MEDIUM)
                
                # Extract CWE information
                metadata = extra.get('metadata', {})
                cwe_ids = metadata.get('cwe', [])
                if isinstance(cwe_ids, str):
                    cwe_ids = [cwe_ids]
                
                finding = SecurityFinding(
                    file_path=result.get('path', ''),
                    line_number=result.get('start', {}).get('line', 0),
                    vulnerability_type=self._map_semgrep_rule_to_vuln_type(result.get('check_id', '')),
                    severity=severity,
                    title=result.get('check_id', 'Semgrep Security Issue'),
                    description=extra.get('message', ''),
                    code_snippet=extra.get('lines', ''),
                    recommendation="Review and address the security issue identified by Semgrep",
                    confidence=extra.get('confidence', 'medium'),
                    cwe_id=cwe_ids,
                    tool_source="Semgrep"
                )
                findings.append(finding)
                
            except Exception as e:
                logger.warning(f"Failed to convert Semgrep result: {e}")
                continue
        
        return findings
    
    def _convert_safety_results(self, safety_results: List[Dict]) -> List[SecurityFinding]:
        """Convert Safety results to SecurityFinding objects"""
        findings = []
        
        for result in safety_results:
            try:
                finding = SecurityFinding(
                    file_path=result.get('filename', 'requirements.txt'),
                    line_number=0,
                    vulnerability_type=VulnerabilityType.DEFAULT,
                    severity=SeverityLevel.HIGH,  # Safety reports are generally high severity
                    title=f"Vulnerable dependency: {result.get('package', 'Unknown')}",
                    description=result.get('advisory', ''),
                    recommendation=f"Update {result.get('package', 'package')} to version {result.get('safe_version', 'latest')} or higher",
                    confidence="high",
                    cwe_id=result.get('cve', ''),
                    tool_source="Safety"
                )
                findings.append(finding)
                
            except Exception as e:
                logger.warning(f"Failed to convert Safety result: {e}")
                continue
        
        return findings
    
    def _map_bandit_test_to_vuln_type(self, test_name: str) -> VulnerabilityType:
        """Map Bandit test names to vulnerability types"""
        test_mapping = {
            'hardcoded_password': VulnerabilityType.HARDCODED_SECRETS,
            'hardcoded_bind_all_interfaces': VulnerabilityType.INFORMATION_DISCLOSURE,
            'sql_injection': VulnerabilityType.SQL_INJECTION,
            'shell_injection': VulnerabilityType.COMMAND_INJECTION,
            'weak_cryptographic_key': VulnerabilityType.INSECURE_CRYPTO,
            'insecure_hash': VulnerabilityType.INSECURE_CRYPTO,
            'eval_used': VulnerabilityType.COMMAND_INJECTION,
            'exec_used': VulnerabilityType.COMMAND_INJECTION,
        }
        
        for key, vuln_type in test_mapping.items():
            if key in test_name.lower():
                return vuln_type
        
        return VulnerabilityType.DEFAULT
    
    def _map_semgrep_rule_to_vuln_type(self, rule_id: str) -> VulnerabilityType:
        """Map Semgrep rule IDs to vulnerability types"""
        rule_id_lower = rule_id.lower()
        
        if 'sql' in rule_id_lower and 'injection' in rule_id_lower:
            return VulnerabilityType.SQL_INJECTION
        elif 'xss' in rule_id_lower or 'cross-site-scripting' in rule_id_lower:
            return VulnerabilityType.XSS
        elif 'command' in rule_id_lower and 'injection' in rule_id_lower:
            return VulnerabilityType.COMMAND_INJECTION
        elif 'path' in rule_id_lower and 'traversal' in rule_id_lower:
            return VulnerabilityType.PATH_TRAVERSAL
        elif 'hardcoded' in rule_id_lower or 'secret' in rule_id_lower:
            return VulnerabilityType.HARDCODED_SECRETS
        elif 'crypto' in rule_id_lower or 'hash' in rule_id_lower:
            return VulnerabilityType.INSECURE_CRYPTO
        elif 'auth' in rule_id_lower:
            return VulnerabilityType.AUTH_BYPASS
        
        return VulnerabilityType.DEFAULT


class TraditionalSASTTools:
    """Synchronous SAST tools integration (legacy compatibility)"""
    
    @staticmethod
    def run_bandit(target_path: str) -> List[Dict]:
        """Run Bandit security scanner"""
        try:
            # Try programmatic approach first
            try:
                from bandit import config as bandit_config
                from bandit import manager as bandit_manager
                
                # Configure Bandit
                conf = bandit_config.BanditConfig()
                b_mgr = bandit_manager.BanditManager(conf, 'file')
                
                if os.path.isfile(target_path):
                    b_mgr.discover_files([target_path])
                else:
                    b_mgr.discover_files([target_path], recursive=True)
                
                b_mgr.run_tests()
                
                results = []
                for result in b_mgr.get_issue_list():
                    results.append({
                        'filename': result.fname,
                        'line_number': result.lineno,
                        'test_name': result.test,
                        'issue_severity': result.severity,
                        'issue_confidence': result.confidence,
                        'issue_text': result.text,
                        'code': result.get_code()
                    })
                return results
                
            except ImportError:
                # Fallback to command line if bandit not available programmatically
                return TraditionalSASTTools._run_bandit_cli(target_path)
                
        except Exception as e:
            logger.error(f"Bandit analysis failed: {e}")
            return []
    
    @staticmethod
    def _run_bandit_cli(target_path: str) -> List[Dict]:
        """Run Bandit via command line"""
        try:
            cmd = ["bandit", "-r", "-f", "json", target_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.stdout:
                data = json.loads(result.stdout)
                return data.get('results', [])
            
            return []
            
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError) as e:
            logger.warning(f"Bandit CLI execution failed: {e}")
            return []
    
    @staticmethod
    def run_semgrep(target_path: str) -> List[Dict]:
        """Run Semgrep security scanner"""
        try:
            cmd = [
                "semgrep",
                "--config=auto",
                "--json",
                "--quiet",
                "--timeout=300",
                target_path
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            if result.returncode == 0 and result.stdout:
                data = json.loads(result.stdout)
                return data.get('results', [])
            else:
                logger.warning(f"Semgrep failed with return code {result.returncode}: {result.stderr}")
                return []
                
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError) as e:
            logger.warning(f"Semgrep analysis failed: {e}")
            return []
    
    @staticmethod
    def run_safety(target_path: str) -> List[Dict]:
        """Run Safety scanner for Python dependencies"""
        try:
            # Look for requirements files
            requirements_files = []
            
            if os.path.isfile(target_path):
                if target_path.endswith('requirements.txt'):
                    requirements_files.append(target_path)
            else:
                # Common requirements file names
                req_names = ['requirements.txt', 'requirements-dev.txt', 'dev-requirements.txt']
                for req_name in req_names:
                    req_path = os.path.join(target_path, req_name)
                    if os.path.exists(req_path):
                        requirements_files.append(req_path)
            
            if not requirements_files:
                logger.info("No requirements.txt files found for Safety analysis")
                return []
            
            all_results = []
            for req_file in requirements_files:
                cmd = ["safety", "check", "-r", req_file, "--json"]
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                
                if result.returncode == 0:
                    # No vulnerabilities found
                    continue
                elif result.returncode == 255:
                    # Vulnerabilities found
                    if result.stdout:
                        try:
                            data = json.loads(result.stdout)
                            for item in data:
                                item['filename'] = req_file
                            all_results.extend(data)
                        except json.JSONDecodeError:
                            logger.warning(f"Failed to parse Safety JSON output for {req_file}")
                else:
                    logger.warning(f"Safety check failed for {req_file}: {result.stderr}")
            
            return all_results
            
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.warning(f"Safety analysis failed: {e}")
            return []
    
    @staticmethod
    def run_pip_audit(target_path: str) -> List[Dict]:
        """Run pip-audit for Python dependencies"""
        try:
            if os.path.isfile(target_path):
                if not target_path.endswith('requirements.txt'):
                    return []
                cmd = ["pip-audit", "-r", target_path, "--format=json"]
            else:
                # Check if there's a requirements.txt in the directory
                req_path = os.path.join(target_path, "requirements.txt")
                if not os.path.exists(req_path):
                    return []
                cmd = ["pip-audit", "-r", req_path, "--format=json"]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0 and result.stdout:
                data = json.loads(result.stdout)
                return data.get('vulnerabilities', [])
            else:
                logger.warning(f"pip-audit failed: {result.stderr}")
                return []
                
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError) as e:
            logger.warning(f"pip-audit analysis failed: {e}")
            return [] 
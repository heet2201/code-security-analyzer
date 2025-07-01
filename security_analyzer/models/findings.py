#!/usr/bin/env python3
"""
Data models for security findings and reports
"""

from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any, Union
from pydantic import BaseModel, Field, validator


class SeverityLevel(str, Enum):
    """Security vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnerabilityType(str, Enum):
    """Types of security vulnerabilities"""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    HARDCODED_SECRETS = "hardcoded_secrets"
    INSECURE_CRYPTO = "insecure_crypto"
    AUTH_BYPASS = "auth_bypass"
    INPUT_VALIDATION = "input_validation"
    BUFFER_OVERFLOW = "buffer_overflow"
    RACE_CONDITION = "race_condition"
    INFORMATION_DISCLOSURE = "information_disclosure"
    DENIAL_OF_SERVICE = "denial_of_service"
    DEFAULT = "default"


class ConfidenceLevel(str, Enum):
    """Confidence levels for findings"""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class SecurityFinding(BaseModel):
    """Represents a single security finding"""
    
    file_path: str = Field(..., description="Path to the vulnerable file")
    line_number: int = Field(default=0, description="Line number where the vulnerability was found")
    vulnerability_type: VulnerabilityType = Field(default=VulnerabilityType.DEFAULT)
    severity: SeverityLevel = Field(..., description="Severity level of the vulnerability")
    title: str = Field(..., description="Brief title of the vulnerability")
    description: str = Field(..., description="Detailed description of the vulnerability")
    code_snippet: str = Field(default="", description="Relevant code snippet")
    recommendation: str = Field(..., description="Recommendation for fixing the vulnerability")
    confidence: Union[ConfidenceLevel, str] = Field(default=ConfidenceLevel.MEDIUM)
    cwe_id: Union[List[str], str] = Field(default_factory=list, description="CWE identifier(s)")
    tool_source: str = Field(default="Unknown", description="Tool that detected this finding")
    timestamp: datetime = Field(default_factory=datetime.now)
    
    @validator('line_number')
    def validate_line_number(cls, v):
        return max(0, v)
    
    @validator('cwe_id')
    def normalize_cwe_id(cls, v):
        if isinstance(v, str):
            return [v] if v else []
        return v or []
    
    def __hash__(self):
        """Make findings hashable for deduplication"""
        return hash((self.file_path, self.line_number, self.vulnerability_type, self.title))
    
    class Config:
        use_enum_values = True


class SecuritySummary(BaseModel):
    """Summary statistics for security findings"""
    
    total_findings: int = Field(default=0)
    critical: int = Field(default=0)
    high: int = Field(default=0) 
    medium: int = Field(default=0)
    low: int = Field(default=0)
    info: int = Field(default=0)
    
    files_with_findings: int = Field(default=0)
    vulnerability_types: Dict[str, int] = Field(default_factory=dict)
    tools_used: List[str] = Field(default_factory=list)


class SecurityReport(BaseModel):
    """Complete security analysis report"""
    
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())
    repository_path: str = Field(..., description="Path to the analyzed repository")
    total_files_scanned: int = Field(default=0)
    scan_duration: Optional[float] = Field(default=None, description="Scan duration in seconds")
    
    findings: List[SecurityFinding] = Field(default_factory=list)
    summary: SecuritySummary = Field(default_factory=SecuritySummary)
    recommendations: List[str] = Field(default_factory=list)
    
    # Configuration used for the scan
    scan_config: Optional[Dict[str, Any]] = Field(default_factory=dict)
    
    # Metadata
    analyzer_version: str = Field(default="1.0.0")
    
    def add_finding(self, finding: SecurityFinding):
        """Add a finding and update summary"""
        self.findings.append(finding)
        self._update_summary()
    
    def _update_summary(self):
        """Update summary statistics based on current findings"""
        self.summary.total_findings = len(self.findings)
        
        # Reset counters
        severity_counts = {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
        }
        
        vuln_types = {}
        tools = set()
        files_with_findings = set()
        
        for finding in self.findings:
            # Count by severity
            severity_counts[finding.severity] += 1
            
            # Count by vulnerability type
            vuln_type = finding.vulnerability_type
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
            
            # Track tools and files
            tools.add(finding.tool_source)
            files_with_findings.add(finding.file_path)
        
        # Update summary
        self.summary.critical = severity_counts["critical"]
        self.summary.high = severity_counts["high"]
        self.summary.medium = severity_counts["medium"]
        self.summary.low = severity_counts["low"]
        self.summary.info = severity_counts["info"]
        
        self.summary.files_with_findings = len(files_with_findings)
        self.summary.vulnerability_types = vuln_types
        self.summary.tools_used = list(tools)
    
    def get_critical_and_high_findings(self) -> List[SecurityFinding]:
        """Get only critical and high severity findings"""
        return [f for f in self.findings if f.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]]
    
    def export_to_dict(self) -> Dict[str, Any]:
        """Export report to dictionary format"""
        return self.dict()
    
    class Config:
        use_enum_values = True
        json_encoders = {
            datetime: lambda v: v.isoformat()
        } 
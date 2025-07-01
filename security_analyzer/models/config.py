#!/usr/bin/env python3
"""
Configuration models for the security analyzer
"""

from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field, validator
from enum import Enum


class LLMModelType(str, Enum):
    """Types of LLM models supported"""
    # Closed-source models
    GPT_4_TURBO = "openai/gpt-4o-mini"
    CLAUDE_3_5_SONNET = "anthropic/claude-sonnet-4"
    GEMINI_1_5_PRO = "google/gemini-2.5-flash-preview-05-20"
    
    # Open-source models
    LLAMA_3_3_70B = "meta-llama/llama-3.3-70b-instruct"
    DEEPSEEK_R1 = "deepseek/deepseek-r1-0528"
    MISTRAL_7B = "mistralai/mistral-7b-instruct"
    CODELLAMA_34B = "codellama/CodeLlama-34b-Instruct-hf"


class AgentType(str, Enum):
    """Types of security agents"""
    INJECTION = "injection"
    XSS = "xss"
    CRYPTO = "crypto"
    AUTH = "auth"
    SECRETS = "secrets"
    GENERAL = "general"


class ScanMode(str, Enum):
    """Scan modes for different use cases"""
    QUICK = "quick"          # Fast scan with basic checks
    COMPREHENSIVE = "comprehensive"  # Full analysis with all tools
    TARGETED = "targeted"    # Focus on specific vulnerability types
    CI_CD = "ci_cd"         # Optimized for CI/CD pipelines


class LLMConfig(BaseModel):
    """Configuration for LLM providers"""
    
    api_key: str = Field(..., description="API key for OpenRouter")
    base_url: str = Field(default="https://openrouter.ai/api/v1")
    timeout: int = Field(default=30, description="Request timeout in seconds")
    max_tokens: int = Field(default=2000)
    temperature: float = Field(default=0.1, ge=0.0, le=2.0)
    retry_attempts: int = Field(default=3, ge=1, le=10)
    
    # Model preferences
    default_model: LLMModelType = Field(default=LLMModelType.GPT_4_TURBO)
    fallback_models: List[LLMModelType] = Field(default_factory=lambda: [
        LLMModelType.CLAUDE_3_5_SONNET,
        LLMModelType.LLAMA_3_3_70B
    ])


class ScanConfig(BaseModel):
    """Configuration for security scans"""
    
    # Scan behavior
    scan_mode: ScanMode = Field(default=ScanMode.COMPREHENSIVE)
    max_file_size: int = Field(default=1024*1024, description="Max file size in bytes")
    max_concurrent_files: int = Field(default=5, ge=1, le=20)
    exclude_patterns: List[str] = Field(default_factory=lambda: [
        "*.min.js", "*.map", "node_modules/*", ".git/*", "__pycache__/*",
        "*.pyc", "dist/*", "build/*", "venv/*", "env/*"
    ])
    
    # File types to analyze
    supported_extensions: List[str] = Field(default_factory=lambda: [
        ".py", ".js", ".ts", ".java", ".c", ".cpp", ".cs", ".php",
        ".rb", ".go", ".rs", ".scala", ".kt", ".swift", ".m", ".h",
        ".jsx", ".tsx", ".vue", ".sql", ".yaml", ".yml", ".json",
        ".html", ".txt", ".md", "Dockerfile"
    ])
    
    # Tool configuration
    enable_traditional_sast: bool = Field(default=True)
    enable_bandit: bool = Field(default=True)
    enable_semgrep: bool = Field(default=True)
    enable_safety: bool = Field(default=True)
    
    # Agent configuration
    enabled_agents: List[AgentType] = Field(default_factory=lambda: list(AgentType))
    agent_model_mapping: Dict[AgentType, LLMModelType] = Field(default_factory=dict)


class ReportConfig(BaseModel):
    """Configuration for report generation"""
    
    output_format: str = Field(default="json", pattern="^(json|html|pdf|sarif)$")
    include_code_snippets: bool = Field(default=True)
    max_snippet_lines: int = Field(default=10, ge=1, le=50)
    group_by_severity: bool = Field(default=True)
    include_recommendations: bool = Field(default=True)
    
    # Output paths
    output_directory: str = Field(default="./security_reports")
    filename_template: str = Field(default="security_report_{timestamp}")


class AnalyzerConfig(BaseModel):
    """Main configuration for the security analyzer"""
    
    # Core configuration
    llm: LLMConfig
    scan: ScanConfig = Field(default_factory=ScanConfig)
    report: ReportConfig = Field(default_factory=ReportConfig)
    
    # Logging configuration
    log_level: str = Field(default="INFO", pattern="^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$")
    enable_structured_logging: bool = Field(default=True)
    
    # Performance settings
    enable_caching: bool = Field(default=True)
    cache_ttl: int = Field(default=3600, description="Cache TTL in seconds")
    
    @validator('scan')
    def configure_agent_models(cls, scan_config, values):
        """Auto-configure agent models if not specified"""
        if not scan_config.agent_model_mapping and 'llm' in values:
            # Distribute agents across different models for better performance
            models = [
                LLMModelType.GPT_4_TURBO,
                LLMModelType.CLAUDE_3_5_SONNET,
                LLMModelType.LLAMA_3_3_70B,
                LLMModelType.DEEPSEEK_R1,
                LLMModelType.MISTRAL_7B
            ]
            
            agents = list(AgentType)
            mapping = {}
            
            for i, agent in enumerate(agents):
                mapping[agent] = models[i % len(models)]
            
            scan_config.agent_model_mapping = mapping
        
        return scan_config
    
    @classmethod
    def from_file(cls, config_path: str) -> "AnalyzerConfig":
        """Load configuration from YAML file"""
        import yaml
        
        with open(config_path, 'r') as f:
            config_data = yaml.safe_load(f)
        
        return cls(**config_data)
    
    @classmethod
    def create_default(cls, api_key: str) -> "AnalyzerConfig":
        """Create default configuration with provided API key"""
        return cls(
            llm=LLMConfig(api_key=api_key)
        )
    
    def save_to_file(self, config_path: str):
        """Save configuration to YAML file"""
        import yaml
        
        with open(config_path, 'w') as f:
            yaml.dump(self.dict(), f, default_flow_style=False, indent=2) 
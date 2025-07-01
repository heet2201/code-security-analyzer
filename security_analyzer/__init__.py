#!/usr/bin/env python3
"""
AI-Powered Code Security Analyzer

Advanced Security Engineer Agent for Code Vulnerability Detection
Supports both open-source and closed-source LLMs via OpenRouter API

Features:
- Multi-LLM support (GPT-4, Claude, CodeLlama, etc.)
- Agentic architecture with specialized security agents
- Integration with traditional SAST tools (Bandit, Semgrep)
- Comprehensive vulnerability detection
- Repository-wide security analysis
- Async/await optimizations for performance
"""

__version__ = "1.0.0"
__author__ = "Heet Shah"
__email__ = "heetshah221@gmail.com"

from .core.architecture import AgenticSecurityArchitecture
from .models.findings import SecurityFinding, SecurityReport
from .models.config import AnalyzerConfig
from .tools.llm_provider import LLMProvider

__all__ = [
    "AgenticSecurityArchitecture",
    "SecurityFinding",
    "SecurityReport",
    "AnalyzerConfig",
    "LLMProvider",
] 
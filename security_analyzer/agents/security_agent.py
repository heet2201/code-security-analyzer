#!/usr/bin/env python3
"""
Specialized security agents for different vulnerability types
"""

import asyncio
import logging
from typing import List, Dict, Any, Optional
from abc import ABC, abstractmethod

from ..models.config import AgentType, LLMModelType
from ..models.findings import SecurityFinding, VulnerabilityType, SeverityLevel
from ..tools.llm_provider import AsyncLLMProvider, LLMConfig


logger = logging.getLogger(__name__)


class BaseSecurityAgent(ABC):
    """Base class for all security agents"""
    
    def __init__(self, agent_type: AgentType, llm_provider: AsyncLLMProvider):
        self.agent_type = agent_type
        self.llm_provider = llm_provider
        self.specialized_prompt = self._get_specialized_prompt()
    
    @abstractmethod
    def _get_specialized_prompt(self) -> str:
        """Get the specialized prompt for this agent"""
        pass
    
    async def analyze_async(self, code: str, file_path: str) -> List[SecurityFinding]:
        """Analyze code using the specialized agent"""
        try:
            prompt = self._create_focused_prompt(code, file_path)
            response = await self.llm_provider.analyze_code_async(code, file_path)
            
            if response.error:
                logger.warning(f"{self.agent_type} agent failed: {response.error}")
                return []
            
            findings = self.llm_provider.convert_to_security_findings(response, file_path)
            
            # Filter findings to only those relevant to this agent
            relevant_findings = self._filter_relevant_findings(findings)
            
            return relevant_findings
            
        except Exception as e:
            logger.error(f"Error in {self.agent_type} agent analysis: {e}")
            return []
    
    def _create_focused_prompt(self, code: str, file_path: str) -> str:
        """Create a focused prompt for this specific agent"""
        return f"""
{self.specialized_prompt}

File: {file_path if file_path else "Unknown"}

Code:
```
{code}
```

Focus specifically on {self.agent_type.value} vulnerabilities. Provide detailed analysis in JSON format.
"""
    
    @abstractmethod
    def _filter_relevant_findings(self, findings: List[SecurityFinding]) -> List[SecurityFinding]:
        """Filter findings to only those relevant to this agent"""
        pass


class InjectionAgent(BaseSecurityAgent):
    """Agent specialized in injection vulnerabilities"""
    
    def _get_specialized_prompt(self) -> str:
        return """
You are a specialized security expert focusing on INJECTION VULNERABILITIES. Analyze code for:

1. SQL Injection vulnerabilities
2. NoSQL Injection vulnerabilities
3. Command Injection vulnerabilities
4. Code Injection vulnerabilities
5. LDAP Injection vulnerabilities
6. XPath Injection vulnerabilities
7. Template Injection vulnerabilities
8. Header Injection vulnerabilities

Look for:
- Unsanitized user input in queries/commands
- Dynamic query construction
- Use of eval() or similar functions
- Inadequate input validation
- Missing parameterized queries
- Direct string concatenation in SQL
- Shell command construction from user input
"""
    
    def _filter_relevant_findings(self, findings: List[SecurityFinding]) -> List[SecurityFinding]:
        relevant_types = {
            VulnerabilityType.SQL_INJECTION,
            VulnerabilityType.COMMAND_INJECTION,
            VulnerabilityType.INPUT_VALIDATION
        }
        return [f for f in findings if f.vulnerability_type in relevant_types]


class XSSAgent(BaseSecurityAgent):
    """Agent specialized in XSS vulnerabilities"""
    
    def _get_specialized_prompt(self) -> str:
        return """
You are a specialized security expert focusing on CROSS-SITE SCRIPTING (XSS) VULNERABILITIES. Analyze code for:

1. Reflected XSS vulnerabilities
2. Stored XSS vulnerabilities
3. DOM-based XSS vulnerabilities
4. XSS in JavaScript frameworks
5. Content Security Policy bypasses
6. HTML injection vulnerabilities

Look for:
- Unescaped user input in HTML output
- innerHTML usage with user data
- Dynamic script generation
- Unsafe use of eval() with user input
- Missing output encoding
- Inadequate input sanitization for web context
- Dangerous HTML manipulation functions
"""
    
    def _filter_relevant_findings(self, findings: List[SecurityFinding]) -> List[SecurityFinding]:
        relevant_types = {VulnerabilityType.XSS}
        return [f for f in findings if f.vulnerability_type in relevant_types]


class CryptoAgent(BaseSecurityAgent):
    """Agent specialized in cryptographic vulnerabilities"""
    
    def _get_specialized_prompt(self) -> str:
        return """
You are a specialized security expert focusing on CRYPTOGRAPHIC VULNERABILITIES. Analyze code for:

1. Weak encryption algorithms (DES, RC4, MD5, SHA1)
2. Insecure random number generation
3. Hard-coded cryptographic keys
4. Improper key management
5. Weak password hashing (MD5, SHA1 without salt)
6. Insecure TLS/SSL configurations
7. Cryptographic implementation flaws
8. Side-channel vulnerabilities

Look for:
- Use of deprecated crypto algorithms
- Predictable random numbers
- Hard-coded keys/passwords
- Weak key derivation functions
- Missing salt in password hashing
- Insecure cipher modes
- Certificate validation bypasses
"""
    
    def _filter_relevant_findings(self, findings: List[SecurityFinding]) -> List[SecurityFinding]:
        relevant_types = {
            VulnerabilityType.INSECURE_CRYPTO,
            VulnerabilityType.HARDCODED_SECRETS
        }
        return [f for f in findings if f.vulnerability_type in relevant_types]


class AuthAgent(BaseSecurityAgent):
    """Agent specialized in authentication and authorization vulnerabilities"""
    
    def _get_specialized_prompt(self) -> str:
        return """
You are a specialized security expert focusing on AUTHENTICATION & AUTHORIZATION VULNERABILITIES. Analyze code for:

1. Authentication bypass vulnerabilities
2. Authorization bypass vulnerabilities
3. Session management flaws
4. Privilege escalation vulnerabilities
5. Insecure direct object references
6. Missing access controls
7. JWT vulnerabilities
8. OAuth/OIDC implementation flaws

Look for:
- Missing authentication checks
- Inadequate authorization controls
- Session fixation vulnerabilities
- Insecure session management
- Hard-coded credentials
- Privilege escalation paths
- Missing rate limiting
- Weak password policies
"""
    
    def _filter_relevant_findings(self, findings: List[SecurityFinding]) -> List[SecurityFinding]:
        relevant_types = {
            VulnerabilityType.AUTH_BYPASS,
            VulnerabilityType.HARDCODED_SECRETS
        }
        return [f for f in findings if f.vulnerability_type in relevant_types]


class SecretsAgent(BaseSecurityAgent):
    """Agent specialized in detecting hardcoded secrets and credentials"""
    
    def _get_specialized_prompt(self) -> str:
        return """
You are a specialized security expert focusing on HARDCODED SECRETS AND CREDENTIALS. Analyze code for:

1. API keys and tokens
2. Database passwords
3. Private keys and certificates
4. AWS/Cloud credentials
5. OAuth secrets
6. Encryption keys
7. Service account credentials
8. Third-party service tokens

Look for:
- Hard-coded API keys
- Database connection strings with passwords
- Private SSH/TLS keys in code
- AWS access keys and secrets
- JWT signing keys
- OAuth client secrets
- Service account JSON files
- Any pattern that looks like secrets/credentials
"""
    
    def _filter_relevant_findings(self, findings: List[SecurityFinding]) -> List[SecurityFinding]:
        relevant_types = {VulnerabilityType.HARDCODED_SECRETS}
        return [f for f in findings if f.vulnerability_type in relevant_types]


class GeneralAgent(BaseSecurityAgent):
    """Agent for general security vulnerabilities not covered by specialists"""
    
    def _get_specialized_prompt(self) -> str:
        return """
You are a security expert conducting general security analysis. Look for:

1. Path traversal vulnerabilities
2. Buffer overflow vulnerabilities
3. Race condition vulnerabilities
4. Information disclosure vulnerabilities
5. Denial of service vulnerabilities
6. Business logic flaws
7. File upload vulnerabilities
8. Server-side request forgery (SSRF)

Look for:
- Unsafe file operations
- Memory safety issues
- Concurrency problems
- Information leakage
- Resource exhaustion possibilities
- Logic flaws in business processes
- Unsafe deserialization
- Missing security headers
"""
    
    def _filter_relevant_findings(self, findings: List[SecurityFinding]) -> List[SecurityFinding]:
        # Accept all other vulnerability types not handled by specialist agents
        specialist_types = {
            VulnerabilityType.SQL_INJECTION,
            VulnerabilityType.COMMAND_INJECTION,
            VulnerabilityType.XSS,
            VulnerabilityType.INSECURE_CRYPTO,
            VulnerabilityType.AUTH_BYPASS,
            VulnerabilityType.HARDCODED_SECRETS
        }
        return [f for f in findings if f.vulnerability_type not in specialist_types]


class SecurityAgentFactory:
    """Factory for creating security agents"""
    
    AGENT_CLASSES = {
        AgentType.INJECTION: InjectionAgent,
        AgentType.XSS: XSSAgent,
        AgentType.CRYPTO: CryptoAgent,
        AgentType.AUTH: AuthAgent,
        AgentType.SECRETS: SecretsAgent,
        AgentType.GENERAL: GeneralAgent,
    }
    
    @classmethod
    def create_agent(
        cls, 
        agent_type: AgentType, 
        llm_config: LLMConfig,
        model: Optional[LLMModelType] = None
    ) -> BaseSecurityAgent:
        """Create a security agent of the specified type"""
        
        if agent_type not in cls.AGENT_CLASSES:
            raise ValueError(f"Unknown agent type: {agent_type}")
        
        # Use specific model if provided, otherwise use default
        if model:
            config = LLMConfig(
                api_key=llm_config.api_key,
                base_url=llm_config.base_url,
                default_model=model,
                timeout=llm_config.timeout,
                max_tokens=llm_config.max_tokens,
                temperature=llm_config.temperature
            )
        else:
            config = llm_config
        
        llm_provider = AsyncLLMProvider(config)
        agent_class = cls.AGENT_CLASSES[agent_type]
        
        return agent_class(agent_type, llm_provider)
    
    @classmethod
    def create_all_agents(
        cls, 
        llm_config: LLMConfig,
        agent_model_mapping: Optional[Dict[AgentType, LLMModelType]] = None
    ) -> Dict[AgentType, BaseSecurityAgent]:
        """Create all security agents"""
        
        agents = {}
        
        for agent_type in AgentType:
            model = None
            if agent_model_mapping and agent_type in agent_model_mapping:
                model = agent_model_mapping[agent_type]
            
            agents[agent_type] = cls.create_agent(agent_type, llm_config, model)
        
        return agents


# Legacy class for backward compatibility
class SecurityAgent:
    """Legacy SecurityAgent class for backward compatibility"""
    
    def __init__(self, agent_type: str, llm_provider):
        self.agent_type = agent_type
        self.llm_provider = llm_provider
    
    def analyze(self, code: str, file_path: str) -> List[SecurityFinding]:
        """Legacy analyze method"""
        # Convert to new agent system
        try:
            agent_type_enum = AgentType(agent_type)
        except ValueError:
            agent_type_enum = AgentType.GENERAL
        
        # Create a simple config (this is not ideal but maintains compatibility)
        config = LLMConfig(api_key="dummy")  # This won't work but maintains interface
        async_provider = AsyncLLMProvider(config)
        
        agent = SecurityAgentFactory.create_agent(agent_type_enum, config)
        
        # Run async method synchronously
        return asyncio.run(agent.analyze_async(code, file_path)) 
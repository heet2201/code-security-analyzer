#!/usr/bin/env python3
"""
Enhanced async LLM provider with multi-model support and optimizations
"""

import asyncio
import json
import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
import aiohttp
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
import time

from ..models.config import LLMConfig, LLMModelType
from ..models.findings import SecurityFinding, SeverityLevel, VulnerabilityType


logger = logging.getLogger(__name__)


@dataclass
class LLMResponse:
    """Response from LLM analysis"""
    vulnerabilities: List[Dict[str, Any]]
    overall_risk: str
    summary: str
    model_used: str
    response_time: float
    error: Optional[str] = None


class RateLimiter:
    """Simple rate limiter for API calls"""
    
    def __init__(self, calls_per_minute: int = 60):
        self.calls_per_minute = calls_per_minute
        self.calls = []
    
    async def acquire(self):
        """Acquire permission to make a call"""
        now = time.time()
        
        # Remove calls older than 1 minute
        self.calls = [call_time for call_time in self.calls if now - call_time < 60]
        
        # If we're at the limit, wait
        if len(self.calls) >= self.calls_per_minute:
            sleep_time = 60 - (now - self.calls[0])
            if sleep_time > 0:
                await asyncio.sleep(sleep_time)
                return await self.acquire()
        
        self.calls.append(now)


class AsyncLLMProvider:
    """Enhanced async LLM provider with proper error handling and optimizations"""
    
    def __init__(self, config: LLMConfig):
        self.config = config
        self.session: Optional[aiohttp.ClientSession] = None
        self.rate_limiter = RateLimiter(calls_per_minute=50)  # Conservative rate limit
        
        self.headers = {
            "Authorization": f"Bearer {config.api_key}",
            "Content-Type": "application/json",
            "User-Agent": "AI-Security-Analyzer/1.0.0"
        }
    
    async def __aenter__(self):
        """Async context manager entry"""
        connector = aiohttp.TCPConnector(limit=20, limit_per_host=10)
        timeout = aiohttp.ClientTimeout(total=self.config.timeout)
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=self.headers
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10),
        retry=retry_if_exception_type((aiohttp.ClientError, asyncio.TimeoutError))
    )
    async def _make_api_call(self, model: LLMModelType, prompt: str) -> Dict[str, Any]:
        """Make API call with retry logic"""
        await self.rate_limiter.acquire()
        
        payload = {
            "model": model.value,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
            "stream": False
        }
        
        start_time = time.time()
        
        async with self.session.post(
            f"{self.config.base_url}/chat/completions",
            json=payload
        ) as response:
            response_time = time.time() - start_time
            
            if response.status == 200:
                data = await response.json()
                return {
                    "content": data['choices'][0]['message']['content'],
                    "response_time": response_time,
                    "model": model.value
                }
            elif response.status == 429:  # Rate limited
                await asyncio.sleep(5)
                raise aiohttp.ClientError("Rate limited")
            else:
                error_text = await response.text()
                raise aiohttp.ClientError(f"API error {response.status}: {error_text}")
    
    async def analyze_code_async(
        self, 
        code: str, 
        file_path: str = "", 
        model: Optional[LLMModelType] = None
    ) -> LLMResponse:
        """Analyze code for security vulnerabilities using LLM with async/await"""
        
        if not model:
            model = self.config.default_model
        
        security_prompt = self._create_security_prompt(code, file_path)
        
        try:
            result = await self._make_api_call(model, security_prompt)
            content = result["content"]
            
            # Parse JSON response
            parsed_response = self._parse_llm_response(content)
            
            return LLMResponse(
                vulnerabilities=parsed_response.get("vulnerabilities", []),
                overall_risk=parsed_response.get("overall_risk", "unknown"),
                summary=parsed_response.get("summary", ""),
                model_used=result["model"],
                response_time=result["response_time"]
            )
            
        except Exception as e:
            logger.error(f"LLM analysis failed for {file_path}: {e}")
            
            # Try fallback models
            for fallback_model in self.config.fallback_models:
                if fallback_model != model:
                    try:
                        logger.info(f"Trying fallback model: {fallback_model}")
                        result = await self._make_api_call(fallback_model, security_prompt)
                        content = result["content"]
                        parsed_response = self._parse_llm_response(content)
                        
                        return LLMResponse(
                            vulnerabilities=parsed_response.get("vulnerabilities", []),
                            overall_risk=parsed_response.get("overall_risk", "unknown"),
                            summary=parsed_response.get("summary", ""),
                            model_used=result["model"],
                            response_time=result["response_time"]
                        )
                    except Exception as fallback_error:
                        logger.warning(f"Fallback model {fallback_model} also failed: {fallback_error}")
                        continue
            
            # If all models failed, return error response
            return LLMResponse(
                vulnerabilities=[],
                overall_risk="unknown",
                summary="",
                model_used=model.value,
                response_time=0.0,
                error=str(e)
            )
    
    def _create_security_prompt(self, code: str, file_path: str = "") -> str:
        """Create a comprehensive security analysis prompt"""
        
        return f"""
You are an expert security engineer conducting a comprehensive security analysis. Analyze the following code for security vulnerabilities, malicious patterns, and insecure practices.

File: {file_path if file_path else "Unknown"}

Code:
```
{code}
```

Please identify:
1. Security vulnerabilities (SQL injection, XSS, command injection, path traversal, etc.)
2. Insecure coding practices
3. Potential data exposure risks
4. Authentication/authorization bypass issues
5. Input validation problems
6. Cryptographic weaknesses
7. Hardcoded secrets, credentials, or API keys
8. Suspicious or potentially malicious patterns
9. Buffer overflows and memory safety issues
10. Race conditions and concurrency issues

For each issue found, provide:
- Vulnerability type (use specific categories like 'sql_injection', 'xss', 'hardcoded_secrets', etc.)
- Severity level: "critical", "high", "medium", "low", or "info"
- Line number (if applicable)
- Brief descriptive title
- Detailed description explaining the vulnerability
- Specific recommendation for fixing the issue
- CWE ID if applicable
- Confidence level (0.0 to 1.0)

Respond ONLY in valid JSON format:
{{
    "vulnerabilities": [
        {{
            "type": "vulnerability_type",
            "severity": "severity_level",
            "line": line_number,
            "title": "Brief title",
            "description": "Detailed description of the vulnerability",
            "recommendation": "Specific fix recommendation",
            "cwe_id": "CWE-XXX",
            "confidence": 0.95
        }}
    ],
    "overall_risk": "critical|high|medium|low|info",
    "summary": "Brief summary of all findings and overall security posture"
}}

Be thorough but precise. Only report actual security issues, not general code quality concerns.
"""
    
    def _parse_llm_response(self, content: str) -> Dict[str, Any]:
        """Parse LLM response and extract JSON"""
        try:
            # Find JSON in the response
            json_start = content.find('{')
            json_end = content.rfind('}') + 1
            
            if json_start == -1 or json_end == 0:
                raise ValueError("No JSON found in response")
            
            json_content = content[json_start:json_end]
            return json.loads(json_content)
            
        except (json.JSONDecodeError, ValueError) as e:
            logger.warning(f"Failed to parse LLM response as JSON: {e}")
            logger.debug(f"Raw response: {content}")
            
            # Fallback: try to extract at least some information
            return {
                "vulnerabilities": [],
                "overall_risk": "unknown",
                "summary": "Failed to parse LLM response"
            }
    
    def convert_to_security_findings(
        self, 
        llm_response: LLMResponse, 
        file_path: str
    ) -> List[SecurityFinding]:
        """Convert LLM response to SecurityFinding objects"""
        
        findings = []
        
        for vuln in llm_response.vulnerabilities:
            try:
                # Map vulnerability type
                vuln_type = self._map_vulnerability_type(vuln.get("type", "default"))
                
                # Map severity
                severity = self._map_severity(vuln.get("severity", "medium"))
                
                finding = SecurityFinding(
                    file_path=file_path,
                    line_number=max(0, int(vuln.get("line", 0))),
                    vulnerability_type=vuln_type,
                    severity=severity,
                    title=vuln.get("title", "Security Issue"),
                    description=vuln.get("description", ""),
                    recommendation=vuln.get("recommendation", "Review and fix this security issue"),
                    confidence=str(vuln.get("confidence", "medium")),
                    cwe_id=vuln.get("cwe_id", ""),
                    tool_source=f"LLM-{llm_response.model_used}"
                )
                findings.append(finding)
                
            except Exception as e:
                logger.warning(f"Failed to convert vulnerability to SecurityFinding: {e}")
                continue
        
        return findings
    
    def _map_vulnerability_type(self, vuln_type: str) -> VulnerabilityType:
        """Map string vulnerability type to enum"""
        type_mapping = {
            "sql_injection": VulnerabilityType.SQL_INJECTION,
            "xss": VulnerabilityType.XSS,
            "command_injection": VulnerabilityType.COMMAND_INJECTION,
            "path_traversal": VulnerabilityType.PATH_TRAVERSAL,
            "hardcoded_secrets": VulnerabilityType.HARDCODED_SECRETS,
            "insecure_crypto": VulnerabilityType.INSECURE_CRYPTO,
            "auth_bypass": VulnerabilityType.AUTH_BYPASS,
            "input_validation": VulnerabilityType.INPUT_VALIDATION,
            "buffer_overflow": VulnerabilityType.BUFFER_OVERFLOW,
            "race_condition": VulnerabilityType.RACE_CONDITION,
            "information_disclosure": VulnerabilityType.INFORMATION_DISCLOSURE,
            "denial_of_service": VulnerabilityType.DENIAL_OF_SERVICE,
        }
        
        return type_mapping.get(vuln_type.lower(), VulnerabilityType.DEFAULT)
    
    def _map_severity(self, severity: str) -> SeverityLevel:
        """Map string severity to enum"""
        severity_mapping = {
            "critical": SeverityLevel.CRITICAL,
            "high": SeverityLevel.HIGH,
            "medium": SeverityLevel.MEDIUM,
            "low": SeverityLevel.LOW,
            "info": SeverityLevel.INFO,
        }
        
        return severity_mapping.get(severity.lower(), SeverityLevel.MEDIUM)


# Legacy sync wrapper for backward compatibility
class LLMProvider:
    """Synchronous wrapper for AsyncLLMProvider"""
    
    def __init__(self, api_key: str, model_name: str, base_url: str = "https://openrouter.ai/api/v1"):
        config = LLMConfig(
            api_key=api_key,
            base_url=base_url,
            default_model=LLMModelType(model_name)
        )
        self.async_provider = AsyncLLMProvider(config)
    
    def analyze_code(self, code: str, context: str = "") -> Dict[str, Any]:
        """Synchronous code analysis"""
        async def _analyze():
            async with self.async_provider as provider:
                result = await provider.analyze_code_async(code, context)
                return {
                    "vulnerabilities": result.vulnerabilities,
                    "overall_risk": result.overall_risk,
                    "summary": result.summary,
                    "error": result.error
                }
        
        return asyncio.run(_analyze()) 
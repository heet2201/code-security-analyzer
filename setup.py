#!/usr/bin/env python3

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="ai-security-analyzer",
    version="1.0.0",
    author="Heet Shah",
    author_email="heetshah221@gmail.com",
    description="AI-Powered Code Security Analyzer with Multi-LLM Support",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/heet2201/ai-code-security-analyzer",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.20.0",
            "black>=22.0.0",
            "flake8>=4.0.0",
            "mypy>=0.950",
            "coverage>=6.0.0",
        ],
        "docs": [
            "sphinx>=4.0.0",
            "sphinx-rtd-theme>=1.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "security-analyzer=security_analyzer.cli:main",
            "ai-security-scan=security_analyzer.cli:scan_command",
        ],
    },
    package_data={
        "security_analyzer": [
            "config/*.yaml",
            "templates/*.json",
        ],
    },
    include_package_data=True,
) 
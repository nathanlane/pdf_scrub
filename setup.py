#!/usr/bin/env python3
"""Setup script for PDF Scrub."""

from setuptools import setup, find_packages
import os

# Read README for long description
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Read requirements
with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="pdf-scrub",
    version="1.0.0",
    author="Nathan Lane",
    author_email="",
    description="A Python tool for removing metadata from PDF files",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/nathanlane/pdf_scrub",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Legal Industry",
        "Intended Audience :: End Users/Desktop",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Utilities",
        "Topic :: Office/Business",
        "Topic :: Text Processing",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "pre-commit>=3.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "pdf-scrub=pdf_scrub:main",
        ],
    },
    keywords="pdf metadata privacy security forensics scrubbing anonymization",
    project_urls={
        "Bug Reports": "https://github.com/nathanlane/pdf_scrub/issues",
        "Source": "https://github.com/nathanlane/pdf_scrub",
        "Documentation": "https://github.com/nathanlane/pdf_scrub/blob/main/README.md",
    },
)
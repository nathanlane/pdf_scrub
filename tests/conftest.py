#!/usr/bin/env python3
"""pytest configuration and fixtures for PDF Scrub tests."""

import os
import tempfile
from typing import Generator

import pytest


@pytest.fixture
def temp_dir() -> Generator[str, None, None]:
    """Create a temporary directory for test files."""
    temp_path = tempfile.mkdtemp()
    yield temp_path
    # Cleanup
    import shutil
    shutil.rmtree(temp_path, ignore_errors=True)


@pytest.fixture
def sample_pdf_path(temp_dir: str) -> str:
    """Create a minimal PDF file for testing."""
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import letter
    
    pdf_path = os.path.join(temp_dir, "sample.pdf")
    
    # Create a simple PDF with some content
    c = canvas.Canvas(pdf_path, pagesize=letter)
    c.drawString(100, 750, "Test PDF for scrubbing")
    c.drawString(100, 700, "This is sample content")
    c.save()
    
    return pdf_path


@pytest.fixture
def pdf_scrubber():
    """Create a PDFScrubber instance for testing."""
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from pdf_scrub import PDFScrubber
    return PDFScrubber()
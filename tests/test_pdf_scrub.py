#!/usr/bin/env python3
"""Tests for PDF Scrub functionality."""

import os
import tempfile
import unittest
from unittest.mock import Mock, patch
from typing import Any, Dict

import pytest

# Import the main class (assuming it will be refactored into a package)
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pdf_scrub import PDFScrubber


class TestPDFScrubber(unittest.TestCase):
    """Test cases for PDFScrubber class."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.scrubber = PDFScrubber()

    def test_init(self) -> None:
        """Test PDFScrubber initialization."""
        self.assertIsInstance(self.scrubber.validation_results, dict)
        self.assertEqual(self.scrubber.steganography_threshold, 7.5)

    def test_calculate_entropy_empty_data(self) -> None:
        """Test entropy calculation with empty data."""
        result = self.scrubber.calculate_entropy(b"")
        self.assertEqual(result, 0.0)

    def test_calculate_entropy_uniform_data(self) -> None:
        """Test entropy calculation with uniform data."""
        # All same bytes should have low entropy
        uniform_data = b"A" * 100
        result = self.scrubber.calculate_entropy(uniform_data)
        self.assertEqual(result, 0.0)

    def test_calculate_entropy_random_data(self) -> None:
        """Test entropy calculation with random-like data."""
        # Mix of different bytes should have higher entropy
        mixed_data = bytes(range(256))
        result = self.scrubber.calculate_entropy(mixed_data)
        self.assertGreater(result, 7.0)  # Should be close to 8.0 for perfectly random

    @patch('pikepdf.open')
    def test_extract_metadata_pikepdf_no_metadata(self, mock_pikepdf_open: Mock) -> None:
        """Test pikepdf metadata extraction with no metadata."""
        # Mock PDF with no metadata
        mock_pdf = Mock()
        mock_pdf.docinfo = {}
        mock_pdf.open_metadata.return_value = None
        mock_pdf.pages = []
        mock_pikepdf_open.return_value.__enter__.return_value = mock_pdf

        result = self.scrubber.extract_metadata_pikepdf("dummy_path.pdf")
        self.assertEqual(result, {})

    @patch('builtins.open')
    @patch('PyPDF2.PdfReader')
    def test_extract_metadata_pypdf2_no_metadata(self, mock_reader: Mock, mock_open: Mock) -> None:
        """Test PyPDF2 metadata extraction with no metadata."""
        # Mock PDF reader with no metadata
        mock_reader_instance = Mock()
        mock_reader_instance.metadata = None
        mock_reader_instance.xmp_metadata = None
        mock_reader.return_value = mock_reader_instance

        result = self.scrubber.extract_metadata_pypdf2("dummy_path.pdf")
        self.assertEqual(result, {})

    def test_validate_pdf_structure_nonexistent_file(self) -> None:
        """Test PDF structure validation with nonexistent file."""
        result = self.scrubber.validate_pdf_structure("nonexistent.pdf")
        self.assertIn("structural_issues", result)
        self.assertTrue(len(result["structural_issues"]) > 0)

    def test_detect_steganography_nonexistent_file(self) -> None:
        """Test steganography detection with nonexistent file."""
        result = self.scrubber.detect_steganography("nonexistent.pdf")
        self.assertIn("error", result)

    def test_scrub_pdf_nonexistent_file(self) -> None:
        """Test scrubbing with nonexistent input file."""
        success, result = self.scrubber.scrub_pdf("nonexistent.pdf")
        self.assertFalse(success)
        self.assertIn("error", result)
        self.assertEqual(result["error"], "Input file does not exist")


class TestUtilityFunctions(unittest.TestCase):
    """Test cases for utility functions."""

    def test_print_validation_report(self) -> None:
        """Test validation report printing."""
        from pdf_scrub import print_validation_report
        
        # Mock validation data
        validation_data = {
            "final_analysis": {
                "file_path": "/test/file.pdf",
                "file_size": 12345,
                "forensic_assessment": {
                    "metadata_detected": False,
                    "scrubbing_successful": True,
                    "confidence_level": "HIGH"
                },
                "metadata_checks": {
                    "pypdf2_metadata": {
                        "found_metadata": False,
                        "metadata_items": 0,
                        "details": {}
                    }
                }
            }
        }
        
        # This should not raise an exception
        with patch('builtins.print'):
            print_validation_report(validation_data)


class TestIntegration(unittest.TestCase):
    """Integration tests for PDF scrubbing workflow."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.scrubber = PDFScrubber()
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self) -> None:
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @unittest.skip("Requires sample PDF file")
    def test_full_scrubbing_workflow(self) -> None:
        """Test complete scrubbing workflow with a sample PDF."""
        # This test would require a sample PDF file
        # It's skipped by default but can be enabled for manual testing
        sample_pdf = os.path.join(self.temp_dir, "sample.pdf")
        output_pdf = os.path.join(self.temp_dir, "scrubbed.pdf")
        
        # Would need to create or provide a sample PDF here
        # success, result = self.scrubber.scrub_pdf(sample_pdf, output_pdf)
        # self.assertTrue(success)
        # self.assertTrue(os.path.exists(output_pdf))
        pass


if __name__ == "__main__":
    unittest.main()
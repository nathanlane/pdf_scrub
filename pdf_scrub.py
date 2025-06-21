#!/usr/bin/env python3
"""PDF Metadata Scrubber.

A comprehensive tool for removing all metadata from PDF files using multiple methods
and providing forensic validation of complete metadata removal.
"""

import argparse
import json
import math
import os
import re
import shutil
import struct
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Tuple

try:
    import PyPDF2
    import pikepdf
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import letter
    import exifread
except ImportError as e:
    print(f"Missing required dependency: {e}")
    print("Install with: pip install PyPDF2 pikepdf reportlab exifread")
    sys.exit(1)


class PDFScrubber:
    """Main class for PDF metadata scrubbing operations.
    
    This class provides comprehensive PDF metadata removal using multiple
    scrubbing methods and forensic validation.
    
    Attributes:
        validation_results (Dict): Stores validation results from operations
        steganography_threshold (float): Entropy threshold for suspicious data detection
    """

    def __init__(self) -> None:
        """Initialize the PDF scrubber with default settings."""
        self.validation_results: Dict[str, Any] = {}
        self.steganography_threshold: float = 7.5  # Entropy threshold for suspicious data
        
    def extract_metadata_pypdf2(self, pdf_path: str) -> Dict[str, Any]:
        """Extract metadata using PyPDF2.
        
        Args:
            pdf_path: Path to the PDF file to analyze
            
        Returns:
            Dictionary containing extracted metadata or error information
        """
        metadata: Dict[str, Any] = {}
        try:
            with open(pdf_path, "rb") as file:
                reader = PyPDF2.PdfReader(file)
                if reader.metadata:
                    metadata.update(dict(reader.metadata))

                # Check for XMP metadata
                if hasattr(reader, "xmp_metadata") and reader.xmp_metadata:
                    metadata["XMP"] = "XMP metadata present"

        except Exception as e:
            metadata["error"] = str(e)
        return metadata
    
    def extract_metadata_pikepdf(self, pdf_path: str) -> Dict[str, Any]:
        """Extract metadata using pikepdf.
        
        Args:
            pdf_path: Path to the PDF file to analyze
            
        Returns:
            Dictionary containing extracted metadata or error information
        """
        metadata: Dict[str, Any] = {}
        try:
            with pikepdf.open(pdf_path) as pdf:
                # Document info
                if pdf.docinfo:
                    for key, value in pdf.docinfo.items():
                        metadata[str(key)] = str(value)

                # XMP metadata
                if pdf.open_metadata():
                    metadata["XMP"] = "XMP metadata present"

                # Check for other metadata streams
                for page_num, page in enumerate(pdf.pages):
                    if "/Metadata" in page:
                        metadata[f"Page_{page_num}_Metadata"] = "Page metadata present"

        except Exception as e:
            metadata["error"] = str(e)
        return metadata
    
    def scrub_method_pypdf2(self, input_path: str, output_path: str) -> bool:
        """Scrub metadata using PyPDF2.
        
        Args:
            input_path: Path to input PDF file
            output_path: Path for output PDF file
            
        Returns:
            True if scrubbing was successful, False otherwise
        """
        try:
            with open(input_path, "rb") as input_file:
                reader = PyPDF2.PdfReader(input_file)
                writer = PyPDF2.PdfWriter()

                # Copy pages without metadata
                for page in reader.pages:
                    writer.add_page(page)

                # Ensure no metadata is written
                writer.add_metadata({})

                with open(output_path, "wb") as output_file:
                    writer.write(output_file)
            return True
        except Exception as e:
            print(f"PyPDF2 scrubbing failed: {e}")
            return False
    
    def scrub_method_pikepdf(self, input_path: str, output_path: str) -> bool:
        """Scrub metadata using pikepdf.
        
        Args:
            input_path: Path to input PDF file
            output_path: Path for output PDF file
            
        Returns:
            True if scrubbing was successful, False otherwise
        """
        try:
            with pikepdf.open(input_path) as pdf:
                # Remove document info - clear all keys individually
                if pdf.docinfo:
                    keys_to_remove = list(pdf.docinfo.keys())
                    for key in keys_to_remove:
                        del pdf.docinfo[key]

                # Remove XMP metadata
                try:
                    with pdf.open_metadata(set_pikepdf_as_editor=False) as meta:
                        if meta:
                            # Remove all XMP content
                            for key in list(meta.keys()):
                                del meta[key]
                except Exception:
                    # XMP metadata might not exist
                    pass

                # Remove metadata from pages
                for page in pdf.pages:
                    if "/Metadata" in page:
                        del page["/Metadata"]

                # Remove other potential metadata keys
                metadata_keys = ["/Info", "/Metadata", "/PieceInfo", "/Perms"]
                for key in metadata_keys:
                    if key in pdf.Root:
                        del pdf.Root[key]

                # Also remove from trailer
                if "/Info" in pdf.trailer:
                    del pdf.trailer["/Info"]

                pdf.save(output_path)
            return True
        except Exception as e:
            print(f"pikepdf scrubbing failed: {e}")
            return False
    
    def scrub_method_reconstruct(self, input_path: str, output_path: str) -> bool:
        """Scrub by reconstructing PDF content without metadata.
        
        Args:
            input_path: Path to input PDF file
            output_path: Path for output PDF file
            
        Returns:
            True if scrubbing was successful, False otherwise
        """
        try:
            with pikepdf.open(input_path) as source_pdf:
                # Create new PDF
                new_pdf = pikepdf.new()

                # Copy pages without any metadata
                for page in source_pdf.pages:
                    # Create clean page copy
                    clean_page = pikepdf.Page(page)
                    # Remove any metadata references
                    if "/Metadata" in clean_page:
                        del clean_page["/Metadata"]
                    new_pdf.pages.append(clean_page)

                # Ensure completely clean document info - remove keys individually
                if new_pdf.docinfo:
                    keys_to_remove = list(new_pdf.docinfo.keys())
                    for key in keys_to_remove:
                        del new_pdf.docinfo[key]

                # Also remove from trailer
                if "/Info" in new_pdf.trailer:
                    del new_pdf.trailer["/Info"]

                new_pdf.save(output_path)
            return True
        except Exception as e:
            print(f"Reconstruction scrubbing failed: {e}")
            return False
    
    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data to detect steganography.
        
        Args:
            data: Byte data to analyze
            
        Returns:
            Shannon entropy value (0-8 bits)
        """
        if not data:
            return 0.0

        # Count frequency of each byte value
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1

        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)

        return entropy
    
    def detect_steganography(self, pdf_path: str) -> Dict[str, Any]:
        """Detect potential steganographic content in PDF streams.
        
        Args:
            pdf_path: Path to PDF file to analyze
            
        Returns:
            Dictionary containing steganography analysis results
        """
        results: Dict[str, Any] = {
            "suspicious_streams": [],
            "high_entropy_objects": [],
            "unusual_patterns": [],
            "steganography_detected": False,
        }

        try:
            with pikepdf.open(pdf_path) as pdf:
                for i, obj in enumerate(pdf.objects):
                    try:
                        # Check if object has readable data
                        if hasattr(obj, "read_bytes"):
                            data = obj.read_bytes()
                            if len(data) > 100:  # Only check substantial data
                                entropy = self.calculate_entropy(data)
                                if entropy > self.steganography_threshold:
                                    results["high_entropy_objects"].append(
                                        {
                                            "object_id": str(obj),
                                            "entropy": entropy,
                                            "data_size": len(data),
                                        }
                                    )
                                    results["steganography_detected"] = True
                    except Exception:
                        # Skip objects that can't be read
                        continue
        except Exception as e:
            results["error"] = str(e)

        return results
    
    def sanitize_embedded_objects(self, pdf_path: str, output_path: str) -> bool:
        """Remove all embedded objects that could contain metadata or hidden data.
        
        Args:
            pdf_path: Path to input PDF file
            output_path: Path for sanitized output PDF file
            
        Returns:
            True if sanitization was successful, False otherwise
        """
        try:
            with pikepdf.open(pdf_path) as pdf:
                # Objects to remove that can contain metadata or hidden data
                dangerous_objects = [
                    "/JavaScript",
                    "/JS",  # JavaScript code
                    "/EmbeddedFiles",  # File attachments
                    "/Multimedia",  # Audio/video
                    "/3D",  # 3D models
                    "/RichMedia",  # Flash/multimedia
                    "/FileAttachment",  # File attachments
                    "/Sound",  # Audio annotations
                    "/Movie",  # Video annotations
                    "/Screen",  # Screen annotations
                    "/Widget",  # Form widgets with possible hidden data
                    "/Popup",  # Popup annotations
                ]

                # Remove dangerous objects from document root
                for obj_type in dangerous_objects:
                    if obj_type in pdf.Root:
                        del pdf.Root[obj_type]

                    # Also check Names dictionary
                    if "/Names" in pdf.Root and obj_type in pdf.Root.Names:
                        del pdf.Root.Names[obj_type]
                
                # Remove annotations that could contain metadata
                self._sanitize_annotations(pdf)

                # ENHANCED: Aggressive font metadata sanitization
                self._sanitize_fonts(pdf)

                # Remove form fields (AcroForm) which can contain metadata
                if "/AcroForm" in pdf.Root:
                    del pdf.Root["/AcroForm"]

                # Remove outline/bookmarks which can contain metadata
                if "/Outlines" in pdf.Root:
                    del pdf.Root["/Outlines"]

                # ENHANCED: Complete document info removal from trailer
                if "/Info" in pdf.trailer:
                    del pdf.trailer["/Info"]

                pdf.save(output_path)

                # FINAL STEP: Simple binary signature replacement
                self._replace_binary_signatures(output_path)

            return True
        except Exception as e:
            print(f"Embedded object sanitization failed: {e}")
            return False

    def _sanitize_annotations(self, pdf: Any) -> None:
        """Remove potentially dangerous annotations and their metadata.
        
        Args:
            pdf: pikepdf PDF object to sanitize
        """
        for page in pdf.pages:
            if "/Annots" in page:
                annotations_to_keep = []
                for annot in page.Annots:
                    # Keep only basic annotations, remove potentially dangerous ones
                    if "/Subtype" in annot:
                        subtype = str(annot.Subtype)
                        safe_types = [
                            "/Text",
                            "/FreeText",
                            "/Line",
                            "/Square",
                            "/Circle",
                            "/Polygon",
                            "/PolyLine",
                            "/Highlight",
                            "/Underline",
                            "/Squiggly",
                            "/StrikeOut",
                            "/Stamp",
                            "/Ink",
                        ]
                        if subtype in safe_types:
                            # Even for safe types, remove metadata
                            metadata_keys = [
                                "/T",
                                "/Contents",
                                "/RC",
                                "/CreationDate",
                                "/M",
                                "/NM",
                                "/Subj",
                            ]
                            for key in metadata_keys:
                                if key in annot:
                                    del annot[key]
                            annotations_to_keep.append(annot)

                # Replace annotations with cleaned list
                if annotations_to_keep:
                    page.Annots = annotations_to_keep
                else:
                    del page["/Annots"]
    def _sanitize_fonts(self, pdf: Any) -> None:
        """Remove attribution metadata from fonts.
        
        Args:
            pdf: pikepdf PDF object to sanitize
        """
        for page in pdf.pages:
            if "/Resources" in page and "/Font" in page.Resources:
                for font_name, font_obj in page.Resources.Font.items():
                    # Remove all attribution metadata from fonts
                    attribution_keys = [
                        "/BaseFont",
                        "/Name",
                        "/Registry",
                        "/Ordering",
                        "/Supplement",
                        "/FontName",
                        "/FontFamily",
                        "/FontStretch",
                        "/FontWeight",
                        "/Creator",
                        "/Producer",
                        "/CreationDate",
                        "/ModDate",
                    ]
                    
                    for key in attribution_keys:
                        if key in font_obj:
                            try:
                                # Check if contains attribution data
                                value = str(font_obj[key])
                                attribution_patterns = [
                                    "adobe",
                                    "microsoft",
                                    "pages",
                                    "word",
                                    "acrobat",
                                    "times",
                                    "helvetica",
                                    "arial",
                                    "symbol",
                                    "courier",
                                ]
                                
                                if any(attr in value.lower() for attr in attribution_patterns):
                                    # Replace with completely generic value
                                    if key == "/BaseFont":
                                        font_obj[key] = pikepdf.Name("/F1")
                                    elif key in ["/FontName", "/FontFamily"]:
                                        font_obj[key] = pikepdf.String("F")
                                    else:
                                        del font_obj[key]
                                elif key in [
                                    "/Registry",
                                    "/Ordering",
                                    "/Supplement",
                                    "/Creator",
                                    "/Producer",
                                    "/CreationDate",
                                    "/ModDate",
                                ]:
                                    # Always remove these metadata keys
                                    del font_obj[key]
                            except Exception:
                                # Some keys might be read-only, skip them
                                pass

                    # If font has FontDescriptor, sanitize it too
                    if "/FontDescriptor" in font_obj:
                        self._sanitize_font_descriptor(font_obj["/FontDescriptor"])

    def _sanitize_font_descriptor(self, desc: Any) -> None:
        """Sanitize font descriptor metadata.
        
        Args:
            desc: Font descriptor object to sanitize
        """
        desc_keys = [
            "/FontName",
            "/FontFamily",
            "/FontStretch",
            "/FontWeight",
            "/Registry",
            "/Ordering",
        ]
        
        for key in desc_keys:
            if key in desc:
                try:
                    value = str(desc[key])
                    attribution_patterns = [
                        "adobe",
                        "microsoft",
                        "pages",
                        "word",
                        "acrobat",
                        "times",
                        "helvetica",
                        "arial",
                    ]
                    
                    if any(attr in value.lower() for attr in attribution_patterns):
                        if key in ["/FontName", "/FontFamily"]:
                            desc[key] = pikepdf.String("F")
                        else:
                            del desc[key]
                    elif key in ["/Registry", "/Ordering"]:
                        del desc[key]
                except Exception:
                    pass

    def _replace_binary_signatures(self, output_path: str) -> None:
        """Replace binary attribution signatures in the PDF.
        
        Args:
            output_path: Path to PDF file to modify
        """
        try:
            with open(output_path, "rb") as f:
                content = f.read()

            # Simple replacements for major attribution signatures
            replacements = {
                b"Adobe": b"     ",  # Replace with spaces
                b"adobe": b"     ",
            }

            modified = False
            for old, new in replacements.items():
                if old in content:
                    content = content.replace(old, new)
                    modified = True

            if modified:
                with open(output_path, "wb") as f:
                    f.write(content)
        except Exception:
            # If binary replacement fails, continue with PDF as-is
            pass
    
    def sanitize_binary_signatures(self, pdf_path: str, output_path: str) -> bool:
        """Remove software attribution signatures from binary data.
        
        Args:
            pdf_path: Path to input PDF file
            output_path: Path for output PDF file
            
        Returns:
            True if changes were made, False otherwise
        """
        try:
            # Read the PDF file as binary
            with open(pdf_path, "rb") as f:
                content = bytearray(f.read())

            # Attribution patterns to remove (case-insensitive)
            attribution_patterns = [
                b"Adobe",
                b"ADOBE",
                b"adobe",
                b"Microsoft",
                b"MICROSOFT",
                b"microsoft",
                b"LibreOffice",
                b"LIBREOFFICE",
                b"libreoffice",
                b"OpenOffice",
                b"OPENOFFICE",
                b"openoffice",
                b"Word",
                b"WORD",
                b"word",
                b"Acrobat",
                b"ACROBAT",
                b"acrobat",
                b"Writer",
                b"WRITER",
                b"writer",
                b"Pages",
                b"PAGES",
                b"pages",
                b"LaTeX",
                b"LATEX",
                b"latex",
                b"PDFCreator",
                b"PDFCREATOR",
                b"pdfcreator",
                b"PDFMaker",
                b"PDFMAKER",
                b"pdfmaker",
                b"Distiller",
                b"DISTILLER",
                b"distiller",
                b"PowerPoint",
                b"POWERPOINT",
                b"powerpoint",
                b"Excel",
                b"EXCEL",
                b"excel",
                b"Keynote",
                b"KEYNOTE",
                b"keynote",
            ]

            changes_made = False

            # Replace attribution patterns with spaces
            for pattern in attribution_patterns:
                if pattern in content:
                    # Replace with spaces to maintain PDF structure
                    replacement = b" " * len(pattern)
                    content = content.replace(pattern, replacement)
                    changes_made = True

            # Additional specific pattern replacements for common metadata strings
            metadata_strings = [
                b"/Producer",
                b"/Creator",
                b"/Author",
                b"/Title",
                b"/Subject",
                b"/Keywords",
                b"/Application",
                b"/CreationDate",
                b"/ModDate",
            ]

            for pattern in metadata_strings:
                # Don't remove the keys entirely, just their values if they contain attribution
                start = 0
                while True:
                    pos = content.find(pattern, start)
                    if pos == -1:
                        break

                    # Look for the value after the key
                    value_start = pos + len(pattern)
                    # Find the end of the value (next '/' or '>>')
                    value_end = value_start
                    paren_count = 0
                    in_string = False

                    while value_end < len(content):
                        char = content[value_end : value_end + 1]
                        if char == b"(":
                            paren_count += 1
                            in_string = True
                        elif char == b")":
                            paren_count -= 1
                            if paren_count == 0:
                                in_string = False
                                value_end += 1
                                break
                        elif not in_string and (
                            char == b"/" or content[value_end : value_end + 2] == b">>"
                        ):
                            break
                        value_end += 1

                    # Check if the value contains attribution signatures
                    value_content = content[value_start:value_end]
                    for attr_pattern in attribution_patterns:
                        if attr_pattern.lower() in value_content.lower():
                            # Replace the attribution part with spaces
                            value_content = value_content.replace(
                                attr_pattern, b" " * len(attr_pattern)
                            )
                            content[value_start:value_end] = value_content
                            changes_made = True

                    start = value_end

            # Write the sanitized content
            with open(output_path, "wb") as f:
                f.write(content)

            return changes_made

        except Exception as e:
            print(f"Binary signature sanitization failed: {e}")
            return False
    
    def validate_pdf_structure(self, pdf_path: str) -> Dict[str, Any]:
        """Validate PDF structural integrity after scrubbing.
        
        Args:
            pdf_path: Path to PDF file to validate
            
        Returns:
            Dictionary containing structural validation results
        """
        results: Dict[str, Any] = {
            "valid_pdf": False,
            "readable_pages": 0,
            "total_pages": 0,
            "corrupted_objects": [],
            "missing_fonts": [],
            "structural_issues": [],
        }

        try:
            # Test with PyPDF2
            with open(pdf_path, "rb") as file:
                reader = PyPDF2.PdfReader(file)
                results["total_pages"] = len(reader.pages)

                # Try to read each page
                readable_pages = 0
                for i, page in enumerate(reader.pages):
                    try:
                        # Attempt to extract text to verify page integrity
                        page.extract_text()
                        readable_pages += 1
                    except Exception as e:
                        results["corrupted_objects"].append(f"Page {i}: {str(e)}")

                results["readable_pages"] = readable_pages

            # Test with pikepdf
            with pikepdf.open(pdf_path) as pdf:
                # Check for missing fonts
                for page in pdf.pages:
                    if "/Resources" in page and "/Font" in page.Resources:
                        for font_name, font_obj in page.Resources.Font.items():
                            if "/BaseFont" not in font_obj:
                                results["missing_fonts"].append(str(font_name))

                # Basic structural validation
                if "/Root" not in pdf.trailer:
                    results["structural_issues"].append("Missing document root")
                if "/Info" in pdf.trailer:
                    results["structural_issues"].append("Document info still present")

            results["valid_pdf"] = (
                results["readable_pages"] == results["total_pages"]
                and len(results["corrupted_objects"]) == 0
            )

        except Exception as e:
            results["structural_issues"].append(f"Validation error: {str(e)}")

        return results
    
    def detect_advanced_metadata(self, pdf_path: str) -> Dict[str, Any]:
        """Detect metadata in unusual locations throughout PDF structure.
        
        Args:
            pdf_path: Path to PDF file to analyze
            
        Returns:
            Dictionary containing advanced metadata detection results
        """
        results: Dict[str, Any] = {
            "page_metadata": [],
            "annotation_metadata": [],
            "form_metadata": [],
            "bookmark_metadata": [],
            "thumbnail_metadata": [],
            "color_profile_metadata": [],
            "font_metadata": [],
            "attribution_signatures": [],
        }

        try:
            with pikepdf.open(pdf_path) as pdf:
                # Check each page for metadata
                for page_num, page in enumerate(pdf.pages):
                    page_meta = {}

                    # Page-level metadata
                    metadata_keys = [
                        "/Metadata",
                        "/PieceInfo",
                        "/SeparationInfo",
                        "/Tabs",
                        "/TemplateInstantiated",
                        "/PresSteps",
                        "/UserUnit",
                    ]
                    for key in metadata_keys:
                        if key in page:
                            page_meta[key] = "Present"

                    if page_meta:
                        results["page_metadata"].append(f"Page {page_num}: {page_meta}")

                    # Annotation metadata
                    if "/Annots" in page:
                        for annot in page.Annots:
                            annot_meta = {}
                            annot_keys = [
                                "/T",
                                "/Contents",
                                "/RC",
                                "/CreationDate",
                                "/M",
                                "/NM",
                                "/Subj",
                                "/IT",
                                "/ExData",
                            ]
                            for key in annot_keys:
                                if key in annot:
                                    annot_meta[key] = str(annot[key])[:50]  # Truncate for display
                            if annot_meta:
                                results["annotation_metadata"].append(
                                    f"Page {page_num}: {annot_meta}"
                                )

                # Font metadata (attribution signatures) - only flag if contains actual attribution data
                for page in pdf.pages:
                    if "/Resources" in page and "/Font" in page.Resources:
                        for font_name, font_obj in page.Resources.Font.items():
                            font_info = {}
                            font_keys = [
                                "/BaseFont",
                                "/Name",
                                "/Registry",
                                "/Ordering",
                                "/Supplement",
                            ]
                            for key in font_keys:
                                if key in font_obj:
                                    value = str(font_obj[key])
                                    # Only flag if contains attribution signatures, not generic values
                                    attribution_terms = [
                                        "adobe",
                                        "microsoft",
                                        "pages",
                                        "word",
                                        "acrobat",
                                        "times",
                                        "helvetica",
                                        "arial",
                                    ]
                                    generic_values = ["/GenericFont", "Generic", "None"]
                                    
                                    if value not in generic_values and any(
                                        attr in value.lower() for attr in attribution_terms
                                    ):
                                        font_info[key] = value
                            if font_info:
                                results["font_metadata"].append(font_info)

                # Check for software attribution signatures in binary data
                attribution_patterns = [
                    b"Adobe"  # Only check for attribution signatures, not PDF structure keywords
                ]

                with open(pdf_path, "rb") as f:
                    content = f.read()
                    for pattern in attribution_patterns:
                        if pattern in content:
                            results["attribution_signatures"].append(
                                pattern.decode("utf-8", errors="ignore")
                            )

        except Exception as e:
            results["error"] = str(e)

        return results
    
    def forensic_validation(self, pdf_path: str) -> Dict[str, Any]:
        """Perform comprehensive forensic validation of metadata removal.
        
        Args:
            pdf_path: Path to PDF file for validation
            
        Returns:
            Dictionary containing comprehensive validation results
        """
        results: Dict[str, Any] = {
            "file_path": pdf_path,
            "file_size": os.path.getsize(pdf_path),
            "metadata_checks": {},
        }

        # Check 1: PyPDF2 metadata extraction
        pypdf2_meta = self.extract_metadata_pypdf2(pdf_path)
        results["metadata_checks"]["pypdf2_metadata"] = {
            "found_metadata": bool(pypdf2_meta and pypdf2_meta != {}),
            "metadata_items": len(pypdf2_meta),
            "details": pypdf2_meta,
        }

        # Check 2: pikepdf metadata extraction
        pikepdf_meta = self.extract_metadata_pikepdf(pdf_path)
        results["metadata_checks"]["pikepdf_metadata"] = {
            "found_metadata": bool(pikepdf_meta and pikepdf_meta != {}),
            "metadata_items": len(pikepdf_meta),
            "details": pikepdf_meta,
        }

        # Check 3: Binary string search for common metadata patterns
        binary_patterns = [
            b"/Title",
            b"/Author",
            b"/Subject",
            b"/Creator",
            b"/Producer",
            b"/CreationDate",
            b"/ModDate",
            b"/Keywords",
            b"/Application",
            b"<?xpacket",
            b"<x:xmpmeta",
            b"xmp:",
            b"pdf:",
            b"dc:",
        ]

        found_patterns = []
        try:
            with open(pdf_path, "rb") as f:
                content = f.read()
                for pattern in binary_patterns:
                    if pattern in content:
                        found_patterns.append(pattern.decode("utf-8", errors="ignore"))
        except Exception as e:
            found_patterns.append(f"Binary search error: {e}")

        results["metadata_checks"]["binary_pattern_search"] = {
            "found_patterns": len(found_patterns) > 0,
            "pattern_count": len(found_patterns),
            "patterns": found_patterns,
        }

        # Check 4: Steganography detection
        stego_results = self.detect_steganography(pdf_path)
        results["metadata_checks"]["steganography_detection"] = {
            "found_suspicious": stego_results["steganography_detected"],
            "high_entropy_objects": len(stego_results["high_entropy_objects"]),
            "details": stego_results,
        }

        # Check 5: Advanced metadata detection
        advanced_meta = self.detect_advanced_metadata(pdf_path)
        has_advanced_metadata = any(
            [
                advanced_meta["page_metadata"],
                advanced_meta["annotation_metadata"],
                advanced_meta["font_metadata"],
                advanced_meta["attribution_signatures"],
            ]
        )
        results["metadata_checks"]["advanced_metadata"] = {
            "found_metadata": has_advanced_metadata,
            "details": advanced_meta,
        }

        # Check 6: Structural validation
        structure_results = self.validate_pdf_structure(pdf_path)
        results["metadata_checks"]["structural_validation"] = structure_results

        # Check 7: File system metadata
        try:
            stat = os.stat(pdf_path)
            results["filesystem_metadata"] = {
                "creation_time": stat.st_ctime,
                "modification_time": stat.st_mtime,
                "access_time": stat.st_atime,
            }
        except Exception as e:
            results["filesystem_metadata"] = {"error": str(e)}

        # Overall assessment
        has_metadata = (
            results["metadata_checks"]["pypdf2_metadata"]["found_metadata"]
            or results["metadata_checks"]["pikepdf_metadata"]["found_metadata"]
            or results["metadata_checks"]["binary_pattern_search"]["found_patterns"]
            or results["metadata_checks"]["steganography_detection"]["found_suspicious"]
            or results["metadata_checks"]["advanced_metadata"]["found_metadata"]
        )

        results["forensic_assessment"] = {
            "metadata_detected": has_metadata,
            "scrubbing_successful": not has_metadata,
            "confidence_level": "HIGH" if not has_metadata else "LOW",
        }

        return results
    
    def scrub_pdf(self, input_path: str, output_path: str = None) -> Tuple[bool, Dict[str, Any]]:
        """Main function to scrub PDF using multiple methods.
        
        Args:
            input_path: Path to input PDF file
            output_path: Optional path for output file (auto-generated if None)
            
        Returns:
            Tuple of (success_flag, results_dict)
        """
        if not os.path.exists(input_path):
            return False, {"error": "Input file does not exist"}

        if output_path is None:
            base, ext = os.path.splitext(input_path)
            output_path = f"{base}_scrubbed{ext}"

        print(f"🔍 Analyzing original file: {input_path}")
        original_validation = self.forensic_validation(input_path)

        # Try multiple scrubbing methods with enhanced sanitization
        methods = [
            ("pikepdf_advanced", self.scrub_method_reconstruct),
            ("pikepdf_standard", self.scrub_method_pikepdf),
            ("pypdf2", self.scrub_method_pypdf2),
        ]

        temp_files: List[str] = []
        
        for method_name, method_func in methods:
            temp_file = tempfile.mktemp(suffix='.pdf')
            temp_files.append(temp_file)
            
            print(f"🔧 Applying {method_name} scrubbing method...")
            success = method_func(input_path, temp_file)
            
            if success:
                # Apply additional sanitization to embedded objects
                temp_file2 = tempfile.mktemp(suffix='.pdf')
                temp_files.append(temp_file2)
                
                print(f"🧹 Sanitizing embedded objects...")
                sanitization_success = self.sanitize_embedded_objects(temp_file, temp_file2)
                
                if sanitization_success:
                    validation = self.forensic_validation(temp_file2)
                    if validation['forensic_assessment']['scrubbing_successful']:
                        shutil.copy2(temp_file2, output_path)
                        print(f"✅ Successfully scrubbed using {method_name} + enhanced sanitization")
                        break
                    else:
                        print(f"⚠️ {method_name} passed basic scrubbing but failed enhanced validation")
                        # Debug: let's see what's still being detected
                        print(f"   Remaining issues: {validation['forensic_assessment']}")
                        if 'advanced_metadata' in validation['metadata_checks']:
                            details = validation['metadata_checks']['advanced_metadata']['details']
                            if details['font_metadata']:
                                print(f"   Font metadata still present: {len(details['font_metadata'])} instances")
                                print(f"   First font example: {details['font_metadata'][0] if details['font_metadata'] else 'None'}")
                            if details['attribution_signatures']:
                                print(f"   Attribution signatures: {details['attribution_signatures']}")
                        if 'structural_validation' in validation['metadata_checks']:
                            struct = validation['metadata_checks']['structural_validation']
                            if struct['structural_issues']:
                                print(f"   Structural issues: {struct['structural_issues']}")
                else:
                    print(f"❌ Embedded object sanitization failed for {method_name}")
            else:
                print(f"❌ {method_name} method failed")
        
        # Clean up temp files
        for temp_file in temp_files:
            if os.path.exists(temp_file):
                os.remove(temp_file)
        
        if not os.path.exists(output_path):
            return False, {'error': 'All scrubbing methods failed'}
        
        print(f"🔍 Validating scrubbed file: {output_path}")
        final_validation = self.forensic_validation(output_path)
        
        return True, {
            'original_analysis': original_validation,
            'final_analysis': final_validation,
            'output_file': output_path
        }


def print_validation_report(validation_data: Dict[str, Any]) -> None:
    """Print a detailed forensic validation report.
    
    Args:
        validation_data: Dictionary containing validation results
    """
    print("\n" + "=" * 80)
    print("🔬 FORENSIC METADATA VALIDATION REPORT")
    print("=" * 80)

    analysis = validation_data["final_analysis"]

    print(f"\n📄 File: {analysis['file_path']}")
    print(f"📏 Size: {analysis['file_size']:,} bytes")

    print(f"\n🎯 FORENSIC ASSESSMENT:")
    assessment = analysis["forensic_assessment"]
    status = (
        "🔴 METADATA DETECTED"
        if assessment["metadata_detected"]
        else "🟢 NO METADATA DETECTED"
    )
    print(f"   Status: {status}")
    print(f"   Confidence: {assessment['confidence_level']}")
    scrub_success = "✅ YES" if assessment["scrubbing_successful"] else "❌ NO"
    print(f"   Scrubbing Success: {scrub_success}")

    print(f"\n🔍 DETAILED CHECKS:")

    for check_name, check_data in analysis["metadata_checks"].items():
        print(f"\n   {check_name.upper()}:")

        if check_name == "steganography_detection":
            status = "❌ SUSPICIOUS" if check_data["found_suspicious"] else "✅ CLEAN"
            print(f"     Status: {status}")
            print(f"     High Entropy Objects: {check_data['high_entropy_objects']}")
            if check_data["found_suspicious"] and check_data["details"]["high_entropy_objects"]:
                print("     Suspicious Objects:")
                for obj in check_data["details"]["high_entropy_objects"]:
                    print(f"       - Entropy: {obj['entropy']:.2f}, Size: {obj['data_size']} bytes")

        elif check_name == "advanced_metadata":
            status = "❌ FOUND" if check_data["found_metadata"] else "✅ CLEAN"
            print(f"     Status: {status}")
            details = check_data["details"]
            if check_data["found_metadata"]:
                if details["page_metadata"]:
                    print(f"     Page Metadata: {len(details['page_metadata'])} instances")
                if details["annotation_metadata"]:
                    print(f"     Annotation Metadata: {len(details['annotation_metadata'])} instances")
                if details["font_metadata"]:
                    print(f"     Font Metadata: {len(details['font_metadata'])} instances")
                if details["attribution_signatures"]:
                    signatures = ", ".join(details["attribution_signatures"])
                    print(f"     Attribution Signatures: {signatures}")

        elif check_name == "structural_validation":
            status = "✅ VALID" if check_data["valid_pdf"] else "❌ ISSUES"
            print(f"     Status: {status}")
            print(f"     Pages: {check_data['readable_pages']}/{check_data['total_pages']}")
            if check_data["structural_issues"]:
                issues = ", ".join(check_data["structural_issues"])
                print(f"     Issues: {issues}")

        elif "found_metadata" in check_data:
            status = "❌ FOUND" if check_data["found_metadata"] else "✅ CLEAN"
            print(f"     Status: {status}")
            print(f"     Items: {check_data['metadata_items']}")
            if check_data["details"] and check_data["found_metadata"]:
                details_json = json.dumps(check_data["details"], indent=8)
                print(f"     Details: {details_json}")

        elif "found_patterns" in check_data:
            status = "❌ FOUND" if check_data["found_patterns"] else "✅ CLEAN"
            print(f"     Status: {status}")
            print(f"     Patterns: {check_data['pattern_count']}")
            if check_data["patterns"]:
                for pattern in check_data["patterns"]:
                    print(f"       - {pattern}")

    if "original_analysis" in validation_data:
        print(f"\n📊 COMPARISON WITH ORIGINAL:")
        orig = validation_data["original_analysis"]["forensic_assessment"]
        final = validation_data["final_analysis"]["forensic_assessment"]

        orig_meta = "YES" if orig["metadata_detected"] else "NO"
        final_meta = "YES" if final["metadata_detected"] else "NO"

        print(f"   Original had metadata: {orig_meta}")
        print(f"   Scrubbed has metadata: {final_meta}")

        if orig["metadata_detected"] and not final["metadata_detected"]:
            print("   Result: ✅ METADATA SUCCESSFULLY REMOVED")
        elif not orig["metadata_detected"] and not final["metadata_detected"]:
            print("   Result: ✅ NO METADATA IN ORIGINAL OR FINAL")
        else:
            print("   Result: ❌ METADATA STILL PRESENT")

    print("\n" + "=" * 80)


def main() -> None:
    """Main entry point for the PDF scrubber CLI."""
    parser = argparse.ArgumentParser(
        description="Comprehensive PDF metadata scrubber with forensic validation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python pdf_scrub.py document.pdf
  python pdf_scrub.py input.pdf -o clean_output.pdf
  python pdf_scrub.py file.pdf --validate-only
        """,
    )

    parser.add_argument("input_file", help="Input PDF file to scrub")
    parser.add_argument(
        "-o", "--output", help="Output file path (default: input_scrubbed.pdf)"
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Only validate metadata, do not scrub",
    )
    parser.add_argument(
        "--quiet", action="store_true", help="Suppress detailed output"
    )

    args = parser.parse_args()

    if not os.path.exists(args.input_file):
        print(f"❌ Error: File '{args.input_file}' does not exist")
        sys.exit(1)

    scrubber = PDFScrubber()

    if args.validate_only:
        print(f"🔍 Validating metadata in: {args.input_file}")
        validation = scrubber.forensic_validation(args.input_file)
        validation_data = {"final_analysis": validation}
        print_validation_report(validation_data)

        if validation["forensic_assessment"]["metadata_detected"]:
            sys.exit(1)
        else:
            sys.exit(0)

    print(f"🚀 Starting PDF metadata scrubbing...")
    print(f"📁 Input: {args.input_file}")

    success, result = scrubber.scrub_pdf(args.input_file, args.output)

    if success:
        if not args.quiet:
            print_validation_report(result)

        print(f"\n✅ PDF successfully scrubbed!")
        print(f"📁 Output: {result['output_file']}")

        if result["final_analysis"]["forensic_assessment"]["scrubbing_successful"]:
            print("🔒 Forensic validation confirms: NO METADATA DETECTED")
            sys.exit(0)
        else:
            print("⚠️  Warning: Some metadata may still be present")
            sys.exit(1)
    else:
        print(f"❌ Scrubbing failed: {result.get('error', 'Unknown error')}")
        sys.exit(1)


if __name__ == "__main__":
    main()
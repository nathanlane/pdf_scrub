# PDF Scrub 🔒

**Author: Nathan Lane**

Just a little utility for scrubbing PDFs for sensitive submissions, peer review, etc. I am not an expert, but this is a little attempt.

## Overview

A Python tool that removes metadata from PDF files using multiple scrubbing methods and provides comprehensive validation to ensure complete metadata removal.

## Installation

```bash
pip install PyPDF2 pikepdf reportlab exifread
```

## Usage

### Basic Usage
```bash
# Scrub a PDF (creates input_scrubbed.pdf)
python pdf_scrub.py document.pdf

# Specify output file
python pdf_scrub.py input.pdf -o clean_output.pdf

# Validate metadata only (no scrubbing)
python pdf_scrub.py file.pdf --validate-only

# Quiet mode (minimal output)
python pdf_scrub.py file.pdf --quiet
```

### Command Line Options
```
usage: pdf_scrub.py [-h] [-o OUTPUT] [--validate-only] [--quiet] input_file

arguments:
  input_file            Input PDF file to scrub
  -o OUTPUT, --output   Output file path (default: input_scrubbed.pdf)
  --validate-only       Only validate metadata, do not scrub
  --quiet              Suppress detailed output
```

## What It Does

The tool uses multiple methods to remove metadata:

1. **Standard Metadata Removal**: Removes document info (Author, Title, Subject, Creator, etc.)
2. **XMP Metadata Removal**: Eliminates Adobe XMP metadata
3. **Binary Pattern Cleaning**: Removes software attribution signatures
4. **Embedded Object Sanitization**: Cleans metadata from fonts, annotations, and embedded content

## Validation

After scrubbing, the tool validates the result using:
- PyPDF2 metadata extraction
- pikepdf metadata analysis  
- Binary pattern search for metadata signatures
- Structural integrity checks

Exit codes:
- **0**: Success (no metadata detected)
- **1**: Failure (metadata still present or error)

## Example Output

```
🔍 Analyzing original file: document.pdf
🔧 Applying pikepdf_advanced scrubbing method...
🧹 Sanitizing embedded objects...
✅ Successfully scrubbed using pikepdf_advanced + enhanced sanitization
🔍 Validating scrubbed file: document_scrubbed.pdf

✅ PDF successfully scrubbed!
📁 Output: document_scrubbed.pdf
🔒 Forensic validation confirms: NO METADATA DETECTED
```

## Use Cases

- **Academic submissions**: Remove identifying metadata before peer review
- **Legal documents**: Clean files before sharing in litigation
- **Privacy protection**: Remove authorship traces from documents
- **Corporate security**: Strip internal metadata before external sharing

## Technical Details

- **Languages**: Python 3.8+
- **Dependencies**: PyPDF2, pikepdf, reportlab, exifread
- **Processing**: All operations performed locally (no network access)
- **Validation**: Multi-method verification for comprehensive metadata detection

## Limitations

- Cannot remove information visible in document content
- Some complex embedded objects may retain traces
- Visual elements may contain identifying information
- Does not protect against stylistic analysis

## License

MIT License - Use at your own risk. Always verify results meet your security requirements.

# Makefile for PDF Scrub development

.PHONY: help install install-dev test test-cov lint format type-check security clean build upload docs

help:
	@echo "Available commands:"
	@echo "  install      Install package in development mode"
	@echo "  install-dev  Install package with development dependencies"
	@echo "  test         Run tests"
	@echo "  test-cov     Run tests with coverage report"
	@echo "  lint         Run linting (flake8)"
	@echo "  format       Format code with black and isort"
	@echo "  type-check   Run type checking with mypy"
	@echo "  security     Run security checks (bandit)"
	@echo "  clean        Clean build artifacts"
	@echo "  build        Build package"
	@echo "  upload       Upload package to PyPI"
	@echo "  docs         Build documentation"
	@echo "  pre-commit   Install pre-commit hooks"

install:
	pip install -e .

install-dev:
	pip install -e .[dev]
	pip install -r requirements-dev.txt

test:
	pytest

test-cov:
	pytest --cov=pdf_scrub --cov-report=html --cov-report=term-missing

lint:
	flake8 pdf_scrub.py tests/

format:
	black pdf_scrub.py tests/
	isort pdf_scrub.py tests/

type-check:
	mypy pdf_scrub.py

security:
	bandit -r . -f json -o bandit-report.json
	safety check

clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf .coverage
	rm -rf htmlcov/
	rm -rf .mypy_cache/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

build: clean
	python -m build

upload: build
	twine upload dist/*

docs:
	@echo "Documentation generation not yet implemented"

pre-commit:
	pre-commit install
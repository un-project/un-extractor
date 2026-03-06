# Contributing to UN Extractor

Thank you for your interest in contributing to the UN Extractor project! This guide will help you get started with development.

## Getting Started

### Prerequisites
- Python 3.8.1 or higher
- `pdftohtml` utility (for PDF→XML conversion)
- Git

### Setup Development Environment

We recommend using `uv` (modern Python package manager, faster than pip):

```bash
git clone https://github.com/un-project/un-extractor.git
cd un-extractor
uv venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
uv pip install -e '.[dev]'
```

Or using traditional pip:

```bash
python -m venv venv
source venv/bin/activate
pip install -e '.[dev]'
```

## Development Workflow

### Running Tests

```bash
# Run all tests
uv run pytest

# Run with verbose output
uv run pytest -xvs

# Run specific test file
uv run pytest tests/test_extractor.py -v

# Run with coverage
uv run pytest --cov=un_extractor tests/
```

### Code Quality Checks

```bash
# Format code with black
uv run black un_extractor/ tests/

# Lint with flake8
uv run flake8 un_extractor/ tests/

# Type checking with mypy
uv run mypy un_extractor/

# All checks together
uv run black un_extractor/ tests/ && \
uv run flake8 un_extractor/ tests/ && \
uv run mypy un_extractor/ && \
uv run pytest
```

## Project Structure

```
un-extractor/
├── un_extractor/          # Main package
│   ├── __init__.py
│   ├── __main__.py        # Entry point for `python -m un_extractor`
│   ├── extractor.py       # Core extraction logic
│   ├── version.py         # Version string
│   └── cli/
│       ├── __init__.py
│       └── main.py        # CLI argument parsing
├── tests/                 # Test suite
│   ├── __init__.py
│   ├── test_extractor.py  # Unit tests
│   ├── test_integration.py # End-to-end tests
│   ├── test_regex.py      # Regex scanner tests
│   └── data/              # Test fixtures
│       ├── N0553261.xml   # Sample UN document (XML)
│       ├── N0553261.json  # Expected extraction output
│       ├── N0637121.xml   # Alternative document format
│       ├── N0637121.json  # Expected output
│       └── minimal.xml    # Minimal test case
├── pyproject.toml         # Package metadata (PEP 621)
├── setup.cfg              # Tool configuration (black, flake8, mypy, pytest)
├── README.md              # User documentation
├── DESIGN.md              # Architecture documentation (this file)
└── CONTRIBUTING.md        # Developer guide (you are here)
```

## Understanding the Code

### Main Components

1. **`extractor.py`**: Core extraction logic
   - `Extractor` class: Main extraction engine
   - `RegexScanner` class: Pattern matching utility
   - Helper functions: `read_statements()`, `read_paragraphs()`, `xpath_regex()`

2. **`cli/main.py`**: Command-line interface
   - Argument parsing with argparse
   - Input/output handling
   - Logging configuration

3. **Test Files**:
   - `test_extractor.py`: Unit tests for parsing logic
   - `test_integration.py`: End-to-end test with real data
   - `test_regex.py`: Tests for token scanner

### Key Design Decisions

See [DESIGN.md](DESIGN.md) for detailed information about:
- Data flow and architecture
- Layout-based extraction heuristics
- Why certain approaches were chosen
- Known limitations and trade-offs

## Making Changes

### 1. Create a Feature Branch

```bash
git checkout -b feature/your-feature-name
```

### 2. Make Changes

- Update code in appropriate modules
- Add tests for new functionality
- Update docstrings (see `extractor.py` for style)
- Keep changes focused and well-documented

### 3. Test Your Changes

```bash
# Run affected tests
uv run pytest tests/test_extractor.py -xvs

# Run all tests
uv run pytest

# Check code quality
uv run black un_extractor/ tests/
uv run flake8 un_extractor/ tests/
uv run mypy un_extractor/
```

### 4. Commit and Push

```bash
git add .
git commit -m "feature: descriptive message about changes"
git push origin feature/your-feature-name
```

### 5. Create a Pull Request

- Link to relevant issues
- Describe changes and motivation
- Ensure all tests pass

## Common Tasks

### Adding a New Test

```python
# tests/test_extractor.py
def test_new_feature():
    """Test description."""
    extractor = Extractor()
    # Test code here
    assert result == expected
```

Run it:
```bash
uv run pytest tests/test_extractor.py::test_new_feature -xvs
```

### Debugging Extraction Issues

```python
# Enable debug logging
import logging
logging.getLogger("un-extractor").setLevel(logging.DEBUG)

# Extract with verbose output
extractor = Extractor()
report = extractor.get_report(open("document.xml"))
```

Or from command line:
```bash
uv run un_extractor --verbose document.xml output.json
```

### Working with Test Data

To add a new test PDF:

```bash
# Convert PDF to XML
pdftohtml -xml -enc UTF-8 your-document.pdf tests/data/your-document.xml

# Extract expected output
uv run un_extractor tests/data/your-document.xml > tests/data/your-document.json

# Verify output is correct (manual review)
# Then add integration test:
```

### Updating Dependencies

Dependencies are specified in `pyproject.toml`. To add a new package:

```toml
[project]
dependencies = [
    "existing-package>=1.0",
    "new-package>=2.0",  # Add here
]

[project.optional-dependencies]
dev = [
    "pytest>=7.0",
    "new-dev-tool>=1.0",  # Or here for dev-only
]
```

Then regenerate lock file:
```bash
uv lock
```

## Code Style

### Python Style
- Follow [PEP 8](https://pep8.org/)
- Use type hints where possible
- Auto-format with `black` (88 char lines)

### Docstrings
- Use Google-style docstrings
- Include brief description, Args, Returns, Raises, Example sections
- See `Extractor.get_report()` for examples

### Comments
- Explain *why*, not *what*
- Keep comments close to code they describe
- Update comments when code changes

## Issues and Bug Reports

### Reporting Bugs

When reporting issues, include:
- Python version (`python --version`)
- PDF source and reproduction steps
- Error message and full traceback
- Expected vs actual behavior

### Requesting Features

- Describe the use case
- Explain why it's needed
- Suggest possible implementation if you have ideas

## Performance Considerations

- `ExtractorExtractor` processes documents sequentially
- XPath queries can be slow on large documents
- Consider caching if processing multiple formats
- Profile with `profile` module for optimization

## Questions?

- Check [DESIGN.md](DESIGN.md) for architecture details
- Review existing tests for usage examples
- Look at function docstrings for API details
- Open an issue for clarification

Thank you for contributing!

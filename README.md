# un-extractor - an extractor for UN general assembly records

For example:

```bash
un_extractor input.xml output.json
```

## Install

### From source code

**Using uv (recommended - fastest installation):**
```bash
git clone https://github.com/un-project/un-extractor.git
cd un-extractor
uv venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
uv pip install -e .
```

For development with uv:
```bash
uv pip install -e '.[dev]'
```

**Using pip:**
```bash
git clone https://github.com/un-project/un-extractor.git
cd un-extractor
pip install -e .
```

For development:
```bash
pip install -e '.[dev]'
```

## Input Preparation

UN General Assembly records are typically provided as PDF files. To use `un_extractor`, you must first convert the PDF to XML format using the `pdftohtml` command with UTF‑8 encoding:

```bash
pdftohtml -xml -enc UTF-8 -stdout input.pdf | un_extractor --quiet > output.json
```

Or convert to an XML file first, then extract:

```bash
pdftohtml -xml -enc UTF-8 input.pdf input.xml
un_extractor input.xml output.json
```

## Usage

```
un_extractor [options] [infile] [outfile]
```

Options:
- `-v, --verbose`: Enable verbose output (debug logging)
- `-q, --quiet`: Suppress status messages (useful for piping)
- `--validate-only`: Validate XML structure without extracting
- `--version`: Show version number

Arguments:
- `infile`: XML input file (defaults to stdin)
- `outfile`: JSON output file (defaults to stdout)

Examples:

```bash
# Extract from file to file
un_extractor meeting.xml meeting.json

# Using uv to run the tool
uv run un_extractor meeting.xml meeting.json

# Pipe from pdftohtml directly
pdftohtml -xml -enc UTF-8 -stdout meeting.pdf | un_extractor --quiet > meeting.json

# Using uv with piped input
pdftohtml -xml -enc UTF-8 -stdout meeting.pdf | uv run un_extractor --quiet > meeting.json

# Validate XML before extraction
un_extractor --validate-only meeting.xml

# Enable verbose logging for debugging
un_extractor -v meeting.xml meeting.json
```

## Development

Create a virtual environment and install the development dependencies:

**Using uv (recommended):**
```bash
uv venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
uv pip install -e '.[dev]'
```

**Using pip:**
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install --upgrade pip setuptools
pip install -e '.[dev]'
```

Run tests with your installed environment:

```bash
# If using uv
uv run pytest

# If using pip/venv
pytest
```

Or use uv to run tests without explicit venv activation:
```bash
uv run pytest
```

A minimal example recording (XML plus expected JSON) lives in
``tests/data``; the integration test verifies that the extractor produces
identical output.  This can be useful when debugging improvements or
refactoring.

### Continuous integration & quality checks

A GitHub Actions workflow (``.github/workflows/ci.yml``) exercises the
project on push or pull request.  It installs runtime and development
requirements then runs:

* ``black`` for code formatting (``--check``)
* ``flake8`` linting
* ``mypy`` static typing
* the unit/integration test suite

To set up the environment locally you can use the optional "dev"
extra defined in ``pyproject.toml``:

```bash
pip install -e '.[dev]'
```

or, if you only need the runtime library, simply ``pip install .``.

The project uses PEP‑621 ``pyproject.toml`` for metadata and dependencies.
The project targets Python 3.7 and later; Python 2 is no longer supported.

## License

un-extractor is available under the MIT License. You should find the LICENSE in the root of the project.

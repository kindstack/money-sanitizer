# Contributing to Money File Sanitizer

Thank you for your interest in contributing to this project!

## Development Setup

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd <repository-directory>
   ```

2. Create a virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. Install test dependencies:
   ```bash
   pip install -r requirements-test.txt
   ```

## Running Tests

Run the full test suite:
```bash
python -m pytest tests/ -v
```

Run a specific test class:
```bash
python -m pytest tests/test_sanitize_ofx.py::TestQifBasic -v
```

Run with coverage (if installed):
```bash
pip install pytest-cov
python -m pytest tests/ --cov=sanitize-ofx --cov-report=term-missing
```

## Code Style

- Follow PEP 8 guidelines
- Use type hints where appropriate
- Keep functions focused and well-documented
- Ensure all tests pass before submitting changes

## Submitting Changes

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Make your changes
4. Run the tests to ensure nothing is broken
5. Commit your changes (`git commit -am 'Add your feature'`)
6. Push to the branch (`git push origin feature/your-feature`)
7. Open a Pull Request

## Reporting Issues

When reporting issues, please include:
- Python version (`python --version`)
- Operating system
- Sample input file (sanitized of personal data) if applicable
- Expected vs actual behavior

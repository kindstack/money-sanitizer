# Money File Sanitizer

This repository contains `sanitize-ofx.py`, a utility script that prepares QIF and OFX bank export files so that Microsoft Money Sunset Edition can import them without errors.

## Features
- Normalizes text to Money-safe ASCII for both QIF and OFX inputs.
- Cleans and formats dates, amounts, and transaction metadata to meet Money's expectations.
- Adds or repairs essential OFX fields such as `TRNUID`, balances, and financial institution metadata.
- Provides command-line options for writing output to a new file or in place, with informative logging.

## Requirements
- Python 3.10 or newer.
- No third-party dependencies; the script uses only the Python standard library.

## Installation
1. Clone or download this repository.
2. Ensure `python3` points to a Python 3.10+ interpreter.
3. Optionally make the script executable: `chmod +x sanitize-ofx.py`.

## Usage
```bash
python sanitize-ofx.py --input path/to/statement.qif
```

Common options:
- `-o, --output`: Specify the destination file. Default is `<original name>.sanitized<extension>` next to the input.
- `--in-place`: Overwrite the original file (mutually exclusive with `--output`).
- `-v, --verbose`: Enable debug logging for troubleshooting.

The script writes sanitized data using Windows-style CRLF endings, matching Money's expectations.

## Development Notes
- QIF processing preserves split transactions and enforces Money-specific tag limits.
- OFX processing converts XML into SGML format with the required header block.
- Logging uses the standard library; tune verbosity with `-v` during experimentation.

## License
Released under the MIT License. See `LICENSE` for details.

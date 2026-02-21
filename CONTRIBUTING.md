# Contributing to secimport

Thank you for your interest in contributing! This project is designed to make it easy to add new integrations for security data sources.

## Getting Started

```bash
git clone https://github.com/zeroinsec/secimport.git
cd secimport
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

Verify your setup:

```bash
pytest                  # All tests pass
ruff check src tests    # No lint errors
black --check src tests # Properly formatted
```

## What Can You Contribute?

### 1. New API Connector

Add a connector for a security tool (scanner, CMDB, IPAM, directory, cloud).

**Steps:**

1. Pick the right category folder under `src/secimport/connectors/`:
   - `scanners/` -- vulnerability scanners
   - `cmdb/` -- configuration management databases
   - `ipam/` -- IP address management
   - `directory/` -- directory services (AD, LDAP)
   - `cloud/` -- cloud providers

2. Create your connector file inheriting from the category base:

```python
from .base import BaseScannerConnector  # or BaseCMDBConnector, etc.

class MyScannerConnector(BaseScannerConnector):
    name = "myscanner"
    vendor = "MyVendor"
    description = "MyScanner vulnerability scanner"
    auth_types = ("api_key",)
    _test_endpoint = "/api/v1/status"

    def _auth_headers(self):
        return {"X-Api-Key": self.auth.credentials["api_key"]}

    def get_scans(self, limit=None, since=None):
        # Implement API call
        ...

    def get_vulnerabilities(self, scan_id=None, severity=None,
                            since=None, limit=None):
        # Implement API call, yield ParsedVulnerability
        ...

    def get_assets(self, limit=None):
        # Implement API call
        ...

    def _parse_vulnerability(self, raw):
        return ParsedVulnerability(
            scanner_id=str(raw["id"]),
            title=raw["name"],
            severity=normalize_severity(raw["severity"], "generic"),
            extra=raw,
        )
```

3. Export it in the category's `__init__.py`
4. Add tests in `tests/`
5. Add optional dependencies to `pyproject.toml` if needed

**What you get for free from the base class:**
- `connect()` / `disconnect()` / `test_connection()`
- HTTP client setup with auth headers
- Context manager support
- Auth type validation
- Auto-registration in `ConnectorRegistry`

### 2. New File Parser

Add a parser for a CSV/Excel export format from a security tool.

**Steps:**

1. Pick the right folder under `src/secimport/parsers/`:
   - `vulnerabilities/` -- scanner export CSVs
   - `assets/` -- asset/CMDB spreadsheets
   - `owners/` -- owner/IP mapping files

2. Create your parser file:

```python
from ..base import BaseParser
from ...models.base import ParsedVulnerability
from ...normalizers.severity import normalize_severity

class MyScannerVulnParser(BaseParser):
    name = "myscanner_vuln"
    source = "myscanner"
    data_type = "vulnerability"
    description = "MyScanner vulnerability CSV export"

    # Columns that uniquely identify this format
    DETECTION_COLUMNS = (
        "Finding ID", "Risk Level", "Target Host",
    )

    # Map source columns to model fields
    COLUMN_MAPPING = {
        "Finding ID": "scanner_id",
        "CVE": "cve_id",
        "Finding Name": "title",
        "Risk Level": "severity",
        "Target Host": "hostname",
        "Target IP": "ip_address",
    }

    def _parse_row(self, row):
        mapped = dict(row)
        extra = mapped.pop("extra", {})
        mapped["severity"] = normalize_severity(
            mapped.get("severity"), "generic"
        )
        mapped["extra"] = extra
        return ParsedVulnerability(**mapped)
```

3. Export it in the category's `__init__.py`
4. Add tests with sample CSV data

**What you get for free from the base class:**
- CSV/Excel file reading
- Column mapping via `COLUMN_MAPPING`
- Auto-detection via `DETECTION_COLUMNS`
- Auto-registration in `ParserRegistry`
- Error handling per row (bad rows are logged and skipped)

### 3. Bug Fixes and Improvements

- Fix bugs in existing connectors or parsers
- Improve severity normalization mappings
- Add missing column mappings to existing parsers
- Improve documentation

## Code Style

| Rule | Setting |
|------|---------|
| Line length | 100 |
| Formatter | `black` |
| Linter | `ruff` |
| Type hints | Required on all public methods |
| Docstrings | Google style |

Run before submitting:

```bash
black src tests
ruff check src tests
pytest
```

## Testing

- All new code must have tests
- Use `pytest` fixtures for test data
- For parsers, create temp CSV files with `_write_csv()` helper
  (see `tests/test_parsers.py` for examples)
- For connectors, use `respx` to mock HTTP responses

## Optional Dependencies

If your connector or parser needs a third-party library:

1. Add it to `pyproject.toml` under `[project.optional-dependencies]`:

```toml
myscanner = ["myscanner-sdk>=1.0.0"]
```

2. Add it to the `all` group
3. Import it inside methods (not at module level) so the package
   works without the optional dependency installed

## Pull Request Process

1. Fork the repo and create a feature branch
2. Write your code following the patterns above
3. Add tests
4. Run `black`, `ruff`, and `pytest`
5. Submit a PR with a clear description of what you added

## Questions?

Open an issue on GitHub -- we're happy to help!

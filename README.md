# secimport

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)

Parse and normalize security data imports -- vulnerability scans, assets, CMDB, IPAM, and more.

**secimport** provides a unified Python interface for connecting to security data sources. It normalizes data from vulnerability scanners, CMDBs, IPAMs, directory services, and cloud providers into consistent Pydantic models so you can focus on building workflows, not wrangling formats.

## Installation

```bash
pip install secimport
```

Install with optional connector dependencies:

```bash
# Specific connectors
pip install "secimport[qualys]"
pip install "secimport[tenable]"
pip install "secimport[aws,azure,gcp]"

# Everything
pip install "secimport[all]"

# Development
pip install "secimport[dev]"
```

## Quick Start

### Scanner Connector

```python
from secimport import QualysConnector, ConnectionConfig, AuthConfig

config = ConnectionConfig(base_url="https://qualysapi.qualys.com")
auth = AuthConfig(
    auth_type="basic",
    credentials={"username": "user", "password": "pass"},
)

with QualysConnector(config, auth) as qualys:
    for vuln in qualys.get_vulnerabilities():
        print(vuln.cve_id, vuln.severity, vuln.hostname)
```

### Severity Normalization

Each scanner uses different severity scales. secimport normalizes them all:

```python
from secimport import normalize_severity

normalize_severity("5", "qualys")        # "Critical"
normalize_severity("Severe", "rapid7")   # "Critical"
normalize_severity("Info", "nessus")     # "Low"
normalize_severity("Log", "openvas")     # "Low"
```

### Connector Registry

All connectors auto-register on import. Discover what's available:

```python
from secimport import ConnectorRegistry

for name, cls in ConnectorRegistry.list_connectors().items():
    print(f"{name}: {cls.vendor} - {cls.description}")
```

## Supported Sources

### Vulnerability Scanners

| Scanner | Connector | Auth Types | Status |
|---------|-----------|------------|--------|
| Qualys VMDR | `QualysConnector` | basic, api_key | Stub |
| Nessus | `NessusConnector` | api_key, basic | Stub |
| Tenable.io | `TenableConnector` | api_key | Stub |
| Rapid7 InsightVM | `Rapid7Connector` | basic, api_key | Stub |
| OpenVAS / Greenbone | `OpenVASConnector` | basic | Stub |
| CrowdStrike Spotlight | `CrowdStrikeConnector` | oauth2 | Stub |

### Planned Integrations (Contributions Welcome)

| Category | Systems |
|----------|---------|
| **CMDB** | ServiceNow, BMC Helix |
| **IPAM** | Infoblox, NetBox, SolarWinds |
| **Directory** | Active Directory, Azure AD, LDAP |
| **Cloud** | AWS (tags), Azure (tags), GCP (labels) |
| **File Parsers** | Qualys CSV, Nessus CSV, asset spreadsheets, owner mappings |

## Data Models

All connectors output normalized [Pydantic](https://docs.pydantic.dev/) models:

### ParsedVulnerability

| Field | Type | Description |
|-------|------|-------------|
| `scanner_id` | `str?` | Scanner-specific ID (QID, Plugin ID) |
| `cve_id` | `str?` | CVE identifier |
| `title` | `str` | Vulnerability title |
| `severity` | `str` | Normalized: Critical, High, Medium, Low |
| `cvss_score` | `float?` | CVSS score (0-10) |
| `hostname` | `str?` | Affected hostname |
| `ip_address` | `str?` | Affected IP |
| `port` | `int?` | Affected port |
| `first_detected` | `datetime?` | First detection date |
| `extra` | `dict` | Raw scanner-specific fields |

### ParsedAsset

| Field | Type | Description |
|-------|------|-------------|
| `hostname` | `str?` | Hostname |
| `ip_address` | `str?` | IP address |
| `asset_type` | `str?` | Server, Workstation, Network Device |
| `environment` | `str?` | Production, Development, Test |
| `owner_email` | `str?` | Asset owner email |
| `department` | `str?` | Owning department |
| `operating_system` | `str?` | OS name |
| `extra` | `dict` | Raw source-specific fields |

### ParsedOwnerMapping

| Field | Type | Description |
|-------|------|-------------|
| `ip_address` | `str?` | Single IP |
| `ip_range` | `str?` | CIDR notation (10.0.0.0/24) |
| `hostname_pattern` | `str?` | Glob or regex pattern |
| `owner_email` | `str?` | Owner email |
| `department` | `str?` | Department |
| `source_system` | `str?` | IPAM, CMDB, AD |
| `confidence` | `float` | Confidence score (0-1) |
| `extra` | `dict` | Raw source-specific fields |

## Architecture

```
secimport/
├── models/              # Pydantic data models
│   └── base.py          # ParsedVulnerability, ParsedAsset, ParsedOwnerMapping
├── normalizers/         # Cross-scanner normalization
│   └── severity.py      # Severity mapping (Qualys 1-5 → Critical/High/Medium/Low)
├── connectors/          # API connectors
│   ├── base.py          # BaseConnector, ConnectionConfig, AuthConfig, ConnectorRegistry
│   ├── scanners/        # Vulnerability scanners
│   │   ├── base.py      # BaseScannerConnector (shared connect/test/disconnect)
│   │   ├── qualys.py
│   │   ├── nessus.py
│   │   ├── tenable.py
│   │   ├── rapid7.py
│   │   ├── openvas.py
│   │   └── crowdstrike.py
│   ├── cmdb/            # CMDB connectors (planned)
│   ├── ipam/            # IPAM connectors (planned)
│   ├── directory/       # Directory service connectors (planned)
│   └── cloud/           # Cloud provider connectors (planned)
├── parsers/             # File parsers (planned)
│   ├── vulnerabilities/ # Scanner CSV/Excel parsers
│   ├── assets/          # Asset spreadsheet parsers
│   └── owners/          # Owner mapping parsers
└── detectors/           # Auto-detection (planned)
```

## Contributing

We welcome contributions! This project is designed to make it easy to add new connectors.

### Development Setup

```bash
git clone https://github.com/zeroinsec/secimport.git
cd secimport
pip install -e ".[dev]"
pytest                  # Run tests
ruff check src tests    # Lint
black src tests         # Format
```

### Adding a New Connector

1. **Pick a category** -- `scanners/`, `cmdb/`, `ipam/`, `directory/`, or `cloud/`

2. **Create your connector file** inheriting from the appropriate base class:

```python
"""
MyScanner API Connector.

API Docs: https://docs.myscanner.com/api

Status: STUB - Community contribution welcome!
"""

from datetime import datetime
from typing import Any, ClassVar, Dict, Iterator, List, Optional, Tuple

from ...models.base import ParsedVulnerability
from ...normalizers.severity import normalize_severity
from .base import BaseScannerConnector


class MyScannerConnector(BaseScannerConnector):
    """
    MyScanner API connector.

    Usage::

        from secimport.connectors.scanners import MyScannerConnector
        from secimport.connectors.base import ConnectionConfig, AuthConfig

        config = ConnectionConfig(base_url="https://api.myscanner.com")
        auth = AuthConfig(auth_type="api_key", credentials={"api_key": "xxx"})

        with MyScannerConnector(config, auth) as scanner:
            for vuln in scanner.get_vulnerabilities():
                print(vuln.cve_id, vuln.severity)
    """

    name: ClassVar[str] = "myscanner"
    vendor: ClassVar[str] = "MyVendor"
    description: ClassVar[str] = "MyScanner vulnerability scanner"
    auth_types: ClassVar[Tuple[str, ...]] = ("api_key",)

    _test_endpoint: ClassVar[str] = "/api/v1/status"

    ENDPOINTS: ClassVar[Dict[str, str]] = {
        "scans": "/api/v1/scans",
        "vulnerabilities": "/api/v1/vulns",
    }

    def _auth_headers(self) -> Dict[str, str]:
        """Return auth headers for the API."""
        return {"X-Api-Key": self.auth.credentials["api_key"]}

    def get_scans(self, limit=None, since=None) -> List[Dict[str, Any]]:
        raise NotImplementedError("Community contribution welcome!")

    def get_vulnerabilities(self, scan_id=None, severity=None, since=None, limit=None):
        raise NotImplementedError("Community contribution welcome!")

    def get_assets(self, limit=None):
        raise NotImplementedError("Community contribution welcome!")

    def _parse_vulnerability(self, raw: Dict[str, Any]) -> ParsedVulnerability:
        return ParsedVulnerability(
            scanner_id=str(raw.get("id", "")),
            cve_id=raw.get("cve"),
            title=raw.get("name", "Unknown"),
            severity=normalize_severity(raw.get("severity"), "generic"),
            extra=raw,
        )
```

3. **Export it** in the category's `__init__.py`

4. **Add tests** in `tests/`

5. **Submit a PR**

### What the Base Classes Give You for Free

- **`connect()`** -- builds an `httpx.Client` with your auth headers and runs `test_connection()`
- **`disconnect()`** -- closes the HTTP client and resets status
- **`test_connection()`** -- pings your `_test_endpoint`
- **Context manager** -- `with MyConnector(...) as c:` auto-connects/disconnects
- **Auth validation** -- rejects unsupported auth types at init
- **Auto-registration** -- your connector appears in `ConnectorRegistry` on import

You only need to implement: `_auth_headers()`, `_parse_vulnerability()`, and your data methods.

### Code Style

- Line length: 100
- Formatter: `black`
- Linter: `ruff`
- Type hints: Required
- Docstrings: Google style

### Optional Dependencies

If your connector needs a third-party library, add it to `pyproject.toml` under `[project.optional-dependencies]`:

```toml
myscanner = ["myscanner-sdk>=1.0.0"]
```

And add it to the `all` group.

## License

Apache 2.0 -- see [LICENSE](LICENSE) for details.

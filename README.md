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

### Parse a File (Auto-Detection)

```python
from secimport import parse_file

# Auto-detects source (Qualys, Nessus, etc.) from column headers
data, result = parse_file("scan_export.csv")

for vuln in data:
    print(vuln.cve_id, vuln.severity, vuln.hostname)

print(f"Parsed {result.parsed_count} from {result.source_type}")
```

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

### Registry Discovery

All connectors and parsers auto-register on import:

```python
from secimport import ConnectorRegistry, ParserRegistry

for name, cls in ConnectorRegistry.list_connectors().items():
    print(f"{name}: {cls.vendor} - {cls.description}")

for name, cls in ParserRegistry.list_parsers().items():
    print(f"{name}: {cls.source} ({cls.data_type})")
```

## Supported Sources

### Vulnerability Scanners

| Scanner | Connector | Parser | Auth Types |
|---------|-----------|--------|------------|
| Qualys VMDR | `QualysConnector` | `QualysVulnParser` | basic, api_key |
| Nessus | `NessusConnector` | `NessusVulnParser` | api_key, basic |
| Tenable.io | `TenableConnector` | `TenableVulnParser` | api_key |
| Rapid7 InsightVM | `Rapid7Connector` | `Rapid7VulnParser` | basic, api_key |
| OpenVAS / Greenbone | `OpenVASConnector` | `OpenVASVulnParser` | basic |
| CrowdStrike Spotlight | `CrowdStrikeConnector` | `CrowdStrikeVulnParser` | oauth2 |
| Generic | -- | `GenericVulnParser` | -- |

### CMDB

| System | Connector | Parser | Auth Types |
|--------|-----------|--------|------------|
| ServiceNow | `ServiceNowConnector` | `ServiceNowAssetParser` | basic, oauth2 |
| BMC Helix | `BMCHelixConnector` | -- | basic, token |

### IPAM

| System | Connector | Parser | Auth Types |
|--------|-----------|--------|------------|
| Infoblox | `InfobloxConnector` | `IPAMOwnerParser` | basic |
| NetBox | `NetBoxConnector` | -- | token |
| SolarWinds | `SolarWindsConnector` | -- | basic |
| Generic | -- | `GenericOwnerParser` | -- |

### Directory Services

| System | Connector | Auth Types |
|--------|-----------|------------|
| Active Directory | `ActiveDirectoryConnector` | ldap |
| Azure AD | `AzureADConnector` | oauth2 |

### Cloud Providers

| Provider | Connector | Auth Types |
|----------|-----------|------------|
| AWS | `AWSConnector` | aws_credentials |
| Azure | `AzureConnector` | azure_credentials |
| GCP | `GCPConnector` | gcp_credentials |

### File Parsers

| Parser | Data Type | Auto-Detected |
|--------|-----------|---------------|
| `GenericAssetParser` | asset | Yes |
| `ServiceNowAssetParser` | asset | Yes |
| `GenericOwnerParser` | owner | Yes |
| `IPAMOwnerParser` | owner | Yes |

## Data Models

All connectors and parsers output normalized [Pydantic](https://docs.pydantic.dev/) models:

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
│   └── severity.py      # Severity mapping (Qualys 1-5 -> Critical/High/Medium/Low)
├── connectors/          # API connectors
│   ├── base.py          # BaseConnector, ConnectorRegistry, auth + connection infra
│   ├── scanners/        # Vulnerability scanners (Qualys, Nessus, Tenable, etc.)
│   ├── cmdb/            # CMDB (ServiceNow, BMC Helix)
│   ├── ipam/            # IPAM (Infoblox, NetBox, SolarWinds)
│   ├── directory/       # Directory services (AD, Azure AD)
│   └── cloud/           # Cloud providers (AWS, Azure, GCP)
├── parsers/             # File parsers (CSV/Excel)
│   ├── base.py          # BaseParser, ParserRegistry, column mapping + detection
│   ├── vulnerabilities/ # Scanner CSV parsers (Qualys, Nessus, Tenable, etc.)
│   ├── assets/          # Asset spreadsheet parsers
│   └── owners/          # Owner mapping parsers
└── detectors/           # Auto-detection engine
    └── auto_detect.py   # detect_parser(), detect_source(), parse_file()
```

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide.

### Development Setup

```bash
git clone https://github.com/zeroinsec/secimport.git
cd secimport
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest                  # Run tests
ruff check src tests    # Lint
black src tests         # Format
```

### What the Base Classes Give You for Free

**Connectors** (`BaseConnector`):
- `connect()` / `disconnect()` / `test_connection()` with auth hooks
- Context manager (`with MyConnector(...) as c:`)
- Auth validation at init
- Auto-registration in `ConnectorRegistry`

**Parsers** (`BaseParser`):
- CSV/Excel file reading
- Column mapping (`COLUMN_MAPPING` dict)
- Auto-detection from column fingerprints (`DETECTION_COLUMNS`)
- Auto-registration in `ParserRegistry`

You only implement: `_auth_headers()` + data methods (connectors), or `COLUMN_MAPPING` + `_parse_row()` (parsers).

### Code Style

- Line length: 100
- Formatter: `black`
- Linter: `ruff`
- Type hints: Required
- Docstrings: Google style

## License

Apache 2.0 -- see [LICENSE](LICENSE) for details.

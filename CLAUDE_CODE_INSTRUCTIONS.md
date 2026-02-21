# Claude Code Instructions for secimport

## Project Overview

**secimport** is an open-source Python library for parsing and connecting to security data sources. It provides both file parsers (CSV/Excel) and API connectors for vulnerability scanners, CMDBs, IPAMs, and more.

**Goal:** Community contributes connectors → ZeroinSEC benefits from integrations

**License:** Apache 2.0

---

## Current State

### Completed ✅
```
src/secimport/
├── models/
│   └── base.py                    # ParsedVulnerability, ParsedAsset, ParsedOwnerMapping
├── normalizers/
│   └── severity.py                # Severity normalization across scanners
├── connectors/
│   ├── base.py                    # BaseConnector, ConnectionConfig, AuthConfig
│   └── scanners/
│       ├── base.py                # BaseScannerConnector
│       ├── qualys.py              # Qualys VMDR connector (stub)
│       ├── nessus.py              # Nessus connector (stub)
│       ├── tenable.py             # Tenable.io connector (stub)
│       ├── rapid7.py              # Rapid7 InsightVM connector (stub)
│       ├── openvas.py             # OpenVAS connector (stub)
│       └── crowdstrike.py         # CrowdStrike Spotlight connector (stub)
├── parsers/
│   ├── vulnerabilities/           # Empty - needs file parsers
│   ├── assets/                    # Empty - needs file parsers
│   └── owners/                    # Empty - needs file parsers
└── detectors/                     # Empty - needs auto-detection
```

### Needs to be Built 🚧

| Category | Connectors Needed |
|----------|-------------------|
| **CMDB** | ServiceNow, BMC Helix |
| **IPAM** | Infoblox, NetBox, SolarWinds |
| **Directory** | Active Directory, Azure AD, LDAP |
| **Cloud** | AWS (tags), Azure (tags), GCP (tags) |
| **File Parsers** | Qualys CSV, Nessus CSV, asset spreadsheets, owner mappings |
| **Detectors** | Auto-detect source type from file columns |
| **Main Entry** | `__init__.py` with clean exports |
| **README.md** | Full documentation |
| **CONTRIBUTING.md** | How to add new connectors |
| **Tests** | Unit tests for all connectors |

---

## Patterns to Follow

### Base Connector Pattern

Every connector must:
1. Inherit from appropriate base class
2. Set `name`, `vendor`, `description`, `auth_types`
3. Implement `connect()`, `disconnect()`, `test_connection()`, `get_rate_limit_status()`
4. Implement data-specific methods

### Connector File Template
```python
"""
{System Name} API Connector.

API Docs: {link to docs}

Status: STUB - Community contribution welcome!
"""

from typing import Iterator, List, Optional, Dict, Any
from datetime import datetime

from ..base import BaseConnector, ConnectionConfig, AuthConfig, ConnectorStatus


class {SystemName}Connector(Base{Type}Connector):
    """
    {Description}
    
    Usage:
        from secimport.connectors.{category} import {SystemName}Connector
        ...
    """
    
    name = "{lowercase_name}"
    vendor = "{Vendor}"
    description = "{Description}"
    auth_types = ["api_key", "basic", "oauth2"]  # supported types
    
    ENDPOINTS = {
        # API endpoints
    }
    
    def connect(self) -> bool:
        # Connection logic using httpx
        pass
    
    def disconnect(self) -> None:
        # Cleanup
        pass
    
    def test_connection(self) -> bool:
        # Verify connection works
        pass
    
    def get_rate_limit_status(self) -> Dict[str, Any]:
        # Return rate limit info
        pass
    
    # ... data-specific methods
```

---

## Tasks for Claude Code

### Task 1: Create CMDB Base Connector

Create `src/secimport/connectors/cmdb/base.py` with:
- `BaseCMDBConnector` class extending `BaseConnector`
- Methods: `get_assets()`, `get_asset_by_id()`, `search_assets()`, `get_relationships()`
- Return type: `Iterator[ParsedAsset]`

### Task 2: Create ServiceNow Connector

Create `src/secimport/connectors/cmdb/servicenow.py` with:
- OAuth2 and basic auth support
- Table API integration (`/api/now/table/cmdb_ci_server`)
- CMDB API integration (`/api/now/cmdb/instance`)
- Map ServiceNow fields to `ParsedAsset` model

### Task 3: Create BMC Helix Connector

Create `src/secimport/connectors/cmdb/bmc.py` with:
- REST API integration
- Asset and CI queries

### Task 4: Create IPAM Base Connector

Create `src/secimport/connectors/ipam/base.py` with:
- `BaseIPAMConnector` class extending `BaseConnector`
- Methods: `get_subnets()`, `get_ip_addresses()`, `get_owner_for_ip()`, `get_owner_for_subnet()`
- Return type: `Iterator[ParsedOwnerMapping]`

### Task 5: Create Infoblox Connector

Create `src/secimport/connectors/ipam/infoblox.py` with:
- WAPI REST integration
- Network and IP address queries
- Extensible attributes for owner info

### Task 6: Create NetBox Connector

Create `src/secimport/connectors/ipam/netbox.py` with:
- REST API integration
- Prefixes, IP addresses, tenants
- Can use `pynetbox` library

### Task 7: Create SolarWinds IPAM Connector

Create `src/secimport/connectors/ipam/solarwinds.py` with:
- SWIS (SolarWinds Information Service) API
- Subnet and IP queries

### Task 8: Create Directory Base Connector

Create `src/secimport/connectors/directory/base.py` with:
- `BaseDirectoryConnector` class extending `BaseConnector`
- Methods: `get_users()`, `get_groups()`, `get_computers()`, `search()`
- Return types using models

### Task 9: Create Active Directory Connector

Create `src/secimport/connectors/directory/active_directory.py` with:
- LDAP3 library integration
- Computer objects (for asset ownership)
- User/group queries
- OU structure

### Task 10: Create Azure AD Connector

Create `src/secimport/connectors/directory/azure_ad.py` with:
- Microsoft Graph API
- OAuth2 authentication
- Devices, users, groups

### Task 11: Create Cloud Base Connector

Create `src/secimport/connectors/cloud/base.py` with:
- `BaseCloudConnector` class extending `BaseConnector`
- Methods: `get_resources()`, `get_tags()`, `get_owner_from_tags()`
- Return type: `Iterator[ParsedAsset]` or `Iterator[ParsedOwnerMapping]`

### Task 12: Create AWS Connector

Create `src/secimport/connectors/cloud/aws.py` with:
- boto3 integration
- EC2 instances with tags
- Resource Groups Tagging API
- Extract owner from tags (Owner, Team, Department, etc.)

### Task 13: Create Azure Connector

Create `src/secimport/connectors/cloud/azure.py` with:
- Azure SDK integration
- Resource Manager API
- Tag extraction for ownership

### Task 14: Create GCP Connector

Create `src/secimport/connectors/cloud/gcp.py` with:
- Google Cloud Asset API
- Labels for ownership

### Task 15: Create File Parsers

Create parsers in `src/secimport/parsers/`:
- `vulnerabilities/qualys.py` - Parse Qualys CSV exports
- `vulnerabilities/nessus.py` - Parse Nessus CSV exports
- `vulnerabilities/tenable.py` - Parse Tenable CSV exports
- `assets/csv_generic.py` - Parse generic asset spreadsheets
- `owners/csv_generic.py` - Parse owner mapping spreadsheets

Each parser should:
- Have `COLUMN_MAPPING` dict
- Have `DETECTION_COLUMNS` for auto-detect
- Implement `detect(columns) -> float` (confidence 0-1)
- Implement `parse(df) -> Iterator[Model]`

### Task 16: Create Auto-Detector

Create `src/secimport/detectors/auto_detect.py` with:
- Registry of all parsers
- `detect_source(columns: List[str]) -> str` function
- `detect_data_type(columns: List[str]) -> str` function
- Returns best matching parser/connector

### Task 17: Create Scanner Connector Exports

Update `src/secimport/connectors/scanners/__init__.py`:
```python
from .qualys import QualysConnector
from .nessus import NessusConnector
from .tenable import TenableConnector
from .rapid7 import Rapid7Connector
from .openvas import OpenVASConnector
from .crowdstrike import CrowdStrikeConnector

__all__ = [
    "QualysConnector",
    "NessusConnector",
    ...
]
```

Do the same for all connector categories.

### Task 18: Create Main Package Entry

Update `src/secimport/__init__.py` with:
- Version
- Clean imports for common use cases
- `parse_file()` function
- `detect_source()` function

### Task 19: Create README.md

Create comprehensive README with:
- Badges (PyPI, License, Python versions)
- One-line description
- Installation instructions
- Quick start examples for:
  - File parsing
  - Scanner connector
  - CMDB connector
  - IPAM connector
- Supported sources table
- API reference summary
- Contributing link
- License

### Task 20: Create CONTRIBUTING.md

Create contributor guide with:
- Development setup
- How to add a new connector (step-by-step)
- How to add a new parser
- Code style (black, ruff)
- Testing requirements
- PR process

### Task 21: Create Tests

Create tests in `tests/`:
- `test_models.py` - Test Pydantic models
- `test_normalizers.py` - Test severity normalization
- `test_parsers/` - Test each file parser
- `test_connectors/` - Test connector init (mocked)

Use pytest with fixtures. Mock HTTP calls with `respx`.

### Task 22: Create CHANGELOG.md

Create changelog following Keep a Changelog format.

---

## Models Reference

### ParsedVulnerability
- scanner_id, cve_id, title, severity, cvss_score
- description, solution
- hostname, ip_address, port, protocol
- first_detected, last_detected
- extra: Dict[str, Any]

### ParsedAsset
- hostname, ip_address, mac_address, serial_number, asset_tag
- asset_type, environment, criticality
- owner_email, owner_name, department, business_unit, cost_center
- operating_system, os_version, location
- extra: Dict[str, Any]

### ParsedOwnerMapping
- ip_address, ip_range, hostname_pattern, subnet
- owner_email, owner_name, department, business_unit, location
- source_system, confidence
- extra: Dict[str, Any]

---

## Dependencies Available

Core (always installed):
- pandas, pydantic, httpx

Optional (per connector):
- qualys: qualysapi
- tenable: pytenable
- servicenow: pysnc
- netbox: pynetbox
- infoblox: infoblox-client
- ldap: ldap3
- aws: boto3
- azure: azure-identity, azure-mgmt-resource
- gcp: google-cloud-asset

---

## Code Style

- Line length: 100
- Formatter: black
- Linter: ruff
- Type hints: Required
- Docstrings: Google style

---

## Important Notes

1. All connectors are STUBS - implement with `raise NotImplementedError("Community contribution welcome!")`
2. Provide complete usage example in docstring
3. List API endpoints in ENDPOINTS dict
4. Include link to official API docs
5. Handle authentication properly (basic, api_key, oauth2)
6. Use httpx for HTTP clients
7. Return normalized models (ParsedVulnerability, ParsedAsset, ParsedOwnerMapping)
8. Include rate limit info

---

## Run Order

Execute tasks in this order:
1. Tasks 1-3 (CMDB)
2. Tasks 4-7 (IPAM)
3. Tasks 8-10 (Directory)
4. Tasks 11-14 (Cloud)
5. Task 15 (File Parsers)
6. Task 16 (Auto-Detector)
7. Tasks 17-18 (Exports and Main)
8. Tasks 19-20 (Docs)
9. Tasks 21-22 (Tests and Changelog)

---

## When Complete

After all tasks:
1. Run `pip install -e ".[dev]"` to install
2. Run `pytest` to verify tests pass
3. Run `black src tests` to format
4. Run `ruff check src tests` to lint
5. Commit and push


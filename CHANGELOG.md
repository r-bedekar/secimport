# Changelog

All notable changes to this project will be documented in this file.

## [0.1.0] - 2026-02-21

### Added

- **Models**: `ParsedVulnerability`, `ParsedAsset`, `ParsedOwnerMapping`, `ParseResult`
- **Normalizers**: Severity normalization across Qualys, Nessus, Tenable, Rapid7, OpenVAS
- **Connector infrastructure**: `BaseConnector`, `ConnectorRegistry`, `ConnectionConfig`, `AuthConfig`
- **Scanner connectors**: Qualys, Nessus, Tenable, Rapid7, OpenVAS, CrowdStrike (stubs)
- **CMDB connectors**: ServiceNow, BMC Helix (stubs)
- **IPAM connectors**: Infoblox, NetBox, SolarWinds (stubs)
- **Directory connectors**: Active Directory, Azure AD (stubs)
- **Cloud connectors**: AWS, Azure, GCP (stubs)
- **Parser infrastructure**: `BaseParser`, `ParserRegistry`, column mapping, auto-detection
- **Vulnerability parsers**: Qualys, Nessus, Tenable, Rapid7, CrowdStrike, OpenVAS, Generic
- **Asset parsers**: Generic CSV, ServiceNow CMDB
- **Owner parsers**: Generic CSV, IPAM
- **Auto-detector**: `parse_file()`, `detect_source()`, `detect_parser()`
- 91 tests covering models, normalizers, connectors, parsers, and detection

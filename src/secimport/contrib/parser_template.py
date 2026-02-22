# """
# Template for creating a new secimport file parser.
#
# Copy this file and fill in the blanks to add a new CSV/Excel parser.
#
# Steps:
#     1. Copy this file to src/secimport/parsers/<name>.py
#     2. Rename the class and fill in ClassVar metadata
#     3. Define COLUMN_MAP and REQUIRED_COLUMNS
#     4. Implement _parse_row()
#     5. Add the import to src/secimport/parsers/__init__.py
#     6. The parser auto-registers on import -- detection works automatically
#
# See the Qualys or Nessus parsers for real examples.
# """
#
# from typing import Any, ClassVar, Dict, Set
#
# from secimport.models.base import ParsedVulnerability
# from secimport.parsers.base import BaseParser
#
#
# class MyNewParser(BaseParser):
#     """Parser for <Vendor> <Product> CSV/Excel exports."""
#
#     # -- Class-level metadata (required) --
#     name: ClassVar[str] = "my_new_parser"
#     source: ClassVar[str] = "my_source"
#     data_type: ClassVar[str] = "vulnerability"
#
#     # Columns that MUST be present for detection to succeed
#     REQUIRED_COLUMNS: ClassVar[Set[str]] = {
#         "vulnerability_id",
#         "asset_name",
#         "severity",
#     }
#
#     # Map source columns -> normalized model fields
#     COLUMN_MAP: ClassVar[Dict[str, str]] = {
#         "vulnerability_id": "scanner_id",
#         "asset_name": "hostname",
#         "severity": "severity",
#         "description": "description",
#         "cvss_score": "cvss_score",
#     }
#
#     def _parse_row(self, mapped: Dict[str, Any]) -> ParsedVulnerability:
#         """Convert a single mapped row to a normalized model."""
#         return ParsedVulnerability(
#             scanner_id=mapped.get("scanner_id"),
#             title=mapped.get("scanner_id", "Unknown"),
#             hostname=mapped.get("hostname"),
#             severity=mapped.get("severity", "Low"),
#             cvss_score=(
#                 float(mapped["cvss_score"]) if mapped.get("cvss_score") else None
#             ),
#             description=mapped.get("description"),
#             source_system=self.source,
#         )

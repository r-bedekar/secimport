# """
# Template for creating a new secimport connector.
#
# Copy this file and fill in the blanks to add a new connector.
#
# Steps:
#     1. Copy this file to src/secimport/connectors/<category>/<name>.py
#     2. Rename the class and fill in ClassVar metadata
#     3. Implement _auth_headers() and data methods
#     4. Add the import to your category's __init__.py
#     5. The connector auto-registers on import -- no extra wiring needed
#
# See the Splunk or CrowdStrike Falcon connectors for real examples.
# """
#
# from datetime import datetime
# from typing import Any, ClassVar, Dict, Iterator, Optional, Tuple
#
# from secimport.connectors.base import BaseConnector
# from secimport.models.base import ParsedAsset
#
#
# class MyNewConnector(BaseConnector):
#     """
#     <Vendor> <Product> connector.
#
#     API Docs: https://docs.example.com/api
#     """
#
#     # -- Class-level metadata (required) --
#     name: ClassVar[str] = "my_new_connector"
#     vendor: ClassVar[str] = "Acme Corp"
#     description: ClassVar[str] = "Acme Widget Scanner"
#     auth_types: ClassVar[Tuple[str, ...]] = ("api_key",)
#
#     # Endpoint used by BaseConnector.test_connection()
#     _test_endpoint: ClassVar[str] = "/api/v1/status"
#
#     # API endpoints used by data methods
#     ENDPOINTS: ClassVar[Dict[str, str]] = {
#         "assets": "/api/v1/assets",
#         "vulns": "/api/v1/vulnerabilities",
#     }
#
#     # -- Auth headers --
#     def _auth_headers(self) -> Dict[str, str]:
#         """Return headers for authenticated requests."""
#         return {"X-API-Key": self.auth.credentials.get("api_key", "")}
#
#     # -- Data methods (implement the ones your source supports) --
#     def get_assets(
#         self,
#         limit: Optional[int] = None,
#         since: Optional[datetime] = None,
#     ) -> Iterator[ParsedAsset]:
#         """
#         Fetch assets from the API.
#
#         Use self._client.get() for HTTP requests.
#         Use self._paginate_offset() for paginated endpoints.
#         """
#         raise NotImplementedError("TODO: implement")
#
#     # -- Parse helper --
#     def _parse_asset(self, raw: Dict[str, Any]) -> ParsedAsset:
#         """Map a raw API record to a normalized ParsedAsset."""
#         return ParsedAsset(
#             hostname=raw.get("hostname"),
#             ip_address=raw.get("ip"),
#             source_system=self.name,
#             extra=raw,
#         )

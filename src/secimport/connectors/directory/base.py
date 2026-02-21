"""
Base class for directory service connectors.

Extend this for: Active Directory, Azure AD / Entra ID, LDAP, Okta, etc.
"""

from abc import abstractmethod
from typing import Any, Dict, Iterator, Optional

from ...models.base import ParsedAsset
from ..base import BaseConnector


class BaseDirectoryConnector(BaseConnector):
    """
    Base class for all directory service API connectors.

    Inherits connection plumbing (``connect``, ``test_connection``,
    ``disconnect``, auth hooks) from ``BaseConnector``.

    Subclass contract:
        * Override ``_auth_headers`` / ``_test_endpoint`` as needed.
        * Implement ``get_users``, ``get_groups``, ``get_computers``, ``search``.
        * Implement ``_parse_computer`` to map raw directory data to the model.
    """

    # -- abstract data methods -------------------------------------------------

    @abstractmethod
    def get_users(
        self,
        limit: Optional[int] = None,
        search_filter: Optional[str] = None,
    ) -> Iterator[Dict[str, Any]]:
        """
        Get users from the directory service.

        Args:
            limit: Maximum number of users to return.
            search_filter: Optional filter string (LDAP filter, OData, etc.).

        Yields:
            User attribute dicts from the directory.
        """
        ...

    @abstractmethod
    def get_groups(
        self,
        limit: Optional[int] = None,
    ) -> Iterator[Dict[str, Any]]:
        """
        Get groups from the directory service.

        Args:
            limit: Maximum number of groups to return.

        Yields:
            Group attribute dicts from the directory.
        """
        ...

    @abstractmethod
    def get_computers(
        self,
        limit: Optional[int] = None,
    ) -> Iterator[ParsedAsset]:
        """
        Get computer / device objects from the directory.

        Args:
            limit: Maximum number of computers to return.

        Yields:
            ``ParsedAsset`` objects representing directory computer entries.
        """
        ...

    @abstractmethod
    def search(
        self,
        query: str,
        limit: Optional[int] = None,
    ) -> Iterator[Dict[str, Any]]:
        """
        Run a free-form search against the directory.

        Args:
            query: Search query (LDAP filter, OData query, etc.).
            limit: Maximum number of results to return.

        Yields:
            Matching directory entry dicts.
        """
        ...

    # -- parse helper ----------------------------------------------------------

    @abstractmethod
    def _parse_computer(self, raw: Dict[str, Any]) -> ParsedAsset:
        """Map a single raw directory record to ``ParsedAsset``."""
        ...

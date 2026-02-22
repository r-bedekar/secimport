"""
Reusable pagination patterns for API connectors.

Provides offset-based, cursor-based, and token-based pagination
so that concrete connectors declare their pagination style rather
than re-implementing loop logic.
"""

import logging
from typing import Any, Dict, Iterator, Optional

logger = logging.getLogger("secimport.connectors.pagination")


class PaginationMixin:
    """
    Mixin providing reusable pagination helpers.

    Requires ``self._client`` (httpx.Client) to be set before use.
    Typically inherited by ``BaseConnector`` so all connectors can
    call ``self._paginate_*()`` in their data methods.
    """

    def _paginate_offset(
        self,
        endpoint: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        limit_param: str = "limit",
        offset_param: str = "offset",
        page_size: int = 100,
        max_results: Optional[int] = None,
        results_key: Optional[str] = None,
    ) -> Iterator[Dict[str, Any]]:
        """
        Paginate using offset/limit parameters.

        Args:
            endpoint: API endpoint path.
            params: Base query parameters.
            limit_param: Name of the limit query param.
            offset_param: Name of the offset query param.
            page_size: Number of records per page.
            max_results: Stop after this many total records.
            results_key: JSON key containing the results array.
                If None, the response is expected to be a list.

        Yields:
            Individual result dicts.
        """
        params = dict(params or {})
        offset = 0
        total_yielded = 0

        while True:
            params[limit_param] = page_size
            params[offset_param] = offset

            response = self._client.get(endpoint, params=params)  # type: ignore[union-attr]
            response.raise_for_status()
            data = response.json()

            items = data[results_key] if results_key else data
            if not items:
                break

            for item in items:
                yield item
                total_yielded += 1
                if max_results and total_yielded >= max_results:
                    return

            if len(items) < page_size:
                break
            offset += page_size

    def _paginate_cursor(
        self,
        endpoint: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        cursor_param: str = "cursor",
        cursor_response_key: str = "next_cursor",
        page_size: int = 100,
        max_results: Optional[int] = None,
        results_key: Optional[str] = None,
    ) -> Iterator[Dict[str, Any]]:
        """
        Paginate using cursor-based pagination.

        Args:
            endpoint: API endpoint path.
            params: Base query parameters.
            cursor_param: Query parameter name for the cursor.
            cursor_response_key: JSON key containing the next cursor value.
            page_size: Number of records per page.
            max_results: Stop after this many total records.
            results_key: JSON key containing the results array.

        Yields:
            Individual result dicts.
        """
        params = dict(params or {})
        params["limit"] = page_size
        total_yielded = 0
        cursor: Optional[str] = None

        while True:
            if cursor:
                params[cursor_param] = cursor

            response = self._client.get(endpoint, params=params)  # type: ignore[union-attr]
            response.raise_for_status()
            data = response.json()

            items = data[results_key] if results_key else data
            if not items:
                break

            for item in items:
                yield item
                total_yielded += 1
                if max_results and total_yielded >= max_results:
                    return

            cursor = data.get(cursor_response_key)
            if not cursor:
                break

    def _paginate_token(
        self,
        endpoint: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        token_param: str = "next_token",
        token_response_key: str = "next_token",
        page_size: int = 100,
        max_results: Optional[int] = None,
        results_key: Optional[str] = None,
    ) -> Iterator[Dict[str, Any]]:
        """
        Paginate using token-based pagination (AWS style).

        Args:
            endpoint: API endpoint path.
            params: Base query parameters.
            token_param: Query parameter name for the continuation token.
            token_response_key: JSON key containing the next token.
            page_size: Number of records per page.
            max_results: Stop after this many total records.
            results_key: JSON key containing the results array.

        Yields:
            Individual result dicts.
        """
        params = dict(params or {})
        params["limit"] = page_size
        total_yielded = 0
        token: Optional[str] = None

        while True:
            if token:
                params[token_param] = token

            response = self._client.get(endpoint, params=params)  # type: ignore[union-attr]
            response.raise_for_status()
            data = response.json()

            items = data[results_key] if results_key else data
            if not items:
                break

            for item in items:
                yield item
                total_yielded += 1
                if max_results and total_yielded >= max_results:
                    return

            token = data.get(token_response_key)
            if not token:
                break

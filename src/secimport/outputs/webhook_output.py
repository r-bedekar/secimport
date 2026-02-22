"""Webhook output sink."""

import json
from typing import Any, Dict, Iterator, Optional

from .base import BaseOutput


class WebhookOutput(BaseOutput):
    """POST enriched assets to a webhook URL."""

    output_type = "webhook"

    def __init__(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        batch_size: int = 100,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self.url = url
        self.headers = headers or {"Content-Type": "application/json"}
        self.batch_size = batch_size

    def write(self, records: Iterator[Dict[str, Any]]) -> int:
        import httpx

        count = 0
        batch: list[Dict[str, Any]] = []

        for record in records:
            batch.append(record)
            if len(batch) >= self.batch_size:
                self._send_batch(batch, httpx)
                count += len(batch)
                batch = []

        if batch:
            self._send_batch(batch, httpx)
            count += len(batch)

        return count

    def _send_batch(self, batch: list[Dict[str, Any]], httpx: Any) -> None:
        """Send a batch of records to the webhook."""
        response = httpx.post(
            self.url,
            headers=self.headers,
            content=json.dumps(batch, default=str),
            timeout=30,
        )
        response.raise_for_status()

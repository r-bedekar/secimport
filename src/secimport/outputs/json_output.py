"""JSON file output sink."""

import json
from pathlib import Path
from typing import Any, Dict, Iterator

from .base import BaseOutput


class JSONOutput(BaseOutput):
    """Write enriched assets to a JSON file."""

    output_type = "json"

    def __init__(self, path: str, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.path = Path(path)

    def write(self, records: Iterator[Dict[str, Any]]) -> int:
        items = list(records)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps(items, indent=2, default=str),
            encoding="utf-8",
        )
        return len(items)

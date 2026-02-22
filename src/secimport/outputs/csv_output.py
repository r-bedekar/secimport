"""CSV file output sink."""

import csv
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from .base import BaseOutput


class CSVOutput(BaseOutput):
    """Write enriched assets to a CSV file."""

    output_type = "csv"

    def __init__(self, path: str, columns: Optional[List[str]] = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.path = Path(path)
        self.columns = columns

    def write(self, records: Iterator[Dict[str, Any]]) -> int:
        items = list(records)
        if not items:
            return 0

        self.path.parent.mkdir(parents=True, exist_ok=True)
        fieldnames = self.columns or sorted(items[0].keys())

        with self.path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for item in items:
                writer.writerow(item)

        return len(items)

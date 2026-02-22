"""Stdout output sink."""

import json
import sys
from typing import Any, Dict, Iterator

from .base import BaseOutput


class StdoutOutput(BaseOutput):
    """Print enriched assets to stdout as JSON lines."""

    output_type = "stdout"

    def __init__(self, pretty: bool = False, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.pretty = pretty

    def write(self, records: Iterator[Dict[str, Any]]) -> int:
        count = 0
        for record in records:
            if self.pretty:
                json.dump(record, sys.stdout, indent=2, default=str)
            else:
                json.dump(record, sys.stdout, default=str)
            sys.stdout.write("\n")
            count += 1
        return count

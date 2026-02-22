"""Output sinks for enriched data."""

from .base import BaseOutput, OutputRegistry
from .csv_output import CSVOutput
from .json_output import JSONOutput
from .stdout_output import StdoutOutput
from .webhook_output import WebhookOutput

__all__ = [
    "BaseOutput",
    "CSVOutput",
    "JSONOutput",
    "OutputRegistry",
    "StdoutOutput",
    "WebhookOutput",
]

"""Owner mapping file parsers."""

from .csv_generic import GenericOwnerParser
from .ipam import IPAMOwnerParser

__all__ = [
    "GenericOwnerParser",
    "IPAMOwnerParser",
]

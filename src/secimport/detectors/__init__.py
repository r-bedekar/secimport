"""Auto-detection of data source and type from file columns."""

from .auto_detect import detect_all, detect_data_type, detect_parser, detect_source, parse_file

__all__ = [
    "detect_all",
    "detect_data_type",
    "detect_parser",
    "detect_source",
    "parse_file",
]

"""
Auto-detection of data source and type from file columns.

Scans all registered parsers and picks the best match based on
column-name fingerprinting. Community contributors: your parser
is automatically included when its module is imported.
"""

import logging
from pathlib import Path
from typing import Iterator, List, Optional, Tuple, Type, Union

from pydantic import BaseModel

from ..models.base import ParseResult
from ..parsers.base import BaseParser, ParserRegistry

logger = logging.getLogger("secimport.detectors")

# Minimum confidence to consider a parser a match
_MIN_CONFIDENCE = 0.5


def detect_parser(
    file_path: Union[str, Path],
    *,
    data_type: Optional[str] = None,
) -> Optional[Type[BaseParser]]:
    """
    Detect the best parser for a file based on its column headers.

    Args:
        file_path: Path to the CSV/Excel file.
        data_type: Optionally restrict to a data type
                   (``"vulnerability"``, ``"asset"``, ``"owner"``).

    Returns:
        The best matching parser class, or None if no match above threshold.
    """
    columns = BaseParser.get_columns(file_path)
    if not columns:
        logger.warning("No columns found in %s", file_path)
        return None

    if data_type:
        candidates = ParserRegistry.by_data_type(data_type)
    else:
        candidates = ParserRegistry.list_parsers()

    best_parser: Optional[Type[BaseParser]] = None
    best_score = 0.0

    for name, parser_cls in candidates.items():
        score = parser_cls.detect(columns)
        logger.debug("detect: %s scored %.2f for %s", name, score, file_path)
        if score > best_score:
            best_score = score
            best_parser = parser_cls

    if best_score >= _MIN_CONFIDENCE:
        logger.info(
            "Detected %s (confidence=%.2f) for %s",
            best_parser.name if best_parser else "none",
            best_score,
            file_path,
        )
        return best_parser

    logger.warning(
        "No parser matched %s above threshold (best=%.2f)", file_path, best_score
    )
    return None


def detect_source(file_path: Union[str, Path]) -> Optional[str]:
    """
    Detect the source system name for a file.

    Returns:
        Source name string (e.g. "qualys", "nessus") or None.
    """
    parser = detect_parser(file_path)
    return parser.source if parser else None


def detect_data_type(file_path: Union[str, Path]) -> Optional[str]:
    """
    Detect the data type for a file.

    Returns:
        Data type string ("vulnerability", "asset", "owner") or None.
    """
    parser = detect_parser(file_path)
    return parser.data_type if parser else None


def detect_all(
    file_path: Union[str, Path],
) -> List[Tuple[Type[BaseParser], float]]:
    """
    Return all parsers with their confidence scores, sorted highest first.

    Useful for debugging or presenting choices to the user.
    """
    columns = BaseParser.get_columns(file_path)
    if not columns:
        return []

    results = []
    for _name, parser_cls in ParserRegistry.list_parsers().items():
        score = parser_cls.detect(columns)
        if score > 0:
            results.append((parser_cls, score))

    results.sort(key=lambda x: x[1], reverse=True)
    return results


def parse_file(
    file_path: Union[str, Path],
    *,
    parser_name: Optional[str] = None,
    data_type: Optional[str] = None,
    sheet_name: Optional[str] = None,
) -> Tuple[Iterator[BaseModel], ParseResult]:
    """
    Auto-detect and parse a file, returning results and metadata.

    This is the main entry point for file parsing. It detects the
    parser, parses the file, and returns both the data iterator
    and a ParseResult summary.

    Args:
        file_path: Path to the CSV/Excel file.
        parser_name: Force a specific parser by name (skip detection).
        data_type: Hint for detection ("vulnerability", "asset", "owner").
        sheet_name: For Excel files, which sheet to read.

    Returns:
        Tuple of (data iterator, ParseResult metadata).

    Raises:
        ValueError: If no parser can be detected or found.
    """
    path = Path(file_path)

    # Resolve parser
    if parser_name:
        parser_cls = ParserRegistry.get(parser_name)
        if not parser_cls:
            raise ValueError(
                f"Unknown parser {parser_name!r}. "
                f"Available: {list(ParserRegistry.list_parsers().keys())}"
            )
    else:
        parser_cls = detect_parser(path, data_type=data_type)
        if not parser_cls:
            raise ValueError(
                f"Could not detect parser for {path}. "
                f"Use parser_name= to specify one explicitly."
            )

    parser = parser_cls()
    result = ParseResult(
        source_type=parser.source,
        data_type=parser.data_type,
        file_path=str(path),
    )

    def _counting_iterator() -> Iterator[BaseModel]:
        """Wrap parser output to count successes and errors."""
        for item in parser.parse(path, sheet_name=sheet_name):
            result.parsed_count += 1
            result.total_rows += 1
            yield item

    return _counting_iterator(), result

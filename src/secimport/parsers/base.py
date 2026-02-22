"""
Base parser class for all file parsers.

All parsers inherit from BaseParser and implement detect() + parse().
Community contributors: Create a new file in the appropriate folder
and implement these methods for your data source.
"""

import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, ClassVar, Dict, Iterator, List, Optional, Tuple, Type, Union

import pandas as pd
from pydantic import BaseModel

logger = logging.getLogger("secimport.parsers")


class ParserRegistry:
    """
    Registry for discovering available parsers.

    Parsers are auto-registered when their module is imported.
    Use ``ParserRegistry.list_parsers()`` to discover all loaded parsers.
    """

    _parsers: Dict[str, Type["BaseParser"]] = {}

    @classmethod
    def register(cls, parser_cls: Type["BaseParser"]) -> Type["BaseParser"]:
        """Register a parser class by its ``name``."""
        cls._parsers[parser_cls.name] = parser_cls
        return parser_cls

    @classmethod
    def get(cls, name: str) -> Optional[Type["BaseParser"]]:
        """Look up a parser by name."""
        return cls._parsers.get(name)

    @classmethod
    def list_parsers(cls) -> Dict[str, Type["BaseParser"]]:
        """Return all registered parsers."""
        return dict(cls._parsers)

    @classmethod
    def by_data_type(cls, data_type: str) -> Dict[str, Type["BaseParser"]]:
        """Return parsers filtered by data_type (vulnerability, asset, owner)."""
        return {
            name: p
            for name, p in cls._parsers.items()
            if p.data_type == data_type
        }


class BaseParser(ABC):
    """
    Abstract base class for all file parsers.

    Provides shared file-reading logic (CSV/Excel) and detection
    infrastructure so concrete parsers only declare their unique
    column mapping and detection columns.

    Subclass contract:
        * Set ``name``, ``source``, ``data_type``, ``description``.
        * Set ``COLUMN_MAPPING`` to map source columns -> model fields.
        * Set ``DETECTION_COLUMNS`` for auto-detection fingerprinting.
        * Implement ``_parse_row`` to convert a row dict to a model instance.

    Example::

        class MyParser(BaseParser):
            name = "my_scanner_vuln"
            source = "my_scanner"
            data_type = "vulnerability"
            description = "My Scanner vulnerability CSV parser"
            DETECTION_COLUMNS = ("Plugin ID", "Risk", "Host")
            COLUMN_MAPPING = {"Plugin ID": "scanner_id", "Risk": "severity"}

            def _parse_row(self, row: Dict[str, Any]) -> ParsedVulnerability:
                ...
    """

    # -- class-level metadata (override in subclasses) -------------------------

    name: ClassVar[str] = "base"
    source: ClassVar[str] = "unknown"
    data_type: ClassVar[str] = "unknown"  # vulnerability, asset, owner
    description: ClassVar[str] = "Base parser"

    #: Columns that fingerprint this source (used for auto-detection).
    DETECTION_COLUMNS: ClassVar[Tuple[str, ...]] = ()

    #: Map source column names -> model field names.
    COLUMN_MAPPING: ClassVar[Dict[str, str]] = {}

    # -- auto-registration -----------------------------------------------------

    def __init_subclass__(cls, **kwargs: Any) -> None:
        """Auto-register concrete parsers."""
        super().__init_subclass__(**kwargs)
        if isinstance(cls.DETECTION_COLUMNS, list):
            cls.DETECTION_COLUMNS = tuple(cls.DETECTION_COLUMNS)
        if not getattr(cls, "__abstractmethods__", None) and cls.name != "base":
            ParserRegistry.register(cls)

    # -- detection -------------------------------------------------------------

    @classmethod
    def detect(cls, columns: List[str]) -> float:
        """
        Return confidence (0.0-1.0) that the given columns match this parser.

        Default implementation checks what fraction of DETECTION_COLUMNS
        appear in the provided column list (case-insensitive).
        Override for more sophisticated detection.

        Args:
            columns: Column names from the file header.

        Returns:
            Confidence score between 0.0 and 1.0.
        """
        if not cls.DETECTION_COLUMNS:
            return 0.0
        columns_lower = {c.lower().strip() for c in columns}
        matches = sum(
            1 for dc in cls.DETECTION_COLUMNS if dc.lower().strip() in columns_lower
        )
        return matches / len(cls.DETECTION_COLUMNS)

    # -- file reading ----------------------------------------------------------

    @staticmethod
    def read_file(
        file_path: Union[str, Path],
        *,
        sheet_name: Optional[str] = None,
    ) -> pd.DataFrame:
        """
        Read a CSV or Excel file into a DataFrame.

        Auto-detects format by extension (.csv, .xlsx, .xls).

        Args:
            file_path: Path to the file.
            sheet_name: For Excel files, which sheet to read.

        Returns:
            pandas DataFrame with the file contents.
        """
        path = Path(file_path)
        suffix = path.suffix.lower()

        if suffix == ".csv":
            return pd.read_csv(path, dtype=str, keep_default_na=False)
        elif suffix in (".xlsx", ".xls"):
            return pd.read_excel(
                path, sheet_name=sheet_name or 0, dtype=str, keep_default_na=False
            )
        else:
            # Try CSV as fallback
            logger.warning("Unknown extension %s, trying CSV", suffix)
            return pd.read_csv(path, dtype=str, keep_default_na=False)

    @staticmethod
    def get_columns(file_path: Union[str, Path]) -> List[str]:
        """Read only the header row and return column names."""
        path = Path(file_path)
        suffix = path.suffix.lower()

        if suffix == ".csv":
            df = pd.read_csv(path, nrows=0)
        elif suffix in (".xlsx", ".xls"):
            df = pd.read_excel(path, nrows=0)
        else:
            df = pd.read_csv(path, nrows=0)

        return list(df.columns)

    # -- mapped row helper -----------------------------------------------------

    def _map_columns(self, row: Dict[str, Any]) -> Dict[str, Any]:
        """
        Apply COLUMN_MAPPING to a row dict, renaming source columns
        to model field names. Unmapped columns go into 'extra'.
        """
        mapped: Dict[str, Any] = {}
        extra: Dict[str, Any] = {}

        # Build case-insensitive lookup for column mapping
        mapping_lower = {k.lower(): v for k, v in self.COLUMN_MAPPING.items()}

        for col, value in row.items():
            target = mapping_lower.get(col.lower().strip())
            if target:
                mapped[target] = value
            else:
                extra[col] = value

        mapped["extra"] = extra
        return mapped

    # -- parsing ---------------------------------------------------------------

    @abstractmethod
    def _parse_row(self, row: Dict[str, Any]) -> BaseModel:
        """Convert a single mapped row dict to the appropriate model instance."""
        ...

    def parse(
        self,
        file_path: Union[str, Path],
        *,
        sheet_name: Optional[str] = None,
        result: Optional[Any] = None,
    ) -> Iterator[BaseModel]:
        """
        Parse a file and yield normalized model instances.

        Reads the file, applies column mapping, and delegates each row
        to ``_parse_row``. Logs and skips rows that fail to parse.

        Args:
            file_path: Path to the CSV/Excel file.
            sheet_name: For Excel files, which sheet to read.
            result: Optional ``ParseResult`` to track row counts and errors.

        Yields:
            Pydantic model instances (ParsedVulnerability, ParsedAsset, etc.)
        """
        df = self.read_file(file_path, sheet_name=sheet_name)
        logger.info(
            "%s: parsing %d rows from %s", self.name, len(df), file_path
        )

        for idx, row in df.iterrows():
            if result is not None:
                result.total_rows += 1
            try:
                mapped = self._map_columns(row.to_dict())
                item = self._parse_row(mapped)
                if result is not None:
                    result.parsed_count += 1
                yield item
            except Exception as exc:
                logger.warning(
                    "%s: failed to parse row %d: %s", self.name, idx, exc
                )
                if result is not None:
                    result.error_count += 1
                    result.errors.append(f"Row {idx}: {exc}")

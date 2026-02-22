"""
Base output sink and registry.

All output sinks auto-register via ``__init_subclass__``.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Iterator, Optional, Type


class OutputRegistry:
    """Registry of available output sinks."""

    _registry: Dict[str, Type["BaseOutput"]] = {}

    @classmethod
    def register(cls, name: str, output_cls: Type["BaseOutput"]) -> None:
        cls._registry[name] = output_cls

    @classmethod
    def get(cls, name: str) -> Optional[Type["BaseOutput"]]:
        return cls._registry.get(name)

    @classmethod
    def list_outputs(cls) -> Dict[str, Type["BaseOutput"]]:
        return dict(cls._registry)


class BaseOutput(ABC):
    """
    Base class for output sinks.

    Subclasses must define ``output_type`` and implement ``write()``.
    """

    output_type: str = ""

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if cls.output_type:
            OutputRegistry.register(cls.output_type, cls)

    def __init__(self, options: Optional[Dict[str, Any]] = None) -> None:
        self.options = options or {}

    @abstractmethod
    def write(self, records: Iterator[Dict[str, Any]]) -> int:
        """
        Write enriched asset records to the output.

        Args:
            records: Iterator of dict-serialized EnrichedAsset records.

        Returns:
            Number of records written.
        """
        ...

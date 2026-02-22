"""
Plugin discovery for third-party connectors and parsers.

Third-party packages can register connectors and parsers by declaring
entry points in their ``pyproject.toml``::

    [project.entry-points."secimport.connectors"]
    my_connector = "my_package.connector:MyConnector"

    [project.entry-points."secimport.parsers"]
    my_parser = "my_package.parser:MyParser"

Call ``discover_plugins()`` at startup to load all installed plugins.
"""

import importlib.metadata
import logging
from typing import Dict, List

logger = logging.getLogger("secimport.plugins")

CONNECTOR_GROUP = "secimport.connectors"
PARSER_GROUP = "secimport.parsers"


def discover_plugins() -> Dict[str, List[str]]:
    """
    Discover and load all installed secimport plugins.

    Scans Python entry points for ``secimport.connectors`` and
    ``secimport.parsers`` groups. Each entry point is loaded,
    which triggers auto-registration via ``__init_subclass__``.

    Returns:
        Dict with keys 'connectors' and 'parsers', each containing
        a list of successfully loaded plugin names.
    """
    loaded: Dict[str, List[str]] = {"connectors": [], "parsers": []}

    for group, key in [(CONNECTOR_GROUP, "connectors"), (PARSER_GROUP, "parsers")]:
        eps = importlib.metadata.entry_points()
        # Python 3.12+ returns a SelectableGroups; 3.10-3.11 returns dict
        if hasattr(eps, "select"):
            entries = eps.select(group=group)
        elif isinstance(eps, dict):
            entries = eps.get(group, [])
        else:
            entries = [ep for ep in eps if ep.group == group]

        for ep in entries:
            try:
                ep.load()  # Importing triggers auto-registration
                loaded[key].append(ep.name)
                logger.info("Loaded plugin: %s (%s)", ep.name, group)
            except Exception as exc:
                logger.warning(
                    "Failed to load plugin %s from %s: %s",
                    ep.name,
                    group,
                    exc,
                )

    return loaded

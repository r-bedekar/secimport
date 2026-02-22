"""
Ingestion runner — orchestrates multi-source ingestion and enrichment.

Reads a config file, instantiates connectors and outputs, feeds data
through the correlator, and writes enriched assets to outputs.
"""

import logging
from pathlib import Path

from .config.loader import OutputConfig, SecimportConfig, SourceConfig, load_config
from .connectors.base import AuthConfig, ConnectionConfig, ConnectorRegistry
from .enrichment.correlator import AssetCorrelator
from .outputs.base import OutputRegistry

logger = logging.getLogger("secimport.runner")


class IngestionRunner:
    """
    Orchestrates the full ingestion pipeline.

    1. Read config → instantiate sources
    2. Ingest data → feed correlator
    3. Optionally deduplicate
    4. Write enriched assets to outputs
    """

    def __init__(self, config: SecimportConfig) -> None:
        self.config = config
        self.correlator = AssetCorrelator()

    @classmethod
    def from_config(cls, path: str | Path) -> "IngestionRunner":
        """Create a runner from a YAML config file."""
        config = load_config(path)
        return cls(config)

    def run(self) -> None:
        """Execute the full ingestion pipeline."""
        # Ingest from all sources
        for source_cfg in self.config.sources:
            try:
                self._ingest_source(source_cfg)
            except Exception as exc:
                logger.error("Failed to ingest from %s: %s", source_cfg.name, exc)

        # Deduplicate if configured
        if self.config.enrichment.deduplicate:
            merges = self.correlator.deduplicate()
            if merges:
                logger.info("Deduplicated %d asset pairs", merges)

        # Write to outputs
        for output_cfg in self.config.outputs:
            try:
                self._write_output(output_cfg)
            except Exception as exc:
                logger.error("Failed to write output %s: %s", output_cfg.type, exc)

        logger.info(
            "Pipeline complete: %d enriched assets", self.correlator.asset_count
        )

    def _ingest_source(self, source_cfg: "SourceConfig") -> None:
        """Ingest data from a single configured source."""

        connector_cls = ConnectorRegistry.get(source_cfg.connector)
        if connector_cls is None:
            logger.warning(
                "Unknown connector: %s (skipping %s)",
                source_cfg.connector,
                source_cfg.name,
            )
            return

        conn_config = ConnectionConfig(
            base_url=source_cfg.base_url,
            verify_ssl=source_cfg.verify_ssl,
            timeout=source_cfg.timeout,
            max_retries=source_cfg.max_retries,
        )
        auth_config = AuthConfig(
            auth_type=source_cfg.auth_type,
            credentials=source_cfg.credentials,
        )

        connector = connector_cls(conn_config, auth_config)

        with connector:
            # Try to ingest assets or endpoints depending on connector type
            count = 0
            if hasattr(connector, "get_endpoints"):
                try:
                    count += self.correlator.ingest_endpoints(
                        connector.get_endpoints()
                    )
                except NotImplementedError:
                    pass

            if hasattr(connector, "get_assets"):
                try:
                    count += self.correlator.ingest_assets(
                        connector.get_assets()
                    )
                except NotImplementedError:
                    pass

            if hasattr(connector, "get_devices"):
                try:
                    count += self.correlator.ingest_network_observations(
                        connector.get_devices()
                    )
                except NotImplementedError:
                    pass

            logger.info(
                "Ingested %d records from %s (%s)",
                count,
                source_cfg.name,
                source_cfg.connector,
            )

    def _write_output(self, output_cfg: "OutputConfig") -> None:
        """Write enriched assets to a single output."""

        output_cls = OutputRegistry.get(output_cfg.type)
        if output_cls is None:
            logger.warning("Unknown output type: %s", output_cfg.type)
            return

        # Build output instance
        kwargs = dict(output_cfg.options)
        if output_cfg.path:
            kwargs["path"] = output_cfg.path
        if output_cfg.url:
            kwargs["url"] = output_cfg.url

        output = output_cls(**kwargs)

        # Serialize enriched assets to dicts
        def _records():
            for asset in self.correlator.get_enriched_assets():
                yield asset.model_dump(exclude_none=True)

        count = output.write(_records())
        logger.info("Wrote %d records to %s output", count, output_cfg.type)

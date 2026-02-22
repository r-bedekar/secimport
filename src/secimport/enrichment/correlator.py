"""
Asset correlator — merges records from multiple sources into enriched assets.

The correlator maintains in-memory indexes on hostnames, IPs, MACs,
serial numbers, and agent IDs. As records are ingested, it attempts
to match them to existing enriched assets. When a match is found,
fields are merged with provenance tracking. When no match is found,
a new enriched asset is created.
"""

from typing import Iterator, List, Optional

from ..models.base import (
    ParsedAsset,
    ParsedEndpoint,
    ParsedNetworkObservation,
    ParsedOwnerMapping,
    ParsedVulnerability,
)
from ..normalizers.hostname import normalize_hostname, normalize_ip, normalize_mac
from .models import CorrelationKey, EnrichedAsset, GapReport, MatchResult
from .scoring import MatchWeights, SourceConfidence


class AssetCorrelator:
    """
    Correlates and enriches assets from multiple security sources.

    Usage::

        correlator = AssetCorrelator()
        correlator.ingest_assets(scanner_assets)
        correlator.ingest_endpoints(edr_endpoints)
        correlator.ingest_vulnerabilities(vulns)

        for enriched in correlator.get_enriched_assets():
            print(enriched.hostname, enriched.present_in_sources)

        gap = correlator.gap_analysis("crowdstrike", "qualys")
        print(f"In EDR but not scanner: {len(gap.in_a_not_b)}")
    """

    def __init__(self) -> None:
        self._assets: List[EnrichedAsset] = []
        # Indexes: identifier_value -> list of asset indexes
        self._hostname_idx: dict[str, list[int]] = {}
        self._ip_idx: dict[str, list[int]] = {}
        self._mac_idx: dict[str, list[int]] = {}
        self._serial_idx: dict[str, list[int]] = {}
        self._agent_id_idx: dict[str, list[int]] = {}

    @property
    def asset_count(self) -> int:
        """Number of unique enriched assets."""
        return len(self._assets)

    # -- Ingestion Methods ---------------------------------------------------

    def ingest_assets(self, assets: Iterator[ParsedAsset]) -> int:
        """
        Ingest parsed assets (from scanners, CMDB, IPAM, cloud).

        Returns the number of records ingested.
        """
        count = 0
        for asset in assets:
            source = asset.source_system or "unknown"
            confidence = SourceConfidence.get(source)

            key = self._build_key(
                hostname=asset.hostname,
                ip_address=asset.ip_address,
                mac_address=asset.mac_address,
                serial_number=asset.serial_number,
            )

            match = self._find_match(key)
            if match.matched and match.enriched_asset_index is not None:
                enriched = self._assets[match.enriched_asset_index]
            else:
                enriched = EnrichedAsset()
                self._assets.append(enriched)

            enriched.correlation_key.merge(key)
            enriched.present_in_sources.add(source)
            enriched.source_records.setdefault(source, []).append(
                asset.model_dump(exclude_none=True)
            )

            enriched.set_field("hostname", asset.hostname, source, confidence)
            enriched.set_field("ip_address", asset.ip_address, source, confidence)
            enriched.set_field("mac_address", asset.mac_address, source, confidence)
            enriched.set_field("serial_number", asset.serial_number, source, confidence)
            enriched.set_field("operating_system", asset.operating_system, source, confidence)
            enriched.set_field("os_version", asset.os_version, source, confidence)
            enriched.set_field("asset_type", asset.asset_type, source, confidence)
            enriched.set_field("owner_email", asset.owner_email, source, confidence)
            enriched.set_field("owner_name", asset.owner_name, source, confidence)
            enriched.set_field("department", asset.department, source, confidence)
            enriched.set_field("location", asset.location, source, confidence)

            self._update_indexes(len(self._assets) - 1, key)
            count += 1
        return count

    def ingest_endpoints(self, endpoints: Iterator[ParsedEndpoint]) -> int:
        """
        Ingest parsed endpoints (from EDR, AV, XDR).

        Returns the number of records ingested.
        """
        count = 0
        for ep in endpoints:
            source = ep.source_system or "unknown"
            confidence = SourceConfidence.get(source)

            key = self._build_key(
                hostname=ep.hostname,
                ip_address=ep.ip_address,
                mac_address=ep.mac_address,
                serial_number=ep.serial_number,
                agent_id=ep.agent_id,
            )

            match = self._find_match(key)
            if match.matched and match.enriched_asset_index is not None:
                enriched = self._assets[match.enriched_asset_index]
            else:
                enriched = EnrichedAsset()
                self._assets.append(enriched)

            enriched.correlation_key.merge(key)
            enriched.present_in_sources.add(source)
            enriched.source_records.setdefault(source, []).append(
                ep.model_dump(exclude_none=True)
            )

            enriched.set_field("hostname", ep.hostname, source, confidence)
            enriched.set_field("ip_address", ep.ip_address, source, confidence)
            enriched.set_field("mac_address", ep.mac_address, source, confidence)
            enriched.set_field("serial_number", ep.serial_number, source, confidence)
            enriched.set_field("agent_id", ep.agent_id, source, confidence)
            enriched.set_field("operating_system", ep.operating_system, source, confidence)
            enriched.set_field("os_version", ep.os_version, source, confidence)
            enriched.set_field("asset_type", ep.endpoint_type, source, confidence)
            enriched.set_field("owner_email", ep.owner_email, source, confidence)
            enriched.set_field("owner_name", ep.owner_name, source, confidence)
            enriched.set_field("department", ep.department, source, confidence)
            enriched.set_field("agent_status", ep.agent_status, source, confidence)
            enriched.set_field("policy_status", ep.policy_status, source, confidence)
            enriched.set_field("isolation_status", ep.isolation_status, source, confidence)

            self._update_indexes(len(self._assets) - 1, key)
            count += 1
        return count

    def ingest_vulnerabilities(self, vulns: Iterator[ParsedVulnerability]) -> int:
        """
        Ingest vulnerabilities and attach them to matching enriched assets.

        Returns the number of records ingested.
        """
        count = 0
        for vuln in vulns:
            source = vuln.source_system or "unknown"
            key = self._build_key(
                hostname=vuln.hostname,
                ip_address=vuln.ip_address,
            )

            match = self._find_match(key)
            if match.matched and match.enriched_asset_index is not None:
                enriched = self._assets[match.enriched_asset_index]
            else:
                enriched = EnrichedAsset()
                enriched.correlation_key.merge(key)
                self._assets.append(enriched)
                self._update_indexes(len(self._assets) - 1, key)

            enriched.present_in_sources.add(source)
            enriched.vulnerability_count += 1
            severity = (vuln.severity or "").lower()
            if severity == "critical":
                enriched.critical_vuln_count += 1
            elif severity == "high":
                enriched.high_vuln_count += 1

            count += 1
        return count

    def ingest_owner_mappings(self, mappings: Iterator[ParsedOwnerMapping]) -> int:
        """
        Ingest owner mappings and apply them to matching enriched assets.

        Returns the number of records applied.
        """
        count = 0
        for mapping in mappings:
            source = mapping.source_system or "unknown"
            confidence = SourceConfidence.get(source) * mapping.confidence

            key = self._build_key(
                hostname=None,
                ip_address=mapping.ip_address,
            )

            match = self._find_match(key)
            if match.matched and match.enriched_asset_index is not None:
                enriched = self._assets[match.enriched_asset_index]
                enriched.set_field("owner_email", mapping.owner_email, source, confidence)
                enriched.set_field("owner_name", mapping.owner_name, source, confidence)
                enriched.set_field("department", mapping.department, source, confidence)
                enriched.set_field("location", mapping.location, source, confidence)
                count += 1
        return count

    def ingest_network_observations(
        self, observations: Iterator[ParsedNetworkObservation]
    ) -> int:
        """
        Ingest NDR observations and correlate with existing assets.

        Returns the number of records ingested.
        """
        count = 0
        for obs in observations:
            source = obs.source_system or "unknown"
            confidence = SourceConfidence.get(source)

            key = self._build_key(
                hostname=obs.hostname,
                ip_address=obs.ip_address,
                mac_address=obs.mac_address,
            )

            match = self._find_match(key)
            if match.matched and match.enriched_asset_index is not None:
                enriched = self._assets[match.enriched_asset_index]
            else:
                enriched = EnrichedAsset()
                self._assets.append(enriched)

            enriched.correlation_key.merge(key)
            enriched.present_in_sources.add(source)

            enriched.set_field("hostname", obs.hostname, source, confidence)
            enriched.set_field("ip_address", obs.ip_address, source, confidence)
            enriched.set_field("mac_address", obs.mac_address, source, confidence)

            self._update_indexes(len(self._assets) - 1, key)
            count += 1
        return count

    # -- Query Methods -------------------------------------------------------

    def get_enriched_assets(self) -> Iterator[EnrichedAsset]:
        """Yield all enriched assets."""
        yield from self._assets

    def gap_analysis(self, source_a: str, source_b: str) -> GapReport:
        """
        Compute coverage gaps between two sources.

        Args:
            source_a: First source system name.
            source_b: Second source system name.

        Returns:
            A GapReport showing assets in A not B, in B not A, and in both.
        """
        report = GapReport(source_a=source_a, source_b=source_b)

        for asset in self._assets:
            in_a = source_a in asset.present_in_sources
            in_b = source_b in asset.present_in_sources

            if in_a and in_b:
                report.in_both.append(asset.correlation_key)
            elif in_a:
                report.in_a_not_b.append(asset.correlation_key)
            elif in_b:
                report.in_b_not_a.append(asset.correlation_key)

        return report

    def deduplicate(self) -> int:
        """
        Merge enriched assets that share identifiers.

        Returns the number of merges performed.
        """
        merges = 0
        i = 0
        while i < len(self._assets):
            j = i + 1
            while j < len(self._assets):
                if self._assets[i].correlation_key.overlaps(
                    self._assets[j].correlation_key
                ):
                    self._merge_assets(i, j)
                    # Remove j, shift everything down
                    self._assets.pop(j)
                    merges += 1
                    # Don't increment j — the next asset slid into j's slot
                else:
                    j += 1
            i += 1

        if merges:
            self._rebuild_indexes()

        return merges

    # -- Internal Helpers ----------------------------------------------------

    def _build_key(
        self,
        hostname: Optional[str] = None,
        ip_address: Optional[str] = None,
        mac_address: Optional[str] = None,
        serial_number: Optional[str] = None,
        agent_id: Optional[str] = None,
    ) -> CorrelationKey:
        """Build a normalized CorrelationKey from raw fields."""
        key = CorrelationKey()

        hn = normalize_hostname(hostname)
        if hn:
            key.hostnames.add(hn)

        ip = normalize_ip(ip_address)
        if ip:
            key.ip_addresses.add(ip)

        mac = normalize_mac(mac_address)
        if mac:
            key.mac_addresses.add(mac)

        if serial_number and serial_number.strip():
            key.serial_numbers.add(serial_number.strip().lower())

        if agent_id and agent_id.strip():
            key.agent_ids.add(agent_id.strip())

        return key

    def _find_match(self, key: CorrelationKey) -> MatchResult:
        """
        Find the best matching enriched asset for a correlation key.

        Checks indexes in order of match weight (agent_id > serial > MAC > hostname > IP).
        """
        best_idx: Optional[int] = None
        best_confidence = 0.0
        matched_on: list[str] = []

        # Check each identifier type from highest to lowest weight
        for id_type, values, idx_map in [
            ("agent_id", key.agent_ids, self._agent_id_idx),
            ("serial_number", key.serial_numbers, self._serial_idx),
            ("mac_address", key.mac_addresses, self._mac_idx),
            ("hostname", key.hostnames, self._hostname_idx),
            ("ip_address", key.ip_addresses, self._ip_idx),
        ]:
            for val in values:
                if val in idx_map:
                    weight = MatchWeights.get(id_type)
                    if weight > best_confidence:
                        best_confidence = weight
                        best_idx = idx_map[val][0]  # Take first match
                        matched_on = [id_type]
                    elif weight == best_confidence and best_idx is not None:
                        matched_on.append(id_type)

        if best_idx is not None:
            return MatchResult(
                matched=True,
                confidence=best_confidence,
                matched_on=matched_on,
                enriched_asset_index=best_idx,
            )
        return MatchResult()

    def _update_indexes(self, asset_idx: int, key: CorrelationKey) -> None:
        """Add a correlation key's identifiers to the lookup indexes."""
        for val in key.hostnames:
            self._hostname_idx.setdefault(val, [])
            if asset_idx not in self._hostname_idx[val]:
                self._hostname_idx[val].append(asset_idx)

        for val in key.ip_addresses:
            self._ip_idx.setdefault(val, [])
            if asset_idx not in self._ip_idx[val]:
                self._ip_idx[val].append(asset_idx)

        for val in key.mac_addresses:
            self._mac_idx.setdefault(val, [])
            if asset_idx not in self._mac_idx[val]:
                self._mac_idx[val].append(asset_idx)

        for val in key.serial_numbers:
            self._serial_idx.setdefault(val, [])
            if asset_idx not in self._serial_idx[val]:
                self._serial_idx[val].append(asset_idx)

        for val in key.agent_ids:
            self._agent_id_idx.setdefault(val, [])
            if asset_idx not in self._agent_id_idx[val]:
                self._agent_id_idx[val].append(asset_idx)

    def _rebuild_indexes(self) -> None:
        """Rebuild all indexes from scratch (after deduplication)."""
        self._hostname_idx.clear()
        self._ip_idx.clear()
        self._mac_idx.clear()
        self._serial_idx.clear()
        self._agent_id_idx.clear()
        for i, asset in enumerate(self._assets):
            self._update_indexes(i, asset.correlation_key)

    def _merge_assets(self, keep_idx: int, merge_idx: int) -> None:
        """Merge asset at merge_idx into asset at keep_idx."""
        keep = self._assets[keep_idx]
        merge = self._assets[merge_idx]

        keep.correlation_key.merge(merge.correlation_key)
        keep.present_in_sources |= merge.present_in_sources

        # Merge provenance fields — higher confidence wins
        for field in [
            "hostname", "ip_address", "mac_address", "serial_number",
            "agent_id", "operating_system", "os_version", "asset_type",
            "owner_email", "owner_name", "department", "location",
            "agent_status", "policy_status", "isolation_status",
        ]:
            other_prov = getattr(merge, field)
            if other_prov is not None:
                current = getattr(keep, field)
                if current is None or other_prov.confidence > current.confidence:
                    setattr(keep, field, other_prov)

        keep.vulnerability_count += merge.vulnerability_count
        keep.critical_vuln_count += merge.critical_vuln_count
        keep.high_vuln_count += merge.high_vuln_count

        for src, records in merge.source_records.items():
            keep.source_records.setdefault(src, []).extend(records)

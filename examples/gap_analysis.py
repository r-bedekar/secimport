#!/usr/bin/env python3
"""
Example: Gap analysis across multiple security tools.

Demonstrates how to identify assets that are visible to one
security tool but missing from another — critical for ensuring
complete coverage of security controls.
"""

from secimport.enrichment.correlator import AssetCorrelator
from secimport.models.base import ParsedAsset, ParsedEndpoint, ParsedNetworkObservation


def main():
    correlator = AssetCorrelator()

    # Simulate 3 sources with overlapping but incomplete coverage
    # Scanner sees: host1, host2, host3, host4, host5
    correlator.ingest_assets(iter([
        ParsedAsset(hostname=f"host{i}", ip_address=f"10.0.0.{i}", source_system="qualys")
        for i in range(1, 6)
    ]))

    # EDR sees: host1, host2, host3 (missing host4, host5)
    correlator.ingest_endpoints(iter([
        ParsedEndpoint(hostname=f"host{i}", ip_address=f"10.0.0.{i}", source_system="crowdstrike")
        for i in range(1, 4)
    ]))

    # NDR sees: host2, host3, host4, host5, host6 (host6 is rogue!)
    correlator.ingest_network_observations(iter([
        ParsedNetworkObservation(
            ip_address=f"10.0.0.{i}", hostname=f"host{i}", source_system="darktrace"
        )
        for i in range(2, 7)
    ]))

    print(f"Total unique assets: {correlator.asset_count}\n")

    # Gap: Scanner vs EDR
    gap_scanner_edr = correlator.gap_analysis("qualys", "crowdstrike")
    print("Scanner vs EDR:")
    print(f"  Both:        {len(gap_scanner_edr.in_both)}")
    print(f"  Scanner only: {len(gap_scanner_edr.in_a_not_b)} (need EDR agent)")
    print(f"  EDR only:     {len(gap_scanner_edr.in_b_not_a)}")
    print(f"  Coverage:     {gap_scanner_edr.coverage_a_to_b:.0%}\n")

    # Gap: Scanner vs NDR
    gap_scanner_ndr = correlator.gap_analysis("qualys", "darktrace")
    print("Scanner vs NDR:")
    print(f"  Both:        {len(gap_scanner_ndr.in_both)}")
    print(f"  Scanner only: {len(gap_scanner_ndr.in_a_not_b)}")
    print(f"  NDR only:     {len(gap_scanner_ndr.in_b_not_a)} (rogue/unmanaged?)")
    print(f"  Coverage:     {gap_scanner_ndr.coverage_a_to_b:.0%}\n")

    # Gap: EDR vs NDR
    gap_edr_ndr = correlator.gap_analysis("crowdstrike", "darktrace")
    print("EDR vs NDR:")
    print(f"  Both:        {len(gap_edr_ndr.in_both)}")
    print(f"  EDR only:     {len(gap_edr_ndr.in_a_not_b)}")
    print(f"  NDR only:     {len(gap_edr_ndr.in_b_not_a)} (need EDR agent)")
    print(f"  Coverage:     {gap_edr_ndr.coverage_a_to_b:.0%}")


if __name__ == "__main__":
    main()

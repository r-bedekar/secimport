#!/usr/bin/env python3
"""
Example: Multi-source asset enrichment pipeline.

Demonstrates how to correlate assets from a vulnerability scanner,
an EDR agent, and an IPAM system into a single enriched view.
"""

from secimport.enrichment.correlator import AssetCorrelator
from secimport.models.base import ParsedAsset, ParsedEndpoint, ParsedOwnerMapping


def main():
    correlator = AssetCorrelator()

    # 1. Ingest assets from a vulnerability scanner
    scanner_assets = iter([
        ParsedAsset(
            hostname="web01.example.com",
            ip_address="10.0.1.10",
            operating_system="Ubuntu 22.04",
            source_system="qualys",
        ),
        ParsedAsset(
            hostname="db01.example.com",
            ip_address="10.0.1.20",
            operating_system="RHEL 9",
            source_system="qualys",
        ),
        ParsedAsset(
            hostname="app01.example.com",
            ip_address="10.0.1.30",
            operating_system="Windows Server 2022",
            source_system="qualys",
        ),
    ])
    print(f"Ingested {correlator.ingest_assets(scanner_assets)} scanner assets")

    # 2. Ingest endpoints from an EDR
    edr_endpoints = iter([
        ParsedEndpoint(
            hostname="web01.example.com",
            ip_address="10.0.1.10",
            agent_id="falcon-001",
            agent_status="Online",
            policy_status="Compliant",
            source_system="crowdstrike",
        ),
        ParsedEndpoint(
            hostname="db01.example.com",
            ip_address="10.0.1.20",
            agent_id="falcon-002",
            agent_status="Online",
            policy_status="Non-Compliant",
            source_system="crowdstrike",
        ),
        # Note: app01 has NO EDR agent — this is a coverage gap!
    ])
    print(f"Ingested {correlator.ingest_endpoints(edr_endpoints)} EDR endpoints")

    # 3. Ingest owner mappings from IPAM
    owner_mappings = iter([
        ParsedOwnerMapping(
            ip_address="10.0.1.10",
            owner_email="webteam@example.com",
            department="Engineering",
            source_system="infoblox",
        ),
        ParsedOwnerMapping(
            ip_address="10.0.1.20",
            owner_email="dba@example.com",
            department="Data Services",
            source_system="infoblox",
        ),
    ])
    print(f"Applied {correlator.ingest_owner_mappings(owner_mappings)} owner mappings")

    # 4. View enriched assets
    print(f"\n{'='*60}")
    print(f"Enriched Assets: {correlator.asset_count}")
    print(f"{'='*60}\n")

    for asset in correlator.get_enriched_assets():
        hostname = asset.hostname.value if asset.hostname else "N/A"
        sources = ", ".join(sorted(asset.present_in_sources))
        owner = asset.owner_email.value if asset.owner_email else "N/A"
        agent = asset.agent_status.value if asset.agent_status else "No Agent"
        policy = asset.policy_status.value if asset.policy_status else "N/A"

        print(f"  {hostname}")
        print(f"    Sources: {sources}")
        print(f"    Owner: {owner}")
        print(f"    EDR: {agent} | Policy: {policy}")
        print()

    # 5. Gap analysis: which assets are in the scanner but NOT in EDR?
    gap = correlator.gap_analysis("qualys", "crowdstrike")
    print(f"{'='*60}")
    print(f"Gap Analysis: qualys vs crowdstrike")
    print(f"{'='*60}")
    print(f"  In both:          {len(gap.in_both)}")
    print(f"  In scanner only:  {len(gap.in_a_not_b)}  <-- MISSING EDR COVERAGE")
    print(f"  In EDR only:      {len(gap.in_b_not_a)}")
    print(f"  Coverage:         {gap.coverage_a_to_b:.0%}")

    for key in gap.in_a_not_b:
        hostnames = ", ".join(key.hostnames) or ", ".join(key.ip_addresses)
        print(f"    ! {hostnames} — needs EDR agent")


if __name__ == "__main__":
    main()

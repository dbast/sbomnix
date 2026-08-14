#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Focused tests for native vulnxscan SARIF output."""

import json
from types import SimpleNamespace

import pandas as pd
import pytest

from common import columns as cols
from vulnxscan.evidence import build_evidence_report, finding_id
from vulnxscan.reporting import write_reports
from vulnxscan.sarif import findings_to_sarif
from vulnxscan.vulnscan import VulnScan
from vulnxscan.vulnxscan_cli import getargs


def _normalized(rows, scanner_columns=("grype", "osv", "vulnix"), sbom_csv=None):
    return build_evidence_report(
        [pd.DataFrame(rows)],
        scanner_columns=list(scanner_columns),
        sbom_csv=sbom_csv,
    )


def _sarif(report, **kwargs):
    return findings_to_sarif(
        report.report,
        evidence_document=report.document,
        tool_version="1.8.0",
        **kwargs,
    )


def test_empty_findings_produce_valid_empty_sarif():
    document = findings_to_sarif(pd.DataFrame(), tool_version="1.8.0")

    assert document == {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "vulnxscan",
                        "informationUri": "https://github.com/tiiuae/sbomnix",
                        "version": "1.8.0",
                        "rules": [],
                    }
                },
                "results": [],
            }
        ],
    }


def test_golden_finding_merges_scanner_provenance_and_preserves_unicode():
    report = _normalized(
        [
            {
                cols.VULN_ID: "CVE-2026-12345",
                cols.PACKAGE: "openssl-ü",
                cols.VERSION: "3.0.14",
                cols.SEVERITY: "high",
                cols.SCANNER: scanner,
            }
            for scanner in ("vulnix", "grype")
        ]
    )

    document = _sarif(report)
    driver = document["runs"][0]["tool"]["driver"]
    results = document["runs"][0]["results"]

    assert driver["rules"] == [
        {
            "id": "CVE-2026-12345",
            "shortDescription": {"text": "CVE-2026-12345"},
            "properties": {"tags": ["security", "vulnerability"]},
            "helpUri": "https://nvd.nist.gov/vuln/detail/CVE-2026-12345",
            "help": {
                "text": (
                    "NVD record: "
                    "https://nvd.nist.gov/vuln/detail/CVE-2026-12345\n"
                    "Nixpkgs Security Tracker: "
                    "https://tracker.security.nixos.org/suggestions/by-cve/"
                    "CVE-2026-12345/"
                ),
                "markdown": (
                    "[NVD record](https://nvd.nist.gov/vuln/detail/"
                    "CVE-2026-12345) | "
                    "[Nixpkgs Security Tracker](https://tracker.security.nixos.org/"
                    "suggestions/by-cve/CVE-2026-12345/)"
                ),
            },
        }
    ]
    assert results == [
        {
            "ruleId": "CVE-2026-12345",
            "ruleIndex": 0,
            "level": "error",
            "message": {"text": "CVE-2026-12345 affects openssl-ü 3.0.14"},
            "partialFingerprints": {
                "primaryLocationLineHash": (
                    "ce19f4b0b432b4f7f12cd5e572a48ec0864cf34fe336985ced99abdaf44db81f"
                ),
                "vulnxscan/v1": (
                    "ce19f4b0b432b4f7f12cd5e572a48ec0864cf34fe336985ced99abdaf44db81f"
                ),
            },
            "properties": {
                "package": "openssl-ü",
                "version": "3.0.14",
                "severity": "high",
                "sources": ["grype", "vulnix"],
                "evidenceScope": "package_version_only",
                "patchState": "package_version_only",
            },
        }
    ]
    assert len(results[0]["partialFingerprints"]["vulnxscan/v1"]) == 64
    assert (
        results[0]["partialFingerprints"]["primaryLocationLineHash"]
        == (results[0]["partialFingerprints"]["vulnxscan/v1"])
    )


def test_rules_and_results_have_vulnerability_and_package_cardinality():
    report = _normalized(
        [
            {
                cols.VULN_ID: vuln_id,
                cols.PACKAGE: package,
                cols.VERSION: "1.0",
                cols.SEVERITY: "medium",
                cols.SCANNER: "osv",
            }
            for vuln_id, package in (
                ("GHSA-abcd-1234-5678", "one"),
                ("GHSA-abcd-1234-5678", "two"),
                ("OSV-2026-1", "one"),
            )
        ],
        scanner_columns=("osv",),
    )

    document = _sarif(report)

    assert [rule["id"] for rule in document["runs"][0]["tool"]["driver"]["rules"]] == [
        "GHSA-abcd-1234-5678",
        "OSV-2026-1",
    ]
    ghsa_rule, osv_rule = document["runs"][0]["tool"]["driver"]["rules"]
    assert ghsa_rule["helpUri"] == ("https://github.com/advisories/GHSA-abcd-1234-5678")
    assert ghsa_rule["help"]["markdown"] == (
        "[GitHub Advisory](https://github.com/advisories/GHSA-abcd-1234-5678) | "
        "[OSV record](https://osv.dev/GHSA-abcd-1234-5678)"
    )
    assert osv_rule["help"] == {
        "text": "Vulnerability record: https://osv.dev/OSV-2026-1",
        "markdown": "[Vulnerability record](https://osv.dev/OSV-2026-1)",
    }
    assert [
        (result["ruleId"], result["properties"]["package"])
        for result in document["runs"][0]["results"]
    ] == [
        ("GHSA-abcd-1234-5678", "one"),
        ("GHSA-abcd-1234-5678", "two"),
        ("OSV-2026-1", "one"),
    ]


@pytest.mark.parametrize(
    ("severity", "level", "score"),
    [
        ("critical", "error", None),
        ("high", "error", None),
        ("medium", "warning", None),
        ("low", "note", None),
        ("unknown", "warning", None),
        ("9.8", "error", 9.8),
        ("5.0", "warning", 5.0),
        ("2.0", "note", 2.0),
    ],
)
def test_severity_mapping_preserves_original_score(severity, level, score):
    report = _normalized(
        [
            {
                cols.VULN_ID: "CVE-1",
                cols.PACKAGE: "hello",
                cols.VERSION: "1.0",
                cols.SEVERITY: severity,
                cols.SCANNER: "grype",
            }
        ],
        scanner_columns=("grype",),
    )

    result = _sarif(report)["runs"][0]["results"][0]

    assert result["level"] == level
    assert result["properties"]["severity"] == severity
    assert result["properties"].get("cvssScore") == score


def test_output_order_and_json_are_deterministic():
    rows = [
        {
            cols.VULN_ID: vuln_id,
            cols.PACKAGE: package,
            cols.VERSION: version,
            cols.SEVERITY: "medium",
            cols.SCANNER: "grype",
        }
        for vuln_id, package, version in (
            ("CVE-2", "zlib", "2"),
            ("CVE-1", "zlib", "3"),
            ("CVE-1", "openssl", "1"),
        )
    ]

    first = _sarif(_normalized(rows, scanner_columns=("grype",)))
    second = _sarif(_normalized(reversed(rows), scanner_columns=("grype",)))

    assert json.dumps(first, ensure_ascii=False) == json.dumps(
        second, ensure_ascii=False
    )
    assert [
        (item["ruleId"], item["properties"]["package"], item["properties"]["version"])
        for item in first["runs"][0]["results"]
    ] == [
        ("CVE-1", "openssl", "1"),
        ("CVE-1", "zlib", "3"),
        ("CVE-2", "zlib", "2"),
    ]


def test_fingerprint_distinguishes_versions_but_ignores_nix_paths():
    def document(version, drv_hash):
        fid = finding_id("CVE-1", "hello", version)
        frame = pd.DataFrame(
            [
                {
                    cols.VULN_ID: "CVE-1",
                    cols.PACKAGE: "hello",
                    cols.VERSION_LOCAL: version,
                    cols.SEVERITY: "high",
                    cols.FINDING_ID: fid,
                    "grype": "1",
                }
            ]
        )
        evidence = {
            "findings": [{cols.FINDING_ID: fid, "scanners": ["grype"]}],
            "components": [
                {
                    cols.FINDING_ID: fid,
                    cols.DRV_PATH: f"/nix/store/{drv_hash}-hello.drv",
                    "output_paths": [f"/nix/store/{drv_hash}-hello"],
                }
            ],
        }
        return findings_to_sarif(
            frame, evidence_document=evidence, tool_version="1.8.0"
        )

    old = document("1.0", "aaaaaaaa")
    rebuilt = document("1.0", "bbbbbbbb")
    upgraded = document("2.0", "cccccccc")
    old_result = old["runs"][0]["results"][0]
    rebuilt_result = rebuilt["runs"][0]["results"][0]
    upgraded_result = upgraded["runs"][0]["results"][0]

    assert old_result["partialFingerprints"] == rebuilt_result["partialFingerprints"]
    assert old_result["partialFingerprints"] != upgraded_result["partialFingerprints"]
    assert (
        old_result["properties"]["drvPaths"] != rebuilt_result["properties"]["drvPaths"]
    )
    assert (
        old_result["properties"]["storePaths"]
        != rebuilt_result["properties"]["storePaths"]
    )


def test_concurrent_package_versions_have_distinct_fingerprints():
    report = _normalized(
        [
            {
                cols.VULN_ID: "CVE-1",
                cols.PACKAGE: "hello",
                cols.VERSION: version,
                cols.SEVERITY: "high",
                cols.SCANNER: "grype",
            }
            for version in ("1.0", "2.0")
        ],
        scanner_columns=("grype",),
    )

    results = _sarif(report)["runs"][0]["results"]
    fingerprints = {
        result["partialFingerprints"]["primaryLocationLineHash"] for result in results
    }

    assert len(results) == len(fingerprints) == 2


def test_optional_file_level_location_has_no_fake_region():
    report = _normalized(
        [
            {
                cols.VULN_ID: "CVE-1",
                cols.PACKAGE: "hello",
                cols.VERSION: "1.0",
                cols.SEVERITY: "",
                cols.SCANNER: "osv",
            }
        ],
        scanner_columns=("osv",),
    )

    without_location = _sarif(report)["runs"][0]["results"][0]
    with_location = _sarif(report, location="nix/closure definition.nix")["runs"][0][
        "results"
    ][0]

    assert "locations" not in without_location
    assert with_location["locations"] == [
        {
            "physicalLocation": {
                "artifactLocation": {"uri": "nix/closure%20definition.nix"}
            }
        }
    ]
    assert "severity" not in with_location["properties"]
    assert "cvssScore" not in with_location["properties"]


def test_sarif_writer_excludes_whitelisted_and_patch_suppressed_findings(tmp_path):
    active = _normalized(
        [
            {
                cols.VULN_ID: "CVE-1",
                cols.PACKAGE: "hello",
                cols.VERSION: "1.0",
                cols.SEVERITY: "high",
                cols.SCANNER: "grype",
            }
        ],
        scanner_columns=("grype",),
    )
    active.report[cols.WHITELIST] = True
    out = tmp_path / "vulns.sarif"

    write_reports(
        active.report,
        out,
        output_format="sarif",
        evidence_document=active.document,
    )

    assert json.loads(out.read_text(encoding="utf-8"))["runs"][0]["results"] == []

    drv_path = "/nix/store/aaaaaaaa-hello.drv"
    sbom_csv = tmp_path / "sbom.csv"
    pd.DataFrame(
        [
            {
                cols.STORE_PATH: drv_path,
                cols.PNAME: "hello",
                cols.VERSION: "1.0",
                cols.OUTPUT_PATHS_JSON: "[]",
                cols.PATCH_PATHS_JSON: json.dumps(
                    ["/nix/store/src/CVE-2-security.patch"]
                ),
            }
        ]
    ).to_csv(sbom_csv, index=False)
    suppressed = _normalized(
        [
            {
                cols.VULN_ID: "CVE-2",
                cols.PACKAGE: "hello",
                cols.VERSION: "1.0",
                cols.SEVERITY: "high",
                cols.SCANNER: "grype",
                cols.COMPONENT_REF: drv_path,
            }
        ],
        scanner_columns=("grype",),
        sbom_csv=sbom_csv,
    )

    assert suppressed.report.empty
    assert _sarif(suppressed)["runs"][0]["results"] == []


def test_clean_scan_writes_an_empty_sarif_file(tmp_path):
    out = tmp_path / "vulns.sarif"
    args = SimpleNamespace(
        out=out,
        format="sarif",
        sarif_location=None,
        evidence_out=None,
        whitelist=None,
        triage=False,
    )

    VulnScan().report(args, sbom_csv=None)

    assert json.loads(out.read_text(encoding="utf-8"))["runs"][0]["results"] == []


def test_cli_selects_sarif_defaults_and_rejects_misleading_locations():
    args = getargs([".#pkg", "--format", "sarif", "--sarif-location", "flake.nix"])

    assert args.out == "vulns.sarif"
    assert args.format == "sarif"
    assert args.sarif_location.as_posix() == "flake.nix"
    assert getargs([".#pkg"]).out == "vulns.csv"

    with pytest.raises(SystemExit):
        getargs([".#pkg", "--sarif-location", "flake.nix"])
    with pytest.raises(SystemExit):
        getargs([".#pkg", "--format", "sarif", "--sarif-location", "../flake.nix"])

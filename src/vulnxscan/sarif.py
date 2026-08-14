#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""SARIF 2.1.0 serialization for normalized vulnxscan findings."""

import hashlib
import json
import math
import pathlib
from urllib.parse import quote

import pandas as pd

from common import columns as cols
from common.log import LOG
from common.pkgmeta import get_py_pkg_version

_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_INFORMATION_URI = "https://github.com/tiiuae/sbomnix"
_SCANNERS = ("grype", "osv", "vulnix")


def findings_to_sarif(  # noqa: PLR0914
    findings,
    *,
    evidence_document=None,
    tool_version=None,
    location=None,
):
    """Return SARIF for final normalized, filtered finding rows."""
    findings = findings if findings is not None else pd.DataFrame()
    records = sorted(
        findings.to_dict("records"),
        key=lambda row: (
            _text(row.get(cols.VULN_ID)),
            _text(row.get(cols.PACKAGE)),
            _version(row),
        ),
    )
    evidence_document = evidence_document or {}
    evidence_findings = {
        item.get(cols.FINDING_ID): item
        for item in evidence_document.get("findings", [])
    }
    evidence_components = {}
    for component in evidence_document.get("components", []):
        evidence_components.setdefault(component.get(cols.FINDING_ID), []).append(
            component
        )

    rule_ids = sorted({_text(row.get(cols.VULN_ID)) for row in records})
    rule_indexes = {rule_id: index for index, rule_id in enumerate(rule_ids)}
    urls = {
        rule_id: next(
            (
                _text(row.get(cols.URL))
                for row in records
                if _text(row.get(cols.VULN_ID)) == rule_id and _text(row.get(cols.URL))
            ),
            "",
        )
        for rule_id in rule_ids
    }
    rules = []
    for rule_id in rule_ids:
        rule = {
            "id": rule_id,
            "shortDescription": {"text": rule_id},
            "properties": {"tags": ["security", "vulnerability"]},
        }
        links = _rule_links(rule_id, urls[rule_id])
        if links:
            rule["helpUri"] = links[0][1]
            rule["help"] = {
                "text": "\n".join(f"{label}: {url}" for label, url in links),
                "markdown": " | ".join(f"[{label}]({url})" for label, url in links),
            }
        rules.append(rule)

    results = []
    for row in records:
        vuln_id = _text(row.get(cols.VULN_ID))
        package = _text(row.get(cols.PACKAGE))
        version = _version(row)
        severity = _text(row.get(cols.SEVERITY))
        fid = row.get(cols.FINDING_ID)
        evidence = evidence_findings.get(fid, {})
        sources = sorted(evidence.get("scanners", [])) or sorted(
            scanner for scanner in _SCANNERS if _is_true(row.get(scanner))
        )
        properties: dict[str, object] = {"package": package, "version": version}
        if severity:
            properties["severity"] = severity
        score = _numeric_severity(severity)
        if score is not None:
            properties["cvssScore"] = score
        if sources:
            properties["sources"] = sources
        for column, name in (
            (cols.EVIDENCE_SCOPE, "evidenceScope"),
            (cols.PATCH_STATE, "patchState"),
        ):
            value = _text(row.get(column))
            if value:
                properties[name] = value
        components = evidence_components.get(fid, [])
        drv_paths = sorted(
            {
                _text(component.get(cols.DRV_PATH))
                for component in components
                if _text(component.get(cols.DRV_PATH))
            }
        )
        store_paths = sorted(
            {
                _text(path)
                for component in components
                for path in component.get("output_paths", [])
                if _text(path)
            }
        )
        if drv_paths:
            properties["drvPaths"] = drv_paths
        if store_paths:
            properties["storePaths"] = store_paths

        fingerprint = _fingerprint(vuln_id, package, version)
        result = {
            "ruleId": vuln_id,
            "ruleIndex": rule_indexes[vuln_id],
            "level": _sarif_level(severity),
            "message": {"text": f"{vuln_id} affects {package} {version}".rstrip()},
            # GitHub currently consumes only primaryLocationLineHash. The
            # versioned key retains the producer-defined identity for other
            # consumers. Both intentionally exclude Nix hashes.
            "partialFingerprints": {
                "primaryLocationLineHash": fingerprint,
                "vulnxscan/v1": fingerprint,
            },
            "properties": properties,
        }
        if location is not None:
            result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": quote(str(location), safe="/")}
                    }
                }
            ]
        results.append(result)

    return {
        "$schema": _SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "vulnxscan",
                        "informationUri": _INFORMATION_URI,
                        "version": tool_version or get_py_pkg_version(),
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def write_sarif(document, path):
    """Atomically write a SARIF document."""
    out_path = pathlib.Path(path)
    tmp_path = out_path.with_name(f".{out_path.name}.tmp")
    try:
        with open(tmp_path, "w", encoding="utf-8") as outfile:
            json.dump(document, outfile, indent=2, ensure_ascii=False)
            outfile.write("\n")
        tmp_path.replace(out_path)
    finally:
        tmp_path.unlink(missing_ok=True)
    LOG.info("Wrote: %s", out_path)


def _fingerprint(vuln_id, package, version):
    """Identify a versioned vulnerability/package across rebuild changes."""
    payload = json.dumps(
        [vuln_id, package, version], ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _rule_links(rule_id, existing_url):
    encoded_id = quote(rule_id, safe="")
    normalized = rule_id.casefold()
    if normalized.startswith("cve-"):
        return [
            (
                "NVD record",
                existing_url or f"https://nvd.nist.gov/vuln/detail/{encoded_id}",
            ),
            (
                "Nixpkgs Security Tracker",
                f"https://tracker.security.nixos.org/suggestions/by-cve/{encoded_id}/",
            ),
        ]
    if normalized.startswith("ghsa-"):
        links = [("GitHub Advisory", f"https://github.com/advisories/{encoded_id}")]
        if existing_url:
            links.append(("OSV record", existing_url))
        return links
    return [("Vulnerability record", existing_url)] if existing_url else []


def _sarif_level(severity):
    normalized = severity.strip().casefold()
    named_levels = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "moderate": "warning",
        "low": "note",
        "none": "note",
    }
    if normalized in named_levels:
        return named_levels[normalized]
    score = _numeric_severity(severity)
    if score is None:
        return "warning"
    return "error" if score >= 7 else "warning" if score >= 4 else "note"


def _numeric_severity(severity):
    try:
        score = float(severity)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(score) or not 0 <= score <= 10:
        return None
    return score


def _version(row):
    return _text(row.get(cols.VERSION_LOCAL) or row.get(cols.VERSION))


def _text(value):
    if value is None or pd.isna(value):
        return ""
    return str(value)


def _is_true(value):
    return value is True or _text(value).strip().casefold() in {"1", "true"}

"""NVD CVE lookup proxy.

Proxies the public NVD CVE API. Optional NVD_API_KEY env var raises the
rate limit from 5 req / 30s (anonymous) to 50 req / 30s (authenticated).
"""

from __future__ import annotations

import logging
import os
from typing import Any

import httpx
from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/cve", tags=["cve"])
_logger = logging.getLogger(__name__)

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")


def _headers() -> dict[str, str]:
    h = {"User-Agent": "red-arsenal/1.0"}
    if NVD_API_KEY:
        h["apiKey"] = NVD_API_KEY
    return h


def _summarize(vuln: dict[str, Any]) -> dict[str, Any]:
    """Flatten an NVD vulnerability entry into something the UI can render."""
    cve = vuln.get("cve", {})
    descs = cve.get("descriptions") or []
    desc = next((d.get("value") for d in descs if d.get("lang") == "en"), "")

    metrics = cve.get("metrics") or {}
    cvss = (
        (metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or [{}])[0]
        .get("cvssData", {})
    )
    weaknesses = cve.get("weaknesses") or []
    cwes: list[str] = []
    for w in weaknesses:
        for d in w.get("description") or []:
            v = d.get("value")
            if v and v not in cwes:
                cwes.append(v)

    refs = [r.get("url") for r in (cve.get("references") or []) if r.get("url")][:8]

    return {
        "id": cve.get("id"),
        "published": cve.get("published"),
        "modified": cve.get("lastModified"),
        "description": desc[:1200],
        "severity": cvss.get("baseSeverity") or "UNKNOWN",
        "score": cvss.get("baseScore"),
        "vector": cvss.get("vectorString"),
        "cwes": cwes,
        "references": refs,
    }


@router.get("/lookup")
async def lookup_cve(
    cve_id: str | None = None,
    keyword: str | None = None,
    limit: int = 10,
) -> dict[str, Any]:
    """Look up CVEs by exact ID or keyword search."""
    if not cve_id and not keyword:
        raise HTTPException(400, "Provide either cve_id or keyword")
    if cve_id and not cve_id.upper().startswith("CVE-"):
        raise HTTPException(400, "cve_id must look like CVE-YYYY-NNNN")

    params: dict[str, Any] = {}
    if cve_id:
        params["cveId"] = cve_id.upper().strip()
    else:
        params["keywordSearch"] = keyword
        params["resultsPerPage"] = max(1, min(limit, 50))

    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            r = await client.get(NVD_BASE, params=params, headers=_headers())
        if r.status_code == 404:
            return {"total": 0, "results": []}
        if r.status_code == 403:
            raise HTTPException(
                429,
                "NVD rate-limited the request. Set NVD_API_KEY in .env to "
                "raise the limit from 5 to 50 requests / 30s.",
            )
        r.raise_for_status()
    except httpx.HTTPError as exc:
        _logger.warning("NVD lookup failed: %s", exc)
        raise HTTPException(502, f"NVD upstream error: {exc}") from exc

    data = r.json()
    vulns = data.get("vulnerabilities") or []
    return {
        "total": data.get("totalResults", len(vulns)),
        "results": [_summarize(v) for v in vulns],
        "api_key_in_use": bool(NVD_API_KEY),
    }

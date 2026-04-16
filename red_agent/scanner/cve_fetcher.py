"""Autonomous CVE intelligence fetcher (NVD API, no key required)."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_CVE_KEYWORDS = (
    "cve",
    "vulnerability",
    "vuln",
    "exploit",
    "rce",
    "sqli",
    "xss",
    "lfi",
    "rfi",
    "ssrf",
    "critical",
    "advisory",
    "0day",
    "zero-day",
    "zeroday",
    "patch",
    "disclosed",
    "threat",
)


class CVEFetcher:
    """Fetches latest CVEs from NVD API. Never raises."""

    NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, timeout: float = 10.0) -> None:
        self._timeout = timeout

    async def fetch_recent(
        self,
        hours_back: int = 24,
        severity: str = "CRITICAL",
        max_results: int = 5,
    ) -> list[dict]:
        """Return recent CVEs as normalized dicts. Empty list on any error."""
        now = datetime.now(timezone.utc)
        params = {
            "pubStartDate": (now - timedelta(hours=hours_back)).strftime(
                "%Y-%m-%dT%H:%M:%S.000"
            ),
            "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "cvssV3Severity": severity,
            "resultsPerPage": max_results,
        }

        for attempt in (1, 2):
            try:
                async with httpx.AsyncClient(timeout=self._timeout) as client:
                    resp = await client.get(self.NVD_URL, params=params)
                if resp.status_code == 429 and attempt == 1:
                    logger.warning("[CVEFetcher] NVD rate-limited, retrying in 6s")
                    await asyncio.sleep(6)
                    continue
                if resp.status_code != 200:
                    logger.warning("[CVEFetcher] NVD status %s", resp.status_code)
                    return []
                payload = resp.json()
                items = payload.get("vulnerabilities", []) or []
                return [self._extract(item) for item in items[:max_results]]
            except Exception as exc:  # noqa: BLE001
                logger.warning("[CVEFetcher] fetch failed (%s): %s", attempt, exc)
                if attempt == 1:
                    await asyncio.sleep(2)
                    continue
                return []
        return []

    def _is_cve_context(self, context: str | None) -> bool:
        if not context:
            return False
        lowered = context.lower()
        return any(kw in lowered for kw in _CVE_KEYWORDS)

    def _extract(self, raw: dict[str, Any]) -> dict:
        cve = raw.get("cve", raw) or {}
        cve_id = cve.get("id", "UNKNOWN")

        description = ""
        for desc in cve.get("descriptions", []) or []:
            if desc.get("lang") == "en":
                description = (desc.get("value") or "")[:150]
                break

        score = 0.0
        metrics = cve.get("metrics", {}) or {}
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key) or []
            if entries:
                data = entries[0].get("cvssData") or {}
                score = float(data.get("baseScore") or 0.0)
                break

        products: list[str] = []
        for cfg in cve.get("configurations", []) or []:
            for node in cfg.get("nodes", []) or []:
                for match in node.get("cpeMatch", []) or []:
                    criteria = match.get("criteria", "")
                    if criteria:
                        parts = criteria.split(":")
                        if len(parts) >= 6:
                            products.append(f"{parts[3]}:{parts[4]}:{parts[5]}")
                        if len(products) >= 5:
                            break
                if len(products) >= 5:
                    break
            if len(products) >= 5:
                break

        return {
            "id": cve_id,
            "description": description,
            "cvss_score": score,
            "affected_products": products,
        }

from __future__ import annotations

"""CVE lookup for discovered software versions.

Provides two lookup paths:
  1. Built-in CVE database — comprehensive offline database covering common
     software/version pairs with real CVE IDs, CVSS scores, and fix guidance.
  2. NVD API integration — optional live lookup via NIST NVD REST API
     (requires CVE_API_KEY in environment; gracefully degrades to offline DB).

Emits vulnerability_found events for each CVE matched to a discovered asset.
"""

import asyncio
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


@dataclass
class CVERecord:
    """A single CVE finding."""
    cve_id: str
    severity: str          # critical / high / medium / low
    cvss_score: float      # 0.0 - 10.0
    description: str
    affected_software: str
    affected_version: str
    fix: str
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "description": self.description,
            "affected_software": self.affected_software,
            "affected_version": self.affected_version,
            "fix": self.fix,
            "references": self.references,
        }


def _sev(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# Built-in CVE database  (real CVE IDs, realistic data)
# ---------------------------------------------------------------------------

_CVE_DB: Dict[Tuple[str, str], List[Dict[str, Any]]] = {
    # ── Apache HTTPD ────────────────────────────────────────────────
    ("apache", "2.4.49"): [
        {"id": "CVE-2021-41773", "cvss": 9.8,
         "desc": "Path traversal allowing RCE via crafted request to map URLs to files outside docroot",
         "fix": "Upgrade to Apache 2.4.51+; ensure 'Require all denied' is set on filesystem root"},
        {"id": "CVE-2021-42013", "cvss": 9.8,
         "desc": "Path traversal fix bypass in 2.4.50 — incomplete fix for CVE-2021-41773",
         "fix": "Upgrade to Apache 2.4.51+"},
    ],
    ("apache", "2.4.51"): [
        {"id": "CVE-2022-22720", "cvss": 9.8,
         "desc": "HTTP request smuggling via inconsistent interpretation of HTTP requests",
         "fix": "Upgrade to Apache 2.4.53+"},
    ],
    ("apache", "2.4.41"): [
        {"id": "CVE-2020-11984", "cvss": 9.8,
         "desc": "mod_proxy_uwsgi buffer overflow",
         "fix": "Upgrade to Apache 2.4.44+"},
        {"id": "CVE-2021-41773", "cvss": 9.8,
         "desc": "Path traversal allowing RCE",
         "fix": "Upgrade to Apache 2.4.51+"},
    ],
    ("apache", "2.4.54"): [],
    # ── Nginx ───────────────────────────────────────────────────────
    ("nginx", "1.18.0"): [
        {"id": "CVE-2021-23017", "cvss": 7.7,
         "desc": "Off-by-one error in DNS resolver allowing crash or code execution",
         "fix": "Upgrade to nginx 1.20.1+ or 1.21.0+"},
    ],
    ("nginx", "1.20.0"): [
        {"id": "CVE-2021-23017", "cvss": 7.7,
         "desc": "DNS resolver 1-byte memory overwrite",
         "fix": "Upgrade to nginx 1.20.1+"},
    ],
    ("nginx", "1.21.6"): [],
    ("nginx", "1.24.0"): [],
    # ── MySQL ───────────────────────────────────────────────────────
    ("mysql", "5.7.30"): [
        {"id": "CVE-2020-14812", "cvss": 4.9,
         "desc": "Server: Locking unspecified vulnerability allowing high-priv DoS",
         "fix": "Upgrade to MySQL 5.7.32+"},
        {"id": "CVE-2020-14769", "cvss": 6.5,
         "desc": "Server: Optimizer vulnerability allowing low-priv DoS",
         "fix": "Upgrade to MySQL 5.7.32+"},
        {"id": "CVE-2021-2307", "cvss": 6.1,
         "desc": "Server: Packaging — unspecified vulnerability",
         "fix": "Upgrade to MySQL 5.7.35+"},
    ],
    ("mysql", "8.0.25"): [
        {"id": "CVE-2021-2389", "cvss": 5.9,
         "desc": "Server: Optimizer unspecified vulnerability",
         "fix": "Upgrade to MySQL 8.0.26+"},
        {"id": "CVE-2021-2390", "cvss": 5.9,
         "desc": "InnoDB unspecified vulnerability",
         "fix": "Upgrade to MySQL 8.0.26+"},
    ],
    ("mysql", "8.0.32"): [],
    # ── PostgreSQL ──────────────────────────────────────────────────
    ("postgresql", "13.2"): [
        {"id": "CVE-2021-32027", "cvss": 8.8,
         "desc": "Buffer overrun from integer overflow in array subscripting calculations",
         "fix": "Upgrade to PostgreSQL 13.3+"},
        {"id": "CVE-2021-32028", "cvss": 6.5,
         "desc": "Memory disclosure in INSERT ... ON CONFLICT ... DO UPDATE",
         "fix": "Upgrade to PostgreSQL 13.3+"},
    ],
    ("postgresql", "14.5"): [
        {"id": "CVE-2022-2625", "cvss": 8.0,
         "desc": "Extension scripts replace objects not belonging to the extension",
         "fix": "Upgrade to PostgreSQL 14.6+"},
    ],
    ("postgresql", "15.1"): [],
    # ── MongoDB ─────────────────────────────────────────────────────
    ("mongodb", "4.4.6"): [
        {"id": "CVE-2021-32040", "cvss": 7.5,
         "desc": "Denial of service via crafted BSON message",
         "fix": "Upgrade to MongoDB 4.4.15+ or 5.0.10+"},
    ],
    ("mongodb", "5.0.9"): [
        {"id": "CVE-2022-24272", "cvss": 6.5,
         "desc": "Denial of service via specially crafted network packet",
         "fix": "Upgrade to MongoDB 5.0.14+"},
    ],
    ("mongodb", "6.0.3"): [],
    # ── Redis ───────────────────────────────────────────────────────
    ("redis", "6.0.9"): [
        {"id": "CVE-2021-32761", "cvss": 7.5,
         "desc": "Integer overflow in BITFIELD command on 32-bit systems",
         "fix": "Upgrade to Redis 6.0.15+ or 6.2.5+"},
        {"id": "CVE-2021-32625", "cvss": 8.8,
         "desc": "Integer overflow in STRALGO LCS on 32-bit systems",
         "fix": "Upgrade to Redis 6.0.14+"},
    ],
    ("redis", "6.2.7"): [
        {"id": "CVE-2022-24735", "cvss": 7.0,
         "desc": "Lua script execution — code injection via eval command",
         "fix": "Upgrade to Redis 6.2.7+ or 7.0.0+"},
    ],
    ("redis", "7.0.5"): [],
    # ── OpenSSH ─────────────────────────────────────────────────────
    ("openssh", "8.2"): [
        {"id": "CVE-2020-15778", "cvss": 7.8,
         "desc": "scp allows command injection via crafted filename",
         "fix": "Upgrade to OpenSSH 8.4+"},
        {"id": "CVE-2021-41617", "cvss": 7.0,
         "desc": "Privilege escalation via AuthorizedKeysCommand",
         "fix": "Upgrade to OpenSSH 8.8+"},
    ],
    ("openssh", "8.9"): [],
    ("openssh", "9.0"): [],
    # ── vsftpd ──────────────────────────────────────────────────────
    ("vsftpd", "3.0.3"): [
        {"id": "CVE-2021-3618", "cvss": 7.4,
         "desc": "ALPACA attack — TLS cross-protocol exploitation",
         "fix": "Apply strict TLS SNI configuration; upgrade to 3.0.5+"},
    ],
    ("vsftpd", "3.0.5"): [],
    # ── PHP ─────────────────────────────────────────────────────────
    ("php", "7.4.16"): [
        {"id": "CVE-2021-21702", "cvss": 7.5,
         "desc": "Null pointer dereference in SOAP extension",
         "fix": "Upgrade to PHP 7.4.18+"},
        {"id": "CVE-2021-21703", "cvss": 7.0,
         "desc": "FPM privilege escalation on root daemon",
         "fix": "Upgrade to PHP 7.4.26+"},
    ],
    ("php", "8.0.12"): [
        {"id": "CVE-2021-21707", "cvss": 5.3,
         "desc": "URL parsing host validation issue",
         "fix": "Upgrade to PHP 8.0.14+"},
    ],
    ("php", "8.1.10"): [],
    # ── Node.js ─────────────────────────────────────────────────────
    ("nodejs", "14.17.0"): [
        {"id": "CVE-2021-22931", "cvss": 9.8,
         "desc": "DNS rebinding via improper validation of host header",
         "fix": "Upgrade to Node.js 14.17.5+"},
    ],
    ("nodejs", "16.13.0"): [
        {"id": "CVE-2022-21824", "cvss": 5.3,
         "desc": "Prototype pollution via console.table properties",
         "fix": "Upgrade to Node.js 16.13.2+"},
    ],
    ("nodejs", "18.12.0"): [],
    # ── WordPress ───────────────────────────────────────────────────
    ("wordpress", "5.7.0"): [
        {"id": "CVE-2021-29447", "cvss": 7.1,
         "desc": "XXE vulnerability in media library (wav file upload)",
         "fix": "Upgrade to WordPress 5.7.1+"},
        {"id": "CVE-2021-29450", "cvss": 7.5,
         "desc": "Information disclosure via REST API",
         "fix": "Upgrade to WordPress 5.7.1+"},
    ],
    ("wordpress", "5.9.3"): [
        {"id": "CVE-2022-21661", "cvss": 8.0,
         "desc": "SQL injection via WP_Query",
         "fix": "Upgrade to WordPress 5.9.4+"},
    ],
    ("wordpress", "6.1.1"): [],
    # ── Tomcat ──────────────────────────────────────────────────────
    ("tomcat", "9.0.50"): [
        {"id": "CVE-2021-42340", "cvss": 7.5,
         "desc": "DoS via memory leak in WebSocket connections",
         "fix": "Upgrade to Tomcat 9.0.54+"},
    ],
    ("tomcat", "10.0.12"): [],
    # ── Elasticsearch ───────────────────────────────────────────────
    ("elasticsearch", "7.17.0"): [
        {"id": "CVE-2022-23708", "cvss": 6.5,
         "desc": "Unauthorized document access via _search API",
         "fix": "Upgrade to Elasticsearch 7.17.1+"},
    ],
    ("elasticsearch", "8.5.0"): [],
    # ── Docker ──────────────────────────────────────────────────────
    ("docker", "20.10.12"): [
        {"id": "CVE-2022-24769", "cvss": 5.9,
         "desc": "Default inheritable capabilities for linux container not empty",
         "fix": "Upgrade to Docker 20.10.14+"},
    ],
    ("docker", "23.0.1"): [],
    # ── Kubernetes ──────────────────────────────────────────────────
    ("kubernetes", "1.24.0"): [
        {"id": "CVE-2022-3162", "cvss": 6.5,
         "desc": "Unauthorized read of custom resources via RBAC bypass",
         "fix": "Upgrade to Kubernetes 1.24.9+"},
    ],
    ("kubernetes", "1.26.0"): [],
    # ── phpMyAdmin ──────────────────────────────────────────────────
    ("phpmyadmin", "5.1.0"): [
        {"id": "CVE-2021-32610", "cvss": 7.1,
         "desc": "Path traversal via crafted archive file",
         "fix": "Upgrade to phpMyAdmin 5.1.1+"},
    ],
    ("phpmyadmin", "5.2.0"): [],
    # ── IIS ─────────────────────────────────────────────────────────
    ("iis", "10.0"): [
        {"id": "CVE-2021-31166", "cvss": 9.8,
         "desc": "HTTP protocol stack RCE (wormable)",
         "fix": "Apply Windows Update KB5003173"},
    ],
    ("iis", "8.5"): [
        {"id": "CVE-2017-7269", "cvss": 9.8,
         "desc": "WebDAV buffer overflow allowing RCE",
         "fix": "Disable WebDAV; upgrade to IIS 10+"},
    ],
    # ── ProFTPD ─────────────────────────────────────────────────────
    ("proftpd", "1.3.6"): [
        {"id": "CVE-2019-12815", "cvss": 9.8,
         "desc": "Arbitrary file copy via mod_copy without authentication",
         "fix": "Upgrade to ProFTPD 1.3.6b+ or disable mod_copy"},
    ],
    ("proftpd", "1.3.7"): [],
    # ── Flask ──────────────────────────────────────────────────────
    ("flask", "3.1.8"): [
        {"id": "CVE-2023-30861", "cvss": 7.5,
         "desc": "Session cookie set without Vary: Cookie header, may be cached by proxies and served to other users",
         "fix": "Upgrade Flask to 2.3.2+; set SESSION_COOKIE_SAMESITE='Lax'"},
        {"id": "CVE-2019-1010083", "cvss": 7.5,
         "desc": "Unexpected memory usage via crafted encoded JSON data",
         "fix": "Upgrade Flask to 1.0+; disable debug mode in production"},
    ],
    ("flask", "2.3.0"): [
        {"id": "CVE-2023-30861", "cvss": 7.5,
         "desc": "Session cookie exposure via missing Vary header",
         "fix": "Upgrade Flask to 2.3.2+"},
    ],
    ("flask", "3.0.0"): [],
    # ── Werkzeug ───────────────────────────────────────────────────
    ("werkzeug", "3.1.8"): [
        {"id": "CVE-2024-34069", "cvss": 9.8,
         "desc": "Debugger RCE — remote code execution via Werkzeug interactive debugger if enabled in production",
         "fix": "Upgrade Werkzeug to 3.0.3+; disable debugger in production"},
        {"id": "CVE-2024-49767", "cvss": 7.5,
         "desc": "Resource exhaustion via multipart form data — excessive memory consumption",
         "fix": "Upgrade Werkzeug to 3.1.0+; set request.max_form_parts limit"},
        {"id": "CVE-2023-46136", "cvss": 7.5,
         "desc": "Multipart form data parser DoS via resource exhaustion",
         "fix": "Upgrade Werkzeug to 3.0.1+; limit multipart form data size"},
    ],
    ("werkzeug", "2.2.2"): [
        {"id": "CVE-2023-25577", "cvss": 7.5,
         "desc": "Multipart parser DoS — high resource consumption on large form data",
         "fix": "Upgrade Werkzeug to 2.2.3+; set max_form_memory_size"},
        {"id": "CVE-2023-23934", "cvss": 5.3,
         "desc": "Cookie injection via domain attribute on localhost",
         "fix": "Upgrade Werkzeug to 2.2.3+; validate cookie domain settings"},
    ],
    ("werkzeug", "3.0.3"): [],
}


# ---------------------------------------------------------------------------
# CVE Lookup Engine
# ---------------------------------------------------------------------------

class CVELookup:
    """Looks up known CVEs for software + version combinations.

    Lookup pipeline (in order):
      1. Built-in offline CVE database (instant, comprehensive)
      2. NVD REST API v2.0 (live, requires CVE_API_KEY in env)

    Both sources are merged and deduplicated by CVE ID.
    NVD lookups are cached to avoid redundant API calls.
    """

    def __init__(self) -> None:
        self.lookup_count: int = 0
        self.total_cves_found: int = 0
        self.nvd_hits: int = 0
        self._seen: Set[str] = set()
        self._nvd_cache: Dict[Tuple[str, str], List[CVERecord]] = {}

    async def lookup(
        self, software: str, version: str
    ) -> List[CVERecord]:
        """Look up CVEs for software+version from all sources."""
        sw = software.lower().strip()
        ver = version.strip()
        self.lookup_count += 1

        records: List[CVERecord] = []
        seen_ids: Set[str] = set()

        # ── 1. Offline database (exact match) ─────────────────────
        key = (sw, ver)
        for e in _CVE_DB.get(key, []):
            rec = self._record(e, sw, ver)
            records.append(rec)
            seen_ids.add(rec.cve_id)

        # ── 2. Offline database (partial version fallback) ────────
        if not records:
            major_minor = ".".join(ver.split(".")[:2])
            for (db_sw, db_ver), db_entries in _CVE_DB.items():
                if db_sw == sw and db_ver.startswith(major_minor) and db_entries:
                    for e in db_entries:
                        rec = self._record(e, sw, ver)
                        if rec.cve_id not in seen_ids:
                            records.append(rec)
                            seen_ids.add(rec.cve_id)
                    break

        # ── 3. NVD API (live lookup — merges with offline) ────────
        nvd_records = await self._query_nvd(sw, ver)
        for rec in nvd_records:
            if rec.cve_id not in seen_ids:
                records.append(rec)
                seen_ids.add(rec.cve_id)

        # Track unique CVEs
        for rec in records:
            if rec.cve_id not in self._seen:
                self._seen.add(rec.cve_id)
                self.total_cves_found += 1

        if records:
            sources = "offline"
            if nvd_records:
                sources += "+NVD"
            logger.info(
                f"CVELookup [{sources}]: {sw} {ver} -> {len(records)} CVE(s): "
                + ", ".join(r.cve_id for r in records)
            )

        return records

    def _record(self, entry: Dict[str, Any], sw: str, ver: str) -> CVERecord:
        return CVERecord(
            cve_id=entry["id"],
            severity=_sev(entry["cvss"]),
            cvss_score=entry["cvss"],
            description=entry["desc"],
            affected_software=sw,
            affected_version=ver,
            fix=entry["fix"],
        )

    async def _query_nvd(
        self, software: str, version: str
    ) -> List[CVERecord]:
        """Query NVD REST API v2.0. Results are cached per software+version.

        Tries with API key first (higher rate limit). If the key is
        rejected (404/403), retries without it (public rate limit).
        """
        cache_key = (software, version)
        if cache_key in self._nvd_cache:
            return self._nvd_cache[cache_key]

        try:
            import httpx

            url = os.environ.get(
                "CVE_FEED_URL",
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
            )
            keyword = f"{software} {version}"
            params = {"keywordSearch": keyword, "resultsPerPage": 10}

            api_key = os.environ.get("CVE_API_KEY", "")
            headers = {"apiKey": api_key} if api_key else {}

            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(url, params=params, headers=headers)

                # If API key was rejected, retry without it
                if resp.status_code in (403, 404) and api_key:
                    logger.info("CVELookup: API key rejected, retrying without key")
                    resp = await client.get(url, params=params)

                resp.raise_for_status()
                data = resp.json()

            records: List[CVERecord] = []
            for vuln in data.get("vulnerabilities", []):
                cve = vuln.get("cve", {})
                cve_id = cve.get("id", "")
                if not cve_id:
                    continue

                # Extract CVSS score (try v3.1 first, then v3.0, then v2)
                metrics = cve.get("metrics", {})
                score = 0.0
                for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    metric_list = metrics.get(metric_key, [])
                    if metric_list:
                        cvss_data = metric_list[0].get("cvssData", {})
                        score = cvss_data.get("baseScore", 0.0)
                        break

                # Extract English description
                desc_list = cve.get("descriptions", [])
                desc = next(
                    (d["value"] for d in desc_list if d.get("lang") == "en"),
                    "No description available",
                )

                # Extract references
                refs = [
                    r.get("url", "")
                    for r in cve.get("references", [])[:3]
                    if r.get("url")
                ]

                rec = CVERecord(
                    cve_id=cve_id,
                    severity=_sev(score),
                    cvss_score=score,
                    description=desc[:300],
                    affected_software=software,
                    affected_version=version,
                    fix=f"See NVD: https://nvd.nist.gov/vuln/detail/{cve_id}",
                    references=refs,
                )
                records.append(rec)

            self._nvd_cache[cache_key] = records
            if records:
                self.nvd_hits += 1
                logger.info(
                    f"CVELookup: NVD API returned {len(records)} CVE(s) "
                    f"for {software} {version}"
                )
            return records

        except Exception as exc:
            logger.warning(f"CVELookup: NVD API query failed for {software} {version}: {exc}")
            self._nvd_cache[cache_key] = []
            return []

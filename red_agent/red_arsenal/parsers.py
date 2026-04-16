"""Normalize each tool's stdout into a shared `ToolResult` dict.

Shape:
    {
      "tool":       str,
      "target":     str,
      "ok":         bool,
      "duration_s": float,
      "returncode": int,
      "findings":   list[dict],     # tool-specific normalized rows
      "raw_tail":   str,            # last 2KB of stdout (for debugging)
      "error":      str | None,
    }

Every parser is defensive — a broken row never raises, it just gets skipped
so the agent still sees the rest of the scan.
"""

from __future__ import annotations

import json
import re
from typing import Any

from .runner import RunResult

RAW_TAIL_BYTES = 2048


def _base(tool: str, target: str, raw: RunResult) -> dict:
    return {
        "tool": tool,
        "target": target,
        "ok": raw.ok,
        "duration_s": raw.duration_s,
        "returncode": raw.returncode,
        "findings": [],
        "raw_tail": raw.text_out()[-RAW_TAIL_BYTES:],
        "error": None if raw.ok else (raw.text_err()[-500:] or "non-zero exit"),
    }


def _jsonl(text: str) -> list[dict]:
    out: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


# -------- Recon ----------------------------------------------------------

def parse_nmap(raw: RunResult, target: str) -> dict:
    """Parse nmap XML output from `-oX -`."""
    out = _base("nmap", target, raw)
    try:
        import xmltodict
        data = xmltodict.parse(raw.text_out())
    except Exception as e:
        out["error"] = f"xml parse failed: {e}"
        return out

    hosts = data.get("nmaprun", {}).get("host", [])
    if isinstance(hosts, dict):
        hosts = [hosts]
    for host in hosts:
        addr = host.get("address", {})
        ip = addr.get("@addr") if isinstance(addr, dict) else None
        ports_block = host.get("ports", {}) or {}
        ports = ports_block.get("port", [])
        if isinstance(ports, dict):
            ports = [ports]
        for p in ports:
            state = (p.get("state") or {}).get("@state")
            service = p.get("service") or {}
            out["findings"].append({
                "host": ip,
                "port": int(p.get("@portid", 0)),
                "protocol": p.get("@protocol"),
                "state": state,
                "service": service.get("@name"),
                "product": service.get("@product"),
                "version": service.get("@version"),
            })
    return out


def parse_httpx(raw: RunResult, target: str) -> dict:
    out = _base("httpx", target, raw)
    for row in _jsonl(raw.text_out()):
        out["findings"].append({
            "url": row.get("url"),
            "status_code": row.get("status_code"),
            "title": row.get("title"),
            "tech": row.get("tech") or row.get("technologies"),
            "webserver": row.get("webserver"),
            "content_length": row.get("content_length"),
        })
    return out


def parse_katana(raw: RunResult, target: str) -> dict:
    out = _base("katana", target, raw)
    # katana JSONL nests the URL under `request.endpoint`/`request.url` and
    # the source under `timestamp`/`response.status_code`. Top-level
    # `endpoint` and `url` keys do NOT exist in recent versions.
    for row in _jsonl(raw.text_out()):
        if not isinstance(row, dict):
            continue
        request = row.get("request") or {}
        response = row.get("response") or {}
        url = (
            request.get("endpoint")
            or request.get("url")
            or row.get("endpoint")
            or row.get("url")
        )
        out["findings"].append({
            "url": url,
            "method": request.get("method"),
            "source": row.get("source") or row.get("timestamp"),
            "status_code": response.get("status_code"),
        })
    # Plain-text fallback
    if not out["findings"]:
        for line in raw.text_out().splitlines():
            line = line.strip()
            if line.startswith("http"):
                out["findings"].append({"url": line})
    return out


def parse_gau(raw: RunResult, target: str) -> dict:
    out = _base("gau", target, raw)
    for line in raw.text_out().splitlines():
        line = line.strip()
        if line.startswith("http"):
            out["findings"].append({"url": line})
    return out


def parse_waybackurls(raw: RunResult, target: str) -> dict:
    out = _base("waybackurls", target, raw)
    for line in raw.text_out().splitlines():
        line = line.strip()
        if line.startswith("http"):
            out["findings"].append({"url": line})
    return out


def parse_nuclei(raw: RunResult, target: str) -> dict:
    out = _base("nuclei", target, raw)
    for row in _jsonl(raw.text_out()):
        info = row.get("info", {}) or {}
        out["findings"].append({
            "template_id": row.get("template-id") or row.get("templateID"),
            "name": info.get("name"),
            "severity": info.get("severity"),
            "host": row.get("host"),
            "matched_at": row.get("matched-at") or row.get("matched_at"),
            "tags": info.get("tags"),
        })
    return out


def parse_dirsearch(raw: RunResult, target: str) -> dict:
    out = _base("dirsearch", target, raw)
    # dirsearch plain output: "[HH:MM:SS] 200 -   123B  - /path"
    pattern = re.compile(r"\s*(\d{3})\s+-\s+(\S+)\s+-\s+(\S+)")
    for line in raw.text_out().splitlines():
        m = pattern.search(line)
        if m:
            out["findings"].append({
                "status": int(m.group(1)),
                "size": m.group(2),
                "path": m.group(3),
            })
    return out


def parse_gobuster(raw: RunResult, target: str) -> dict:
    out = _base("gobuster", target, raw)
    # "/admin   (Status: 301) [Size: 312] [--> /admin/]"
    pattern = re.compile(r"^(\S+)\s+\(Status:\s*(\d+)\)\s*(?:\[Size:\s*(\d+)\])?")
    for line in raw.text_out().splitlines():
        m = pattern.search(line.strip())
        if m:
            out["findings"].append({
                "path": m.group(1),
                "status": int(m.group(2)),
                "size": int(m.group(3)) if m.group(3) else None,
            })
    return out


# -------- API ------------------------------------------------------------

def parse_arjun(raw: RunResult, target: str) -> dict:
    out = _base("arjun", target, raw)
    # arjun -oJ writes JSON to a file; when we use -oT stdout has a list
    text = raw.text_out()
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            for url, info in data.items():
                params = info.get("params") if isinstance(info, dict) else info
                out["findings"].append({"url": url, "params": params})
        elif isinstance(data, list):
            out["findings"].append({"params": data})
    except json.JSONDecodeError:
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("[+]") or line.startswith("Parameters:"):
                out["findings"].append({"line": line})
    return out


def parse_x8(raw: RunResult, target: str) -> dict:
    out = _base("x8", target, raw)
    # x8 --output-format json emits one JSON object
    try:
        data = json.loads(raw.text_out())
        if isinstance(data, list):
            for row in data:
                out["findings"].append(row)
        elif isinstance(data, dict):
            out["findings"].append(data)
    except json.JSONDecodeError:
        for line in raw.text_out().splitlines():
            if "Found" in line or "param" in line.lower():
                out["findings"].append({"line": line.strip()})
    return out


def parse_paramspider(raw: RunResult, target: str) -> dict:
    out = _base("paramspider", target, raw)
    for line in raw.text_out().splitlines():
        line = line.strip()
        if line.startswith("http") and "=" in line:
            out["findings"].append({"url": line})
    return out


def parse_ffuf(raw: RunResult, target: str) -> dict:
    out = _base("ffuf", target, raw)
    try:
        data = json.loads(raw.text_out())
        for row in data.get("results", []):
            out["findings"].append({
                "url": row.get("url"),
                "input": row.get("input"),
                "status": row.get("status"),
                "length": row.get("length"),
                "words": row.get("words"),
            })
    except json.JSONDecodeError:
        pass
    return out


# -------- Network --------------------------------------------------------

def parse_arp_scan(raw: RunResult, target: str) -> dict:
    out = _base("arp-scan", target, raw)
    # "192.168.1.5  aa:bb:cc:dd:ee:ff  Vendor"
    pattern = re.compile(
        r"^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]{17})\s*(.*)$"
    )
    for line in raw.text_out().splitlines():
        m = pattern.match(line.strip())
        if m:
            out["findings"].append({
                "ip": m.group(1),
                "mac": m.group(2),
                "vendor": m.group(3).strip() or None,
            })
    return out


def parse_rustscan(raw: RunResult, target: str) -> dict:
    out = _base("rustscan", target, raw)
    # rustscan -> "Open 192.168.1.1:22"
    for line in raw.text_out().splitlines():
        m = re.match(r"Open\s+(\S+?):(\d+)", line.strip())
        if m:
            out["findings"].append({"host": m.group(1), "port": int(m.group(2))})
    return out


def parse_masscan(raw: RunResult, target: str) -> dict:
    out = _base("masscan", target, raw)
    # masscan -oJ is a JSON array
    try:
        text = raw.text_out().strip()
        if text.startswith("["):
            data = json.loads(text.rstrip(",\n ") + ("]" if not text.endswith("]") else ""))
        else:
            data = _jsonl(text)
        for row in data:
            ports = row.get("ports") or []
            for p in ports:
                out["findings"].append({
                    "ip": row.get("ip"),
                    "port": p.get("port"),
                    "proto": p.get("proto"),
                    "status": p.get("status"),
                })
    except Exception:
        pass
    return out


def parse_enum4linux_ng(raw: RunResult, target: str) -> dict:
    out = _base("enum4linux-ng", target, raw)
    # -oJ file vs stdout — if json parse fails, return raw sections
    try:
        data = json.loads(raw.text_out())
        out["findings"].append(data)
    except json.JSONDecodeError:
        out["findings"].append({"raw": raw.text_out()[-4000:]})
    return out


def parse_nbtscan(raw: RunResult, target: str) -> dict:
    out = _base("nbtscan", target, raw)
    for line in raw.text_out().splitlines():
        parts = line.split()
        if len(parts) >= 2 and re.match(r"\d+\.\d+\.\d+\.\d+", parts[0]):
            out["findings"].append({
                "ip": parts[0],
                "name": parts[1] if len(parts) > 1 else None,
                "details": " ".join(parts[2:]) if len(parts) > 2 else None,
            })
    return out


def parse_smbmap(raw: RunResult, target: str) -> dict:
    out = _base("smbmap", target, raw)
    for line in raw.text_out().splitlines():
        line = line.rstrip()
        if not line.strip():
            continue
        out["findings"].append({"line": line})
    return out


def parse_rpcclient(raw: RunResult, target: str) -> dict:
    out = _base("rpcclient", target, raw)
    for line in raw.text_out().splitlines():
        if line.strip():
            out["findings"].append({"line": line.rstrip()})
    return out


# -------- sqlmap ---------------------------------------------------------

_SQLMAP_DUMP_HEADER = re.compile(r"^Database:\s*(\S+)|^Table:\s*(\S+)")
_SQLMAP_INJECTABLE = re.compile(r"Parameter:\s*([^\(]+)\(([^)]+)\)")
_SQLMAP_DBMS = re.compile(r"back-end DBMS:\s*(.+)")


_SQLMAP_FATAL_PATTERNS = (
    "connection timed out to the target URL",
    "connection refused",
    "host seems down",
    "no usable links found",
    "unable to connect to the target URL",
    "name or service not known",
    "all tested parameters do not appear to be injectable",
)


def parse_sqlmap(
    raw: RunResult,
    target: str,
    mode: str = "detect",
    extra: dict | None = None,
) -> dict:
    """sqlmap output is human-readable; we keep the FULL stdout in `raw_full`
    (uncapped) so the LLM and dashboard see the entire dump, and also extract
    structured `findings` for fast UI rendering."""
    out = _base("sqlmap", target, raw)
    out["mode"] = mode
    if extra:
        out.update({k: v for k, v in extra.items() if v is not None})

    text = raw.text_out()
    # Override raw_tail with full output — exfiltrated data must reach the user
    out["raw_tail"] = text[-32000:]  # 32KB cap (way more than default 2KB)
    out["raw_full"] = text

    # Strip ANSI just in case --disable-coloring missed something
    text = re.sub(r"\x1b\[[0-9;]*m", "", text)

    # sqlmap exits 0 even when the target is unreachable. Promote the most
    # informative critical line to `error` so the UI doesn't show a clean DONE
    # for a run that never even reached the target.
    lower = text.lower()
    fatal_msg: str | None = None
    for pat in _SQLMAP_FATAL_PATTERNS:
        if pat in lower:
            for line in text.splitlines():
                if pat in line.lower():
                    fatal_msg = line.strip().lstrip("\r")
                    break
            if fatal_msg:
                break
    if fatal_msg:
        out["ok"] = False
        out["error"] = fatal_msg[:500]

    findings: list[dict] = []
    lines = text.splitlines()

    # 1) DBMS fingerprint
    for line in lines:
        m = _SQLMAP_DBMS.search(line)
        if m:
            findings.append({"type": "dbms", "value": m.group(1).strip()})
            break

    # 2) Injectable parameters
    for line in lines:
        m = _SQLMAP_INJECTABLE.search(line)
        if m:
            findings.append({
                "type": "injection",
                "param": m.group(1).strip(),
                "place": m.group(2).strip(),
            })

    # 3) Databases
    if mode == "dbs":
        in_block = False
        for line in lines:
            if "available databases" in line:
                in_block = True
                continue
            if in_block:
                s = line.strip()
                if s.startswith("[*]"):
                    findings.append({"type": "database", "name": s.removeprefix("[*]").strip()})
                elif s and not s.startswith("[") and not s.startswith("Database"):
                    in_block = False

    # 4) Tables
    if mode == "tables":
        cur_db = (extra or {}).get("db")
        in_block = False
        for line in lines:
            s = line.strip()
            if s.startswith("Database:"):
                cur_db = s.split(":", 1)[1].strip()
            elif s.startswith("|") and not s.startswith("| "):
                # table separator row, ignore
                continue
            elif s.startswith("|") and len(s) > 2 and "table" not in s.lower():
                name = s.strip("|").strip()
                if name and name not in ("Tables", ""):
                    findings.append({"type": "table", "db": cur_db, "name": name})

    # 5) Dump rows — capture every "| ... |" data row inside a table block
    if mode == "dump":
        cur_db = None
        cur_table = None
        for line in lines:
            s = line.strip()
            if s.startswith("Database:"):
                cur_db = s.split(":", 1)[1].strip()
                continue
            if s.startswith("Table:"):
                cur_table = s.split(":", 1)[1].strip()
                continue
            if s.startswith("|") and s.endswith("|") and cur_table:
                cells = [c.strip() for c in s.strip("|").split("|")]
                # Skip pure separator rows
                if any(c for c in cells):
                    findings.append({
                        "type": "row",
                        "db": cur_db,
                        "table": cur_table,
                        "cells": cells,
                    })

    out["findings"] = findings
    return out

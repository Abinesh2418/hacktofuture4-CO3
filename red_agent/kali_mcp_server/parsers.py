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
    for row in _jsonl(raw.text_out()):
        if isinstance(row, dict):
            out["findings"].append({
                "url": row.get("endpoint") or row.get("url"),
                "source": row.get("source"),
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

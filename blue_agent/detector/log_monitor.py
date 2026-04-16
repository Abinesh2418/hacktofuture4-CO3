"""Real-Time Detection (Feature 1) — Continuously tail system logs for Red signatures.

Maintains an internal rotating log buffer (simulating /var/log/syslog or
auth.log) that is injected with realistic Red-agent entries every 1.5 seconds.
A separate tail loop processes new lines every 1 second and pattern-matches
against known Red signatures.

Signature → event mapping:
    nmap pattern found       → port_scanned
    CVE lookup pattern found → cve_detected
    Exploit string found     → exploit_attempted

Both loops run as asyncio coroutines — neither blocks the other or the
intrusion / anomaly detectors.
"""

import asyncio
import logging
import random
import re
from collections import deque
from datetime import datetime
from typing import Deque, List, Tuple

from core.event_bus import event_bus

logger = logging.getLogger(__name__)

TARGET_IP = "172.25.8.172"

# ---------------------------------------------------------------------------
# Simulated Red-agent log templates
# Each entry is (template_string, signature_category)
# ---------------------------------------------------------------------------
RED_LOG_TEMPLATES: List[Tuple[str, str]] = [
    # nmap patterns → port_scanned
    ("nmap -sV -p {port} {target}", "nmap"),
    ("nmap -sS --open -T4 {target}", "nmap"),
    ("nmap -A -p- {target}", "nmap"),
    ("nmap -sU --top-ports 100 {target}", "nmap"),
    # CVE lookup patterns → cve_detected
    ("searchsploit CVE-{year}-{cve_id}", "cve_lookup"),
    ("curl https://nvd.nist.gov/vuln/detail/CVE-{year}-{cve_id}", "cve_lookup"),
    ("python3 cve_check.py --id CVE-{year}-{cve_id} --target {target}", "cve_lookup"),
    # Exploit strings → exploit_attempted
    ("msfconsole -x 'use exploit/multi/handler; set LHOST {target}; run'", "exploit"),
    ("python3 exploit_{service}.py --target {target} --port {port}", "exploit"),
    ("hydra -l admin -P /usr/share/wordlists/rockyou.txt {target} {service}", "exploit"),
    ("./exploit.sh --rhost {target} --rport {port} --payload reverse_shell", "exploit"),
    # SQL injection attacks on Flask /search endpoint → sql_injection
    ("sqlmap -u http://{target}:5000/search?q=test --dbs --level=5 --risk=3", "sql_injection"),
    ("sqlmap -u http://{target}:5000/search?q=Widget --batch --dump", "sql_injection"),
    ("curl 'http://{target}:5000/search?q=%27+OR+1%3D1--'", "sql_injection"),
    ("python3 sqli_exploit.py --url http://{target}:5000/search --param q", "sql_injection"),
    # Credential brute-force on Flask /login → credential_attack
    ("hydra -l admin -P /usr/share/wordlists/rockyou.txt {target} http-post-form '/login:username=^USER^&password=^PASS^:Invalid'", "credential_attack"),
    ("python3 brute_login.py --url http://{target}:5000/login --wordlist rockyou.txt", "credential_attack"),
    ("curl -X POST http://{target}:5000/login -d 'username=admin&password=admin123'", "credential_attack"),
    ("wfuzz -z file,passwords.txt -d 'username=admin&password=FUZZ' http://{target}:5000/login", "credential_attack"),
    # Directory traversal on Flask /profile → directory_traversal
    ("curl 'http://{target}:5000/profile?id=../../etc/passwd'", "directory_traversal"),
    ("curl 'http://{target}:5000/profile?id=....//....//etc/shadow'", "directory_traversal"),
    ("dotdotpwn -m http -h {target} -x 5000 -f /etc/passwd -k root", "directory_traversal"),
    # IDOR on Flask /profile → idor
    ("python3 idor_enum.py --url http://{target}:5000/profile --param id --range 1-1000", "idor"),
    ("curl 'http://{target}:5000/profile?id=2' -H 'Cookie: session=user1_token'", "idor"),
]

# Signature category → event type
SIGNATURE_TO_EVENT = {
    "nmap": "port_scanned",
    "cve_lookup": "cve_detected",
    "exploit": "exploit_attempted",
    "sql_injection": "sql_injection_attempted",
    "credential_attack": "credential_attack_detected",
    "directory_traversal": "directory_traversal_attempted",
    "idor": "idor_attempted",
}

# Regex to extract CVE IDs from log lines
CVE_REGEX = re.compile(r"CVE-(\d{4})-(\d+)")

PORT_SERVICE_MAP = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    80: "http",
    443: "https",
    3306: "mysql",
    5000: "flask",
    8080: "http",
    5432: "postgresql",
}


def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def _render_template(template: str) -> str:
    """Fill a log template with random but plausible values."""
    port = random.choice(list(PORT_SERVICE_MAP.keys()))
    service = PORT_SERVICE_MAP.get(port, "http")
    return template.format(
        port=port,
        target=TARGET_IP,
        year=random.randint(2020, 2024),
        cve_id=random.randint(10000, 99999),
        service=service,
    )


class LogMonitor:
    """Tails an internal simulated log buffer and pattern-matches Red signatures.

    Emits:
        port_scanned      — when an nmap pattern is found
        cve_detected      — when a CVE lookup pattern is found
        exploit_attempted — when an exploit string is found
    """

    def __init__(self) -> None:
        self._log_buffer: Deque[Tuple[str, str]] = deque(maxlen=500)
        # (log_line, signature_category)
        self._running: bool = False
        self._inject_task: "asyncio.Task | None" = None
        self._cursor: int = 0  # how many buffer entries have been processed
        self.detection_count: int = 0

    # ------------------------------------------------------------------
    # Log injection (simulates Red agent writing to system logs)
    # ------------------------------------------------------------------

    async def _inject_logs(self) -> None:
        """Inject 1–3 Red log entries into the buffer every 1.5 seconds."""
        while self._running:
            count = random.randint(1, 3)
            for _ in range(count):
                template, sig_type = random.choice(RED_LOG_TEMPLATES)
                line = _render_template(template)
                timestamped = f"{_ts()} {line}"
                self._log_buffer.append((timestamped, sig_type))
            await asyncio.sleep(1.5)

    # ------------------------------------------------------------------
    # Log tailing (processes new buffer entries, matches signatures)
    # ------------------------------------------------------------------

    def _extract_context(self, line: str) -> dict:
        """Pull port, service, CVE, and source_ip from a log line."""
        ctx: dict = {"target": TARGET_IP, "source_ip": f"10.0.0.{random.randint(2, 254)}"}

        # Port
        for p in sorted(PORT_SERVICE_MAP.keys(), reverse=True):
            if str(p) in line:
                ctx["port"] = p
                ctx["service"] = PORT_SERVICE_MAP[p]
                break

        # Service keyword fallback
        if "service" not in ctx:
            for svc in PORT_SERVICE_MAP.values():
                if svc in line.lower():
                    ctx["service"] = svc
                    break

        # CVE
        cve_match = CVE_REGEX.search(line)
        if cve_match:
            ctx["cve_id"] = f"CVE-{cve_match.group(1)}-{cve_match.group(2)}"
            ctx["service_name"] = ctx.get("service", "unknown")

        return ctx

    async def _tail_loop(self) -> None:
        """Process new log buffer entries every 1 second. Non-blocking."""
        while self._running:
            try:
                buffer_snapshot = list(self._log_buffer)
                new_entries = buffer_snapshot[self._cursor:]
                self._cursor = len(buffer_snapshot)

                for line, sig_type in new_entries:
                    event_type = SIGNATURE_TO_EVENT.get(sig_type)
                    if not event_type:
                        continue

                    ctx = self._extract_context(line)
                    ts = _ts()

                    label_map = {
                        "port_scanned": "nmap pattern",
                        "cve_detected": "CVE lookup pattern",
                        "exploit_attempted": "exploit string",
                    }
                    label = label_map.get(event_type, sig_type)

                    print(
                        f"{ts} < log_monitor: {label} found in logs "
                        f"→ emitting {event_type}"
                    )
                    print(
                        f'{ts} > event_bus.emit("{event_type}", {ctx})'
                    )

                    self.detection_count += 1
                    await event_bus.emit(event_type, ctx)

            except Exception as exc:
                logger.error(f"LogMonitor tail error: {exc}")

            await asyncio.sleep(1)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start log injection and tailing concurrently."""
        self._running = True
        ts = _ts()
        print(
            f"{ts} < log_monitor: Log monitoring started "
            f"— tailing internal buffer for Red signatures"
        )
        # Run injection as a background task so the tail loop can await
        self._inject_task = asyncio.create_task(
            self._inject_logs(), name="log_injector"
        )
        await self._tail_loop()

    async def stop(self) -> None:
        """Stop both the tail loop and the injection task."""
        self._running = False
        if self._inject_task and not self._inject_task.done():
            self._inject_task.cancel()
            try:
                await self._inject_task
            except asyncio.CancelledError:
                pass

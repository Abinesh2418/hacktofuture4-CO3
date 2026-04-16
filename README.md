# HackToFuture 4.0 — Team CO3

> **HTF 4.0 ARENA — Red vs Blue AI Cyber Battleground**
> An autonomous AI-powered cybersecurity simulation where a Red agent attacks and a Blue agent defends in real time.

---

## Problem Statement

Modern cybersecurity teams struggle to train for real-world attack-defense scenarios. Traditional red team / blue team exercises are expensive, slow, and require large specialist teams. There is no accessible, automated platform where both sides operate simultaneously and the defense team can see threats as they emerge and respond in real time.

**Who is affected:** Security teams, SOC analysts, cybersecurity trainees, and organizations running internal audits.

---

## Proposed Solution

**HTF Arena** is a live Red vs Blue cybersecurity simulation platform powered by autonomous AI agents:

- The **Red Agent** (attacker) runs a 3-agent CrewAI crew — an Infrastructure Auditor, a Risk Analyst, and a Technical Verification Engineer — that scans a target, assesses risk, and produces a detailed security report.
- The **Blue Agent** (defender) receives the Red report in real time, runs it through an IDS and SIEM engine, queues fixes for operator approval, and applies remediations with a single click.
- Both sides stream live tool calls, logs, and status updates to a shared **Arena Dashboard** that the operator watches in real time.

What makes it unique:
- Fully autonomous AI agents using CrewAI + Azure OpenAI GPT-4o
- Real-time event bus connecting Red findings directly to Blue remediation
- Human-in-the-loop approval workflow — the operator approves or rejects each fix
- Built-in IDS (15 signature rules) and SIEM (7 MITRE ATT&CK phase correlation)
- Live score tracking for both teams

---

## Features

### Red Agent (Attacker)
- 3-agent CrewAI crew: Infrastructure Auditor → Risk Analyst → Technical Verification Engineer
- 9 assessment tools: `nmap_scan`, `httpx_probe`, `gobuster_scan`, `nuclei_scan`, `katana_crawl`, `dirsearch_scan`, `nuclei_exploit`, `ffuf_fuzz`, `nmap_vuln_scan`
- Simulated tool results when Kali MCP server is unavailable (Windows-safe)
- Streams every tool card to the dashboard in real time via WebSocket
- Chat interface — type a target and the crew launches automatically

### Blue Agent (Defender)
- **Remediation Engine** — parses Red reports, maps 13 finding categories to fix actions, queues all fixes for operator approval
- **IDS Engine** — 15 signature rules (SIG-001 to SIG-015), fires an alert card per Red finding, maps each to a MITRE ATT&CK technique
- **SIEM Engine** — correlates events across 7 attack phases (Reconnaissance, Exploitation, Exfiltration, Persistence, Impact, Defense Evasion, Privilege Escalation), produces a risk score (0–10)
- **Approval Workflow** — operator clicks ✓ APPLY per fix or ✓ APPROVE ALL to apply everything at once
- SSH Scanner — connects to a live host, discovers services, performs CVE lookup, and applies fixes
- Defense endpoints: close port, harden service, isolate host, apply patch, verify fix

### Arena Dashboard
- Split-screen Red vs Blue battleground
- Real-time tool call cards with RUNNING → DONE / FAILED status
- Live log streams for both agents
- Draggable divider between Red and Blue panels
- Live score ticker (Red score vs Blue score)
- Scoreboard tab with full history
- Download full battle report as `.txt`

### Auth Service
- User registration and login with JWT tokens
- TOTP-based MFA (QR code setup)
- Per-team score tracking via REST API

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   Arena Dashboard (React)                │
│         WebSocket ◄──────────────────► WebSocket        │
│              ws://localhost:8001/ws/red                  │
│              ws://localhost:8002/ws/blue                 │
└──────────────┬──────────────────────────┬───────────────┘
               │                          │
       ┌───────▼────────┐       ┌─────────▼──────────┐
       │  Red Agent API │       │  Blue Agent API     │
       │  :8001         │       │  :8002              │
       │                │       │                     │
       │  CrewAI Crew   │       │  RemediationEngine  │
       │  ├ Auditor     │       │  IDSEngine          │
       │  ├ Analyst     │  ───► │  SIEMEngine         │
       │  └ Verifier    │       │  SSHScanner         │
       │                │       │  DefensePlanner     │
       └────────────────┘       └─────────────────────┘
               │                          │
               └──────────┬───────────────┘
                          │
                  ┌───────▼────────┐
                  │  Event Bus     │
                  │  (pub/sub)     │
                  │  core/         │
                  └───────┬────────┘
                          │
                  ┌───────▼────────┐
                  │  Auth Service  │
                  │  :8003         │
                  └────────────────┘
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Frontend** | React 18, TypeScript, Vite, Axios, native WebSocket |
| **Backend** | FastAPI, Uvicorn, Pydantic v2 |
| **AI Agents** | CrewAI (multi-agent framework), Azure OpenAI GPT-4o |
| **Auth** | JWT, TOTP (pyotp), bcrypt |
| **Real-time** | WebSocket (FastAPI), asyncio event bus (pub/sub) |
| **Security Tools** | nmap, nuclei, gobuster, httpx, ffuf, katana, dirsearch (via MCP / simulated) |
| **IDS / SIEM** | Custom Python engines, 15 IDS signatures, MITRE ATT&CK phase mapping |
| **SSH Scanning** | Paramiko |
| **Environment** | Python 3.12, Node.js 18+, Windows / Linux |

---

## API Endpoints

### Red Agent (:8001)
| Method | Path | Description |
|--------|------|-------------|
| POST | `/chat` | Chat with Red agent, launch assessment |
| POST | `/scan/recon` | Start recon session |
| POST | `/exploit/auto` | Start exploit/verify session |
| GET | `/report/download/{id}` | Download assessment report |
| WS | `/ws/red` | Live tool calls and logs |

### Blue Agent (:8002)
| Method | Path | Description |
|--------|------|-------------|
| POST | `/remediate/run-sample` | Run full Red→Blue pipeline with sample report |
| POST | `/remediate/ingest-report` | Ingest a custom Red report |
| GET | `/remediate/pending` | List fixes awaiting approval |
| POST | `/remediate/approve/{id}` | Approve and apply a single fix |
| POST | `/remediate/approve-all` | Approve and apply all pending fixes |
| POST | `/remediate/reject/{id}` | Reject a pending fix |
| GET | `/ids/status` | IDS engine status and alert summary |
| GET | `/ids/alerts` | Recent IDS alert list |
| GET | `/siem/report` | Correlated SIEM report with timeline |
| GET | `/siem/status` | SIEM engine status |
| POST | `/scan/ssh` | Run SSH scan on a live host |
| WS | `/ws/blue` | Live tool calls and logs |

### Auth Service (:8003)
| Method | Path | Description |
|--------|------|-------------|
| POST | `/auth/register` | Register a new user |
| POST | `/auth/login` | Login and receive JWT |
| GET | `/scores` | Get current Red/Blue scores |

---

## Project Setup

### Prerequisites
- Python 3.12+
- Node.js 18+ and npm
- Azure OpenAI API key (GPT-4o deployment)

### 1. Clone and configure

```bash
git clone <repo-url>
cd hacktofuture4-CO3

# Copy environment template and fill in your Azure key
cp .env.example .env
```

Edit `.env`:
```env
AZURE_OPENAI_API_KEY=your_key_here
AZURE_OPENAI_ENDPOINT=https://your-resource.cognitiveservices.azure.com/
AZURE_OPENAI_API_VERSION=2024-12-01-preview
AZURE_OPENAI_MODEL=gpt-4o
```

### 2. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 3. Run everything (recommended)

```bash
./run.sh
```

This starts all services and opens the Arena Dashboard automatically:

| Service | URL |
|---------|-----|
| Arena Dashboard | http://localhost:5173 |
| Red Agent API | http://localhost:8001 |
| Blue Agent API | http://localhost:8002 |
| Auth Service | http://localhost:8003 |

### 4. Run specific modes

```bash
./run.sh arena      # Auth + backends + Arena dashboard only
./run.sh backends   # All 3 backends only (no frontend)
./run.sh red        # Red agent only
./run.sh blue       # Blue agent only
```

---

## How to Use the Arena

1. Open http://localhost:5173 and register an account
2. Set up MFA with your authenticator app
3. Log in — you land on the Arena battle screen

**Red side (left panel):**
- Type a target URL or IP in the terminal input (e.g. `http://172.25.8.172:5000`)
- The Red crew launches automatically — watch tool cards appear in real time

**Blue side (right panel):**
- Click **⟳ SEND REPORT** to receive the Red team's findings
- The Blue agent runs IDS detection, SIEM correlation, and queues fix cards
- Click **✓ APPLY** on individual fixes or **✓ APPROVE ALL** to apply everything
- Watch the Blue Log panel for IDS alerts and SIEM correlation reports

**Scoreboard:**
- Click **🏆 SCOREBOARD** tab to see live Red vs Blue scores
- Click **⬇ REPORT** to download the full battle report as a `.txt` file

---

## Project Structure

```
hacktofuture4-CO3/
├── run.sh                        # Unified launcher for all services
├── requirements.txt
├── core/
│   └── event_bus.py              # Async pub/sub event bus (Red ↔ Blue)
├── auth_service/                 # JWT + MFA auth service (:8003)
├── red_agent/
│   ├── agents/
│   │   ├── crew.py               # CrewAI 3-agent crew definition
│   │   └── tools.py              # 9 assessment tools with dashboard streaming
│   ├── backend/
│   │   ├── main.py               # FastAPI app (:8001)
│   │   ├── routers/chat_routes.py
│   │   └── services/
│   │       ├── orchestrator.py   # Mission lifecycle management
│   │       ├── llm_client.py     # Azure OpenAI client
│   │       └── red_service.py
│   └── report_ingester.py        # Parses Red reports into findings
├── blue_agent/
│   ├── remediation/
│   │   ├── remediation_engine.py # Approval-based fix pipeline
│   │   └── flask_fixer.py        # Fix implementations
│   ├── ids/
│   │   └── ids_engine.py         # IDS: 15 signatures, real-time alerts
│   ├── siem/
│   │   └── siem_engine.py        # SIEM: event correlation, risk scoring
│   ├── scanner/
│   │   └── ssh_scanner.py        # SSH-based service + CVE scanner
│   └── backend/
│       ├── main.py               # FastAPI app (:8002)
│       ├── routers/              # defend, patch, strategy, scan, remediation, ids, siem
│       └── services/blue_service.py
└── dashboard/
    └── src/
        ├── pages/ArenaDashboard.tsx   # Main battle UI
        ├── api/
        │   ├── blueApi.ts
        │   └── redApi.ts
        └── hooks/
            ├── useRedWs.ts            # Red WebSocket hook
            └── useBlueWs.ts           # Blue WebSocket hook
```

---

## Rules

- Work must be done ONLY in the forked repository
- Only Four Contributors are allowed
- After 36 hours, make a PR to the Main Repository
- Do not copy code from other teams
- All commits must be from individual GitHub accounts
- Final submission must be pushed before the deadline

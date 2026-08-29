# Autonomous Red Team Recon & Surface Analyzer 🎯🤖

An agentic reconnaissance framework designed for automated, hypothesis-driven attack surface discovery. Unlike traditional, static tool chains that generate noisy outputs, this system dynamically evaluates target context in real time, prioritizes high-value assets, enforces strict scope boundaries, and models the target's attack surface using a directed graph.

---

## 🌟 Key Features

* **Strict Scope Guardrails:** Pre-execution validation layer ensures that no outbound probes or command executions occur against targets outside user-configured domains or IP CIDRs.
* **Deterministic Tool Integration:** Uses safe subprocess wrappers (`shell=False`) to invoke security binaries (e.g., `subfinder`, `httpx`), eliminating command injection vectors while outputting normalized JSON payloads.
* **Graph-Based Attack Surface Modeling:** Built on `NetworkX` to structure discovered entities (Domains, IPs, Ports, Web Apps, Technologies) and their relational edges (`RESOLVES_TO`, `HAS_PORT`, `USES_TECH`).
* **Resilient Execution Engine:** Native error handling and fallback logic allow the agent to gracefully handle missing binaries, timeouts, or rate limits without interrupting the recon cycle.
* **Automated Artifact Generation:** Automatically exports structured Attack Graph JSON data and formatted Executive Markdown reports.

---

## 🏗️ Architecture Overview

```text
               ┌─────────────────────────────┐
               │    Target Input & Scope     │
               │   Validator Guardrail       │
               └──────────────┬──────────────┘
                              │
                              ▼
               ┌─────────────────────────────┐
               │    Recon Agent Planner      │
               └──────────────┬──────────────┘
                              │
       ┌──────────────────────┴──────────────────────┐
       ▼                                             ▼
┌─────────────────────────────┐               ┌─────────────────────────────┐
│ Subdomain Enumeration       │               │ Web Fingerprinting          │
│ (Subfinder Wrapper)         │               │ (HTTPX Wrapper)             │
└──────────────┬──────────────┘               └──────────────┬──────────────┘
               │                                             │
               └──────────────────────┬──────────────────────┘
                                      │
                                      ▼
                       ┌─────────────────────────────┐
                       │   NetworkX Graph Engine     │
                       └──────────────┬──────────────┘
                                      │
                                      ▼
                       ┌─────────────────────────────┐
                       │  JSON & Markdown Reports    │
                       └─────────────────────────────┘
```
---
## 📂 Repository Structure

```text
agentic-recon/
├── config/
│   └── scope.json            # Target domain, CIDR, and IP scope definitions
├── src/
│   ├── agent/
│   │   └── planner.py        # Core planning & decision loop
│   ├── graph/
│   │   └── attack_graph.py   # NetworkX graph representation engine
│   ├── tools/
│   │   ├── base.py           # Base abstract tool execution wrapper
│   │   └── discovery.py      # Subfinder & HTTPX tool implementations
│   └── utils/
│       └── scope.py          # Scope validation & safety engine
├── reports/                  # Generated JSON graph & Markdown outputs
├── main.py                   # Main CLI entry point
├── requirements.txt          # Project dependencies
└── README.md                 # Project documentation

```
---
## 🚀 Getting Started
```text
### Prerequisites

* Python 3.9+
* Optional (for live scanning): Pre-installed security binaries on your system `PATH`:
  * Subfinder
  * HTTPX

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-username/agentic-recon.git
   cd agentic-recon
   
   1. Install Python Dependencies
        pip install -r requirements.txt
        
   2. Configure Scope Boundary
        Edit config/scope.json to specify your allowed targets
        
{
  "allowed_domains": [
    "example.com"
  ],
  "allowed_cidrs": [
    "192.0.2.0/24"
  ],
  "blocked_ips": [
    "192.0.2.5"
  ]
}
   ```
---
## 💻 Usage
```text
Run the main execution pipeline against an in-scope target domain:

```bash
python main.py -d example.com

Flag,Long Argument,Description,Default
-d,--domain,Required. Target seed domain,N/A
-c,--config,Path to scope JSON file,config/scope.json
-o,--output,Directory for exported reports,reports
```
---
## 📊 Sample Output

Upon completion, output files are exported to the `reports/` folder:

* `reports/example.com_attack_graph.json`: Raw node-link graph data structure.
* `reports/example.com_summary.md`: Executive summary table detailing asset counts and strategic findings.

### Executive Summary Snapshot

| Entity Metric | Count |
| :--- | :--- |
| **Total Graph Nodes** | 8 |
| **Total Relationships (Edges)** | 6 |
| **Discovered Domains/Subdomains** | 3 |
| **Resolved IP Addresses** | 1 |
| **Open Service Ports** | 0 |
| **Web Applications Identified** | 2 |

---

## 🛡️ Security & Scope Policy

This tool includes active safety guardrails. Any host, IP, or subdomain resolved during execution that does not explicitly match the constraints declared in `config/scope.json` will be safely blocked prior to tool invocation.

---

## 📝 License

Distributed under the MIT License. See `LICENSE` for details.
---
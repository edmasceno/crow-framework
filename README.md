# 🐦‍⬛ Crow Framework

**Crow** is a high-performance, modular Digital Forensics and Incident Response (DFIR) stream correlation engine written in pure Python. Designed as the cloud-native surveillance wing of **Project Chimera** (alongside *Salamandra* and *Black Ant*), Crow ingests massive volumes of heterogeneous JSONL telemetry, reconstructs chronological attack timelines, and detects multi-stage Tactics, Techniques, and Procedures (TTPs) across Kubernetes clusters and microservice architectures.

---

## ⚙️ Core Architecture

1. **O(1) Memory Stream Ingestion (`crow/core/ingestion.py`):** 
   Uses Python Generators (`yield`) to process multi-gigabyte `.jsonl` and `.log` files line-by-line without exhausting system RAM. Includes fault-tolerant parsing and UTC timezone normalization.
2. **Dynamic SIEM Normalization (`crow/core/models.py`):** 
   Translates raw, unstructured logs from API Gateways, Kafka queues, and Identity Providers into immutable, strongly-typed `LogEvent` dataclasses.
3. **Timeline Correlation Engine (`crow/core/engine.py`):** 
   Groups fragmented microservice events by `correlation_id` and enforces strict chronological sorting to evaluate stateful, multi-step kill chains.
4. **Decoupled Heuristic Contract (`crow/heuristics/base.py`):** 
   Built on the Strategy Pattern using Abstract Base Classes (`HeuristicBase`). The core engine is completely agnostic to detection logic, allowing new rules to be injected dynamically without touching the core pipeline.

---

## 🛡️ Active Detection Heuristics (8 Modules)

| Heuristic Module | Severity | Target TTP / Scenario |
| :--- | :---: | :--- |
| **`SSRF_Redirect_Tracker`** | `CRITICAL` | Detects WAF/allowlist bypasses where an HTTP redirect (`301`/`302`/`307`/`308`) forces an outbound connection to internal RFC 1918 subnets or Cloud Metadata APIs (`169.254.169.254`). |
| **`Segregation_of_Duties_Bypass`** | `HIGH` | Stateful cross-event rule that flags internal fraud when the exact same identity (`principal`) modifies (`rule_updated`) and approves (`rule_approved`) a business or security rule. |
| **`Anti_Forensics_Activity`** | `CRITICAL` | Detects non-admin workloads (`svc-*`, `pod-*`, service accounts) attempting to destroy audit trails or monitoring infrastructure (e.g., `delete-consumer-group`, `StopLogging`, `DeleteTrail`). |
| **`Workload_Token_Bootstrap`** | `HIGH` | Monitors identity pipelines for lateral movement where high-persistence JWT tokens are issued to edge workloads under anomalous or external correlation contexts. |
| **`Financial_Fraud_Batch`** | `CRITICAL` | Flags automated high-volume financial settlements (`auto_approved`) exceeding safety thresholds (> 40,000 units). |
| **`Massive_Data_Exfiltration`** | `CRITICAL` | Tracks egress volume and alerts when external (non-RFC 1918) IP addresses download large data blobs (> 1 MB). |
| **`Gateway_Error_Spike`** | `MEDIUM` | Identifies bursts of `502`/`503` HTTP status codes within a transaction timeline, indicating denial-of-service or service crashes triggered by exploit attempts. |
| **`Authorized_Scanner_Noise`** | `LOW` | Classifies known internal vulnerability scanners via `user_agent` inspection to reduce SOC alert fatigue. |

---

## 📂 Project Structure

```text
crow_framework/
├── crow/
│   ├── __init__.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── models.py          # Immutable LogEvent and Alert dataclasses
│   │   ├── ingestion.py       # O(1) generator stream & SIEM normalization
│   │   └── engine.py          # Timeline grouping & dependency injection
│   └── heuristics/
│       ├── __init__.py
│       ├── base.py            # Abstract Base Class (HeuristicBase contract)
│       ├── ssrf_tracker.py    # RFC 1918 & Metadata redirect detection
│       ├── sod_bypass.py      # Stateful Segregation of Duties tracker
│       ├── anti_forensics.py  # Audit destruction detection
│       └── advanced_rules.py  # Exfiltration, Fraud, Token & Noise rules
└── main.py                    # CLI entrypoint
```

---

## 💻 Getting Started

### Prerequisites
- **Python 3.10+**
- **Zero external dependencies!** Crow relies purely on the Python standard library for maximum portability across restricted environments and minimal container images (Alpine/Distroless).

### Execution

1. Place your target telemetry logs inside the `logs/` directory (default) or specify a custom path. Crow supports `.jsonl` and JSON-formatted `.log` files out-of-the-box.
2. Run the main engine:

```bash
# Run against the default logs directory
python main.py

# Or specify a custom target directory/file and output report path
python main.py -t path/to/custom_logs/ -o custom_alerts.json
```

3. Check the CLI output for the real-time detection log:

```text
[INFO] Phase 1/2: Consuming stream and building timelines...
[INFO] Built 69 distinct timelines.
[INFO] Phase 2/2: Applying heuristic intelligence...
[WARNING] [ALERT GENERATED] Massive_Data_Exfiltration | Timeline: ART-7742-DL1
[WARNING] [ALERT GENERATED] Segregation_of_Duties_Bypass | Timeline: APR-2211-APPROVE
[INFO] Analysis completed. Total alerts: 9.
```

4. Find the full forensic report exported in **`alerts_output.json`**.

---

## 🧠 Adding New Detection Rules

To add a new rule, simply create a new heuristic class implementing `HeuristicBase`:

```python
from typing import List, Optional
from crow.heuristics.base import HeuristicBase
from crow.core.models import LogEvent, Alert

class MyCustomRule(HeuristicBase):
    @property
    def name(self) -> str: 
        return "My_Custom_Threat"
    
    @property
    def description(self) -> str: 
        return "What this rule detects."
    
    def analyze(self, events: List[LogEvent]) -> Optional[Alert]:
        for event in events:
            if event.event_type == "malicious_action":
                return Alert(
                    heuristic_name=self.name, 
                    severity="HIGH", 
                    description="Threat detected!", 
                    correlation_id=event.correlation_id, 
                    events=[event]
                )
        return None
```

Then, inject it into the `heuristics` list inside `main.py`.

---
*Part of **Project Chimera** — Created for the Detection Engineering & DFIR community.*

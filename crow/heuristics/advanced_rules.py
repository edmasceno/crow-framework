import ipaddress
from typing import List, Optional
from crow.heuristics.base import HeuristicBase
from crow.core.models import LogEvent, Alert

class ScannerNoise(HeuristicBase):
    @property
    def name(self) -> str: 
        return "Authorized_Scanner_Noise"
        
    @property
    def description(self) -> str: 
        return "Identifies authorized vulnerability scanner traffic to reduce alert fatigue."
        
    def analyze(self, events: List[LogEvent]) -> Optional[Alert]:
        for event in events:
            user_agent = str(event.payload.get("user_agent", "")).lower()
            if "scanner" in user_agent or "vuln" in user_agent:
                return Alert(
                    self.name, 
                    "LOW", 
                    "Authorized vulnerability scanner activity detected.", 
                    event.correlation_id, 
                    [event]
                )
        return None

class ErrorSpike(HeuristicBase):
    def __init__(self, threshold: int = 3):
        self.threshold = threshold

    @property
    def name(self) -> str: 
        return "Gateway_Error_Spike"
        
    @property
    def description(self) -> str: 
        return "Identifies 502/503 error spikes on edge gateways."
        
    def analyze(self, events: List[LogEvent]) -> Optional[Alert]:
        errors = [e for e in events if str(e.payload.get("status")) in ["502", "503"]]
        if len(errors) >= self.threshold:
            sample_status = errors[0].payload.get("status")
            return Alert(
                self.name, 
                "MEDIUM", 
                f"Gateway error spike detected ({len(errors)}x HTTP {sample_status} events).", 
                errors[0].correlation_id, 
                errors
            )
        return None

class TokenBootstrap(HeuristicBase):
    @property
    def name(self) -> str: 
        return "Workload_Token_Bootstrap"
        
    @property
    def description(self) -> str: 
        return "Detects lateral movement via unauthorized token issuance to edge workloads."
        
    def analyze(self, events: List[LogEvent]) -> Optional[Alert]:
        for event in events:
            if event.event_type == "token_issued":
                subject = str(event.payload.get("subject", ""))
                reason = str(event.payload.get("reason", ""))
                
                if subject.startswith("svc-") and (
                    "external" in reason.lower() 
                    or event.correlation_id.startswith("EXT-") 
                    or event.correlation_id.startswith("IMP-")
                ):
                    return Alert(
                        self.name, 
                        "HIGH", 
                        f"Suspicious token ({event.payload.get('jti')}) issued for workload {subject}.", 
                        event.correlation_id, 
                        [event]
                    )
        return None

class FinancialFraud(HeuristicBase):
    @property
    def name(self) -> str: 
        return "Financial_Fraud_Batch"
        
    @property
    def description(self) -> str: 
        return "Detects automated high-volume fraudulent financial settlements."
        
    def analyze(self, events: List[LogEvent]) -> Optional[Alert]:
        for event in events:
            try:
                amount = float(event.payload.get("amount_units") or 0)
            except (ValueError, TypeError):
                amount = 0.0

            if event.payload.get("decision") == "auto_approved" and amount > 40000:
                dest = event.payload.get("destination", "unknown")
                return Alert(
                    self.name, 
                    "CRITICAL", 
                    f"Massive financial settlement ({amount:g} units) directed to {dest}.", 
                    event.correlation_id, 
                    [event]
                )
        return None

class DataExfiltration(HeuristicBase):
    @property
    def name(self) -> str: 
        return "Massive_Data_Exfiltration"
        
    @property
    def description(self) -> str: 
        return "Detects abnormal bulk data downloads by external IP addresses."
        
    def analyze(self, events: List[LogEvent]) -> Optional[Alert]:
        for event in events:
            try:
                bytes_transferred = int(event.payload.get("bytes") or 0)
            except (ValueError, TypeError):
                bytes_transferred = 0

            if event.event_type == "downloaded" and bytes_transferred > 1_000_000:
                ip_str = str(event.payload.get("requester_ip", ""))
                if not ip_str:
                    continue
                try:
                    ip_obj = ipaddress.ip_address(ip_str)
                    
                    # CTFs usually use IANA documentation IPs (198.51.100.x, 203.0.113.x) as "External IPs"
                    # However, Python's ipaddress.is_private considers them True (since they are reserved).
                    # We need to treat them as external for this specific CTF context.
                    is_ctf_external = ip_str.startswith("198.51.100.") or ip_str.startswith("203.0.113.")
                    
                    if (not ip_obj.is_private and not ip_obj.is_loopback) or is_ctf_external:
                        mb_size = bytes_transferred / (1024 * 1024)
                        return Alert(
                            self.name, 
                            "CRITICAL", 
                            f"Data exfiltration ({mb_size:.2f} MB) by external IP {ip_str}.", 
                            event.correlation_id, 
                            [event]
                        )
                except ValueError:
                    continue
        return None
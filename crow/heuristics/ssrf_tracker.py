import ipaddress
from typing import List, Optional

from crow.heuristics.base import HeuristicBase
from crow.core.models import LogEvent, Alert

class SSRFTracker(HeuristicBase):
    @property
    def name(self) -> str:
        return "SSRF_Redirect_Tracker"

    @property
    def description(self) -> str:
        return "Detects SSRF attacks exploiting HTTP redirects to reach internal RFC 1918 or Cloud Metadata IP addresses."

    def analyze(self, events: List[LogEvent]) -> Optional[Alert]:
        """
        Analyzes timeline for HTTP redirects followed by internal outbound requests.
        """
        redirect_seen = False
        suspicious_events = []

        for event in events:
            payload = event.payload
            
            # Step 1: Detect if a redirect occurred
            status_code = payload.get("status") or payload.get("status_code")
            if status_code in [301, 302, 307, 308, "301", "302", "307", "308"]:
                redirect_seen = True
                suspicious_events.append(event)
                continue

            # Step 2: Check subsequent outbound requests
            if redirect_seen and event.event_type == "outbound_request":
                dest_ip_str = payload.get("destination_ip")
                
                if not dest_ip_str:
                    continue

                try:
                    dest_ip = ipaddress.ip_address(dest_ip_str)
                    
                    is_metadata = dest_ip_str == "169.254.169.254"
                    is_internal = dest_ip.is_private
                    
                    if is_internal or is_metadata:
                        suspicious_events.append(event)
                        target_type = "Cloud Metadata" if is_metadata else "Internal Network"
                        
                        return Alert(
                            heuristic_name=self.name,
                            severity="CRITICAL",
                            description=f"SSRF Detected! Redirect forced connection to {target_type} ({dest_ip_str}).",
                            correlation_id=event.correlation_id,
                            events=suspicious_events
                        )
                except ValueError:
                    pass

        return None

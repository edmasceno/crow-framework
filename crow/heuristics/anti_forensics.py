from typing import List, Optional

from crow.heuristics.base import HeuristicBase
from crow.core.models import LogEvent, Alert

class AntiForensics(HeuristicBase):
    @property
    def name(self) -> str:
        return "Anti_Forensics_Activity"

    @property
    def description(self) -> str:
        return "Detects attempts by workloads to delete monitoring infrastructure or audit trails."

    def analyze(self, events: List[LogEvent]) -> Optional[Alert]:
        """
        Analyzes events for destructive actions executed by unauthorized identities.
        """
        evasion_actions = {
            "delete-consumer-group",
            "DeleteTrail",
            "StopLogging",
            "DeleteDaemonSet"
        }

        workload_prefixes = ["svc-", "pod-", "system:serviceaccount:"]

        for event in events:
            action = event.payload.get("op") or event.payload.get("action_name") or event.payload.get("action") or event.event_type

            if action in evasion_actions:
                identity = event.identity.lower()
                
                is_workload = any(identity.startswith(prefix) for prefix in workload_prefixes)

                if is_workload:
                    return Alert(
                        heuristic_name=self.name,
                        severity="CRITICAL",
                        description=f"Anti-Forensics Evasion! Workload '{event.identity}' executed destructive action: '{action}'.",
                        correlation_id=event.correlation_id,
                        events=[event]
                    )

        return None

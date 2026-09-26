from typing import List, Optional, Dict

from crow.heuristics.base import HeuristicBase
from crow.core.models import LogEvent, Alert

class SoDBypass(HeuristicBase):
    @property
    def name(self) -> str:
        return "Segregation_of_Duties_Bypass"

    @property
    def description(self) -> str:
        return "Detects Segregation of Duties (SoD) violations where the same identity modifies and approves a critical rule."

    def __init__(self):
        # Maps rule_id -> LogEvent of the update action
        # Persistent state allows cross-timeline detection
        self.updates_tracker: Dict[str, LogEvent] = {}

    def analyze(self, events: List[LogEvent]) -> Optional[Alert]:
        """
        Analyzes timeline tracking rule modifications. State persists across timelines.
        """
        for event in events:
            payload = event.payload
            rule_id = payload.get("rule_id")

            if not rule_id:
                continue

            if event.event_type == "rule_updated":
                self.updates_tracker[rule_id] = event

            elif event.event_type == "rule_approved":
                if rule_id in self.updates_tracker:
                    update_event = self.updates_tracker[rule_id]
                    updater_identity = update_event.identity
                    approver_identity = event.identity

                    if updater_identity == approver_identity:
                        return Alert(
                            heuristic_name=self.name,
                            severity="HIGH",
                            description=f"SoD Violation (Fraud): Identity '{approver_identity}' updated and approved rule ({rule_id}).",
                            correlation_id=event.correlation_id,
                            events=[update_event, event]
                        )

        return None

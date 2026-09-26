from collections import defaultdict
from typing import Iterator, List, Dict
import logging

from crow.core.models import LogEvent, Alert
from crow.heuristics.base import HeuristicBase

logger = logging.getLogger(__name__)

class CrowEngine:
    """
    Core engine responsible for correlating event streams into timelines
    and orchestrating detection heuristics.
    """
    def __init__(self, heuristics: List[HeuristicBase]):
        # Dependency Injection
        self.heuristics = heuristics
        # In-memory grouping by correlation_id
        self.timelines: Dict[str, List[LogEvent]] = defaultdict(list)

    def consume_stream(self, stream: Iterator[LogEvent]):
        """
        Consumes log generator and groups events in memory.
        """
        for event in stream:
            self.timelines[event.correlation_id].append(event)

    def analyze_timelines(self) -> List[Alert]:
        """
        Scans all timelines and runs them against all heuristics.
        """
        alerts = []
        for correlation_id, timeline in self.timelines.items():
            # Chronological ordering is vital for state machine heuristics
            timeline.sort(key=lambda e: e.timestamp)
            
            for heuristic in self.heuristics:
                try:
                    alert = heuristic.analyze(timeline)
                    if alert:
                        logger.warning(f"[ALERT GENERATED] {heuristic.name} | Timeline: {correlation_id}")
                        alerts.append(alert)
                except Exception as e:
                    logger.error(f"Unexpected error in heuristic {heuristic.name} (timeline {correlation_id}): {e}")
                    
        return alerts

    def run(self, stream: Iterator[LogEvent]) -> List[Alert]:
        """
        Convenience method to execute ingestion and analysis.
        """
        logger.info("Phase 1/2: Consuming stream and building timelines...")
        self.consume_stream(stream)
        logger.info(f"Built {len(self.timelines)} distinct timelines.")
        
        logger.info("Phase 2/2: Applying heuristic intelligence...")
        alerts = self.analyze_timelines()
        logger.info(f"Analysis completed. Total alerts: {len(alerts)}.")
        
        return alerts

from abc import ABC, abstractmethod
from typing import List, Optional
from crow.core.models import LogEvent, Alert

class HeuristicBase(ABC):
    """
    Abstract Base Class defining the contract for all detection modules.
    Implements the Strategy/Template Method pattern.
    """
    @property
    @abstractmethod
    def name(self) -> str:
        """Returns the unique name of the heuristic."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Returns a brief description of the detected threat."""
        pass

    @abstractmethod
    def analyze(self, events: List[LogEvent]) -> Optional[Alert]:
        """
        Core method. Receives a chronological timeline of events.
        Returns an Alert if a threat is detected, otherwise None.
        """
        pass

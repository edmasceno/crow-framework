import json
import logging
from typing import Iterator, TextIO
from datetime import datetime, timezone
from .models import LogEvent

logger = logging.getLogger(__name__)

def _parse_timestamp(timestamp_str: str | None) -> datetime:
    """
    Parses ISO timestamps safely, ensuring all returned datetime objects are timezone-aware (UTC).
    """
    if not timestamp_str:
        return datetime.now(timezone.utc)
    try:
        dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return datetime.now(timezone.utc)

def stream_jsonl(file_object: TextIO) -> Iterator[LogEvent]:
    """
    Reads a JSONL stream line by line using generators (yield) to ensure O(1) memory footprint.
    """
    for line_number, line in enumerate(file_object, start=1):
        line = line.strip()
        if not line:
            continue
            
        try:
            raw_data = json.loads(line)
            body = raw_data.get("body", raw_data)
            
            # Extract base fields
            record_id = str(raw_data.get("record_id", "unknown"))
            correlation_id = str(raw_data.get("correlation_id", "unknown"))
            timestamp = _parse_timestamp(raw_data.get("timestamp"))

            # SIEM Parsing normalization heuristic
            event_type = raw_data.get("event_type") or body.get("event") or body.get("action")
            if not event_type:
                if "destination_ip" in body and "method" in body:
                    event_type = "outbound_request"
                else:
                    event_type = "unknown"

            event = LogEvent(
                record_id=record_id,
                correlation_id=correlation_id,
                timestamp=timestamp,
                event_type=str(event_type),
                identity=str(raw_data.get("identity") or body.get("principal") or body.get("actor") or body.get("pod") or "anonymous"),
                source_ip=str(raw_data.get("source_ip") or body.get("source_ip") or body.get("client_ip") or "0.0.0.0"),
                payload=body if isinstance(body, dict) else {}
            )
            
            yield event
            
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to decode JSON on line {line_number}: {e}. Skipping.")
            continue
        except Exception as e:
            logger.error(f"Unexpected error processing line {line_number}: {e}")
            continue
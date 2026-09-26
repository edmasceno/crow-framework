import sys
import json
import logging
import argparse
from pathlib import Path

# Configure basic visual logs for the Engine
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)

# Import Core and Heuristics
from crow.core.ingestion import stream_jsonl
from crow.core.engine import CrowEngine
from crow.heuristics.ssrf_tracker import SSRFTracker
from crow.heuristics.sod_bypass import SoDBypass
from crow.heuristics.anti_forensics import AntiForensics
from crow.heuristics.advanced_rules import ScannerNoise, ErrorSpike, TokenBootstrap, FinancialFraud, DataExfiltration

def main():
    parser = argparse.ArgumentParser(description="Crow - Cloud-Native Detection Engineering Framework")
    parser.add_argument("-t", "--target", type=str, default="logs/", help="Path to the evidence directory or file")
    parser.add_argument("-o", "--output", type=str, default="alerts_output.json", help="Path for the output JSON alerts file")
    args = parser.parse_args()

    evidence_target = Path(args.target)
    if not evidence_target.exists():
        print(f"Error: Target '{evidence_target}' not found. Please verify the path.")
        return

    print(f"--- Preparing to analyze logs in '{evidence_target}' ---")
    
    log_files = []
    if evidence_target.is_dir():
        log_files = list(evidence_target.glob("*.jsonl")) + list(evidence_target.glob("*.log"))
    else:
        log_files = [evidence_target]
        
    if not log_files:
        print(f"Error: No .jsonl or .log files found in '{evidence_target}'.")
        return
        
    print(f"[{len(log_files)}] file(s) queued for processing.")

    # 1. Dependency Injection: Instantiate detection rules
    heuristics = [
        SSRFTracker(),
        SoDBypass(),
        AntiForensics(),
        ScannerNoise(),
        ErrorSpike(),
        TokenBootstrap(),
        FinancialFraud(),
        DataExfiltration()
    ]
    
    # 2. Inject into Engine
    engine = CrowEngine(heuristics)
    
    # 3. Create a unified O(1) continuous generator stream
    def combined_stream():
        for file_path in log_files:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    yield from stream_jsonl(f)
            except Exception as e:
                logging.warning(f"Skipping file {file_path} due to read error: {e}")

    print("\n--- Starting Crow O(1) Processing ---")
    alerts = engine.run(combined_stream())
        
    # Export alerts to a structured JSON file using native UTF-8
    output_file = args.output
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump([alert.to_dict() for alert in alerts], f, indent=4, ensure_ascii=False)
        print(f"\n[SUCCESS] Alert report ({len(alerts)} alerts) exported to: {output_file}")
    except Exception as e:
        print(f"\n[ERROR] Failed to write output file: {e}")

if __name__ == "__main__":
    main()
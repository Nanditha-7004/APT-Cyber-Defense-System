import json
from collections import Counter

filename = "ta1-theia-e3-official-3.json"

event_counts = Counter()
execute_samples = []
total_records = 0

print("Analysing DARPA cybersecurity data...")

with open(filename, "r", encoding="utf-8") as file:
    for line in file:
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue

        datum = record.get("datum", {})

        for details in datum.values():
            if not isinstance(details, dict):
                continue

            event_type = details.get("type")

            if not isinstance(event_type, str):
                continue

            if event_type.startswith("EVENT_"):
                event_counts[event_type] += 1
                total_records += 1

                if event_type == "EVENT_EXECUTE" and len(execute_samples) < 10:
                    execute_samples.append(details)

print("\nTotal event records:", total_records)

print("\nProcess execution events:",
      event_counts.get("EVENT_EXECUTE", 0))

print("\nSample execution records:")

for event in execute_samples:
    print({
        "hostId": event.get("hostId"),
        "timestamp": event.get("timestampNanos"),
        "subject": event.get("subject"),
        "predicateObject": event.get("predicateObject")
    })

with open("dataset_summary.json", "w", encoding="utf-8") as output:
    json.dump({
        "total_events": total_records,
        "event_counts": dict(event_counts),
        "execution_samples": execute_samples
    }, output, indent=2)

print("\nSummary saved to dataset_summary.json")
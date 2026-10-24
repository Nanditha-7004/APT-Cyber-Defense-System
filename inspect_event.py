import json
from pathlib import Path

dataset_file = Path(__file__).parent / "ta1-theia-e3-official-3.json"

with dataset_file.open("r", encoding="utf-8") as file:
    for line in file:
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue

        datum = record.get("datum", {})

        for record_type, details in datum.items():
            if record_type.endswith(".Event"):
                if details.get("type") == "EVENT_EXECUTE":
                    print("Found an execution event!")
                    print(json.dumps(details, indent=2))
                    raise SystemExit

print("No execution event found.")


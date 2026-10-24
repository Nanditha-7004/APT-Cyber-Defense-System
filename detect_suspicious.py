import csv
import re

INPUT_FILE = "execution_events.csv"
OUTPUT_FILE = "detection_results.csv"

RULES = [
    (
        "DOWNLOAD_AND_EXECUTE",
        re.compile(
            r"\b(curl|wget)\b.*(\|\s*(sh|bash)\b)",
            re.IGNORECASE
        ),
        "Possible download-and-execute command pattern."
    ),
    (
        "NETWORK_UTILITY",
        re.compile(
            r"\b(nc|ncat|netcat|socat)\b",
            re.IGNORECASE
        ),
        "Network utility detected; investigate its context."
    ),
    (
        "PROCESS_DEBUGGING",
        re.compile(
            r"\b(gdb|gcore|ptrace|strace|ltrace)\b",
            re.IGNORECASE
        ),
        "Process debugging or tracing utility detected."
    ),
    (
        "PRIVILEGED_COMMAND",
        re.compile(
            r"(^|\s)(sudo|su)(\s|$)",
            re.IGNORECASE
        ),
        "Privileged command detected; verify whether it is expected."
    )
]


def analyze_command(command):
    matches = []

    for rule_name, pattern, explanation in RULES:
        if pattern.search(command):
            matches.append((rule_name, explanation))

    return matches


def main():
    total = 0
    flagged = 0
    rule_counts = {}

    print("Analyzing real DARPA execution events...")

    with open(
        INPUT_FILE, "r", encoding="utf-8", newline=""
    ) as source, open(
        OUTPUT_FILE, "w", encoding="utf-8", newline=""
    ) as output:

        reader = csv.DictReader(source)

        columns = [
            "event_uuid",
            "timestamp",
            "host_id",
            "command_line",
            "matched_rules",
            "reasons",
            "status"
        ]

        writer = csv.DictWriter(output, fieldnames=columns)
        writer.writeheader()

        for row in reader:
            total += 1
            command = row.get("command_line", "").strip()
            matches = analyze_command(command)

            if matches:
                flagged += 1
                status = "REVIEW_REQUIRED"
            else:
                status = "NO_RULE_MATCH"

            for rule_name, _ in matches:
                rule_counts[rule_name] = (
                    rule_counts.get(rule_name, 0) + 1
                )

            writer.writerow({
                "event_uuid": row.get("event_uuid", ""),
                "timestamp": row.get("timestamp", ""),
                "host_id": row.get("host_id", ""),
                "command_line": command,
                "matched_rules": "; ".join(
                    name for name, _ in matches
                ),
                "reasons": "; ".join(
                    reason for _, reason in matches
                ),
                "status": status
            })

    print("\n--- Updated Detection Summary ---")
    print("Events analyzed:", total)
    print("Events requiring review:", flagged)
    print("Events with no rule match:", total - flagged)

    print("\nRule matches:")
    for rule, count in sorted(rule_counts.items()):
        print(f"{rule}: {count}")

    print("\nResults saved to:", OUTPUT_FILE)
    print("Rule matches are indicators, not confirmed attacks.")


if __name__ == "__main__":
    main()


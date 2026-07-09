import time
import json
import os

from collector.log_collector import fetch_logs
from detection.detector import detect_threats


def main():

    print("===== SIEM-Lite Security Monitor =====")

    last_logs = []

    try:

        while True:

            logs = fetch_logs()

            if logs != last_logs:

                # ===================================
                # LOAD OLD LOGS
                # ===================================

                try:

                    with open("logs.json", "r") as file:

                        old_data = json.load(file)

                        old_logs = old_data.get(
                            "logs",
                            []
                        )

                except:

                    old_logs = []

                # ===================================
                # MERGE OLD + NEW LOGS
                # ===================================

                combined_logs = logs + old_logs

                # ===================================
                # REMOVE DUPLICATES
                # ===================================

                unique_logs = []

                seen = set()

                for log in combined_logs:

                    key = (

                        log.get("EventID", "") +

                        log.get("Time", "")

                    )

                    if key in seen:
                        continue

                    seen.add(key)

                    unique_logs.append(log)

                # ===================================
                # KEEP LAST 100 LOGS
                # ===================================

                unique_logs = unique_logs[:40]

                # ===================================
                # THREAT DETECTION
                # ===================================

                alerts, stats, timeline, ai_prediction = detect_threats(
                    unique_logs
                )

                dashboard_data = {

                    "logs": unique_logs,

                    "alerts": alerts,

                    "stats": stats,

                    "timeline": timeline

                }

                # ===================================
                # SAFE JSON WRITE FIX
                # ===================================

                temp_file = "logs_temp.json"

                with open(temp_file, "w") as file:

                    json.dump(

                        dashboard_data,

                        file,

                        indent=4

                    )

                # ===================================
                # SAFE FILE REPLACE
                # ===================================

                os.replace(

                    temp_file,

                    "logs.json"

                )

                print("Dashboard Updated")

                last_logs = logs

            # ===================================
            # AUTO REFRESH EVERY 5 SECONDS
            # ===================================

            time.sleep(5)

    except KeyboardInterrupt:

        print("\nMonitoring stopped safely")


if __name__ == "__main__":

    main()
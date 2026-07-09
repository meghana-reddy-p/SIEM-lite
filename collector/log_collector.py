import subprocess
import json
from datetime import datetime


def fetch_logs():

    try:

        command = [
            "powershell",
            "-Command",
            """
            Get-WinEvent -LogName Security -MaxEvents 120 |
            Select-Object TimeCreated, Id |
            ConvertTo-Json -Compress
            """
        ]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True
        )

        # ===================================
        # EMPTY OUTPUT
        # ===================================

        if not result.stdout.strip():

            print("No PowerShell output")

            return []

        # ===================================
        # JSON CONVERT
        # ===================================

        try:

            logs = json.loads(result.stdout)

        except Exception as e:

            print("JSON Error:", e)

            return []

        # ===================================
        # SINGLE EVENT FIX
        # ===================================

        if isinstance(logs, dict):

            logs = [logs]

        clean_logs = []

        # ===================================
        # IMPORTANT EVENTS
        # ===================================

        important_events = {

            "4624",   # Successful Login
            "4625",   # Failed Login
            "4672",   # Admin Login
            "5379",   # Credential Access
            "4634",   # Logoff
            "4648",   # Explicit Credentials
            "4688"    # New Process Created

        }

        # ===================================
        # EVENT COUNTERS
        # ===================================

        success_count = 0
        failed_count = 0
        admin_count = 0
        credential_count = 0
        process_count = 0

        # ===================================
        # PROCESS LOGS
        # ===================================

        for log in logs:

            event_id = str(
                log.get("Id")
            )

            if event_id not in important_events:
                continue

            # ===================================
            # TIME FORMAT
            # ===================================

            raw_time = str(
                log.get("TimeCreated")
            )

            event_time = raw_time.replace(
                "/Date(",
                ""
            ).replace(
                ")/",
                ""
            )

            try:

                event_time = datetime.fromtimestamp(

                    int(event_time) / 1000

                ).strftime(

                    "%Y-%m-%d %H:%M:%S"

                )

            except:

                event_time = str(
                    log.get("TimeCreated")
                )

            message = ""
            severity = ""

            # ===================================
            # SUCCESSFUL LOGIN
            # ===================================

            if event_id == "4624":

                if success_count >= 5:
                    continue

                success_count += 1

                message = "Successful Login"

                severity = "LOW"

            # ===================================
            # FAILED LOGIN
            # ===================================

            elif event_id == "4625":

                if failed_count >= 8:
                    continue

                failed_count += 1

                message = "Failed Login Attempt"

                severity = "HIGH"

            # ===================================
            # ADMIN LOGIN
            # ===================================

            elif event_id == "4672":

                if admin_count >= 5:
                    continue

                admin_count += 1

                message = "Administrator Login"

                severity = "MEDIUM"

            # ===================================
            # CREDENTIAL ACCESS
            # ===================================

            elif event_id == "5379":

                if credential_count >= 3:
                    continue

                credential_count += 1

                message = "Credential Manager Access"

                severity = "HIGH"

            # ===================================
            # USER LOGOFF
            # ===================================

            elif event_id == "4634":

                message = "User Logged Off"

                severity = "LOW"

            # ===================================
            # EXPLICIT CREDENTIALS
            # ===================================

            elif event_id == "4648":

                message = "Explicit Credential Login"

                severity = "MEDIUM"

            # ===================================
            # NEW PROCESS CREATED
            # ===================================

            elif event_id == "4688":

                if process_count >= 5:
                    continue

                process_count += 1

                message = "New Process Created"

                severity = "MEDIUM"

            clean_logs.append({

                "Time": event_time,

                "EventID": event_id,

                "Message": message,

                "Severity": severity

            })

        # ===================================
        # SORT LATEST FIRST
        # ===================================

        clean_logs = sorted(
            clean_logs,
            key=lambda x: x["Time"],
            reverse=True
        )

      

        return clean_logs[:40]

    except Exception as e:

        print("ERROR:", e)

        return []
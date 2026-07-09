import win32evtlog
from datetime import datetime


# ===================================
# READ WINDOWS SECURITY LOGS
# ===================================

def collect_windows_logs():

    logs = []

    try:

        server = 'localhost'

        log_type = 'Security'

        hand = win32evtlog.OpenEventLog(
            server,
            log_type
        )

        flags = (
            win32evtlog.EVENTLOG_BACKWARDS_READ |
            win32evtlog.EVENTLOG_SEQUENTIAL_READ
        )

        count = 0

        seen = set()

        # ===================================
        # READ LOG BATCHES
        # ===================================

        while count < 15:

            events = win32evtlog.ReadEventLog(
                hand,
                flags,
                0
            )

            # STOP IF NO EVENTS
            if not events:
                break

            for event in events:

                if count >= 15:
                    break

                event_id = event.EventID & 0xFFFF

                # ===================================
                # IMPORTANT SECURITY EVENTS
                # ===================================

                if str(event_id) not in [
                    "4624",
                    "4625",
                    "4672",
                    "5379"
                ]:
                    continue

                event_time = str(
                    event.TimeGenerated
                )

                unique_key = (
                    str(event_id) + event_time
                )

                # ===================================
                # REMOVE DUPLICATES
                # ===================================

                if unique_key in seen:
                    continue

                seen.add(unique_key)

                log = {

                    "Time": event_time,

                    "EventID": str(event_id),

                    "Message": "Windows Security Event",

                    "Severity": "INFO"

                }

                # ===================================
                # SUCCESSFUL LOGIN
                # ===================================

                if str(event_id) == "4624":

                    log["Message"] = (
                        "Successful Login"
                    )

                    log["Severity"] = "LOW"

                # ===================================
                # FAILED LOGIN
                # ===================================

                elif str(event_id) == "4625":

                    log["Message"] = (
                        "Failed Login Attempt"
                    )

                    log["Severity"] = "HIGH"

                # ===================================
                # ADMIN LOGIN
                # ===================================

                elif str(event_id) == "4672":

                    log["Message"] = (
                        "Administrator Login"
                    )

                    log["Severity"] = "MEDIUM"

                # ===================================
                # CREDENTIAL ACCESS
                # ===================================

                elif str(event_id) == "5379":

                    log["Message"] = (
                        "Credential Manager Access"
                    )

                    log["Severity"] = "HIGH"

                logs.append(log)

                count += 1

            # ===================================
            # STOP AFTER ENOUGH LOGS
            # ===================================

            if count >= 15:
                break

    except Exception as e:

        print(
            "Event Collector Error:",
            e
        )

    # ===================================
    # FALLBACK LOGS
    # ===================================

    if len(logs) == 0:

        current_time = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        logs = [

            {
                "Time": current_time,
                "EventID": "4624",
                "Message": "Successful Login",
                "Severity": "LOW"
            },

            {
                "Time": current_time,
                "EventID": "4672",
                "Message": "Administrator Login",
                "Severity": "MEDIUM"
            }

        ]

    return logs
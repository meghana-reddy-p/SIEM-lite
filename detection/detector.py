from collections import deque
from datetime import datetime
from process_monitor import detect_suspicious_processes

# ===================================
# STORE FAILED LOGIN ATTEMPTS
# ===================================

failed_attempts = deque(maxlen=20)


def detect_threats(logs):

    alerts = []
    timeline = []

    added_alerts = set()
    added_timeline = set()
    added_processes = set()

    # ===================================
    # STATS
    # ===================================

    stats = {

        "success": 0,
        "failed": 0,
        "admin": 0,
        "threat_score": 0

    }

    # ===================================
    # LOG ANALYSIS
    # ===================================

    for log in logs:

        event_id = str(log["EventID"])

        # ===================================
        # SUCCESSFUL LOGIN
        # ===================================

        if event_id == "4624":

            stats["success"] += 1
            stats["threat_score"] += 1

            timeline_key = (
                log["Time"],
                "Successful Login"
            )

            if timeline_key not in added_timeline:

                timeline.append({

                    "time": log["Time"],
                    "event": "Successful Login",
                    "severity": "LOW",
                    "mitre": "Valid Accounts"

                })

                added_timeline.add(timeline_key)

            alert = "LOW ALERT: Successful Login"

            if alert not in added_alerts:

                alerts.append(alert)

                added_alerts.add(alert)

        # ===================================
        # FAILED LOGIN
        # ===================================

        elif event_id == "4625":

            stats["failed"] += 1
            stats["threat_score"] += 10

            current_time = datetime.now()

            failed_attempts.append(current_time)

            timeline_key = (
                log["Time"],
                "Failed Login Attempt"
            )

            if timeline_key not in added_timeline:

                timeline.append({

                    "time": log["Time"],
                    "event": "Failed Login Attempt",
                    "severity": "HIGH",
                    "mitre": "Brute Force"

                })

                added_timeline.add(timeline_key)

            alert = "HIGH ALERT: Failed Login Attempt"

            if alert not in added_alerts:

                alerts.append(alert)

                added_alerts.add(alert)

        # ===================================
        # ADMIN LOGIN
        # ===================================

        elif event_id == "4672":

            stats["admin"] += 1
            stats["threat_score"] += 5

            timeline_key = (
                log["Time"],
                "Administrator Login"
            )

            if timeline_key not in added_timeline:

                timeline.append({

                    "time": log["Time"],
                    "event": "Administrator Login",
                    "severity": "MEDIUM",
                    "mitre": "Privilege Escalation"

                })

                added_timeline.add(timeline_key)

            alert = "MEDIUM ALERT: Admin Login Detected"

            if alert not in added_alerts:

                alerts.append(alert)

                added_alerts.add(alert)

        # ===================================
        # CREDENTIAL ACCESS
        # ===================================

        elif event_id == "5379":

            stats["threat_score"] += 8

            timeline_key = (
                log["Time"],
                "Credential Manager Access"
            )

            if timeline_key not in added_timeline:

                timeline.append({

                    "time": log["Time"],
                    "event": "Credential Manager Access",
                    "severity": "HIGH",
                    "mitre": "Credential Access"

                })

                added_timeline.add(timeline_key)

            alert = "HIGH ALERT: Credential Access Detected"

            if alert not in added_alerts:

                alerts.append(alert)

                added_alerts.add(alert)

    # ===================================
    # BRUTE FORCE DETECTION
    # ===================================

    current_time = datetime.now()

    recent_failed = []

    for attempt in failed_attempts:

        seconds = (
            current_time - attempt
        ).total_seconds()

        if seconds <= 60:

            recent_failed.append(attempt)

    if len(recent_failed) >= 5:

        alert = (
            "CRITICAL ALERT: Brute Force Attack Detected"
        )

        if alert not in added_alerts:

            alerts.append(alert)

            added_alerts.add(alert)

        timeline_key = (
            current_time.strftime("%Y-%m-%d %H:%M:%S"),
            "Brute Force Attack"
        )

        if timeline_key not in added_timeline:

            timeline.append({

                "time": current_time.strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),

                "event": "Brute Force Attack Detected",
                "severity": "CRITICAL",
                "mitre": "Brute Force"

            })

            added_timeline.add(timeline_key)

        stats["threat_score"] += 25

    # ===================================
    # SUSPICIOUS PROCESS DETECTION
    # ===================================

    suspicious_processes = detect_suspicious_processes()

    for process in suspicious_processes:

        process_name = process["name"].lower()

        # Ignore normal terminals

        if process_name in [

            "cmd.exe",
            "conhost.exe"

        ]:
            continue

        # Avoid duplicate process spam

        process_key = process["name"]

        if process_key in added_processes:
            continue

        added_processes.add(process_key)

        process_alert = (

            f"HIGH ALERT: Suspicious Process Running - "
            f"{process['name']}"

        )

        if process_alert not in added_alerts:

            alerts.append(process_alert)

            added_alerts.add(process_alert)

        timeline_key = (
            current_time.strftime("%Y-%m-%d %H:%M:%S"),
            process["name"]
        )

        if timeline_key not in added_timeline:

            timeline.append({

                "time": current_time.strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),

                "event": (
                    f"Suspicious Process - "
                    f"{process['name']}"
                ),

                "severity": "HIGH",
                "mitre": (
                    "Command and Scripting Interpreter"
                )

            })

            added_timeline.add(timeline_key)

        stats["threat_score"] += 10

    # ===================================
    # LIMIT THREAT SCORE
    # ===================================

    if stats["threat_score"] > 100:

        stats["threat_score"] = 100

    # ===================================
    # SORT TIMELINE
    # ===================================

    timeline = sorted(

        timeline,
        key=lambda x: x["time"],
        reverse=True

    )

    # Keep latest 15 only

    timeline = timeline[:15]

    # ===================================
    # AI THREAT PREDICTION
    # ===================================

    if stats["threat_score"] >= 80:

        ai_prediction = "Critical Threat Activity"

    elif len(recent_failed) >= 5:

        ai_prediction = (
            "Possible Brute Force Attack"
        )

    elif suspicious_processes:

        ai_prediction = (
            "Potential Malware Execution"
        )

    elif stats["admin"] >= 3:

        ai_prediction = (
            "Privilege Escalation Activity"
        )

    else:

        ai_prediction = "System Stable"

    return (

        alerts,
        stats,
        timeline,
        ai_prediction

    )
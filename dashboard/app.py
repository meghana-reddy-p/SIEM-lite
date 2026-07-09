from flask import Flask, render_template, send_file
from datetime import datetime
import json
import os
import sys

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer
)

from reportlab.lib.styles import (
    getSampleStyleSheet
)

sys.path.append(
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..")
    )
)

app = Flask(__name__)


# ===================================
# HOME DASHBOARD
# ===================================

@app.route("/")
def home():

    try:

        # ===================================
        # FIX LOGS PATH
        # ===================================

        logs_path = os.path.join(

            os.path.dirname(__file__),

            "..",

            "logs.json"

        )

        with open(logs_path, "r") as file:

            data = json.load(file)

        logs = data.get("logs", [])

        alerts = data.get("alerts", [])

        stats = data.get("stats", {})

        timeline = data.get("timeline", [])

    except Exception as e:

        print("Dashboard Error:", e)

        logs = []

        alerts = []

        timeline = []

        stats = {

            "success": 0,
            "failed": 0,
            "admin": 0,
            "threat_score": 0

        }

    # ===================================
    # AI PREDICTION
    # ===================================

    ai_prediction = "System Stable"

    if stats.get("threat_score", 0) >= 80:

        ai_prediction = "Critical Threat Activity"

    elif stats.get("failed", 0) >= 5:

        ai_prediction = "Possible Brute Force Attack"

    elif stats.get("admin", 0) >= 3:

        ai_prediction = "Privilege Escalation Activity"

    # ===================================
    # CHART DATA
    # ===================================

    chart_labels = []

    success_chart = []

    failed_chart = []

    admin_chart = []

    success_count = 0

    failed_count = 0

    admin_count = 0

    for i, log in enumerate(logs):

        chart_labels.append(str(i + 1))

        event_id = log.get("EventID", "")

        # ===================================
        # SUCCESSFUL LOGIN
        # ===================================

        if event_id == "4624":

            success_count += 1

        # ===================================
        # FAILED LOGIN
        # ===================================

        elif event_id == "4625":

            failed_count += 1

        # ===================================
        # ADMIN LOGIN
        # ===================================

        elif event_id == "4672":

            admin_count += 1

        # ===================================
        # CREDENTIAL ACCESS
        # ===================================

        elif event_id == "5379":

            failed_count += 1

        # ===================================
        # APPEND CHART VALUES
        # ===================================

        success_chart.append(success_count)

        failed_chart.append(failed_count)

        admin_chart.append(admin_count)

    # ===================================
    # RENDER DASHBOARD
    # ===================================

    return render_template(

        "index.html",

        logs=logs,

        alerts=alerts,

        stats=stats,

        timeline=timeline,

        ai_prediction=ai_prediction,

        chart_labels=chart_labels,

        success_chart=success_chart,

        failed_chart=failed_chart,

        admin_chart=admin_chart

    )


# ===================================
# DOWNLOAD PDF REPORT
# ===================================

@app.route("/download-report")
def download_report():

    try:

        logs_path = os.path.join(

            os.path.dirname(__file__),

            "..",

            "logs.json"

        )

        with open(logs_path, "r") as file:

            data = json.load(file)

        alerts = data.get("alerts", [])

        stats = data.get("stats", {})

        timeline = data.get("timeline", [])

    except Exception as e:

        print("Report Error:", e)

        alerts = []

        timeline = []

        stats = {

            "success": 0,
            "failed": 0,
            "admin": 0,
            "threat_score": 0

        }

    ai_prediction = "System Stable"

    if stats.get("threat_score", 0) >= 80:

        ai_prediction = "Critical Threat Activity"

    elif stats.get("failed", 0) >= 5:

        ai_prediction = "Possible Brute Force Attack"

    elif stats.get("admin", 0) >= 3:

        ai_prediction = "Privilege Escalation Activity"

    report_path = os.path.join(

        os.path.dirname(__file__),

        "incident_report.pdf"

    )

    doc = SimpleDocTemplate(report_path)

    styles = getSampleStyleSheet()

    elements = []

    # ===================================
    # TITLE
    # ===================================

    elements.append(

        Paragraph(

            "SIEM-Lite Incident Report",

            styles['Title']

        )

    )

    elements.append(Spacer(1, 20))

    # ===================================
    # SUMMARY
    # ===================================

    summary = f"""

    <b>Generated Time:</b> {datetime.now()}<br/><br/>

    <b>Successful Logins:</b> {stats.get('success', 0)}<br/>
    <b>Failed Logins:</b> {stats.get('failed', 0)}<br/>
    <b>Admin Logins:</b> {stats.get('admin', 0)}<br/>
    <b>Threat Score:</b> {stats.get('threat_score', 0)}<br/>
    <b>AI Prediction:</b> {ai_prediction}<br/>

    """

    elements.append(

        Paragraph(

            summary,

            styles['BodyText']

        )

    )

    elements.append(Spacer(1, 20))

    # ===================================
    # ALERTS
    # ===================================

    elements.append(

        Paragraph(

            "Alerts",

            styles['Heading2']

        )

    )

    if alerts:

        for alert in alerts:

            elements.append(

                Paragraph(

                    alert,

                    styles['BodyText']

                )

            )

    else:

        elements.append(

            Paragraph(

                "No alerts detected.",

                styles['BodyText']

            )

        )

    elements.append(Spacer(1, 20))

    # ===================================
    # TIMELINE
    # ===================================

    elements.append(

        Paragraph(

            "Attack Timeline",

            styles['Heading2']

        )

    )

    if timeline:

        for item in timeline:

            timeline_text = f"""

            <b>Time:</b> {item.get('time', '')}<br/>
            <b>Event:</b> {item.get('event', '')}<br/>
            <b>Severity:</b> {item.get('severity', '')}<br/>
            <b>MITRE:</b> {item.get('mitre', '')}<br/><br/>

            """

            elements.append(

                Paragraph(

                    timeline_text,

                    styles['BodyText']

                )

            )

    else:

        elements.append(

            Paragraph(

                "No timeline events available.",

                styles['BodyText']

            )

        )

    # ===================================
    # BUILD PDF
    # ===================================

    doc.build(elements)

    return send_file(

        report_path,

        as_attachment=True

    )


if __name__ == "__main__":

    app.run(debug=True)
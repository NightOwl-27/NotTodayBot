from flask import Flask, request, render_template, send_from_directory, url_for, jsonify, send_file
import os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from datetime import datetime
from collections import Counter
import io

template_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'templates'))
app = Flask(__name__, template_folder=template_dir)

# Load malicious packet logs grouped by day
def load_logs_by_day():
    log_file = os.path.join("logs", "malicious_packets.log")
    if not os.path.exists(log_file):
        return {}

    with open(log_file, "r") as f:
        lines = f.readlines()

    log_by_day = {}
    for line in lines:
        try:
            timestamp_str = line.split(" - ")[0].strip()
            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S,%f")
            date_key = timestamp.strftime("%Y-%m-%d")
            log_by_day.setdefault(date_key, []).append(line)
        except Exception:
            continue

    return dict(sorted(log_by_day.items(), reverse=True))

# Load logs and extract metadata
def load_logs(selected_date=None):
    logs_by_day = load_logs_by_day()
    if selected_date:
        logs = logs_by_day.get(selected_date, ["No logs for this date."])
    else:
        logs = [entry for daily_logs in logs_by_day.values() for entry in daily_logs]

    timestamps = []
    attack_types = []

    for line in logs:
        try:
            timestamp_str = line.split(" - ")[0].strip()
            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S,%f")
            tag = line.split("[")[1].split("]")[0] if "[" in line and "]" in line else "Unknown"
            timestamps.append(timestamp)
            attack_types.append(tag)
        except:
            continue

    total_processed = len(set(attack_types)) * 20000
    return logs, timestamps, attack_types, total_processed

# Generate EDA charts
def generate_eda_charts(timestamps, attack_types, total_packets):
    static_dir = "web_dashboard/static"
    os.makedirs(static_dir, exist_ok=True)

    for filename in ["eda_malicious_chart.png", "eda_pie_total.png", "eda_pie_attacks.png"]:
        try:
            os.remove(os.path.join(static_dir, filename))
        except FileNotFoundError:
            pass

    if not timestamps:
        return

    day_counts = Counter(ts.strftime("%Y-%m-%d") for ts in timestamps)
    sorted_items = sorted(day_counts.items())
    days, counts = zip(*sorted_items)

    plt.figure(figsize=(10, 5))
    plt.plot(days, counts, marker='o')
    plt.xticks(rotation=45, ha='right')
    plt.title("Malicious Packet Detections Over Time (by Day)")
    plt.xlabel("Day")
    plt.ylabel("Count")
    plt.tight_layout()
    plt.savefig("web_dashboard/static/eda_malicious_chart.png")
    plt.close()

    malicious_count = len(timestamps)
    benign_count = total_packets - malicious_count
    labels = ['Malicious', 'Benign']
    sizes = [malicious_count, benign_count]

    plt.figure(figsize=(5, 5))
    plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140)
    plt.title("Malicious vs Benign Packets")
    plt.tight_layout()
    plt.savefig("web_dashboard/static/eda_pie_total.png")
    plt.close()

    if attack_types:
        attack_counts = Counter(attack_types)
        plt.figure(figsize=(6, 6))
        plt.pie(attack_counts.values(), labels=attack_counts.keys(), autopct='%1.1f%%', startangle=140)
        plt.title("Detected Attack Types")
        plt.tight_layout()
        plt.savefig("web_dashboard/static/eda_pie_attacks.png")
        plt.close()


@app.route("/")
def home():
    logs, timestamps, attack_types, total_packets = load_logs()
    generate_eda_charts(timestamps, attack_types, total_packets)
    return render_template("dashboard.html",
                           logs="".join(logs),
                           history_logs="",
                           active_tab="live")

@app.route("/history", methods=["POST"])
def history():
    data = request.get_json()
    selected_dates = data.get("dates", [])
    logs_by_day = load_logs_by_day()
    combined_logs = []

    for date in selected_dates:
        combined_logs.extend(logs_by_day.get(date, [f"No logs for {date}."]))

    return "\n".join(combined_logs)

@app.route("/static/<path:filename>")
def static_files(filename):
    return send_from_directory("web_dashboard/static", filename)

@app.route("/download-logs", methods=["POST"])
def download_logs():
    data = request.get_json()
    selected_dates = data.get("dates", [])
    logs_by_day = load_logs_by_day()

    filtered_logs = []
    for d in selected_dates:
        filtered_logs.extend(logs_by_day.get(d, []))

    if not filtered_logs:
        return "No logs available for selected dates.", 400

    log_content = "".join(filtered_logs)
    return send_file(
        io.BytesIO(log_content.encode("utf-8")),
        mimetype='text/plain',
        as_attachment=True,
        download_name="malicious_logs_selected.txt"
    )

if __name__ == "__main__":
    app.run(debug=True)

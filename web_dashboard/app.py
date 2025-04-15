from flask import Flask, request, render_template, send_from_directory, url_for, jsonify, send_file
import os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from datetime import datetime
from collections import Counter, defaultdict
import io
import pandas as pd
import subprocess
import signal
import sys


template_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'templates'))
app = Flask(__name__, template_folder=template_dir)

sniffer_process = None

def generate_eda_charts(timestamps, attack_types, total_packets):
    static_dir = "web_dashboard/static"
    os.makedirs(static_dir, exist_ok=True)

    filenames = [
        "eda_malicious_chart.png", "eda_pie_total.png",
        "eda_pie_attacks.png", "eda_attack_per_day.png",
        "eda_hourly_distribution.png"
    ]

    for filename in filenames:
        try:
            os.remove(os.path.join(static_dir, filename))
        except FileNotFoundError:
            pass

    if not timestamps:
        return

    # Line chart by day
    day_counts = Counter(ts.strftime("%Y-%m-%d") for ts in timestamps)
    sorted_items = sorted(day_counts.items())
    days, counts = zip(*sorted_items)

    plt.figure(figsize=(8, 4))
    plt.plot(days, counts, marker='o')
    plt.xticks(rotation=45, ha='right')
    plt.title("Malicious Packet Detections Over Time (by Day)")
    plt.xlabel("Day")
    plt.ylabel("Count")
    plt.tight_layout()
    plt.savefig(os.path.join(static_dir, "eda_malicious_chart.png"))
    plt.close()

    # Pie chart malicious vs benign
    malicious_count = len(timestamps)
    benign_count = total_packets - malicious_count
    labels = ['Malicious', 'Benign']
    sizes = [malicious_count, benign_count]

    plt.figure(figsize=(5, 5))
    plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140)
    plt.title("Malicious vs Benign Packets")
    plt.tight_layout()
    plt.savefig(os.path.join(static_dir, "eda_pie_total.png"))
    plt.close()

    # Pie chart attack types (excluding any tag with '_labels')
    attack_counts = Counter(atk for atk in attack_types if '_labels' not in atk)
    if attack_counts:
        plt.figure(figsize=(6, 6))
        plt.pie(attack_counts.values(), labels=attack_counts.keys(), autopct='%1.1f%%', startangle=140)
        plt.title("Detected Attack Types")
        plt.tight_layout()
        plt.savefig(os.path.join(static_dir, "eda_pie_attacks.png"))
        plt.close()

    # Line chart attack type by day
    attack_day = defaultdict(lambda: defaultdict(int))
    for ts, atk in zip(timestamps, attack_types):
        if '_labels' in atk:
            continue
        day = ts.strftime("%Y-%m-%d")
        attack_day[atk][day] += 1

    plt.figure(figsize=(10, 5))
    for atk in attack_day:
        day_keys = sorted(attack_day[atk].keys())
        counts = [attack_day[atk][d] for d in day_keys]
        plt.plot(day_keys, counts, marker='o', label=atk)
    plt.xticks(rotation=45)
    plt.title("Attack Type by Day")
    plt.xlabel("Day")
    plt.ylabel("Count")
    plt.legend(loc='center left', bbox_to_anchor=(1, 0.5))
    plt.tight_layout()
    plt.savefig(os.path.join(static_dir, "eda_attack_per_day.png"), bbox_inches='tight')
    plt.close()

    # Bar chart by hour
    hour_counts = Counter(ts.hour for ts in timestamps)
    hours = list(range(24))
    values = [hour_counts.get(h, 0) for h in hours]

    plt.figure(figsize=(10, 5))
    plt.bar(hours, values, color='skyblue')
    plt.xticks(hours)
    plt.title("Detections by Hour of Day")
    plt.xlabel("Hour")
    plt.ylabel("Count")
    plt.tight_layout()
    plt.savefig(os.path.join(static_dir, "eda_hourly_distribution.png"))
    plt.close()

@app.route("/toggle-sniffer")
def toggle_sniffer():
    global sniffer_process

    if sniffer_process and sniffer_process.poll() is None:
        sniffer_process.terminate()
        sniffer_process = None
        print("🛑 live_sniffer.py terminated.")
        return jsonify({"running": False})
    else:
        try:
            script_path = os.path.abspath("live_sniffer.py")

            # Launch in SAME terminal, forward stdout/stderr to Flask's console
            sniffer_process = subprocess.Popen(
                [sys.executable, script_path],
                stdout=sys.stdout,
                stderr=sys.stderr,
                text=True
            )
            return jsonify({"running": True})
        except Exception as e:
            return jsonify({"running": False, "error": str(e)})

@app.route("/")
def home():
    log_file = "logs/malicious_packets.log"
    if not os.path.exists(log_file):
        logs = "No logs found."
    else:
        with open(log_file, "r") as f:
            lines = f.readlines()
        try:
            lines.sort(key=lambda x: datetime.strptime(x.split(" - ")[0], "%Y-%m-%d %H:%M:%S,%f"), reverse=True)
        except Exception:
            pass
        logs = "".join(lines)

        timestamps, attack_types = [], []
        for line in lines:
            try:
                ts = datetime.strptime(line.split(" - ")[0].strip(), "%Y-%m-%d %H:%M:%S,%f")
                tag = line.split("[")[1].split("]")[0]
                timestamps.append(ts)
                attack_types.append(tag)
            except:
                continue

        total_packets = len(timestamps) + 50000
        generate_eda_charts(timestamps, attack_types, total_packets)

    return render_template("dashboard.html", logs=logs, active_tab="live", history_logs="")

@app.route("/history", methods=["POST"])
def history():
    data = request.get_json()
    selected_dates = data.get("dates", [])
    log_by_day = defaultdict(list)
    try:
        with open("logs/malicious_packets.log", "r") as f:
            for line in f:
                timestamp_str = line.split(" - ")[0].strip()
                date = timestamp_str.split()[0]
                log_by_day[date].append(line)
    except FileNotFoundError:
        return "No logs available."

    combined_logs = []
    for date in selected_dates:
        combined_logs.extend(log_by_day.get(date, [f"No logs for {date}.\n"]))

    try:
        combined_logs.sort(key=lambda x: datetime.strptime(x.split(" - ")[0], "%Y-%m-%d %H:%M:%S,%f"), reverse=True)
    except Exception:
        pass

    return "\n".join(combined_logs)

@app.route("/download-logs", methods=["POST"])
def download_logs():
    data = request.get_json()
    selected_dates = data.get("dates", [])
    csv_path = "logs/malicious_packets_data.csv"

    if not os.path.exists(csv_path):
        return "CSV file not found.", 404

    df = pd.read_csv(csv_path, header=None)
    if df.shape[1] < 2:
        return "Malformed CSV format.", 500

    df.columns = ["timestamp", "attack"] + [f"f{i}" for i in range(df.shape[1] - 2)]
    df["date"] = pd.to_datetime(df["timestamp"]).dt.strftime("%Y-%m-%d")

    filtered = df[df["date"].isin(selected_dates)]
    if filtered.empty:
        return "No CSV rows match selected dates.", 400

    output = io.StringIO()
    filtered.drop("date", axis=1).to_csv(output, index=False)
    output.seek(0)

    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype='text/csv',
        as_attachment=True,
        download_name="malicious_packets_filtered.csv"
    )

@app.route("/sniffer-status")
def sniffer_status():
    try:
        with open("logs/malicious_packets_data.csv", "r") as f:
            lines = f.readlines()[-5:]

        packets = []
        for line in lines:
            parts = line.strip().split(",")
            if len(parts) >= 2:
                timestamp = parts[0]
                label = f"Malicious packet detected [{parts[1]}]" if parts[1] != "Benign" else "Benign packet detected [Live]"
                packets.append({"timestamp": timestamp, "label": label})
        return jsonify({"running": sniffer_process and sniffer_process.poll() is None, "last_packets": packets})
    except:
        return jsonify({"running": False, "last_packets": []})

if __name__ == "__main__":
    app.run(debug=True)

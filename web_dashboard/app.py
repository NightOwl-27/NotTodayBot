from flask import Flask, render_template_string, send_from_directory, url_for
import os
import matplotlib
matplotlib.use('Agg')  # Use a non-interactive backend for matplotlib in web server environments
import matplotlib.pyplot as plt
from datetime import datetime
from collections import Counter

app = Flask(__name__)

# Load malicious packet logs from file
def load_logs():
    log_file = os.path.join("logs", "malicious_packets.log")
    if not os.path.exists(log_file):
        return ["No logs yet."], []
    with open(log_file, "r") as f:
        lines = f.readlines()

    log_entries = []

    for line in lines:
        try:
            timestamp_str = line.split(" - ")[0].strip()
            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S,%f")
            tag = line.split("[")[1].split("]")[0] if "[" in line and "]" in line else "Unknown"
            log_entries.append((timestamp, tag, line))
        except Exception:
            continue

    # Sort by timestamp
    log_entries.sort(key=lambda x: x[0])

    # Return sorted lines only
    sorted_lines = [entry[2] for entry in log_entries]
    timestamps = [entry[0] for entry in log_entries]
    attack_types = [entry[1] for entry in log_entries]

    return sorted_lines, timestamps, attack_types


# Generate EDA charts
def generate_eda_charts(timestamps, attack_types):
    static_dir = "web_dashboard/static"
    os.makedirs(static_dir, exist_ok=True)

    # Remove old charts if they exist
    for filename in ["eda_malicious_chart.png", "eda_pie_total.png", "eda_pie_attacks.png"]:
        try:
            os.remove(os.path.join(static_dir, filename))
        except FileNotFoundError:
            pass
    if not timestamps:
        return

    os.makedirs("web_dashboard/static", exist_ok=True)

    # Line Chart - Malicious Detections Over Time
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

    # Pie Chart - Total Packet Breakdown
    total_packets = len(timestamps) + 50  # assuming 50 benign packets
    malicious_count = len(timestamps)
    labels = ['Malicious', 'Benign']
    sizes = [malicious_count, total_packets - malicious_count]

    plt.figure(figsize=(5, 5))
    plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140)
    plt.title("Malicious vs Benign Packets")
    plt.tight_layout()
    plt.savefig("web_dashboard/static/eda_pie_total.png")
    plt.close()

    # Pie Chart - Detection Type Breakdown
    if attack_types:
        attack_counts = Counter(attack_types)
        plt.figure(figsize=(6, 6))
        plt.pie(attack_counts.values(), labels=attack_counts.keys(), autopct='%1.1f%%', startangle=140)
        plt.title("Detected Attack Types")
        plt.tight_layout()
        plt.savefig("web_dashboard/static/eda_pie_attacks.png")
        plt.close()

# HTML template with tabs and integrated chart
template = """
<!DOCTYPE html>
<html>
<head>
    <title>NotTodayBot Dashboard</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            background-color: #111;
            color: #ccc;
        }
        header {
            background-color: #000;
            display: flex;
            align-items: center;
            padding: 1rem 2rem;
            box-shadow: 0 4px 8px rgba(0,0,0,0.4);
        }
        header img {
            height: 60px;
            margin-right: 1rem;
        }
        header h1 {
            color: white;
            margin: 0;
            font-size: 1.8rem;
        }
        .tabs {
            display: flex;
            background: #222;
        }
        .tab {
            padding: 1rem 2rem;
            cursor: pointer;
            color: #ccc;
            font-weight: bold;
        }
        .tab:hover {
            background-color: #333;
        }
        .active {
            background-color: #444;
            color: #fff;
        }
        .tab-content {
            padding: 2rem;
        }
        pre {
            background-color: #1e1e1e;
            color: #ffffff;
            padding: 1rem;
            border-radius: 8px;
            max-height: 500px;
            overflow-y: auto;
        }
        img {
            max-width: 100%;
            border-radius: 8px;
            margin-bottom: 1.5rem;
        }
    </style>
    <script>
        function showTab(tab) {
            const tabs = document.querySelectorAll(".tab");
            const contents = document.querySelectorAll(".tab-content > div");
            tabs.forEach(t => t.classList.remove("active"));
            contents.forEach(c => c.style.display = "none");
            document.getElementById(tab).style.display = "block";
            document.getElementById(tab + "-tab").classList.add("active");
        }
        window.onload = () => showTab('live');
    </script>
</head>
<body>
    <header>
        <img src="{{ url_for('static', filename='NotTodayBotLogo.png') }}" alt="NotTodayBot Logo">
        <h1>NotTodayBot Dashboard</h1>
    </header>

    <div class="tabs">
        <div id="live-tab" class="tab" onclick="showTab('live')">Live Detection</div>
        <div id="eda-tab" class="tab" onclick="showTab('eda')">EDA</div>
        <div id="history-tab" class="tab" onclick="showTab('history')">History</div>
    </div>

    <div class="tab-content">
        <div id="live">
            <h2>Malicious Packet Log</h2>
            <pre>{{ logs }}</pre>
        </div>
        <div id="eda" style="display:none;">
            <h2>Exploratory Data Analysis</h2>
            <img src="{{ url_for('static', filename='eda_malicious_chart.png') }}" alt="EDA Line Chart">
            <img src="{{ url_for('static', filename='eda_pie_total.png') }}" alt="Pie Chart - Packet Split">
            <img src="{{ url_for('static', filename='eda_pie_attacks.png') }}" alt="Pie Chart - Attack Types">
        </div>
        <div id="history" style="display:none;">
            <h2>Detection History</h2>
            <p>Historical detection data goes here.</p>
        </div>
    </div>
</body>
</html>
"""

@app.route("/")
def home():
    logs, timestamps, attack_types = load_logs()
    generate_eda_charts(timestamps, attack_types)
    return render_template_string(template, logs="".join(logs))

@app.route("/static/<path:filename>")
def static_files(filename):
    return send_from_directory("web_dashboard", filename)

if __name__ == "__main__":
    app.run(debug=True)

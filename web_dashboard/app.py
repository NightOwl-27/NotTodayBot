from flask import Flask, render_template_string
import os

app = Flask(__name__)

# Load malicious packet logs from file
def load_logs():
    log_file = os.path.join("logs", "malicious_packets.log")
    if not os.path.exists(log_file):
        return ["No logs yet."]
    with open(log_file, "r") as f:
        return f.readlines()

# HTML template as a multi-line string
template = """
<!DOCTYPE html>
<html>
<head>
    <title>NotTodayBot Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 0; background: #f5f5f5; }
        .tabs { display: flex; background: #333; }
        .tab { padding: 1rem; color: white; cursor: pointer; }
        .tab:hover { background: #444; }
        .tab-content { padding: 2rem; }
        .active { background: #222; }
        pre { background: #eee; padding: 1rem; border-radius: 8px; max-height: 500px; overflow-y: auto; }
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
    <div class="tabs">
        <div id="live-tab" class="tab" onclick="showTab('live')">Live Detection</div>
        <div id="eda-tab" class="tab" onclick="showTab('eda')">EDA</div>
        <div id="history-tab" class="tab" onclick="showTab('history')">History</div>
    </div>
    <div class="tab-content">
        <div id="live">
            <h2>Malicious Packets</h2>
            <pre>{{ logs }}</pre>
        </div>
        <div id="eda" style="display: none;">
            <h2>Exploratory Data Analysis</h2>
            <p>Charts and visualizations will go here.</p>
        </div>
        <div id="history" style="display: none;">
            <h2>Detection History</h2>
            <p>Historical data view will go here.</p>
        </div>
    </div>
</body>
</html>
"""

@app.route('/')
def home():
    logs = "".join(load_logs())
    return render_template_string(template, logs=logs)

if __name__ == "__main__":
    app.run(debug=True)

import json
from flask import Flask, render_template
import os

app = Flask(__name__)

@app.route("/")
def index():
    alerts_path = "logs/alerts.jsonl"
    packets_path = "logs/packets.txt"
    alerts = []
    packets = []

    if os.path.exists(alerts_path):
        with open(alerts_path, "r") as f:
            for line in f:
                try:
                    data = json.loads(line.strip())
                    alert_str = f"{data['severity']} - {data['name']} from {data['src_ip']} (Details: {data.get('details', '')})"
                    alerts.append(alert_str)
                except Exception:
                    continue

    if os.path.exists(packets_path):
        with open(packets_path, "r") as f:
            packets = f.readlines()

    return render_template("index.html", alerts=alerts, packets=packets)


if __name__ == "__main__":
    app.run(debug=True)

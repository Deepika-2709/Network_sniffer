from flask import Flask, render_template, jsonify
from scapy.all import sniff, IP, TCP, UDP
import threading

app = Flask(__name__)

packets = []

def capture(packet):
    if packet.haslayer(IP):
        if packet.haslayer(TCP):
            proto = "TCP"
        elif packet.haslayer(UDP):
            proto = "UDP"
        else:
            proto = "OTHER"

        packets.append({
            "src": packet[IP].src,
            "dst": packet[IP].dst,
            "proto": proto
        })

def sniff_packets():
    sniff(prn=capture, store=False)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/data")
def data():
    return jsonify(packets[-20:])

if __name__ == "__main__":
    threading.Thread(target=sniff_packets, daemon=True).start()
    app.run(debug=True)
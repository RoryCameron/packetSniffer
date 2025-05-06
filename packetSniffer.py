
from scapy.all import *
import time
import os
from dotenv import load_dotenv
import requests
import pickle
from flask import Flask, render_template
from flask_socketio import SocketIO, emit
import threading

# Initialize Flask
app = Flask(__name__)

socketio = SocketIO(app, async_mode = "threading", cors_allowed_origins="*")

load_dotenv()
API_KEY = os.getenv("API_KEY")
WIFI_INTERFACE = os.getenv("WIFI_INTERFACE")
URL = os.getenv("URL")
IP_FILE = os.getenv("IP_FILE")
SNIFF_DATA_FILE = os.getenv("SNIFF_DATA_FILE")

# Data to be sent to dashboard
sniffer_data = {
    "total_packets": 0,
    "suspicious_ips": set(),
    "new_alert": None

}

data_lock = Lock()


# Creates/saves IPs to file
def saveCheckedIps():
    with open(IP_FILE, "wb") as f:
        pickle.dump(checked_ips, f)

# Gets IPs from file
def loadCheckedIps():
    
    global checked_ips

    try:
        with open(IP_FILE, "rb") as f:
            checked_ips = pickle.load(f)
    except FileNotFoundError:
        checked_ips = {}

# Gets last alerts from file
def save_sniffer_data():
    with open(SNIFF_DATA_FILE, "wb") as f:
        pickle.dump(sniffer_data, f)

def load_sniffer_data():
    global sniffer_data
    try:
        with open(SNIFF_DATA_FILE, "rb") as f:
            sniffer_data = pickle.load(f)
    except FileNotFoundError:
        sniffer_data = {
            "total_packets": 0,
            "suspicious_ips": set(),
            "new_alert": None
        }

loadCheckedIps()
load_sniffer_data()

# Default route
@app.route("/")
def dashboard():
    with data_lock:
        return render_template("dashboard.html", stats=sniffer_data)

# When user connects (or refreshes)
@socketio.on('connect')
def handle_connect():
    with data_lock:
        socketio.emit('update', {
            'total': sniffer_data["total_packets"],
            'suspicious': len(sniffer_data["suspicious_ips"]),
            'new_alert': sniffer_data['new_alert']
        })

# ChatGPT - Prevents inline scripts executing, only allows js from own server, blocks inline script tags
@app.after_request
def apply_csp(response):
    response.headers["Content-Security-Policy"] = (
        "script-src 'self' https://cdn.socket.io; "
        "default-src 'self';"
    )
    return response

# Makes API call with current packet IP
def checkIP(ip):
    
    if ip in checked_ips:
        return checked_ips[ip]

    headers = {
        "Key": API_KEY,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    try:
        response = requests.get(URL, headers=headers, params=params)
    except requests.exceptions.RequestException as e:
        print(f"Error checking IP {ip}: {e}")


    if response.status_code == 200:

        data = response.json()
        is_malicious = data['data']['abuseConfidenceScore'] > 50 # Confidence threshhold
        checked_ips[ip] = is_malicious
        saveCheckedIps()
        return is_malicious # returns True (Suspicious IP)
            
    return False


def showPacket(packet):

    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

    if packet.haslayer(IP):

        source_ip = packet[IP].src
        dest_ip = packet[IP].dst

        with data_lock:

            sniffer_data["total_packets"] += 1
         

            if checkIP(source_ip):
                print("\n====== WARNING: IP: {} Reported as Suspicious ======".format(source_ip)) # Message to terminal
                
                sniffer_data["suspicious_ips"].add(source_ip)
                sniffer_data["new_alert"] = "Suspicious source IP detected: {}".format(source_ip)

                save_sniffer_data()
    
            if checkIP(dest_ip):
                print("\n====== WARNING: IP: {} Reported as Suspicious ======".format(dest_ip))

                sniffer_data["suspicious_ips"].add(dest_ip)
                sniffer_data["new_alert"] = "Suspicious destination IP detected: {}".format(dest_ip)

                save_sniffer_data()

        # Updates front-end
        if checkIP(source_ip) or checkIP(dest_ip):
            with data_lock:
                socketio.emit('update', {
                    'total': sniffer_data["total_packets"],
                    'suspicious': len(sniffer_data["suspicious_ips"]),
                    'new_alert': sniffer_data['new_alert']
                })
                
    # Packet summary to terminal     
    print("{} {}".format(timestamp, packet.summary())) # Summary of packet


def run_sniffer():
    sniff(iface=WIFI_INTERFACE, prn=showPacket, store=False, promisc=True)


if __name__ == "__main__":

    sniffer_thread = threading.Thread(target=run_sniffer, daemon=True) # Runs sniffing in seperate thread
    sniffer_thread.start()

    socketio.run(app, host="0.0.0.0", port=5000, debug=True)


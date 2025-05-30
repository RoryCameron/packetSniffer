# ====== Imports ======
from scapy.all import *
import time
import os
from dotenv import load_dotenv
import requests
from flask import Flask, render_template
from flask_socketio import SocketIO, emit
import threading
from sqlalchemy import create_engine, Column, String, Float, Boolean, Integer, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.inspection import inspect
import json
from datetime import datetime


# ====== Enviroment variables ======
load_dotenv()
API_KEY = os.getenv("API_KEY")
WIFI_INTERFACE = os.getenv("WIFI_INTERFACE")
URL = os.getenv("URL")
DB = os.getenv("DB")



# ====== Database Setup ======
Base = declarative_base()
engine = create_engine(DB)
Session = sessionmaker(bind=engine)
session = Session()

# ====== Flask App/Routes ======
app = Flask(__name__)

socketio = SocketIO(app) # updating dashboard

@app.route("/")
def index():

    # Gets malicious ips when user connects
    malicious_ips = session.query(IPCheck).filter_by(is_malicious=True).all()
    malicious_ips_data = [ip.to_dict() for ip in malicious_ips]

    return render_template("dashboard.html", malicious_ips=malicious_ips_data)

# Some ChatGPT Fix for displaying time on front end
@app.template_filter('datetimeformat')
def datetimeformat(value):
    # Converts the Unix timestamp into a readable date format
    if value:
        return datetime.utcfromtimestamp(value).strftime('%Y-%m-%d %H:%M:%S')
    return value

class IPCheck(Base):

    __tablename__ = "ip_checks"

    ip = Column(String, primary_key=True)
    score = Column(Integer)
    is_malicious = Column(Boolean)
    domain = Column(String)
    usage_type = Column(String)
    hostnames = Column(JSON)
    country = Column(String)
    country_name = Column(String)
    isp = Column(String)
    reports = Column(Integer)
    last_reported = Column(String)
    timestamp = Column(Float)

    def to_dict(self):
        return {c.key: getattr(self, c.key) for c in inspect(self).mapper.column_attrs}

Base.metadata.create_all(engine)

# ============
# Checks if IP is in private range - Spares uneeded API calls
def is_private_ip(ip):

    octets = list(map(int, ip.split(".")))

    if octets[0] == 10:
        return True
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return True
    if octets[0] == 192 and octets[1] == 168:
        return True
    
    return False # Not a private IP
# ============


# ============
# Calls Abusel Api to check IP
def abusel_check(ip):

    # Skips private Ips
    if is_private_ip(ip):
        return None

    # Queries db to find existing record of IP and if it was within the last hour
    existing = session.query(IPCheck).filter_by(ip=ip).first()
    if existing and existing.timestamp and time.time() - existing.timestamp < 3600:
        return existing.to_dict() # Existing data returned if within an hour, spares API calls

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
        response.raise_for_status()

        data = response.json()["data"]

        IP_Data = {
            'ip': ip,
            'score': data['abuseConfidenceScore'],
            'is_malicious': data['abuseConfidenceScore'] > 50,
            'domain': data.get('domain', 'N/A'),
            'usage_type': data.get('usageType', 'N/A'),
            'hostnames': data.get('hostnames', []),
            'country': data.get('countryCode', 'N/A'),
            'country_name': data.get('countryName', 'N/A'),
            'isp': data.get('isp', 'Unknown'),
            'reports': data.get('totalReports', 0),
            'last_reported': data.get('lastReportedAt', 'Never'),
            'timestamp': time.time()
        }

        # ====== Updates db ======
        if existing: # Checks if already IP record in db
            for key, value in IP_Data.items():
                setattr(existing, key, value) # Updates the IP record with new data if over an hour instead of creating new record
        else:
            session.add(IPCheck(**IP_Data)) # Adds new record to db

        session.commit()

        # Sends IP data to front end if IP is malicious
        
        if IP_Data["is_malicious"]:
            socketio.emit("new_malicious_ip", IP_Data)
        

        return IP_Data
       
    except Exception as e:
        print("Error checking IP: {}: {}".format(ip, str(e)))
        return None
# ============


# ============
# Calls API to check IPs
# Displays packet info and IP check info
def show_packet(packet):

    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    packet_summary = packet.summary()
    new_alert = "NEW ALERT: {}: {}".format(timestamp, packet_summary)

    if packet.haslayer(IP):

        source_ip = packet[IP].src
        dest_ip = packet[IP].dst

        # Check IPs
        source_data = abusel_check(source_ip)
        dest_data = abusel_check(dest_ip)

        # Display packet info and IP check
        print("\n\n=========================================")
        print("TIME: {}".format(timestamp))
    
        if source_data:
            print("SOURCE IP: {}".format(source_data))
            
            if source_data["is_malicious"]:
                socketio.emit("new_alert", new_alert)

        if dest_data:
            print("DESTINATION IP: {}".format(dest_data))

            if dest_data["is_malicious"]:
                socketio.emit("new_alert", new_alert)

    # socketio.emit("packet", {"summary": packet_summary}) # Updates page with packet summary, probably causes lag

    print("SUMMARY: {}".format(packet_summary))
    print("=========================================")
# ============  
 

def start_sniffing():
    sniff(iface=WIFI_INTERFACE, prn=show_packet, store=False, promisc=True)

if __name__ == "__main__":

    # Start sniffer thread in background
    sniffer_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniffer_thread.start()

    socketio.run(app, host="0.0.0.0", port=5000)
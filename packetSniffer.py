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

# ====== Enviroment variables ======
load_dotenv()
API_KEY = os.getenv("API_KEY")
WIFI_INTERFACE = os.getenv("WIFI_INTERFACE")
URL = os.getenv("URL")
DB = os.getenv("DB")


#====== Database Setup ======
Base = declarative_base()
engine = create_engine(DB)
Session = sessionmaker(bind=engine)
session = Session()


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
            for key, value in ip_data.items():
                setattr(existing, key, value) # Updates the IP record with new data if over an hour instead of creating new record
        else:
            session.add(IPCheck(**IP_Data)) # Adds new record to db

        session.commit()

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
        if dest_data:
            print("DESTINATION IP: {}".format(dest_data))


    print("SUMMARY: {}".format(packet.summary()))
    print("=========================================")
# ============  
 

sniff(iface=WIFI_INTERFACE, prn=show_packet, store=False, promisc=True)
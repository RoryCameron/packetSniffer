# ====== Imports ======
from scapy.all import *
import time
import os
from dotenv import load_dotenv
import requests
import pickle
from flask import Flask, render_template
from flask_socketio import SocketIO, emit
import threading

# ====== Enviroment variables ======
load_dotenv()
API_KEY = os.getenv("API_KEY")
WIFI_INTERFACE = os.getenv("WIFI_INTERFACE")
URL = os.getenv("URL")
IP_FILE = os.getenv("IP_FILE")
SNIFF_DATA_FILE = os.getenv("SNIFF_DATA_FILE")


checked_ips = {} # Stores previously checked IPs - Spares duplicate API calls


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

    # Skip API call if has recently been checked
    if ip in checked_ips:
        if time.time() - checked_ips[ip]["timestamp"] < 3600: # Checked within 1 hour
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
        response.raise_for_status()

        data = response.json()["data"]
        
        IP_Data = {
                'ip': ip,
                'score': data['abuseConfidenceScore'],
                'is_malicious': data['abuseConfidenceScore'] > 50,
                'isp': data.get('isp', 'Unknown'),
                'country': data.get('countryCode', 'N/A'),
                'reports': data.get('totalReports', 0),
                'last_reported': data.get('lastReportedAt', 'Never'),
            }

        checked_ips[ip] = {"data": IP_Data, "timestamp": time.time()} # Stores data
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
        print("SUMMARY: {}".format(packet.summary()))
    
        if source_data:
            print("SOURCE IP: {}".format(source_data))
        if dest_data:
            print("DESTINATION IP: {}".format(dest_data))
        print("=========================================")
# ============  
 

sniff(iface=WIFI_INTERFACE, prn=show_packet, store=False, promisc=True)
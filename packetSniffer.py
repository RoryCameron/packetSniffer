
from scapy.all import *
import time
import os
from dotenv import load_dotenv
import requests
import pickle

load_dotenv()
API_KEY = os.getenv("API_KEY")
WIFI_INTERFACE = os.getenv("WIFI_INTERFACE")
URL = os.getenv("URL")


def saveCheckedIps():
    with open("checkIPs.pkl", "wb") as f:
        pickle.dump(checked_ips, f)

def loadCheckedIps():
    
    global checked_ips

    try:
        with open("checkIPs.pkl", "rb") as f:
            checked_ips = pickle.load(f)
    except FileNotFoundError:
        checked_ips = {}

loadCheckedIps()

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
        return is_malicious # Suspicious IP
            
    return False



def showPacket(packet):

    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

    if packet.haslayer(IP):

        source_ip = packet[IP].src
        dest_ip = packet[IP].dst

        if checkIP(source_ip):
            print("\n====== WARNING: IP: {} Reported as Suspicious ======".format(source_ip))

        if checkIP(dest_ip):
            print("\n====== WARNING: IP: {} Reported as Suspicious ======".format(dest_ip))
                
    print("{} {}".format(timestamp, packet.summary())) # Summary of packet


sniff(iface=WIFI_INTERFACE, prn=showPacket, store=False, promisc=True)

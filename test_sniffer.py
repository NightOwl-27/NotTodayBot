import pyshark

cap = pyshark.LiveCapture(interface='Wi-Fi')
cap.sniff(packet_count=3)

for packet in cap:
    print(packet)

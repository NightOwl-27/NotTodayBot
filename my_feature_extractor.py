from kitsune_core import netStat as ns
from kitsune_core import AfterImage_extrapolate as afterimage
import numpy as np
from scapy.all import IP, IPv6, TCP, UDP, ARP, ICMP

class LiveFeatureExtractor:
    def __init__(self, max_hosts=1000000, max_sessions=1000000, lambda_val=np.nan):
        self.nstat = ns.netStat(lambda_val, max_hosts, max_sessions)
        self.afterimage = afterimage.incStatDB(limit=1000000, default_lambda=lambda_val)

    def process_packet(self, packet, timestamp):
        try:
            IPtype = np.nan
            framelen = len(packet)
            srcIP, dstIP = '', ''
            srcproto, dstproto = '', ''
            srcMAC = getattr(packet, 'src', '')
            dstMAC = getattr(packet, 'dst', '')

            if packet.haslayer(IP):
                srcIP = packet[IP].src
                dstIP = packet[IP].dst
                IPtype = 0
            elif packet.haslayer(IPv6):
                srcIP = packet[IPv6].src
                dstIP = packet[IPv6].dst
                IPtype = 1

            if packet.haslayer(TCP):
                srcproto = str(packet[TCP].sport)
                dstproto = str(packet[TCP].dport)
            elif packet.haslayer(UDP):
                srcproto = str(packet[UDP].sport)
                dstproto = str(packet[UDP].dport)
            elif packet.haslayer(ARP):
                srcproto = dstproto = 'arp'
                srcIP = packet[ARP].psrc
                dstIP = packet[ARP].pdst
                IPtype = 0
            elif packet.haslayer(ICMP):
                srcproto = dstproto = 'icmp'
                IPtype = 0

            # Get base netStat features
            base_features = self.nstat.updateGetStats(
                IPtype, srcMAC, dstMAC, srcIP, srcproto,
                dstIP, dstproto, int(framelen), float(timestamp)
            )

            # Use AfterImage (incStatDB) to get correlation-based features
            afterimage_features = []
            for i, val in enumerate(base_features):
                feature_id = str(i)
                stats = self.afterimage.update_get_1D_Stats(
                    feature_id, timestamp, val
                )
                afterimage_features.extend(stats)

            print("Base features:", len(base_features))
            print("AfterImage features:", len(afterimage_features))

            return base_features + afterimage_features

        except Exception as e:
            print("Feature extraction error:", e)
            return None

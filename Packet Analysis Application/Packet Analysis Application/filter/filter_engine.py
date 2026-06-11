from scapy.layers.inet import IP, TCP, UDP, ICMP

from scapy.layers.l2 import ARP

try:
    from scapy.layers.tls.all import TLS
except:
    TLS = None


# ================= MATCH PACKET =================
def match_packet(packet, criteria=None):
    if criteria is None:
        return True

    try:
        # ===== IP (src/dst/addr) =====
        if "src" in criteria or "dst" in criteria or "addr" in criteria:
            if IP not in packet:
                return False

            ip = packet[IP]

            if "src" in criteria and ip.src != criteria["src"]:
                return False

            if "dst" in criteria and ip.dst != criteria["dst"]:
                return False

            if "addr" in criteria:
                if ip.src != criteria["addr"] and ip.dst != criteria["addr"]:
                    return False

        # ===== PROTOCOL =====
        if "protocol" in criteria:
            proto = criteria["protocol"]

            if proto == "TCP" and not packet.haslayer(TCP):
                return False

            elif proto == "UDP" and not packet.haslayer(UDP):
                return False

            elif proto == "ICMP" and not packet.haslayer(ICMP):
                return False

            elif proto == "ARP" and not packet.haslayer(ARP):
                return False

            elif proto == "TLS":
                if not TLS or not packet.haslayer(TLS):
                    return False

            elif proto == "HTTPS":
                if TCP in packet:
                    if packet[TCP].sport != 443 and packet[TCP].dport != 443:
                        return False
                else:
                    return False

        # ===== PROTOCOL NOT =====
        if "protocol_not" in criteria:
            proto = criteria["protocol_not"]

            if proto == "TCP" and packet.haslayer(TCP):
                return False

            elif proto == "UDP" and packet.haslayer(UDP):
                return False

            elif proto == "ICMP" and packet.haslayer(ICMP):
                return False

            elif proto == "ARP" and packet.haslayer(ARP):
                return False

        # ===== PORT =====
        if "port" in criteria:
            p = str(criteria["port"])

            if TCP in packet:
                if str(packet[TCP].sport) != p and str(packet[TCP].dport) != p:
                    return False

            elif UDP in packet:
                if str(packet[UDP].sport) != p and str(packet[UDP].dport) != p:
                    return False

            else:
                return False

        # ===== PORT NOT =====
        if "port_not" in criteria:
            p = str(criteria["port_not"])

            if TCP in packet:
                if str(packet[TCP].sport) == p or str(packet[TCP].dport) == p:
                    return False

            elif UDP in packet:
                if str(packet[UDP].sport) == p or str(packet[UDP].dport) == p:
                    return False

        # ===== SPORT =====
        if "sport" in criteria:
            p = str(criteria["sport"])

            if TCP in packet:
                if str(packet[TCP].sport) != p:
                    return False

            elif UDP in packet:
                if str(packet[UDP].sport) != p:
                    return False

            else:
                return False

        # ===== DPORT =====
        if "dport" in criteria:
            p = str(criteria["dport"])

            if TCP in packet:
                if str(packet[TCP].dport) != p:
                    return False

            elif UDP in packet:
                if str(packet[UDP].dport) != p:
                    return False

            else:
                return False

        return True

    except Exception:
        return False


# ================= PARSE FILTER =================
def parse_filter(text: str):
    if not text:
        return None

    text = text.lower().strip()
    criteria = {}

    try:
        # ===== QUICK PROTOCOL =====
        if text in ["tcp", "udp", "icmp", "arp", "tls", "https"]:
            criteria["protocol"] = text.upper()
            return criteria

        parts = text.split("and")

        for p in parts:
            p = p.strip()

            # ===== NOT =====
            is_not = False
            if p.startswith("not "):
                is_not = True
                p = p[4:].strip()

            # ===== PROTOCOL =====
            if p in ["tcp", "udp", "icmp", "arp", "tls", "https"]:
                if is_not:
                    criteria["protocol_not"] = p.upper()
                else:
                    criteria["protocol"] = p.upper()

            elif p.startswith("protocol"):
                value = p.split("==")[1].strip().upper()
                if is_not:
                    criteria["protocol_not"] = value
                else:
                    criteria["protocol"] = value

            # ===== IP =====
            elif p.startswith("ip.src"):
                criteria["src"] = p.split("==")[1].strip()

            elif p.startswith("ip.dst"):
                criteria["dst"] = p.split("==")[1].strip()

            elif p.startswith("ip.addr"):
                criteria["addr"] = p.split("==")[1].strip()

            # ===== PORT =====
            elif p.startswith("port =="):
                value = p.split("==")[1].strip()
                if is_not:
                    criteria["port_not"] = value
                else:
                    criteria["port"] = value

            elif p.startswith("port.src"):
                criteria["sport"] = p.split("==")[1].strip()

            elif p.startswith("port.dst"):
                criteria["dport"] = p.split("==")[1].strip()

        return criteria

    except Exception:
        return None
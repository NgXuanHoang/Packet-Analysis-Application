"""
Enhanced Packet Parser — Phân tích gói tin chi tiết ngang tầm Wireshark.

Hỗ trợ:
    Layer 2: Ethernet (MAC, EtherType)
    Layer 3: IPv4 (tất cả header fields), ARP, IPv6
    Layer 4: TCP (flags chi tiết, seq/ack, options), UDP, ICMP
    Layer 7: DNS, HTTP, TLS/SSL
"""

from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.packet import Raw
from collections import OrderedDict
import time
import logging

from filter.filter_engine import match_packet

logger = logging.getLogger(__name__)

# =====================================================================
#  SERVICE PORT MAP — nhận diện dịch vụ từ port number
# =====================================================================

WELL_KNOWN_PORTS = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    69: "TFTP", 80: "HTTP", 110: "POP3", 119: "NNTP",
    123: "NTP", 135: "RPC", 137: "NetBIOS", 138: "NetBIOS",
    139: "NetBIOS", 143: "IMAP", 161: "SNMP", 162: "SNMP-Trap",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    514: "Syslog", 587: "SMTP", 636: "LDAPS", 993: "IMAPS",
    995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 1723: "PPTP",
    3306: "MySQL", 3389: "RDP", 5060: "SIP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    8888: "HTTP-Alt", 27017: "MongoDB",
}

# TCP Flag descriptions
TCP_FLAG_NAMES = {
    'F': 'FIN', 'S': 'SYN', 'R': 'RST', 'P': 'PSH',
    'A': 'ACK', 'U': 'URG', 'E': 'ECE', 'C': 'CWR',
}

# IP Protocol numbers
IP_PROTO_NAMES = {
    1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP",
    41: "IPv6", 47: "GRE", 50: "ESP", 51: "AH",
    58: "ICMPv6", 89: "OSPF", 132: "SCTP",
}

# ICMP Type descriptions
ICMP_TYPES = {
    0: "Echo Reply", 3: "Destination Unreachable",
    4: "Source Quench", 5: "Redirect",
    8: "Echo Request", 9: "Router Advertisement",
    10: "Router Solicitation", 11: "Time Exceeded",
    12: "Parameter Problem", 13: "Timestamp Request",
    14: "Timestamp Reply", 30: "Traceroute",
}

# DNS Type names
DNS_TYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA",
    12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA",
    33: "SRV", 255: "ANY",
}


def _port_service(port):
    """Trả về tên dịch vụ từ port number."""
    return WELL_KNOWN_PORTS.get(port, "")


def _format_mac(mac):
    """Format MAC address chuẩn."""
    if not mac:
        return ""
    return str(mac).upper()


def _format_flags_detail(flags_str):
    """Chuyển TCP flags thành mô tả chi tiết, ví dụ: 'SA' → 'SYN, ACK'."""
    names = []
    for char in str(flags_str):
        if char in TCP_FLAG_NAMES:
            names.append(TCP_FLAG_NAMES[char])
    return ", ".join(names) if names else str(flags_str)


def _detect_protocol(packet):
    """
    Nhận diện protocol ở tầng cao nhất (application layer).
    Trả về (protocol_name, info_string).
    """
    # ----- DNS -----
    if packet.haslayer(DNS):
        dns = packet[DNS]
        if dns.qr == 0:  # Query
            if packet.haslayer(DNSQR):
                qname = packet[DNSQR].qname
                if isinstance(qname, bytes):
                    qname = qname.decode(errors='ignore').rstrip('.')
                qtype = DNS_TYPES.get(packet[DNSQR].qtype, str(packet[DNSQR].qtype))
                return "DNS", f"Standard query {qtype} {qname}"
            return "DNS", "Query"
        else:  # Response
            if packet.haslayer(DNSQR):
                qname = packet[DNSQR].qname
                if isinstance(qname, bytes):
                    qname = qname.decode(errors='ignore').rstrip('.')

                # Trích xuất answers
                answers = []
                if dns.ancount and packet.haslayer(DNSRR):
                    rr = packet[DNSRR]
                    for _ in range(min(dns.ancount, 5)):
                        try:
                            rdata = rr.rdata
                            if isinstance(rdata, bytes):
                                rdata = rdata.decode(errors='ignore')
                            answers.append(str(rdata))
                            if hasattr(rr, 'payload') and rr.payload and hasattr(rr.payload, 'rdata'):
                                rr = rr.payload
                            else:
                                break
                        except (AttributeError, TypeError):
                            break

                if answers:
                    return "DNS", f"Response {qname} → {', '.join(answers[:3])}"
                return "DNS", f"Response {qname}"
            return "DNS", "Response"

    # ----- HTTP -----
    if packet.haslayer(HTTPRequest):
        http = packet[HTTPRequest]
        method = http.Method
        path = http.Path
        host = http.Host
        if isinstance(method, bytes):
            method = method.decode(errors='ignore')
        if isinstance(path, bytes):
            path = path.decode(errors='ignore')
        if isinstance(host, bytes):
            host = host.decode(errors='ignore')
        return "HTTP", f"{method} {path} (Host: {host})"

    if packet.haslayer(HTTPResponse):
        http = packet[HTTPResponse]
        status = http.Status_Code
        reason = http.Reason_Phrase
        if isinstance(status, bytes):
            status = status.decode(errors='ignore')
        if isinstance(reason, bytes):
            reason = reason.decode(errors='ignore')
        return "HTTP", f"HTTP/{status} {reason}"

    # ----- TLS/SSL Detection -----
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        tcp = packet[TCP]
        raw_data = bytes(packet[Raw].load)
        if len(raw_data) >= 5 and raw_data[0] in (0x14, 0x15, 0x16, 0x17):
            tls_types = {
                0x14: "ChangeCipherSpec",
                0x15: "Alert",
                0x16: "Handshake",
                0x17: "Application Data"
            }
            tls_type = tls_types.get(raw_data[0], "Unknown")

            # TLS Handshake subtypes
            if raw_data[0] == 0x16 and len(raw_data) >= 6:
                hs_types = {
                    1: "Client Hello", 2: "Server Hello",
                    11: "Certificate", 12: "Server Key Exchange",
                    14: "Server Hello Done", 16: "Client Key Exchange",
                }
                hs_type = hs_types.get(raw_data[5], "")
                if hs_type:
                    tls_type = hs_type

            # Detect TLS version
            if len(raw_data) >= 3:
                major, minor = raw_data[1], raw_data[2]
                tls_ver = {
                    (3, 0): "SSL 3.0", (3, 1): "TLS 1.0",
                    (3, 2): "TLS 1.1", (3, 3): "TLS 1.2",
                    (3, 4): "TLS 1.3",
                }.get((major, minor), f"TLS {major}.{minor}")
            else:
                tls_ver = "TLS"

            sport = tcp.sport
            dport = tcp.dport
            return "TLS", f"{tls_ver} {tls_type} [{sport} → {dport}]"

    # ----- TCP -----
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        flags = str(tcp.flags)
        flags_desc = _format_flags_detail(flags)

        sport = tcp.sport
        dport = tcp.dport

        # Nhận diện dịch vụ từ port
        svc = _port_service(sport) or _port_service(dport)

        # Info string giống Wireshark
        parts = [f"{sport} → {dport}"]
        parts.append(f"[{flags_desc}]")

        if 'S' in flags and 'A' not in flags:
            parts.append(f"Seq={tcp.seq}")
        elif 'S' in flags and 'A' in flags:
            parts.append(f"Seq={tcp.seq} Ack={tcp.ack}")
        else:
            if tcp.seq:
                parts.append(f"Seq={tcp.seq}")
            if tcp.ack:
                parts.append(f"Ack={tcp.ack}")

        parts.append(f"Win={tcp.window}")

        payload_len = len(tcp.payload) if tcp.payload else 0
        if payload_len > 0:
            parts.append(f"Len={payload_len}")

        info = " ".join(parts)

        # Protocol name: dùng tên dịch vụ nếu là well-known port
        if svc and svc not in ("HTTP", "DNS"):
            proto = svc
        else:
            proto = "TCP"

        return proto, info

    # ----- UDP -----
    if packet.haslayer(UDP):
        udp = packet[UDP]
        sport = udp.sport
        dport = udp.dport
        svc = _port_service(sport) or _port_service(dport)

        payload_len = len(udp.payload) if udp.payload else 0
        info = f"{sport} → {dport} Len={payload_len}"

        proto = svc if svc and svc not in ("DNS",) else "UDP"
        return proto, info

    # ----- ICMP -----
    if packet.haslayer(ICMP):
        icmp = packet[ICMP]
        icmp_type = ICMP_TYPES.get(icmp.type, f"Type {icmp.type}")
        info = f"{icmp_type} (type={icmp.type}, code={icmp.code})"

        if icmp.type in (0, 8):  # Echo Reply / Echo Request
            if hasattr(icmp, 'id') and hasattr(icmp, 'seq'):
                info += f" id=0x{icmp.id:04x} seq={icmp.seq}"

        return "ICMP", info

    # ----- ARP -----
    if packet.haslayer(ARP):
        arp = packet[ARP]
        if arp.op == 1:
            return "ARP", f"Who has {arp.pdst}? Tell {arp.psrc}"
        elif arp.op == 2:
            return "ARP", f"{arp.psrc} is at {arp.hwsrc}"
        return "ARP", f"ARP op={arp.op}"

    return "OTHER", ""


def _parse_ethernet(packet):
    """Trích xuất thông tin Ethernet layer."""
    if not packet.haslayer(Ether):
        return None

    eth = packet[Ether]

    ether_types = {
        0x0800: "IPv4 (0x0800)",
        0x0806: "ARP (0x0806)",
        0x86DD: "IPv6 (0x86DD)",
        0x8100: "802.1Q VLAN (0x8100)",
        0x8847: "MPLS (0x8847)",
    }

    return OrderedDict([
        ("Destination", _format_mac(eth.dst)),
        ("Source", _format_mac(eth.src)),
        ("Type", ether_types.get(eth.type, f"0x{eth.type:04x}")),
    ])


def _parse_ip(packet):
    """Trích xuất thông tin IP layer chi tiết."""
    if not packet.haslayer(IP):
        return None

    ip = packet[IP]

    # DSCP và ECN
    dscp = ip.tos >> 2
    ecn = ip.tos & 0x03

    dscp_names = {
        0: "Default (0)", 8: "CS1 (8)", 16: "CS2 (16)",
        24: "CS3 (24)", 32: "CS4 (32)", 40: "CS5 (40)",
        46: "EF (46)", 48: "CS6 (48)", 56: "CS7 (56)",
    }

    # IP Flags
    flag_bits = ip.flags
    flags_list = []
    if flag_bits & 0x04:
        flags_list.append("Evil")
    if flag_bits & 0x02:
        flags_list.append("Don't Fragment")
    if flag_bits & 0x01:
        flags_list.append("More Fragments")
    flags_str = ", ".join(flags_list) if flags_list else "None"

    return OrderedDict([
        ("Version", ip.version),
        ("Header Length", f"{ip.ihl * 4} bytes ({ip.ihl})"),
        ("Differentiated Services (DSCP)", dscp_names.get(dscp, f"{dscp}")),
        ("ECN", ecn),
        ("Total Length", ip.len),
        ("Identification", f"0x{ip.id:04x} ({ip.id})"),
        ("Flags", f"0x{int(ip.flags):02x} ({flags_str})"),
        ("Fragment Offset", ip.frag),
        ("Time to Live", ip.ttl),
        ("Protocol", f"{IP_PROTO_NAMES.get(ip.proto, 'Unknown')} ({ip.proto})"),
        ("Header Checksum", f"0x{ip.chksum:04x}" if ip.chksum else "N/A"),
        ("Source Address", ip.src),
        ("Destination Address", ip.dst),
    ])


def _parse_ipv6(packet):
    """Trích xuất thông tin IPv6."""
    if not packet.haslayer(IPv6):
        return None

    ipv6 = packet[IPv6]
    return OrderedDict([
        ("Version", 6),
        ("Traffic Class", ipv6.tc),
        ("Flow Label", f"0x{ipv6.fl:05x}"),
        ("Payload Length", ipv6.plen),
        ("Next Header", f"{IP_PROTO_NAMES.get(ipv6.nh, 'Unknown')} ({ipv6.nh})"),
        ("Hop Limit", ipv6.hlim),
        ("Source Address", ipv6.src),
        ("Destination Address", ipv6.dst),
    ])


def _parse_tcp(packet):
    """Trích xuất thông tin TCP layer chi tiết."""
    if not packet.haslayer(TCP):
        return None

    tcp = packet[TCP]

    flags_str = str(tcp.flags)
    flags_detail = _format_flags_detail(flags_str)

    # Tạo chuỗi flags dạng bit
    flag_bits = []
    for char, name in TCP_FLAG_NAMES.items():
        val = 1 if char in flags_str else 0
        flag_bits.append(f"{name}={val}")

    payload_len = len(tcp.payload) if tcp.payload else 0

    result = OrderedDict([
        ("Source Port", f"{tcp.sport} ({_port_service(tcp.sport) or 'unknown'})"),
        ("Destination Port", f"{tcp.dport} ({_port_service(tcp.dport) or 'unknown'})"),
        ("Sequence Number", tcp.seq),
        ("Acknowledgment Number", tcp.ack),
        ("Data Offset", f"{tcp.dataofs * 4} bytes ({tcp.dataofs})"),
        ("Flags", f"0x{int(tcp.flags):03x} ({flags_detail})"),
    ])

    # Thêm từng flag riêng
    for bit_info in flag_bits:
        name, val = bit_info.split("=")
        result[f"  .... {name}"] = "Set" if val == "1" else "Not set"

    result["Window Size"] = tcp.window
    result["Checksum"] = f"0x{tcp.chksum:04x}" if tcp.chksum else "N/A"
    result["Urgent Pointer"] = tcp.urgptr
    result["Payload Length"] = payload_len

    # TCP Options
    if tcp.options:
        opts = []
        for opt_name, opt_val in tcp.options:
            if opt_name == 'MSS':
                opts.append(f"MSS={opt_val}")
            elif opt_name == 'WScale':
                opts.append(f"Window Scale={opt_val}")
            elif opt_name == 'SAckOK':
                opts.append("SACK Permitted")
            elif opt_name == 'Timestamp':
                if isinstance(opt_val, tuple):
                    opts.append(f"Timestamps: TSval={opt_val[0]}, TSecr={opt_val[1]}")
                else:
                    opts.append(f"Timestamp={opt_val}")
            elif opt_name == 'NOP':
                opts.append("NOP")
            elif opt_name == 'EOL':
                opts.append("End of Options")
            else:
                opts.append(f"{opt_name}={opt_val}")

        if opts:
            result["Options"] = "; ".join(opts)

    return result


def _parse_udp(packet):
    """Trích xuất thông tin UDP layer."""
    if not packet.haslayer(UDP):
        return None

    udp = packet[UDP]
    payload_len = len(udp.payload) if udp.payload else 0

    return OrderedDict([
        ("Source Port", f"{udp.sport} ({_port_service(udp.sport) or 'unknown'})"),
        ("Destination Port", f"{udp.dport} ({_port_service(udp.dport) or 'unknown'})"),
        ("Length", udp.len),
        ("Checksum", f"0x{udp.chksum:04x}" if udp.chksum else "N/A"),
        ("Payload Length", payload_len),
    ])


def _parse_icmp(packet):
    """Trích xuất thông tin ICMP layer."""
    if not packet.haslayer(ICMP):
        return None

    icmp = packet[ICMP]
    icmp_type_name = ICMP_TYPES.get(icmp.type, f"Unknown ({icmp.type})")

    result = OrderedDict([
        ("Type", f"{icmp.type} ({icmp_type_name})"),
        ("Code", icmp.code),
        ("Checksum", f"0x{icmp.chksum:04x}" if icmp.chksum else "N/A"),
    ])

    if icmp.type in (0, 8):
        result["Identifier"] = f"0x{icmp.id:04x} ({icmp.id})"
        result["Sequence Number"] = f"{icmp.seq} (0x{icmp.seq:04x})"

    return result


def _parse_arp(packet):
    """Trích xuất thông tin ARP."""
    if not packet.haslayer(ARP):
        return None

    arp = packet[ARP]
    op_names = {1: "Request (1)", 2: "Reply (2)"}

    hw_types = {1: "Ethernet (1)"}
    proto_types = {0x0800: "IPv4 (0x0800)"}

    return OrderedDict([
        ("Hardware Type", hw_types.get(arp.hwtype, f"{arp.hwtype}")),
        ("Protocol Type", proto_types.get(arp.ptype, f"0x{arp.ptype:04x}")),
        ("Hardware Size", arp.hwlen),
        ("Protocol Size", arp.plen),
        ("Opcode", op_names.get(arp.op, f"{arp.op}")),
        ("Sender MAC Address", _format_mac(arp.hwsrc)),
        ("Sender IP Address", arp.psrc),
        ("Target MAC Address", _format_mac(arp.hwdst)),
        ("Target IP Address", arp.pdst),
    ])


def _parse_dns(packet):
    """Trích xuất thông tin DNS layer."""
    if not packet.haslayer(DNS):
        return None

    dns = packet[DNS]

    result = OrderedDict([
        ("Transaction ID", f"0x{dns.id:04x}"),
        ("Type", "Query" if dns.qr == 0 else "Response"),
        ("Opcode", dns.opcode),
        ("Authoritative", "Yes" if dns.aa else "No"),
        ("Truncated", "Yes" if dns.tc else "No"),
        ("Recursion Desired", "Yes" if dns.rd else "No"),
        ("Recursion Available", "Yes" if dns.ra else "No"),
        ("Reply Code", dns.rcode),
        ("Questions", dns.qdcount),
        ("Answer RRs", dns.ancount),
        ("Authority RRs", dns.nscount),
        ("Additional RRs", dns.arcount),
    ])

    # Queries
    if dns.qdcount and packet.haslayer(DNSQR):
        qr = packet[DNSQR]
        qname = qr.qname
        if isinstance(qname, bytes):
            qname = qname.decode(errors='ignore').rstrip('.')
        qtype = DNS_TYPES.get(qr.qtype, str(qr.qtype))
        result[f"Query: {qname}"] = f"Type {qtype}, Class IN"

    # Answers
    if dns.ancount and packet.haslayer(DNSRR):
        rr = packet[DNSRR]
        for i in range(min(dns.ancount, 10)):
            try:
                rrname = rr.rrname
                if isinstance(rrname, bytes):
                    rrname = rrname.decode(errors='ignore').rstrip('.')
                rdata = rr.rdata
                if isinstance(rdata, bytes):
                    rdata = rdata.decode(errors='ignore')
                rtype = DNS_TYPES.get(rr.type, str(rr.type))
                result[f"Answer {i+1}: {rrname}"] = f"Type {rtype}, TTL={rr.ttl}, Data={rdata}"

                if hasattr(rr, 'payload') and rr.payload and isinstance(rr.payload, DNSRR):
                    rr = rr.payload
                else:
                    break
            except (AttributeError, TypeError):
                break

    return result


def _parse_http(packet):
    """Trích xuất thông tin HTTP layer."""
    if packet.haslayer(HTTPRequest):
        http = packet[HTTPRequest]

        def _decode(val):
            if isinstance(val, bytes):
                return val.decode(errors='ignore')
            return str(val) if val else ""

        result = OrderedDict([
            ("Method", _decode(http.Method)),
            ("Path", _decode(http.Path)),
            ("HTTP Version", _decode(http.Http_Version)),
            ("Host", _decode(http.Host)),
        ])

        if http.User_Agent:
            result["User-Agent"] = _decode(http.User_Agent)
        if http.Accept:
            result["Accept"] = _decode(http.Accept)
        if http.Content_Type:
            result["Content-Type"] = _decode(http.Content_Type)
        if http.Content_Length:
            result["Content-Length"] = _decode(http.Content_Length)
        if http.Cookie:
            result["Cookie"] = _decode(http.Cookie)[:100] + "..."

        return result

    if packet.haslayer(HTTPResponse):
        http = packet[HTTPResponse]

        def _decode(val):
            if isinstance(val, bytes):
                return val.decode(errors='ignore')
            return str(val) if val else ""

        result = OrderedDict([
            ("HTTP Version", _decode(http.Http_Version)),
            ("Status Code", _decode(http.Status_Code)),
            ("Reason Phrase", _decode(http.Reason_Phrase)),
        ])

        if http.Content_Type:
            result["Content-Type"] = _decode(http.Content_Type)
        if http.Content_Length:
            result["Content-Length"] = _decode(http.Content_Length)
        if http.Server:
            result["Server"] = _decode(http.Server)

        return result

    return None


# =====================================================================
#  MAIN PARSE FUNCTION
# =====================================================================

_start_time = None   # thời điểm gói tin đầu tiên (để tính relative time)


def parse_packet(packet, criteria=None):
    """
    Phân tích gói tin Scapy và trả về dict chi tiết.

    Returns:
        dict với keys: summary, details, raw, scapy_pkt
        hoặc None nếu không parse được.
    """
    global _start_time

    try:
        if not match_packet(packet, criteria):
            return None

        # Cho phép cả gói non-IP (ARP)
        has_ip = packet.haslayer(IP) or packet.haslayer(IPv6)
        has_arp = packet.haslayer(ARP)

        if not has_ip and not has_arp:
            return None

        # ===== THỜI GIAN =====
        current_time = time.time()
        if _start_time is None:
            _start_time = current_time

        # ===== DETECT PROTOCOL & INFO =====
        protocol, info = _detect_protocol(packet)

        # ===== SOURCE & DESTINATION =====
        if has_ip:
            ip_layer = packet[IP] if packet.haslayer(IP) else packet[IPv6]
            src = ip_layer.src
            dst = ip_layer.dst
        elif has_arp:
            arp = packet[ARP]
            src = arp.psrc
            dst = arp.pdst
        else:
            src = dst = ""

        # ===== SUMMARY =====
        result = {
            "summary": {
                "time": round(current_time, 3),
                "src": src,
                "dst": dst,
                "protocol": protocol,
                "length": len(packet),
                "info": info,
            },
            "details": OrderedDict(),
            "raw": "",
            "scapy_pkt": packet,
        }

        # ===== DETAILS — layer by layer =====
        details = result["details"]

        # Layer 2: Ethernet
        eth_info = _parse_ethernet(packet)
        if eth_info:
            details["Ethernet II"] = eth_info

        # Layer 3: IP / IPv6 / ARP
        ip_info = _parse_ip(packet)
        if ip_info:
            details[f"Internet Protocol Version 4, Src: {src}, Dst: {dst}"] = ip_info

        ipv6_info = _parse_ipv6(packet)
        if ipv6_info:
            details[f"Internet Protocol Version 6, Src: {src}, Dst: {dst}"] = ipv6_info

        arp_info = _parse_arp(packet)
        if arp_info:
            details["Address Resolution Protocol"] = arp_info

        # Layer 4: TCP / UDP / ICMP
        tcp_info = _parse_tcp(packet)
        if tcp_info:
            tcp = packet[TCP]
            details[f"Transmission Control Protocol, Src Port: {tcp.sport}, Dst Port: {tcp.dport}"] = tcp_info

        udp_info = _parse_udp(packet)
        if udp_info:
            udp = packet[UDP]
            details[f"User Datagram Protocol, Src Port: {udp.sport}, Dst Port: {udp.dport}"] = udp_info

        icmp_info = _parse_icmp(packet)
        if icmp_info:
            details["Internet Control Message Protocol"] = icmp_info

        # Layer 7: DNS / HTTP
        dns_info = _parse_dns(packet)
        if dns_info:
            details["Domain Name System"] = dns_info

        http_info = _parse_http(packet)
        if http_info:
            if packet.haslayer(HTTPRequest):
                details["Hypertext Transfer Protocol (Request)"] = http_info
            else:
                details["Hypertext Transfer Protocol (Response)"] = http_info

        # ===== RAW DATA =====
        if packet.haslayer(Raw):
            result["raw"] = packet[Raw].load.hex()
        elif has_ip:
            try:
                result["raw"] = bytes(packet).hex()
            except Exception:
                pass

        return result

    except Exception as e:
        logger.error(f"Parse error: {e}", exc_info=True)
        return None


def reset_timer():
    """Reset thời gian bắt đầu capture (gọi khi restart)."""
    global _start_time
    _start_time = None
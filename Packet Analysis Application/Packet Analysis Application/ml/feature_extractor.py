"""
Feature Extractor — Trích xuất đặc trưng từ gói tin Scapy
theo format CICIDS2017 để đưa vào ML model.

Sử dụng sliding window theo flow key (src_ip, dst_ip, dst_port)
để tính các features flow-level từ packet-level data.
"""

import time
import numpy as np
from collections import defaultdict, deque


# =====================================================================
#  FLOW TRACKER — theo dõi trạng thái các luồng kết nối
# =====================================================================

class FlowTracker:
    """
    Lưu trữ trạng thái các flow đang hoạt động.
    Flow key = (src_ip, dst_ip, dst_port)

    Mỗi flow lưu:
        - Thời điểm gói tin đầu tiên
        - Danh sách timestamps + lengths gần đây (sliding window)
        - Đếm flags
        - Phân biệt forward / backward packets
    """

    def __init__(self, window_size=50, timeout=120):
        """
        Args:
            window_size: số gói tối đa lưu trong mỗi flow
            timeout: sau bao nhiêu giây không có gói mới thì xóa flow (giải phóng RAM)
        """
        self.window_size = window_size
        self.timeout = timeout
        self.flows = defaultdict(self._new_flow)
        self._last_cleanup = 0  # Sử dụng pkt_time domain, không phải wall-clock

    def _new_flow(self):
        return {
            "start_time": None,
            "fwd_lengths": deque(maxlen=self.window_size),
            "bwd_lengths": deque(maxlen=self.window_size),
            "timestamps": deque(maxlen=self.window_size),
            "total_fwd": 0,
            "total_bwd": 0,
            "syn_count": 0,
            "ack_count": 0,
            "psh_count": 0,
            "last_seen": 0,
        }

    def update(self, flow_key, reverse_key, pkt_time, pkt_len, flags=""):
        """
        Cập nhật flow với gói tin mới.

        Args:
            flow_key: (src, dst, dport) — key chính
            reverse_key: (dst, src, sport) — key ngược
            pkt_time: timestamp
            pkt_len: packet length
            flags: TCP flags string (e.g. "SA", "PA", "S")

        Returns:
            dict — flow state hiện tại
        """
        # Xác định đây là forward hay backward packet
        is_forward = True
        if reverse_key in self.flows and flow_key not in self.flows:
            # Gói này thuộc flow ngược → backward
            flow_key, reverse_key = reverse_key, flow_key
            is_forward = False
        elif reverse_key in self.flows and flow_key in self.flows:
            # Cả 2 key đều tồn tại → dùng flow có start_time sớm hơn
            if self.flows[reverse_key]["start_time"] and self.flows[flow_key]["start_time"]:
                if self.flows[reverse_key]["start_time"] < self.flows[flow_key]["start_time"]:
                    flow_key, reverse_key = reverse_key, flow_key
                    is_forward = False

        flow = self.flows[flow_key]

        # Khởi tạo start_time
        if flow["start_time"] is None:
            flow["start_time"] = pkt_time

        # Cập nhật
        flow["timestamps"].append(pkt_time)
        flow["last_seen"] = pkt_time

        if is_forward:
            flow["fwd_lengths"].append(pkt_len)
            flow["total_fwd"] += 1
        else:
            flow["bwd_lengths"].append(pkt_len)
            flow["total_bwd"] += 1

        # Đếm flags
        if flags:
            flags_str = str(flags)
            if "S" in flags_str and "A" not in flags_str:
                flow["syn_count"] += 1
            if "A" in flags_str:
                flow["ack_count"] += 1
            if "P" in flags_str:
                flow["psh_count"] += 1

        # Dọn dẹp flow cũ định kỳ (mỗi 30 giây theo packet time)
        if pkt_time - self._last_cleanup > 30:
            self._cleanup(pkt_time)
            self._last_cleanup = pkt_time

        return flow

    def _cleanup(self, now):
        """Xóa các flow không hoạt động quá timeout."""
        expired = [
            k for k, v in self.flows.items()
            if now - v["last_seen"] > self.timeout
        ]
        for k in expired:
            del self.flows[k]

    def get_flow_count(self):
        """Trả về số flow đang theo dõi."""
        return len(self.flows)


# =====================================================================
#  FEATURE EXTRACTOR — trích xuất 11 features cho ML model
# =====================================================================

# Thứ tự features PHẢI khớp với lúc train
FEATURE_ORDER = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Mean",
    "Flow Bytes/s",
    "Flow Packets/s",
    "SYN Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
]


class FeatureExtractor:
    """
    Trích xuất features từ gói tin đã parse (output của packet_parser.py)
    để đưa vào ML model predict.
    """

    def __init__(self):
        self.flow_tracker = FlowTracker(window_size=50, timeout=120)

    def extract(self, parsed_packet: dict) -> np.ndarray | None:
        """
        Trích xuất features từ 1 gói tin đã parse.

        Args:
            parsed_packet: dict từ packet_parser.parse_packet()
                Cần có: summary (src, dst, protocol, length, time)
                        details (TCP/UDP info)

        Returns:
            numpy array shape (11,) hoặc None nếu không trích xuất được
        """
        summary = parsed_packet.get("summary", {})
        details = parsed_packet.get("details", {})

        src = summary.get("src", "")
        dst = summary.get("dst", "")
        protocol = summary.get("protocol", "")
        pkt_len = summary.get("length", 0)
        pkt_time = summary.get("time", time.time())

        # Chỉ xử lý TCP/UDP (ML model train trên IP traffic)
        if not src or not dst:
            return None

        # ===== Trích xuất port và flags =====
        src_port = 0
        dst_port = 0
        flags = ""

        # Tìm TCP/UDP layer trong details (key format mới từ enhanced parser)
        for key, val in details.items():
            if key.startswith("Transmission Control"):
                # TCP layer
                try:
                    src_port = int(str(val.get("Source Port", "0")).split()[0])
                except (ValueError, IndexError):
                    src_port = 0
                try:
                    dst_port = int(str(val.get("Destination Port", "0")).split()[0])
                except (ValueError, IndexError):
                    dst_port = 0
                flags = val.get("Flags", "")
                break
            elif key.startswith("User Datagram"):
                # UDP layer
                try:
                    src_port = int(str(val.get("Source Port", "0")).split()[0])
                except (ValueError, IndexError):
                    src_port = 0
                try:
                    dst_port = int(str(val.get("Destination Port", "0")).split()[0])
                except (ValueError, IndexError):
                    dst_port = 0
                break

        # Fallback: parse từ info string "sport → dport ..."
        if dst_port == 0:
            info = summary.get("info", "")
            if "→" in info:
                try:
                    parts = info.split("→")
                    src_port = int(parts[0].strip().split()[-1])
                    dst_port = int(parts[1].strip().split()[0])
                except (ValueError, IndexError):
                    pass

        # ===== Cập nhật Flow Tracker =====
        flow_key = (src, dst, dst_port)
        reverse_key = (dst, src, src_port)
        flow = self.flow_tracker.update(
            flow_key, reverse_key, pkt_time, pkt_len, flags
        )

        # ===== Tính features =====

        # 1. Destination Port
        f_dst_port = dst_port

        # 2. Flow Duration (microseconds, giống CICIDS2017)
        if flow["start_time"]:
            f_duration = (pkt_time - flow["start_time"]) * 1_000_000
        else:
            f_duration = 0

        # 3. Total Fwd Packets
        f_total_fwd = flow["total_fwd"]

        # 4. Total Backward Packets
        f_total_bwd = flow["total_bwd"]

        # 5. Fwd Packet Length Mean
        fwd = list(flow["fwd_lengths"])
        f_fwd_mean = np.mean(fwd) if fwd else 0

        # 6. Bwd Packet Length Mean
        bwd = list(flow["bwd_lengths"])
        f_bwd_mean = np.mean(bwd) if bwd else 0

        # 7. Flow Bytes/s
        duration_sec = f_duration / 1_000_000
        total_bytes = sum(fwd) + sum(bwd)
        f_bytes_per_s = total_bytes / duration_sec if duration_sec > 0 else 0

        # 8. Flow Packets/s
        total_pkts = f_total_fwd + f_total_bwd
        f_pkts_per_s = total_pkts / duration_sec if duration_sec > 0 else 0

        # 9. SYN Flag Count
        f_syn = flow["syn_count"]

        # 10. PSH Flag Count
        f_psh = flow["psh_count"]

        # 11. ACK Flag Count
        f_ack = flow["ack_count"]

        # ===== Tạo feature vector =====
        features = np.array([
            f_dst_port,
            f_duration,
            f_total_fwd,
            f_total_bwd,
            f_fwd_mean,
            f_bwd_mean,
            f_bytes_per_s,
            f_pkts_per_s,
            f_syn,
            f_psh,
            f_ack,
        ], dtype=np.float64)

        # Xử lý NaN / Infinity
        features = np.nan_to_num(features, nan=0, posinf=0, neginf=0)

        return features

    def get_feature_names(self):
        """Trả về danh sách tên features theo thứ tự."""
        return FEATURE_ORDER.copy()

    def reset(self):
        """Reset flow tracker (khi restart capture)."""
        self.flow_tracker = FlowTracker(window_size=50, timeout=120)
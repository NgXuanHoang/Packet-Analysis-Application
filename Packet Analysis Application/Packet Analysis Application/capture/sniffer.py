"""
Packet Capture Engine — Bắt gói tin nâng cao, tương tự Wireshark.

Tính năng:
    - Liệt kê network interfaces (tên, mô tả, IP)
    - BPF capture filter (lọc tại kernel level, hiệu quả hơn display filter)
    - Promiscuous mode
    - Thống kê capture realtime (số gói, tốc độ, thời gian)
    - Snap length (giới hạn kích thước packet capture)
"""

import threading
import time
import logging
from dataclasses import dataclass

from scapy.all import sniff, conf, get_if_list
from parser.packet_parser import parse_packet, reset_timer

logger = logging.getLogger(__name__)


# =====================================================================
#  CAPTURE STATISTICS
# =====================================================================

@dataclass
class CaptureStats:
    """Thống kê capture realtime."""
    packets_captured: int = 0
    packets_dropped: int = 0
    bytes_captured: int = 0
    start_time: float = 0.0

    @property
    def duration(self) -> float:
        if self.start_time == 0:
            return 0.0
        return time.time() - self.start_time

    @property
    def packets_per_second(self) -> float:
        d = self.duration
        if d <= 0:
            return 0.0
        return self.packets_captured / d

    def reset(self):
        self.packets_captured = 0
        self.packets_dropped = 0
        self.bytes_captured = 0
        self.start_time = 0.0


# =====================================================================
#  INTERFACE LISTING
# =====================================================================

def get_interfaces() -> list[dict]:
    """
    Liệt kê network interfaces khả dụng.

    Returns:
        List of {"name": ..., "description": ..., "ip": ...}
    """
    interfaces = []

    try:
        for iface_name, iface_obj in conf.ifaces.items():
            desc = getattr(iface_obj, "description", "") or ""
            ip = getattr(iface_obj, "ip", "") or ""

            # Trên Windows, description dễ đọc hơn name (GUID)
            display = desc if desc else str(iface_name)
            if ip:
                display += f" ({ip})"

            interfaces.append({
                # Truyền trực tiếp Scapy interface object để tránh
                # lỗi "Error opening adapter" trên Windows
                "iface_obj": iface_obj,
                "description": desc,
                "ip": ip,
                "display": display,
            })
    except Exception:
        # Fallback nếu conf.ifaces không khả dụng
        for name in get_if_list():
            interfaces.append({
                "iface_obj": name,
                "description": name,
                "ip": "",
                "display": name,
            })

    return interfaces


# =====================================================================
#  BPF FILTER VALIDATION
# =====================================================================

def validate_bpf(bpf_filter: str) -> tuple[bool, str]:
    """
    Kiểm tra BPF filter hợp lệ.

    Returns:
        (is_valid, error_message)
    """
    if not bpf_filter.strip():
        return True, ""

    try:
        from scapy.arch import get_if_raw_addr
        # Thử compile filter bằng sniff dry-run
        # Scapy sẽ raise nếu BPF syntax sai
        sniff(filter=bpf_filter, count=0, timeout=0, store=False)
        return True, ""
    except Exception as e:
        return False, str(e)


# =====================================================================
#  PACKET CAPTURE ENGINE
# =====================================================================

class PacketCapture:
    """
    Engine bắt gói tin class-based, thay thế module sniffer đơn giản.

    Tương tự Wireshark capture engine:
        - Chọn interface
        - BPF capture filter
        - Promiscuous mode
        - Snap length
        - Thống kê realtime
    """

    def __init__(self):
        self._stop_event = threading.Event()
        self._stats = CaptureStats()
        self._lock = threading.Lock()
        self._running = False

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def stats(self) -> CaptureStats:
        return self._stats

    def start(
        self,
        callback=None,
        error_callback=None,
        interface=None,
        bpf_filter: str = "",
        promiscuous: bool = True,
        snap_length: int = 0,
        criteria: dict = None,
    ):
        """
        Bắt đầu capture (blocking — chạy trong thread riêng).

        Args:
            callback:      hàm nhận parsed packet dict
            error_callback: hàm nhận error string (gọi khi capture lỗi)
            interface:     tên interface (None = mặc định)
            bpf_filter:    BPF capture filter (vd: "tcp port 80")
            promiscuous:   bật promiscuous mode
            snap_length:   giới hạn bytes/packet (0 = không giới hạn)
            criteria:      display filter criteria cho parser
        """
        self._stop_event.clear()
        self._stats.reset()
        self._stats.start_time = time.time()
        self._running = True

        reset_timer()

        def handle_packet(pkt):
            try:
                data = parse_packet(pkt, criteria)
                if data and callback:
                    with self._lock:
                        self._stats.packets_captured += 1
                        self._stats.bytes_captured += len(pkt)
                    callback(data)
                elif not data:
                    with self._lock:
                        self._stats.packets_dropped += 1
            except Exception as e:
                logger.error(f"Packet handle error: {e}")
                with self._lock:
                    self._stats.packets_dropped += 1

        # Build sniff kwargs
        sniff_kwargs = {
            "prn": handle_packet,
            "store": False,
            "stop_filter": lambda _: self._stop_event.is_set(),
            "promisc": promiscuous,
        }

        if interface:
            sniff_kwargs["iface"] = interface

        if bpf_filter.strip():
            sniff_kwargs["filter"] = bpf_filter.strip()

        if snap_length > 0:
            sniff_kwargs["snaplen"] = snap_length

        try:
            sniff(**sniff_kwargs)
        except PermissionError:
            msg = "Cần quyền Administrator để bắt gói tin."
            logger.error(msg)
            if error_callback:
                error_callback(msg)
        except OSError as e:
            msg = f"Lỗi interface: {e}"
            logger.error(msg)
            if error_callback:
                error_callback(msg)
        except Exception as e:
            msg = f"Lỗi capture: {e}"
            logger.error(msg)
            if error_callback:
                error_callback(msg)
        finally:
            self._running = False

    def stop(self):
        """Dừng capture."""
        self._stop_event.set()


# =====================================================================
#  BACKWARD-COMPATIBLE WRAPPERS
# =====================================================================

_default_capture = PacketCapture()


def start_sniffing(interface=None, criteria=None, callback=None):
    """Wrapper tương thích ngược."""
    _default_capture.start(
        callback=callback,
        interface=interface,
        criteria=criteria,
    )


def stop_sniffing():
    """Wrapper tương thích ngược."""
    _default_capture.stop()

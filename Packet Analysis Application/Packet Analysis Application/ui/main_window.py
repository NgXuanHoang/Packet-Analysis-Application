from PyQt5.QtWidgets import (
    QMainWindow, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QHBoxLayout, QWidget, QTreeWidget, QTreeWidgetItem,
    QTextEdit, QAction, QToolBar, QLineEdit, QSplitter, QAbstractItemView,
    QFileDialog, QMessageBox, QHeaderView, QComboBox, QCheckBox, QLabel, QDialog,
    QTabWidget
)
from PyQt5.QtCore import pyqtSignal, Qt, QTimer
from threading import Thread
from capture.sniffer import PacketCapture, get_interfaces
import ipaddress
import logging
import time
from collections import Counter, defaultdict, deque
from datetime import datetime
from scapy.utils import wrpcap, PcapReader
from PyQt5.QtGui import QColor
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

from ai.chat_widget import ChatWidget
from filter.filter_engine import parse_filter, match_packet

from ml.feature_extractor import FeatureExtractor
from ml.predictor import MLPredictor
logger = logging.getLogger(__name__)


# ===== HEX FORMAT =====
def format_hex(data):
    hex_str = ""
    ascii_str = ""

    for i, b in enumerate(data):
        hex_str += f"{b:02x} "
        ascii_str += chr(b) if 32 <= b <= 126 else "."

        if (i + 1) % 16 == 0:
            hex_str += "   " + ascii_str + "\n"
            ascii_str = ""

    return hex_str


class MainWindow(QMainWindow):
    packet_signal = pyqtSignal(dict)
    capture_error_signal = pyqtSignal(str)

    def __init__(self):
        super().__init__()

        self.setWindowTitle("Packet Analysis Application")
        self.setGeometry(100, 100, 1400, 750)

        self.packets = []
        self.sniff_thread = None
        self.current_filter: dict | None = None
        self.feature_extractor = FeatureExtractor()
        self.ml_predictor = MLPredictor("ml")
        # Capture engine
        self.capture = PacketCapture()

        # ===== Statistics counters =====
        self.total_packets = 0
        self.protocol_counter = Counter()
        self.src_ip_counter = Counter()
        self.dst_ip_counter = Counter()
        self.time_counter = Counter()
        self.first_packet_time = None
        # ===== High traffic detection =====
        self.ip_packet_times = defaultdict(deque)
        self.alert_threshold = 3
        self.alert_window = 5  # seconds

        self._last_chart_refresh = 0

        # ===== Packet buffer để batch update UI =====
        self._packet_buffer = []    # buffer gói tin chờ flush
        self._flush_timer = QTimer()
        self._flush_timer.setInterval(100)  # flush mỗi 100ms
        self._flush_timer.timeout.connect(self._flush_packet_buffer)

        # Stats timer
        self.stats_timer = QTimer()
        self.stats_timer.timeout.connect(self._update_stats)

        # ===== UI =====
        self.create_menu()
        self.create_toolbar()
        self.create_filterbar()
        self.init_ui()
        self._create_statusbar()

        self.packet_signal.connect(self._on_packet_received)
        self.capture_error_signal.connect(self._on_capture_error)

    def open_pcap(self):
        self.start_action.setEnabled(True)
        self.stop_action.setEnabled(False)
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Open PCAP",
            "",
            "PCAP Files (*.pcap)"
        )

        if not path:
            return

        # hỏi lưu trước khi mở file mới
        if self.packets:
            if not self.maybe_save():
                return

        try:
            self.clear_packets()
            self._flush_timer.start() # Bật flush timer để UI cập nhật dần

            def load_task():
                try:
                    from parser.packet_parser import parse_packet
                    # Dùng PcapReader (generator) thay vì rdpcap (load hết vào RAM)
                    with PcapReader(path) as reader:
                        for pkt in reader:
                            parsed = parse_packet(pkt)
                            if parsed:
                                # Tái sử dụng hàm đệm buffer, chạy ML ngầm và không chặn UI
                                self._on_packet_received(parsed)
                    print("Loaded:", path)
                except Exception as e:
                    print("Open PCAP worker error:", e)

            # Chạy đọc file trong luồng nền
            thread = Thread(target=load_task, daemon=True)
            thread.start()

        except Exception as e:
            print("Open error:", e)

    def close_file(self):
        if not self.maybe_save():
            return

        self.clear_packets()

    def save_to_file(self):
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Capture",
            "",
            "PCAP Files (*.pcap)"
        )

        if not path:
            return False

        if not path.endswith(".pcap"):
            path += ".pcap"

        try:
            scapy_packets = [
                pkt["scapy_pkt"] for pkt in self.packets if "scapy_pkt" in pkt
            ]

            if not scapy_packets:
                return False

            wrpcap(path, scapy_packets)

            print("Saved PCAP:", path)
            return True

        except Exception as e:
            print("Save error:", e)
            return False

    def maybe_save(self):
        if not self.packets:
            return True

        reply = QMessageBox.question(
            self,
            "Save Capture",
            "Do you want to save captured packets?",
            QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel
        )

        if reply == QMessageBox.Yes:
            return self.save_to_file()
        elif reply == QMessageBox.No:
            return True
        else:
            return False


    # ================= MENU =================
    def create_menu(self):
        menubar = self.menuBar()

        file_menu = menubar.addMenu("File")

        open_action = QAction("Open", self)
        open_action.triggered.connect(self.open_pcap)
        file_menu.addAction(open_action)

        save_action = QAction("Save", self)
        save_action.triggered.connect(self.save_to_file)
        file_menu.addAction(save_action)

        file_menu.addSeparator()

        close_action = QAction("Close", self)
        close_action.triggered.connect(self.close_file)
        file_menu.addAction(close_action)

        file_menu.addSeparator()

        exit_action = QAction("Quit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # ===== Analyze =====
        analyze_menu = menubar.addMenu("Analyze")

        follow_tcp = QAction("Follow TCP Stream", self)
        follow_tcp.triggered.connect(lambda: self.follow_stream("TCP"))
        analyze_menu.addAction(follow_tcp)

        follow_udp = QAction("Follow UDP Stream", self)
        follow_udp.triggered.connect(lambda: self.follow_stream("UDP"))
        analyze_menu.addAction(follow_udp)

        follow_http = QAction("Follow HTTP Stream", self)
        follow_http.triggered.connect(lambda: self.follow_stream("HTTP"))
        analyze_menu.addAction(follow_http)

        follow_tls = QAction("Follow TLS Stream", self)
        follow_tls.triggered.connect(lambda: self.follow_stream("TLS"))
        analyze_menu.addAction(follow_tls)

        follow_arp = QAction("Follow ARP", self)
        follow_arp.triggered.connect(lambda: self.follow_stream("ARP"))
        analyze_menu.addAction(follow_arp)

        follow_icmp = QAction("Follow ICMP", self)
        follow_icmp.triggered.connect(lambda: self.follow_stream("ICMP"))
        analyze_menu.addAction(follow_icmp)

        analyze_menu.addSeparator()

        clear_filter = QAction("Clear Filter", self)
        clear_filter.triggered.connect(self.clear_flow_filter)
        analyze_menu.addAction(clear_filter)

        # ===== Statistics =====
        statistics_menu = menubar.addMenu("Statistics")

        ipv4_menu = statistics_menu.addMenu("IPv4")

        ipv4_all = QAction("All Addresses", self)
        ipv4_all.triggered.connect(lambda: self.show_stats("ipv4", "all"))
        ipv4_menu.addAction(ipv4_all)

        ipv4_src = QAction("Source", self)
        ipv4_src.triggered.connect(lambda: self.show_stats("ipv4", "src"))
        ipv4_menu.addAction(ipv4_src)

        ipv4_dst = QAction("Destination", self)
        ipv4_dst.triggered.connect(lambda: self.show_stats("ipv4", "dst"))
        ipv4_menu.addAction(ipv4_dst)

        ipv4_proto = QAction("Protocol", self)
        ipv4_proto.triggered.connect(lambda: self.show_stats("ipv4", "proto"))
        ipv4_menu.addAction(ipv4_proto)

        ipv6_menu = statistics_menu.addMenu("IPv6")

        ipv6_all = QAction("All Addresses", self)
        ipv6_all.triggered.connect(lambda: self.show_stats("ipv6", "all"))
        ipv6_menu.addAction(ipv6_all)

        ipv6_src = QAction("Source", self)
        ipv6_src.triggered.connect(lambda: self.show_stats("ipv6", "src"))
        ipv6_menu.addAction(ipv6_src)

        ipv6_dst = QAction("Destination", self)
        ipv6_dst.triggered.connect(lambda: self.show_stats("ipv6", "dst"))
        ipv6_menu.addAction(ipv6_dst)

        ipv6_proto = QAction("Protocol", self)
        ipv6_proto.triggered.connect(lambda: self.show_stats("ipv6", "proto"))
        ipv6_menu.addAction(ipv6_proto)

        # ===== Help =====
        help_menu = menubar.addMenu("Help")

        filter_help = QAction("Filter Help", self)
        filter_help.triggered.connect(self.show_filter_help)
        help_menu.addAction(filter_help)

    # ================= TOOLBAR =================
    def create_toolbar(self):
        toolbar = QToolBar("Main Toolbar")
        self.addToolBar(toolbar)

        # Interface selector
        toolbar.addWidget(QLabel(" Interface: "))
        self.iface_combo = QComboBox()
        self.iface_combo.setMinimumWidth(250)
        self._populate_interfaces()
        toolbar.addWidget(self.iface_combo)

        toolbar.addSeparator()

        # Promiscuous mode
        self.promisc_check = QCheckBox("Promiscuous")
        self.promisc_check.setChecked(True)
        toolbar.addWidget(self.promisc_check)

        toolbar.addSeparator()

        # Start / Stop / Restart
        self.start_action = QAction("Start", self)
        self.start_action.triggered.connect(self.start_capture)
        toolbar.addAction(self.start_action)

        self.stop_action = QAction("Stop", self)
        self.stop_action.triggered.connect(self.stop_capture)
        self.stop_action.setEnabled(False)
        toolbar.addAction(self.stop_action)

        self.restart_action = QAction("Restart", self)
        self.restart_action.triggered.connect(self.restart_capture)
        toolbar.addAction(self.restart_action)

    def _populate_interfaces(self):
        """Liệt kê network interfaces vào combo box."""
        self.iface_combo.clear()
        self.iface_combo.addItem("All interfaces (default)", None)

        try:
            for iface in get_interfaces():
                # Lưu Scapy interface object trực tiếp để tránh lỗi adapter trên Windows
                self.iface_combo.addItem(iface["display"], iface["iface_obj"])
        except Exception as e:
            logger.error(f"Cannot list interfaces: {e}")

    def _get_selected_interface(self):
        """Trả về Scapy interface object được chọn, None nếu All."""
        return self.iface_combo.currentData()

    def restart_capture(self):
        if not self.maybe_save():
            return

        self.capture.stop()

        if self.sniff_thread:
            self.sniff_thread.join(timeout=2)

        self.clear_packets()
        self.start_capture()

    # ================= ANALYZE: FOLLOW STREAM =================
    def get_selected_packet(self):
        row = self.table.currentRow()
        if row < 0:
            return None

        item = self.table.item(row, 0)
        if not item:
            return None

        index = item.data(Qt.UserRole)
        if index is None:
            index = int(item.text())

        if index < 0 or index >= len(self.packets):
            return None

        return self.packets[index]

    def get_flow_key(self, pkt):
        s = pkt["summary"]
        details = pkt.get("details", {})

        src = s["src"]
        dst = s["dst"]
        proto = s["protocol"]

        sport = "-"
        dport = "-"

        for layer, fields in details.items():
            for k, v in fields.items():
                if "Source Port" in k:
                    sport = str(v).split()[0]
                if "Destination Port" in k:
                    dport = str(v).split()[0]

        return (src, sport, dst, dport, proto)

    def is_same_flow(self, key1, key2):
        return (
            key1 == key2 or
            (key1[0] == key2[2] and
             key1[1] == key2[3] and
             key1[2] == key2[0] and
             key1[3] == key2[1] and
             key1[4] == key2[4])
        )

    def follow_stream(self, protocol):
        pkt = self.get_selected_packet()
        if not pkt:
            QMessageBox.warning(self, "Error", "Please select a packet")
            return

        key = self.get_flow_key(pkt)
        pkt_proto = pkt["summary"].get("protocol", "").upper()

        if protocol == "TCP":
            if "TCP" not in pkt_proto:
                QMessageBox.warning(self, "Error", "Not TCP")
                return
        elif protocol == "UDP":
            if "UDP" not in pkt_proto:
                QMessageBox.warning(self, "Error", "Not UDP")
                return
        elif protocol == "HTTP":
            if "HTTP" not in pkt_proto:
                QMessageBox.warning(self, "Error", "Not HTTP")
                return
        elif protocol == "TLS":
            if "TLS" not in pkt_proto and "HTTPS" not in pkt_proto:
                QMessageBox.warning(self, "Error", "Not TLS")
                return
        elif protocol == "ICMP":
            if "ICMP" not in pkt_proto:
                QMessageBox.warning(self, "Error", "Not ICMP")
                return
        elif protocol == "ARP":
            if "ARP" not in pkt_proto:
                QMessageBox.warning(self, "Error", "Not ARP")
                return

        self.current_filter = {"flow": key}
        self.reload_table()

    def clear_flow_filter(self):
        self.current_filter = None
        self.filter_input.clear()
        self.reload_table()

    # ================= STATISTICS =================
    def show_stats(self, ip_version, mode):
        counter = Counter()

        for pkt in self.packets:
            details = pkt.get("details", {})

            is_ipv4 = any("Version 4" in k for k in details)
            is_ipv6 = any("Version 6" in k for k in details)

            if ip_version == "ipv4" and not is_ipv4:
                continue
            if ip_version == "ipv6" and not is_ipv6:
                continue

            s = pkt["summary"]

            if mode == "all":
                counter[s["src"]] += 1
                counter[s["dst"]] += 1
            elif mode == "src":
                key = f"{s['src']}:{self.extract_port(pkt)}"
                counter[key] += 1
            elif mode == "dst":
                key = f"{s['dst']}:{self.extract_port(pkt)}"
                counter[key] += 1
            elif mode == "proto":
                counter[s["protocol"]] += 1

        title_map = {
            "ipv4": "IPv4 Statistics",
            "ipv6": "IPv6 Statistics"
        }
        mode_map = {
            "all": "All Addresses",
            "src": "Source Addresses",
            "dst": "Destination Addresses",
            "proto": "Protocols"
        }
        title = f"{title_map.get(ip_version, '')} - {mode_map.get(mode, '')}"
        self.show_stats_window(counter, title=title)

    def show_stats_window(self, counter, title="Statistics"):
        dialog = QDialog(self)
        dialog.setWindowTitle(title)
        dialog.resize(1000, 700)

        layout = QVBoxLayout()

        table = QTableWidget()
        table.setColumnCount(3)
        table.setHorizontalHeaderLabels(["Value", "Count", "Percent (%)"])

        total = sum(counter.values()) if counter else 1
        sorted_items = counter.most_common()

        table.setRowCount(len(sorted_items))

        for row, (key, val) in enumerate(sorted_items):
            percent = (val / total) * 100
            table.setItem(row, 0, QTableWidgetItem(str(key)))
            table.setItem(row, 1, QTableWidgetItem(str(val)))
            table.setItem(row, 2, QTableWidgetItem(f"{percent:.2f}"))

        table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        layout.addWidget(table)
        dialog.setLayout(layout)
        dialog.exec_()

    def extract_port(self, pkt):
        details = pkt.get("details", {})

        for layer, fields in details.items():
            for k, v in fields.items():
                if "Source Port" in k:
                    return str(v).split()[0]

        return "-"

    # ================= HELP =================
    def show_filter_help(self):
        if hasattr(self, "help_window") and self.help_window:
            self.help_window.show()
            self.help_window.raise_()
            return

        self.help_window = QDialog(self)
        self.help_window.setWindowTitle("Filter Help")
        self.help_window.resize(500, 400)

        layout = QVBoxLayout()

        text = QTextEdit()
        text.setReadOnly(True)
        text.setText(
            "=== FILTER HELP ===\n\n"
            "[Protocol]\n"
            "tcp, udp, icmp, arp, tls, https\n\n"
            "[IP]\n"
            "ip.src == X\n"
            "ip.dst == X\n"
            "ip.addr == X\n\n"
            "[Port]\n"
            "port == X\n"
            "port.src == X\n"
            "port.dst == X\n\n"
            "[Examples]\n"
            "tcp and ip.addr == 192.168.1.1\n"
            "udp and port == 53\n"
            "https and ip.dst == 8.8.8.8\n"
        )

        layout.addWidget(text)
        self.help_window.setLayout(layout)
        self.help_window.show()

    # ================= FILTER BAR =================
    def create_filterbar(self):
        self.filterbar = QToolBar("Filter Bar")
        self.addToolBar(self.filterbar)

        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText(
            "Apply filter (tcp, udp, ip.src == 192.168.1.1)"
        )

        self.filter_input.returnPressed.connect(self.apply_filter)
        self.filter_input.textChanged.connect(self.validate_filter)

        self.filterbar.addWidget(self.filter_input)

    # ================= VALIDATE FILTER =================
    def _is_valid_ip(self, ip_str):
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False

    def validate_filter(self):
        text = self.filter_input.text().strip()

        if not text:
            self.filter_input.setStyleSheet("")
            return

        result = parse_filter(text)

        if result is not None:
            self.filter_input.setStyleSheet("background-color: #c4f0c4;")
        else:
            self.filter_input.setStyleSheet("background-color: #f7c6c6;")

    # ================= APPLY FILTER =================
    def apply_filter(self):
        text = self.filter_input.text().strip()

        if not text:
            self.current_filter = None
        else:
            result = parse_filter(text)

            if result is None:
                QMessageBox.warning(self, "Invalid filter", "Filter syntax error!")
                return

            self.current_filter = result

        self.reload_table()

    def _get_displayed_packets(self):
        """Trả về danh sách packets đang hiển thị trên màn hình (theo filter)."""
        if not self.current_filter:
            return self.packets

        result = []
        for p in self.packets:
            # Flow filter (follow stream)
            if "flow" in self.current_filter:
                pkt_key = self.get_flow_key(p)
                if not self.is_same_flow(pkt_key, self.current_filter["flow"]):
                    continue
            else:
                # Dùng scapy match_packet nếu có scapy_pkt
                scapy_pkt = p.get("scapy_pkt")
                if scapy_pkt:
                    if not match_packet(scapy_pkt, self.current_filter):
                        continue
                else:
                    # Fallback: lọc theo summary
                    s = p.get("summary", {})
                    f = self.current_filter
                    if "protocol" in f and s.get("protocol") != f["protocol"]:
                        continue
                    if "src" in f and s.get("src") != f["src"]:
                        continue
                    if "dst" in f and s.get("dst") != f["dst"]:
                        continue
            result.append(p)
        return result

    def _apply_filter_from_chat(self, filter_text):
        """Nhận lệnh filter từ chatbot và áp dụng lên UI."""
        self.filter_input.setText(filter_text)
        self.apply_filter()

    # ================= RELOAD TABLE =================
    def reload_table(self):
        self.table.setRowCount(0)

        for i, pkt in enumerate(self.packets):
            pkt["_index"] = i
            self.add_packet(pkt, add_to_list=False)

    # ================= MAIN UI (ĐÃ TÍCH HỢP CHAT + STATISTICS TAB) =================
    def init_ui(self):
        self.tabs = QTabWidget()

        # =========================
        # TAB 1 - CAPTURE
        # =========================
        capture_tab = QWidget()
        capture_layout = QVBoxLayout()
        capture_layout.setContentsMargins(0, 0, 0, 0)

        # TABLE
        self.table = QTableWidget()
        self.table.setColumnCount(8)
        self.table.verticalHeader().setVisible(False)
        self.table.setHorizontalHeaderLabels([
            "No", "Time", "Source", "Destination", "Protocol", "Length", "Info", "Alert"
        ])
        self.table.cellClicked.connect(self.show_details)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)

        # DETAILS + HEX SPLITTER
        detail_splitter = QSplitter(Qt.Horizontal)

        self.details = QTreeWidget()
        self.details.setHeaderLabel("Packet Details")

        self.raw = QTextEdit()
        self.raw.setReadOnly(True)

        detail_splitter.addWidget(self.details)
        detail_splitter.addWidget(self.raw)
        detail_splitter.setSizes([500, 500])

        capture_layout.addWidget(self.table)
        capture_layout.addWidget(detail_splitter)
        capture_tab.setLayout(capture_layout)

        # =========================
        # TAB 2 - STATISTICS
        # =========================
        stats_tab = QWidget()
        stats_layout = QVBoxLayout()

        stats_info_layout = QHBoxLayout()

        self.total_label = QLabel("Total: 0")
        self.proto_label = QLabel("Protocols: 0")
        self.top_proto_label = QLabel("Top: -")

        self.total_label.setStyleSheet("font-size: 16px; font-weight: bold;")
        self.proto_label.setStyleSheet("font-size: 16px; font-weight: bold; color: purple;")
        self.top_proto_label.setStyleSheet("font-size: 16px; font-weight: bold; color: teal;")

        stats_info_layout.addWidget(self.total_label)
        stats_info_layout.addWidget(self.proto_label)
        stats_info_layout.addWidget(self.top_proto_label)

        self.figure = Figure(figsize=(12, 10))
        self.canvas = FigureCanvas(self.figure)

        stats_layout.addLayout(stats_info_layout)
        stats_layout.addWidget(self.canvas)
        stats_tab.setLayout(stats_layout)

        self.tabs.addTab(capture_tab, "Capture")
        self.tabs.addTab(stats_tab, "Statistics")

        # ===== Phần phải: Chat Panel =====
        self.chat_widget = ChatWidget()
        self.chat_widget.set_packets_ref(lambda: self._get_displayed_packets())
        self.chat_widget.filter_requested.connect(self._apply_filter_from_chat)
        self.chat_widget.setMinimumWidth(320)

        # ===== SPLITTER CHÍNH: trái (tabs) | phải (chat) =====
        main_splitter = QSplitter(Qt.Horizontal)
        main_splitter.addWidget(self.tabs)
        main_splitter.addWidget(self.chat_widget)
        main_splitter.setSizes([900, 380])

        self.setCentralWidget(main_splitter)

        # Header resize
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        header.setSectionResizeMode(3, QHeaderView.Stretch)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.Stretch)
        header.setSectionResizeMode(7, QHeaderView.ResizeToContents)

        self.refresh_chart()

    # ================= STATUS BAR =================
    def _create_statusbar(self):
        self.stats_label = QLabel("Ready")
        self.statusBar().addPermanentWidget(self.stats_label)

    def _update_stats(self):
        stats = self.capture.stats
        d = stats.duration
        mins, secs = divmod(int(d), 60)
        hours, mins = divmod(mins, 60)

        text = (
            f"  Packets: {stats.packets_captured}"
            f"  |  Dropped: {stats.packets_dropped}"
            f"  |  Bytes: {stats.bytes_captured:,}"
            f"  |  Duration: {hours:02d}:{mins:02d}:{secs:02d}"
            f"  |  Rate: {stats.packets_per_second:.1f} pkt/s"
        )
        self.stats_label.setText(text)

    def _on_capture_error(self, msg):
        """Hiển thị lỗi capture trên UI thread."""
        self.stop_capture()
        QMessageBox.warning(self, "Capture Error", msg)

    # ================= START =================
    def start_capture(self):
        if self.packets:
            if not self.maybe_save():
                return
            self.clear_packets()

        if self.sniff_thread and self.sniff_thread.is_alive():
            return

        # Lấy cấu hình từ UI
        iface = self._get_selected_interface()
        promisc = self.promisc_check.isChecked()

        # Lock UI khi đang capture
        self.start_action.setEnabled(False)
        self.stop_action.setEnabled(True)
        self.iface_combo.setEnabled(False)
        self.promisc_check.setEnabled(False)

        self.sniff_thread = Thread(
            target=lambda: self.capture.start(
                callback=self._ml_then_emit,
                error_callback=self.capture_error_signal.emit,
                interface=iface,
                promiscuous=promisc,
            ),
            daemon=True,
        )
        self.sniff_thread.start()
        self.stats_timer.start(1000)
        self._flush_timer.start()  # bắt đầu flush buffer

    # ================= STOP =================
    def stop_capture(self):
        self.capture.stop()
        self.stats_timer.stop()
        self._flush_timer.stop()
        self._flush_packet_buffer()  # flush nốt các gói còn trong buffer
        self._update_stats()
        self.refresh_chart()

        self.start_action.setEnabled(True)
        self.stop_action.setEnabled(False)
        self.iface_combo.setEnabled(True)
        self.promisc_check.setEnabled(True)

    # ================= CLEAR =================
    def clear_packets(self):
        self.table.setRowCount(0)
        self.details.clear()
        self.raw.clear()
        self.packets.clear()
        self.feature_extractor.reset()

        # Reset statistics
        self.total_packets = 0
        self.protocol_counter.clear()
        self.src_ip_counter.clear()
        self.dst_ip_counter.clear()
        self.time_counter.clear()
        self.ip_packet_times.clear()
        self.first_packet_time = None

        self.total_label.setText("Total: 0")
        self.proto_label.setText("Protocols: 0")
        self.top_proto_label.setText("Top: -")

        self.refresh_chart()

    # ================= ML ON SNIFFER THREAD =================
    def _ml_then_emit(self, packet):
        """Chạy trên sniffer thread — ML prediction rồi emit signal về UI."""
        if not packet or "summary" not in packet:
            return

        if self.ml_predictor.is_loaded:
            features = self.feature_extractor.extract(packet)
            if features is not None:
                ml_label, ml_confidence = self.ml_predictor.predict(features)
                packet["ml_prediction"] = {
                    "label": ml_label,
                    "confidence": round(ml_confidence, 3),
                }

        self.packet_signal.emit(packet)


    def normalize_protocol_for_stats(self, protocol):
        if not protocol:
            return "OTHER"

        p = str(protocol).upper()

        if p == "TCP":
            return "TCP"
        elif p == "UDP":
            return "UDP"
        elif p == "ICMP":
            return "ICMP"
        elif p == "ARP":
            return "ARP"
        elif p == "DNS":
            return "DNS"
        elif p in ("HTTP", "HTTP-ALT"):
            return "HTTP"
        elif p in ("TLS", "HTTPS", "HTTPS-ALT"):
            return "TLS"
        else:
            return "OTHER"
    # ================= PACKET BUFFER =================
    def _on_packet_received(self, packet):
        """Nhận packet từ signal (UI thread), chỉ đẩy vào buffer."""
        packet["_index"] = len(self.packets)

        # Update stats counters
        s = packet.get("summary", {})
        protocol = s.get("protocol", "")
        normalized_protocol = self.normalize_protocol_for_stats(protocol)
        src_ip = s.get("src", "N/A")
        dst_ip = s.get("dst", "N/A")

        self.total_packets += 1
        if protocol:
            self.protocol_counter[normalized_protocol] += 1

        if src_ip and src_ip != "N/A":
            self.src_ip_counter[src_ip] += 1
        if dst_ip and dst_ip != "N/A":
            self.dst_ip_counter[dst_ip] += 1

        pkt_time = s.get("time", None)

        if pkt_time is not None:
            try:
                # Lấy mốc thời gian gói đầu tiên
                if not hasattr(self, "first_packet_time") or self.first_packet_time is None:
                    self.first_packet_time = float(pkt_time)

                # Tính thời gian tương đối kể từ lúc bắt đầu
                relative_time = float(pkt_time) - self.first_packet_time

                # Gom packet theo từng giây: 0s, 1s, 2s...
                second_bucket = int(relative_time)
                self.time_counter[second_bucket] += 1

            except (ValueError, TypeError):
                pass

        # High traffic detection — lưu kết quả vào packet
        packet["_alert"] = self.detect_high_traffic(src_ip)

        self.packets.append(packet)
        self._packet_buffer.append(packet)

    def _flush_packet_buffer(self):
        """Flush buffer vào table theo batch — gọi mỗi 100ms."""
        if not self._packet_buffer:
            return

        # Chỉ lấy tối đa 1000 gói mỗi chu kỳ 100ms để tránh đơ giao diện
        MAX_BATCH_SIZE = 1000
        batch = self._packet_buffer[:MAX_BATCH_SIZE]
        self._packet_buffer = self._packet_buffer[MAX_BATCH_SIZE:]

        # Tắt repaint trong lúc thêm hàng loạt
        self.table.setUpdatesEnabled(False)
        try:
            for packet in batch:
                self._insert_packet_row(packet)
        finally:
            self.table.setUpdatesEnabled(True)

        # Update stat labels
        self.total_label.setText(f"Total: {self.total_packets}")
        self.proto_label.setText(f"Protocols: {len(self.protocol_counter)}")

        if self.protocol_counter:
            top_name, top_count = self.protocol_counter.most_common(1)[0]
            self.top_proto_label.setText(f"Top: {top_name} ({top_count})")
        else:
             self.top_proto_label.setText("Top: -")

        # Throttled chart refresh (tối đa mỗi 2 giây)
        now = time.time()
        if now - self._last_chart_refresh > 2.0:
            self.refresh_chart()
            self._last_chart_refresh = now

    # ================= ADD PACKET =================
    def add_packet(self, packet, add_to_list=True):
        """Thêm packet vào table (dùng khi load PCAP hoặc reload)."""
        if not packet or "summary" not in packet:
            return

        if add_to_list:
            if self.ml_predictor.is_loaded:
                features = self.feature_extractor.extract(packet)
                if features is not None:
                    ml_label, ml_confidence = self.ml_predictor.predict(features)
                    packet["ml_prediction"] = {
                        "label": ml_label,
                        "confidence": round(ml_confidence, 3),
                    }
            packet["_index"] = len(self.packets)
            self.packets.append(packet)

        self._insert_packet_row(packet)

    def _insert_packet_row(self, packet):
        """Chèn 1 dòng vào table cho packet."""
        s = packet["summary"]
        packet_index = packet.get("_index", 0)

        if self.current_filter:
            # Flow filter (follow stream)
            if "flow" in self.current_filter:
                pkt_key = self.get_flow_key(packet)
                if not self.is_same_flow(pkt_key, self.current_filter["flow"]):
                    return
            else:
                # Dùng scapy match_packet nếu có scapy_pkt
                scapy_pkt = packet.get("scapy_pkt")
                if scapy_pkt:
                    if not match_packet(scapy_pkt, self.current_filter):
                        return
                else:
                    # Fallback: lọc theo summary
                    if "protocol" in self.current_filter:
                        if s.get("protocol") != self.current_filter["protocol"]:
                            return
                    if "src" in self.current_filter:
                        if s.get("src") != self.current_filter["src"]:
                            return
                    if "dst" in self.current_filter:
                        if s.get("dst") != self.current_filter["dst"]:
                            return

        row = self.table.rowCount()
        self.table.insertRow(row)

        item_no = QTableWidgetItem(str(packet_index))
        item_no.setData(Qt.UserRole, packet_index)

        # Format time kiểu Wireshark (relative từ gói đầu tiên)
        pkt_time = s.get("time", "")
        if pkt_time and self.packets:
            try:
                first_time = self.packets[0]["summary"].get("time", pkt_time)
                relative = float(pkt_time) - float(first_time)
                time_str = f"{relative:.6f}"
            except (ValueError, TypeError):
                time_str = str(pkt_time)
        else:
            time_str = str(pkt_time)

        self.table.setItem(row, 0, item_no)
        self.table.setItem(row, 1, QTableWidgetItem(time_str))
        self.table.setItem(row, 2, QTableWidgetItem(s.get("src", "")))
        self.table.setItem(row, 3, QTableWidgetItem(s.get("dst", "")))
        self.table.setItem(row, 4, QTableWidgetItem(s.get("protocol", "")))
        self.table.setItem(row, 5, QTableWidgetItem(str(s.get("length", ""))))
        self.table.setItem(row, 6, QTableWidgetItem(s.get("info", "")))
        self.table.setItem(row, 7, QTableWidgetItem(packet.get("_alert", "")))

        self.color_row_by_protocol(row, s.get("protocol", ""))

    # ================= COLOR ROW BY PROTOCOL =================
    def color_row_by_protocol(self, row, protocol):
        color = None

        if protocol == "TCP":
            color = QColor(220, 255, 220)   # xanh lá nhạt
        elif protocol == "UDP":
            color = QColor(255, 255, 220)   # vàng nhạt
        elif protocol == "ICMP":
            color = QColor(220, 240, 255)   # xanh dương nhạt
        elif protocol == "ARP":
            color = QColor(255, 230, 200)   # cam nhạt
        elif protocol == "DNS":
            color = QColor(235, 220, 255)   # tím nhạt
        elif protocol == "HTTP":
            color = QColor(255, 210, 210)   # hồng đỏ nhạt
        elif protocol == "HTTP-Alt":
            color = QColor(255, 235, 200)   # cam vàng nhạt
        elif protocol == "HTTPS":
            color = QColor(200, 255, 230)   # xanh mint nhạt
        elif protocol == "HTTPS-Alt":
            color = QColor(200, 245, 255)   # xanh cyan nhạt
        elif protocol == "TLS":
            color = QColor(210, 255, 255)   # xanh ngọc nhạt
        elif protocol == "OTHER":
            color = QColor(235, 235, 235)   # xám nhạt

        if color:
            for col in range(self.table.columnCount()):
                item = self.table.item(row, col)
                if item:
                    item.setBackground(color)
    # ================= HIGH TRAFFIC DETECTION =================
    def detect_high_traffic(self, src_ip):
        """Phát hiện IP gửi quá nhiều gói trong khoảng thời gian ngắn."""
        if not src_ip or src_ip == "N/A":
            return ""

        now = time.time()
        packet_times = self.ip_packet_times[src_ip]

        # Thêm thời điểm hiện tại
        packet_times.append(now)

        # Xóa các packet cũ hơn alert_window (5 giây)
        while packet_times and now - packet_times[0] > self.alert_window:
            packet_times.popleft()

        # Kiểm tra ngưỡng
        if len(packet_times) > self.alert_threshold:
            return "HIGH TRAFFIC"

        return "NORMAL"

    # ================= REFRESH CHART =================
    def refresh_chart(self):
        self.figure.clear()

        ax1 = self.figure.add_subplot(321)  # protocol bar chart
        ax2 = self.figure.add_subplot(322)  # protocol pie chart
        ax3 = self.figure.add_subplot(323)  # top source IP
        ax4 = self.figure.add_subplot(324)  # top destination IP
        ax5 = self.figure.add_subplot(325)  # packets over time
        ax6 = self.figure.add_subplot(326)  # summary

        # ===== 8 protocol chính + màu giống tab Capture =====
        protocol_color_map = {
            "TCP": "#dcffdc",   # QColor(220, 255, 220)
            "UDP": "#ffffdc",   # QColor(255, 255, 220)
            "ICMP": "#dcf0ff",  # QColor(220, 240, 255)
            "ARP": "#ffe6c8",   # QColor(255, 230, 200)
            "DNS": "#ebdcff",   # QColor(235, 220, 255)
            "HTTP": "#ffd2d2",  # QColor(255, 210, 210)
            "TLS": "#d2ffff",   # QColor(210, 255, 255)
            "OTHER": "#ebebeb", # QColor(235, 235, 235)
        }

        ordered_protocols = ["TCP", "UDP", "ICMP", "ARP", "DNS", "HTTP", "TLS", "OTHER"]

        labels = [p for p in ordered_protocols if self.protocol_counter.get(p, 0) > 0]
        values = [self.protocol_counter[p] for p in labels]
        colors = [protocol_color_map[p] for p in labels]

        # === 1. Protocol bar chart ===
        if values:
            ax1.bar(labels, values, color=colors)
            ax1.set_title("Protocol Statistics")
            ax1.set_ylabel("Packets")
            ax1.tick_params(axis='x', rotation=30)

            for i, v in enumerate(values):
                ax1.text(i, v + 0.2, str(v), ha='center', fontsize=9)
        else:
            ax1.text(0.5, 0.5, "No protocol data", ha='center', va='center', fontsize=12)
            ax1.set_title("Protocol Statistics")

        # === 2. Protocol pie chart ===
        # === 2. Protocol pie chart ===
        if values:
            wedges, texts = ax2.pie(
                values,
                startangle=90,
                counterclock=False,
                colors=colors,
                wedgeprops={"width": 0.45, "edgecolor": "white", "linewidth": 2},
                textprops={"fontsize": 9}
            )

            total = sum(values)

            ax2.text(
                0, 0,
                f"Total\n{total}",
                ha="center", va="center",
                fontsize=11, fontweight="bold"
            )

            legend_labels = [
                f"{name}: {self.protocol_counter[name]} ({self.protocol_counter[name] / total * 100:.1f}%)"
                for name in labels
            ]

            ax2.legend(
                wedges,
                legend_labels,
                title="Legend",
                loc="center left",
                bbox_to_anchor=(1.0, 0.5),
                fontsize=9,
                title_fontsize=10
            )

            ax2.set_title("Protocol Distribution")
            ax2.axis("equal")
        else:
            ax2.text(0.5, 0.5, "No data", ha='center', va='center', fontsize=12)
            ax2.set_title("Protocol Distribution")
            ax2.axis("equal")

        # === 3. Top Source IP ===
        top_src = self.src_ip_counter.most_common(5)
        if top_src:
            src_labels = [ip for ip, count in reversed(top_src)]
            src_values = [count for ip, count in reversed(top_src)]
            ax3.barh(src_labels, src_values)
            ax3.set_title("Top Source IP")
            ax3.set_xlabel("Packets")
        else:
            ax3.text(0.5, 0.5, "No source IP data", ha='center', va='center', fontsize=12)
            ax3.set_title("Top Source IP")

        # === 4. Top Destination IP ===
        top_dst = self.dst_ip_counter.most_common(5)
        if top_dst:
            dst_labels = [ip for ip, count in reversed(top_dst)]
            dst_values = [count for ip, count in reversed(top_dst)]
            ax4.barh(dst_labels, dst_values)
            ax4.set_title("Top Destination IP")
            ax4.set_xlabel("Packets")
        else:
            ax4.text(0.5, 0.5, "No destination IP data", ha='center', va='center', fontsize=12)
            ax4.set_title("Top Destination IP")

        # === 5. Packets Over Time ===
        if self.time_counter:
            sorted_times = sorted(self.time_counter.items())
            sorted_times = sorted_times[-20:]   # chỉ lấy 20 mốc gần nhất

            time_values = [count for t, count in sorted_times]
            time_positions = [t for t, count in sorted_times]
            time_labels = [f"{t}s" for t, count in sorted_times]

            ax5.plot(time_positions, time_values, marker='o')
            ax5.set_title("Packets Over Time")
            ax5.set_ylabel("Packets")
            ax5.set_xlabel("Time from start")

            # Chỉ hiện cách 2 nhãn một lần
            step = max(1, len(time_positions) // 6)
            show_positions = time_positions[::step]
            show_labels = time_labels[::step]

            ax5.set_xticks(show_positions)
            ax5.set_xticklabels(show_labels, rotation=0)
        else:
            ax5.text(0.5, 0.5, "No time data", ha='center', va='center', fontsize=12)
            ax5.set_title("Packets Over Time")

        # === 6. Summary ===
        top_protocols = [(p, self.protocol_counter[p]) for p in ordered_protocols if self.protocol_counter.get(p, 0) > 0]
        proto_text = "\n".join([f"{name}: {count}" for name, count in top_protocols]) if top_protocols else "No protocol data"

        ax6.axis("off")
        ax6.text(
            0.02, 0.95,
            f"Summary\n\n"
            f"Total Packets: {self.total_packets}\n"
            f"Unique Protocols: {len([p for p in ordered_protocols if self.protocol_counter.get(p, 0) > 0])}\n\n"
            f"Protocols:\n{proto_text}\n\n"
            f"Unique Source IPs: {len(self.src_ip_counter)}\n"
            f"Unique Destination IPs: {len(self.dst_ip_counter)}",
            va='top',
            fontsize=11
        )

        self.figure.tight_layout()
        self.canvas.draw()
    # ================= SHOW DETAILS =================
    def show_details(self, row, column):
        item = self.table.item(row, 0)
        if not item:
            return
            
        real_index = item.data(Qt.UserRole)
        if real_index is None:
            try:
                real_index = int(item.text())
            except ValueError:
                return

        if real_index < 0 or real_index >= len(self.packets):
            return

        pkt = self.packets[real_index]

        self.details.clear()

        for layer, fields in pkt["details"].items():
            parent = QTreeWidgetItem([layer])
            self.details.addTopLevelItem(parent)

            for k, v in fields.items():
                child = QTreeWidgetItem([f"{k}: {v}"])
                parent.addChild(child)

        self.details.expandAll()

        raw_hex = pkt.get("raw", "")

        try:
            raw_bytes = bytes.fromhex(raw_hex)
            self.raw.setText(format_hex(raw_bytes))
        except ValueError:
            self.raw.setText(raw_hex)
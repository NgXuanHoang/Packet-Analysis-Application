"""
Chat Widget — Giao diện chat tích hợp vào PyQt5.

Gồm:
    - Vùng hiển thị tin nhắn (QTextBrowser)
    - Ô nhập + nút gửi
    - QThread để gọi API không block UI
"""

import re

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QTextBrowser, QLineEdit, QPushButton, QLabel, QTextEdit
)
from PyQt5.QtCore import QThread, pyqtSignal, Qt
from PyQt5.QtGui import QFont, QColor

from ai.ai_agent import AIAgent


# =====================================================================
#  WORKER THREAD — gọi API trên background thread
# =====================================================================

class ChatInput(QTextEdit):
    """Ô nhập chữ cho chat, hỗ trợ expand chiều cao và gửi bằng Enter."""
    returnPressed = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(38)
        self.textChanged.connect(self.adjust_height)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)

    def adjust_height(self):
        doc_height = int(self.document().size().height())
        # Padding khoảng 10px
        new_height = doc_height + 10
        if new_height > 120:
            new_height = 120
        elif new_height < 38:
            new_height = 38
        self.setFixedHeight(new_height)

    def keyPressEvent(self, event):
        # Enter thì gửi. Shift+Enter thì xuống dòng bình thường
        if event.key() == Qt.Key_Return and not event.modifiers() & Qt.ShiftModifier:
            self.returnPressed.emit()
            event.accept()
        else:
            super().keyPressEvent(event)


# =====================================================================
#  WORKER THREAD — gọi API trên background thread
# =====================================================================

class AIWorker(QThread):
    """Thread riêng để gọi API, tránh block UI."""

    finished = pyqtSignal(str)   # trả response text
    error = pyqtSignal(str)      # trả error message

    def __init__(self, agent: AIAgent, query: str, packets: list):
        super().__init__()
        self.agent = agent
        self.query = query
        self.packets = packets

    def run(self):
        try:
            response = self.agent.ask(self.query, self.packets)
            self.finished.emit(response)
        except Exception as e:
            self.error.emit(str(e))


# =====================================================================
#  CHAT WIDGET — giao diện chat panel
# =====================================================================

class ChatWidget(QWidget):
    """Widget chat tích hợp vào MainWindow."""

    filter_requested = pyqtSignal(str)  # signal gửi lệnh filter về MainWindow

    def __init__(self, parent=None):
        super().__init__(parent)
        self.agent = AIAgent()
        self._get_packets = lambda: []  # callable trả về packets hiện tại
        self.worker = None

        self._init_ui()

    def set_packets_ref(self, packets_getter):
        """Gán callable trả về danh sách packets hiện tại.
        Ví dụ: chat_widget.set_packets_ref(lambda: self.packets)
        """
        self._get_packets = packets_getter

    def _init_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(4, 4, 4, 4)

        # ===== Header =====
        header = QLabel("ChatAnalyze")
        header.setFont(QFont("Segoe UI", 11, QFont.Bold))
        header.setAlignment(Qt.AlignCenter)
        header.setStyleSheet(
            "padding: 6px; "
            "background-color: #2d5aa0; "
            "color: white; "
            "border-radius: 4px;"
        )
        layout.addWidget(header)

        # ===== Chat Display =====
        self.chat_display = QTextBrowser()
        self.chat_display.setOpenExternalLinks(False)
        self.chat_display.setFont(QFont("Segoe UI", 10))
        self.chat_display.setStyleSheet(
            "QTextBrowser {"
            "  background-color: #f0f0f0;"
            "  color: #111111;"
            "  border: 1px solid #cccccc;"
            "  border-radius: 4px;"
            "  padding: 8px;"
            "}"
        )

        # Tin nhắn chào mừng
        self.chat_display.setHtml(
            '<p style="color: #555555; font-style: italic;">'
            'Xin chào! Tôi là trợ lý phân tích mạng ChatAnalyze.<br>'
            'Bạn có thể bắt gói tin (Start) hoặc mở file PCAP (Open), '
            'sau đó hỏi tôi bất kỳ điều gì về dữ liệu mạng.'
            '</p>'
        )

        # ===== Input Area =====
        input_layout = QHBoxLayout()

        self.input_field = ChatInput()
        self.input_field.setFont(QFont("Segoe UI", 10))
        self.input_field.setStyleSheet(
            "QTextEdit {"
            "  background-color: #ffffff;"
            "  color: #111111;"
            "  border: 1px solid #cccccc;"
            "  border-radius: 4px;"
            "  padding: 8px;"
            "}"
            "QTextEdit:focus {"
            "  border: 1px solid #2d5aa0;"
            "}"
        )
        self.input_field.returnPressed.connect(self.send_message)
        input_layout.addWidget(self.input_field)

        self.send_btn = QPushButton("Gửi")
        self.send_btn.setFont(QFont("Segoe UI", 10, QFont.Bold))
        self.send_btn.setFixedWidth(60)
        self.send_btn.setStyleSheet(
            "QPushButton {"
            "  background-color: #89b4fa;"
            "  color: #111111;"
            "  border: none;"
            "  border-radius: 4px;"
            "  padding: 8px;"
            "}"
            "QPushButton:hover {"
            "  background-color: #74c7ec;"
            "}"
            "QPushButton:disabled {"
            "  background-color: #dddddd;"
            "  color: #888888;"
            "}"
        )
        self.send_btn.clicked.connect(self.send_message)
        input_layout.addWidget(self.send_btn)

        layout.addWidget(self.chat_display, stretch=1)
        layout.addLayout(input_layout)

        # ===== Clear Button =====
        self.clear_btn = QPushButton("🗑 Xóa lịch sử chat")
        self.clear_btn.setStyleSheet(
            "QPushButton {"
            "  background-color: transparent;"
            "  color: #555555;"
            "  border: 1px solid #cccccc;"
            "  border-radius: 4px;"
            "  padding: 4px;"
            "  font-size: 9pt;"
            "}"
            "QPushButton:hover {"
            "  background-color: #e0e0e0;"
            "}"
        )
        self.clear_btn.clicked.connect(self.clear_chat)
        layout.addWidget(self.clear_btn)

        self.setLayout(layout)

    # ================= SEND MESSAGE =================
    def send_message(self):
        query = self.input_field.toPlainText().strip()
        if not query:
            return

        # Chặn gửi khi worker cũ chưa xong
        if self.worker and self.worker.isRunning():
            return

        # Hiển thị câu hỏi
        self._append_message("user", query)
        self.input_field.clear()

        # Kiểm tra packets
        packets = self._get_packets()

        # Disable input khi đang xử lý
        self._set_loading(True)

        # Cleanup worker cũ
        self._cleanup_worker()

        # Chạy trên worker thread
        self.worker = AIWorker(self.agent, query, list(packets))
        self.worker.finished.connect(self._on_response)
        self.worker.error.connect(self._on_error)
        self.worker.start()

    def _cleanup_worker(self):
        """Disconnect signals và chờ worker cũ hoàn thành."""
        worker = self.worker
        if worker is None:
            return
        try:
            worker.finished.disconnect(self._on_response)
            worker.error.disconnect(self._on_error)
        except TypeError:
            pass
        if worker.isRunning():
            worker.wait(3000)  # chờ tối đa 3s để tránh race condition
        self.worker = None

    def _on_response(self, response: str):
        """Callback khi nhận response từ AI."""
        # Detect [FILTER: xxx] command từ AI
        filter_match = re.search(r'\[FILTER:\s*(.+?)\]', response)
        if filter_match:
            filter_text = filter_match.group(1).strip()
            # Xóa tag khỏi text hiển thị
            display_text = re.sub(r'\[FILTER:\s*.+?\]', '', response).strip()
            if display_text:
                self._append_message("assistant", display_text)
            self._append_message("system",
                f"Filter \"{filter_text}\" đã được áp dụng."
            )
            self.filter_requested.emit(filter_text)
        else:
            self._append_message("assistant", response)

        self._set_loading(False)

    def _on_error(self, error: str):
        """Callback khi gặp lỗi."""
        self._append_message("error", f"Lỗi: {error}")
        self._set_loading(False)

    # ================= UI HELPERS =================
    def _set_loading(self, loading: bool):
        """Toggle trạng thái loading."""
        self.input_field.setEnabled(not loading)
        self.send_btn.setEnabled(not loading)
        if loading:
            self.send_btn.setText("...")
        else:
            self.send_btn.setText("Gửi")

    def _append_message(self, role: str, content: str):
        """Thêm tin nhắn vào chat display."""
        # Escape HTML trong content
        content_escaped = (
            content
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\n", "<br>")
        )

        if role == "user":
            html = (
                f'<div style="margin: 8px 0; text-align: right;">'
                f'<span style="background-color: #89b4fa; color: #111111; '
                f'padding: 6px 12px; border-radius: 12px; '
                f'display: inline-block; max-width: 85%; text-align: left;">'
                f'{content_escaped}'
                f'</span></div>'
            )

        elif role == "assistant":
            html = (
                f'<div style="margin: 8px 0;">'
                f'<span style="color: #2d5aa0; font-weight: bold;">ChatAnalyze:</span><br>'
                f'<span style="background-color: #e0e0e0; color: #111111; '
                f'padding: 8px 12px; border-radius: 12px; '
                f'display: inline-block; max-width: 95%; text-align: left;">'
                f'{content_escaped}'
                f'</span></div>'
            )

        elif role == "system":
            html = (
                f'<div style="margin: 6px 0; text-align: center;">'
                f'<span style="background-color: #d5e6ff; color: #1a4a8a; '
                f'padding: 4px 10px; border-radius: 8px; font-size: 9pt;">'
                f'{content_escaped}'
                f'</span></div>'
            )

        elif role == "error":
            html = (
                f'<div style="margin: 8px 0;">'
                f'<span style="color: #f38ba8;">{content_escaped}</span>'
                f'</div>'
            )
        else:
            html = f'<p>{content_escaped}</p>'

        self.chat_display.append(html)

        # Auto-scroll xuống cuối
        scrollbar = self.chat_display.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def clear_chat(self):
        """Xóa lịch sử chat và reset agent."""
        self.agent.clear_history()
        self.chat_display.clear()
        self.chat_display.setHtml(
            '<p style="color: #555555; font-style: italic;">'
            'Đã xóa lịch sử. Hãy hỏi tôi bất kỳ điều gì!</p>'
        )
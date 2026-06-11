"""
AI Agent Module - Bộ não phân tích thông minh.

Gồm 3 phần:
    1. ContextBuilder  - tổng hợp dữ liệu gói tin thành bản tóm tắt text
    2. PromptBuilder   - ghép system prompt + context + câu hỏi
    3. AIAgent         - gọi API và trả kết quả
"""

import logging
from collections import Counter, defaultdict
from datetime import datetime

from ai.config import AI_CONFIG, SYSTEM_PROMPT

logger = logging.getLogger(__name__)


# =====================================================================
#  CONTEXT BUILDER — đọc self.packets[] và tạo bản tóm tắt cho LLM
# =====================================================================

class ContextBuilder:
    """Tổng hợp danh sách packets thành một đoạn text ngắn gọn,
    chứa đủ thông tin để LLM phân tích mà không vượt token limit."""

    def __init__(self, max_packets=200, max_recent=20):
        self.max_packets = max_packets
        self.max_recent = max_recent

    def build(self, packets: list[dict]) -> str:
        """Trả về string context từ danh sách packets."""
        if not packets:
            return "Chưa có dữ liệu gói tin nào được bắt."

        sections = [
            self._overview(packets),
            self._protocol_distribution(packets),
            self._top_talkers(packets),
            self._port_analysis(packets),
            self._ml_summary(packets),
            self._anomaly_hints(packets),
            self._recent_packets(packets),
        ]

        return "\n\n".join(s for s in sections if s)

    # ---------- Tổng quan ----------
    def _overview(self, packets):
        total = len(packets)
        times = [p["summary"]["time"] for p in packets if p.get("summary", {}).get("time")]
        if len(times) >= 2:
            duration = round(max(times) - min(times), 1)
            start = datetime.fromtimestamp(min(times)).strftime("%H:%M:%S")
            end = datetime.fromtimestamp(max(times)).strftime("%H:%M:%S")
            return (
                f"[TỔNG QUAN]\n"
                f"Tổng số gói tin đang phân tích: {total}\n"
                f"Thời gian: {start} → {end} ({duration}s)"
            )
        return f"[TỔNG QUAN]\nTổng số gói tin đang phân tích: {total}"

    # ---------- Phân bổ Protocol ----------
    def _protocol_distribution(self, packets):
        counter = Counter()
        for p in packets:
            proto = p.get("summary", {}).get("protocol", "OTHER")
            counter[proto] += 1

        total = sum(counter.values())
        lines = []
        for proto, count in counter.most_common():
            pct = round(count / total * 100, 1)
            lines.append(f"  {proto}: {count} ({pct}%)")

        return "[PHÂN BỔ GIAO THỨC]\n" + "\n".join(lines)

    # ---------- Top Talkers ----------
    def _top_talkers(self, packets, top_n=5):
        src_counter = Counter()
        dst_counter = Counter()
        for p in packets:
            s = p.get("summary", {})
            src_counter[s.get("src", "")] += 1
            dst_counter[s.get("dst", "")] += 1

        lines = ["[TOP NGUỒN GỬI]"]
        for ip, count in src_counter.most_common(top_n):
            lines.append(f"  {ip}: {count} gói")

        lines.append("\n[TOP ĐÍCH NHẬN]")
        for ip, count in dst_counter.most_common(top_n):
            lines.append(f"  {ip}: {count} gói")

        return "\n".join(lines)

    # ---------- Phân tích Port ----------
    def _port_analysis(self, packets):
        port_counter = Counter()
        for p in packets:
            s = p.get("summary", {})
            proto = s.get("protocol", "")
            info = s.get("info", "")

            # Trích xuất destination port từ info "sport → dport ..."
            if proto in ("TCP", "UDP", "SSH", "HTTP", "HTTPS", "FTP",
                         "SMTP", "DNS", "RDP", "TLS") and "→" in info:
                try:
                    dport = int(info.split("→")[1].strip().split()[0])
                    layer = "TCP" if proto not in ("UDP",) else "UDP"
                    port_counter[f"{layer}/{dport}"] += 1
                except (ValueError, IndexError):
                    pass

        if not port_counter:
            return None

        lines = ["[TOP CỔNG ĐÍCH]"]
        for port, count in port_counter.most_common(10):
            svc = self._port_to_service(port)
            label = f"{port} ({svc})" if svc else port
            lines.append(f"  {label}: {count} gói")

        return "\n".join(lines)

    @staticmethod
    def _port_to_service(port_str):
        """Map port phổ biến sang tên dịch vụ."""
        services = {
            "TCP/22": "SSH", "TCP/23": "Telnet", "TCP/25": "SMTP",
            "TCP/53": "DNS", "UDP/53": "DNS", "TCP/80": "HTTP",
            "TCP/443": "HTTPS", "TCP/3389": "RDP", "TCP/21": "FTP",
            "TCP/3306": "MySQL", "TCP/5432": "PostgreSQL",
            "TCP/8080": "HTTP-Alt", "UDP/67": "DHCP", "UDP/68": "DHCP",
            "TCP/445": "SMB", "TCP/139": "NetBIOS",
        }
        return services.get(port_str, "")

    # ---------- Tổng hợp kết quả ML ----------
    def _ml_summary(self, packets):
        """Tổng hợp kết quả phân loại từ ML model."""
        ml_packets = [
            p for p in packets
            if p.get("ml_prediction") and p["ml_prediction"]["label"] != "BENIGN"
        ]

        if not ml_packets:
            total_ml = sum(1 for p in packets if p.get("ml_prediction"))
            if total_ml > 0:
                return f"[KẾT QUẢ ML]\n  Model đã phân tích {total_ml} gói tin, tất cả được phân loại BENIGN."
            return None

        # Đếm theo loại tấn công
        attack_counts = Counter()
        attack_ips = defaultdict(set)
        attack_confidence = defaultdict(list)

        for p in ml_packets:
            ml = p["ml_prediction"]
            label = ml["label"]
            conf = ml["confidence"]
            src = p.get("summary", {}).get("src", "")

            attack_counts[label] += 1
            attack_ips[label].add(src)
            attack_confidence[label].append(conf)

        total_ml = sum(1 for p in packets if p.get("ml_prediction"))
        lines = [f"[KẾT QUẢ ML — {len(ml_packets)} gói bất thường / {total_ml} tổng]"]

        for label, count in attack_counts.most_common():
            avg_conf = sum(attack_confidence[label]) / len(attack_confidence[label])
            ips = ", ".join(list(attack_ips[label])[:5])
            lines.append(
                f"  ⚠ {label}: {count} gói (confidence TB: {avg_conf:.0%}) — IP: {ips}"
            )

        return "\n".join(lines)

    # ---------- Rule-based: tìm IP đáng ngờ ----------
    @staticmethod
    def _find_layer(details, prefix):
        """Tìm layer bằng prefix, ví dụ 'Transmission Control' cho TCP."""
        for key, val in details.items():
            if key.startswith(prefix):
                return val
        return None

    def _get_flagged_ips(self, packets):
        """Trả về set các IP bị rule-based đánh dấu đáng ngờ.
        Dùng chung cho _anomaly_hints và _recent_packets."""
        flagged = set()

        # 1. Port scan: 1 IP gửi SYN đến >= 5 port khác nhau
        syn_by_src = defaultdict(set)
        for p in packets:
            tcp_info = self._find_layer(p.get("details", {}), "Transmission Control")
            if tcp_info:
                flags = tcp_info.get("Flags", "")
                if "SYN" in flags and "ACK" not in flags:
                    try:
                        dport = int(str(tcp_info.get("Destination Port", "")).split()[0])
                    except (ValueError, IndexError):
                        continue
                    syn_by_src[p.get("summary", {}).get("src", "")].add(dport)

        for ip, ports in syn_by_src.items():
            if ip and len(ports) >= 5:
                flagged.add(ip)

        # 2. Brute-force: >= 10 kết nối đến SSH/FTP/Telnet/RDP
        conn_to_service = defaultdict(lambda: defaultdict(int))
        for p in packets:
            tcp_info = self._find_layer(p.get("details", {}), "Transmission Control")
            if tcp_info:
                try:
                    dport = int(str(tcp_info.get("Destination Port", "")).split()[0])
                except (ValueError, IndexError):
                    continue
                if dport in (22, 23, 21, 3389):
                    conn_to_service[dport][p.get("summary", {}).get("src", "")] += 1

        for port, sources in conn_to_service.items():
            for ip, count in sources.items():
                if ip and count >= 10:
                    flagged.add(ip)

        # 3. ICMP Flood: >= 20 gói ICMP từ 1 IP
        icmp_by_src = Counter()
        for p in packets:
            if p.get("summary", {}).get("protocol") == "ICMP":
                icmp_by_src[p["summary"].get("src", "")] += 1

        for ip, count in icmp_by_src.items():
            if ip and count >= 20:
                flagged.add(ip)

        return flagged

    # ---------- Phát hiện bất thường sơ bộ ----------
    def _anomaly_hints(self, packets):
        """Phát hiện sơ bộ một số pattern đáng ngờ để AI phân tích sâu."""
        hints = []

        # 1. Port scan
        syn_by_src = defaultdict(set)
        for p in packets:
            tcp_info = self._find_layer(p.get("details", {}), "Transmission Control")
            if tcp_info:
                flags = tcp_info.get("Flags", "")
                if "SYN" in flags and "ACK" not in flags:
                    try:
                        dport = int(str(tcp_info.get("Destination Port", "")).split()[0])
                    except (ValueError, IndexError):
                        continue
                    syn_by_src[p.get("summary", {}).get("src", "")].add(dport)

        for ip, ports in syn_by_src.items():
            if ip and len(ports) >= 5:
                hints.append(
                    f"PORT SCAN: IP {ip} gửi SYN đến {len(ports)} "
                    f"port khác nhau: {sorted(list(ports))[:20]}"
                )

        # 2. Brute-force
        conn_to_service = defaultdict(lambda: defaultdict(int))
        for p in packets:
            tcp_info = self._find_layer(p.get("details", {}), "Transmission Control")
            if tcp_info:
                try:
                    dport = int(str(tcp_info.get("Destination Port", "")).split()[0])
                except (ValueError, IndexError):
                    continue
                if dport in (22, 23, 21, 3389):
                    conn_to_service[dport][p.get("summary", {}).get("src", "")] += 1

        for port, sources in conn_to_service.items():
            for ip, count in sources.items():
                if ip and count >= 10:
                    svc = {22: "SSH", 23: "Telnet", 21: "FTP", 3389: "RDP"}.get(port, str(port))
                    hints.append(
                        f"BRUTE-FORCE: IP {ip} tạo {count} kết nối đến {svc} (port {port})"
                    )

        # 3. ICMP Flood
        icmp_by_src = Counter()
        for p in packets:
            if p.get("summary", {}).get("protocol") == "ICMP":
                icmp_by_src[p["summary"].get("src", "")] += 1

        for ip, count in icmp_by_src.items():
            if ip and count >= 20:
                hints.append(f"ICMP FLOOD: IP {ip} gửi {count} gói ICMP")

        if not hints:
            return "[PHÁT HIỆN BẤT THƯỜNG]\n  Không phát hiện pattern đáng ngờ rõ ràng."

        return "[PHÁT HIỆN BẤT THƯỜNG]\n" + "\n".join(f"  - {h}" for h in hints)

    # ---------- Gói tin chi tiết (ưu tiên đáng ngờ) ----------
    def _recent_packets(self, packets):
        """Ưu tiên gói đáng ngờ (ML hoặc rule-based), bổ sung BENIGN để so sánh."""
        max_benign_context = 10

        # Lấy IP bị rule-based flag
        flagged_ips = self._get_flagged_ips(packets)

        # Phân loại: suspicious = ML bất thường HOẶC IP bị rule-based flag
        suspicious = []
        clean = []
        for p in packets:
            ml = p.get("ml_prediction")
            src = p.get("summary", {}).get("src", "")
            dst = p.get("summary", {}).get("dst", "")

            is_ml_suspicious = ml and ml.get("label") and ml["label"] != "BENIGN"
            is_rule_flagged = src in flagged_ips or dst in flagged_ips

            if is_ml_suspicious or is_rule_flagged:
                suspicious.append(p)
            else:
                clean.append(p)

        # Lấy gói đáng ngờ (ưu tiên, giới hạn max_recent)
        total_suspicious = len(suspicious)
        selected_suspicious = suspicious[-self.max_recent:]

        # Bổ sung BENIGN gần nhất để chatbot có ngữ cảnh so sánh
        remaining = self.max_recent - len(selected_suspicious)
        n_benign = min(remaining, max_benign_context) if remaining > 0 else 0
        selected_clean = clean[-n_benign:] if n_benign > 0 else []

        selected = selected_clean + selected_suspicious
        if not selected:
            return None

        # Sắp xếp theo thời gian
        selected.sort(key=lambda p: p.get("summary", {}).get("time", 0))

        n_sus = len(selected_suspicious)
        n_cln = len(selected_clean)
        header = f"[GÓI TIN CHI TIẾT — {n_sus} đáng ngờ + {n_cln} BENIGN tham chiếu]"

        # Thông báo nếu bị cắt bớt
        if total_suspicious > self.max_recent:
            header += (
                f"\n  Lưu ý: Có tổng cộng {total_suspicious} gói tin đáng ngờ, "
                f"đây là {self.max_recent} gói đại diện gần nhất."
            )

        lines = [header]
        for p in selected:
            s = p.get("summary", {})
            t = datetime.fromtimestamp(s.get("time", 0)).strftime("%H:%M:%S")
            ml = p.get("ml_prediction")
            src = s.get("src", "")

            # Tag nguồn phát hiện
            tags = []
            if ml and ml.get("label") and ml["label"] != "BENIGN":
                tags.append(f"ML:{ml['label']} {ml['confidence']:.0%}")
            if src in flagged_ips:
                tags.append("RULE-FLAGGED")
            tag_str = f" [{', '.join(tags)}]" if tags else ""

            idx = p.get("_index", "?")
            lines.append(
                f"  #{idx} | {t} | "
                f"{src} → {s.get('dst','')} | "
                f"{s.get('protocol','')} | {s.get('length','')}B | "
                f"{s.get('info','')}{tag_str}"
            )
        return "\n".join(lines)


# =====================================================================
#  PROMPT BUILDER — ghép system + context + câu hỏi thành messages
# =====================================================================

class PromptBuilder:
    """Tạo messages array theo format API từ context và câu hỏi."""

    def __init__(self, system_prompt: str = SYSTEM_PROMPT):
        self.system_prompt = system_prompt

    def build(self, context: str, user_query: str, chat_history: list = None) -> dict:
        """
        Trả về dict chứa system prompt và messages.

        Args:
            context: bản tóm tắt dữ liệu mạng từ ContextBuilder
            user_query: câu hỏi người dùng
            chat_history: lịch sử chat [(role, content), ...]

        Returns:
            {"system": str, "messages": list[dict]}
        """
        messages = []

        # Lịch sử chat (nếu có)
        if chat_history:
            for role, content in chat_history:
                messages.append({"role": role, "content": content})

        # Câu hỏi mới kèm context
        user_message = (
            f"--- DỮ LIỆU MẠNG HIỆN TẠI ---\n{context}\n"
            f"--- HẾT DỮ LIỆU ---\n\n"
            f"Câu hỏi: {user_query}"
        )
        messages.append({"role": "user", "content": user_message})

        return {
            "system": self.system_prompt,
            "messages": messages,
        }


# =====================================================================
#  AI AGENT — gọi API và trả kết quả
# =====================================================================

class AIAgent:
    """Agent chính: nhận câu hỏi + packets → trả câu trả lời."""

    def __init__(self):
        self.context_builder = ContextBuilder(
            max_packets=AI_CONFIG["max_packets_in_context"],
            max_recent=AI_CONFIG["max_recent_packets"],
        )
        self.prompt_builder = PromptBuilder()
        self.chat_history: list[tuple[str, str]] = []
        self._client = None

    def _get_client(self):
        """Lazy init API client."""
        if self._client is None:
            provider = AI_CONFIG["provider"]

            if provider == "gemini":
                try:
                    from google import genai
                    self._client = genai.Client(api_key=AI_CONFIG["api_key"])
                except ImportError:
                    raise ImportError(
                        "Cần cài thư viện google-genai: pip install google-genai"
                    )

            elif provider == "anthropic":
                try:
                    from anthropic import Anthropic
                    self._client = Anthropic(api_key=AI_CONFIG["api_key"])
                except ImportError:
                    raise ImportError(
                        "Cần cài thư viện anthropic: pip install anthropic"
                    )

            elif provider == "openai":
                try:
                    from openai import OpenAI
                    self._client = OpenAI(api_key=AI_CONFIG["api_key"])
                except ImportError:
                    raise ImportError(
                        "Cần cài thư viện openai: pip install openai"
                    )
            else:
                raise ValueError(f"Provider không hỗ trợ: {provider}")

        return self._client

    def ask(self, query: str, packets: list[dict]) -> str:
        """
        Gửi câu hỏi đến AI và nhận câu trả lời.

        Args:
            query:   câu hỏi của người dùng
            packets: self.packets từ MainWindow

        Returns:
            str — câu trả lời từ AI
        """
        try:
            # Bước 1: Tổng hợp context
            context = self.context_builder.build(packets)

            # Bước 2: Xây dựng prompt
            prompt = self.prompt_builder.build(
                context=context,
                user_query=query,
                chat_history=self.chat_history[-10:],  # giữ 10 cặp gần nhất
            )

            # Bước 3: Gọi API
            response = self._call_api(prompt)

            # Bước 4: Lưu lịch sử (lưu query gốc + tóm tắt context)
            # Truncate để tránh token quá lớn qua nhiều lượt
            history_query = f"[Context: {len(packets)} packets] {query}"
            history_response = response[:500] + "..." if len(response) > 500 else response
            self.chat_history.append(("user", history_query))
            self.chat_history.append(("assistant", history_response))

            # Giới hạn lịch sử (tránh token quá lớn)
            if len(self.chat_history) > 20:
                self.chat_history = self.chat_history[-20:]

            return response

        except ImportError as e:
            return f"❌ Lỗi thư viện: {e}"
        except Exception as e:
            logger.error(f"AI Agent error: {e}", exc_info=True)
            return f"❌ Lỗi khi gọi AI: {str(e)}"

    def _call_api(self, prompt: dict) -> str:
        """Gọi API theo provider đã cấu hình."""
        client = self._get_client()
        provider = AI_CONFIG["provider"]

        if provider == "gemini":
            from google.genai import types

            # Ghép system prompt vào đầu conversation
            messages = []
            if prompt.get("system"):
                messages.append(
                    types.Content(
                        role="user",
                        parts=[types.Part(text=f"[System Instructions]\n{prompt['system']}")]
                    )
                )
                messages.append(
                    types.Content(
                        role="model",
                        parts=[types.Part(text="Đã hiểu. Tôi sẽ tuân thủ các hướng dẫn trên.")]
                    )
                )

            # Thêm lịch sử chat + câu hỏi mới
            for msg in prompt["messages"]:
                role = "model" if msg["role"] == "assistant" else "user"
                messages.append(
                    types.Content(
                        role=role,
                        parts=[types.Part(text=msg["content"])]
                    )
                )

            response = client.models.generate_content(
                model=AI_CONFIG["model"],
                contents=messages,
                config=types.GenerateContentConfig(
                    max_output_tokens=AI_CONFIG["max_tokens"],
                    temperature=0.7,
                ),
            )
            return response.text

        elif provider == "anthropic":
            response = client.messages.create(
                model=AI_CONFIG["model"],
                max_tokens=AI_CONFIG["max_tokens"],
                system=prompt["system"],
                messages=prompt["messages"],
            )
            return response.content[0].text

        elif provider == "openai":
            messages = [{"role": "system", "content": prompt["system"]}]
            messages.extend(prompt["messages"])

            response = client.chat.completions.create(
                model=AI_CONFIG["model"],
                max_tokens=AI_CONFIG["max_tokens"],
                messages=messages,
            )
            return response.choices[0].message.content

    def clear_history(self):
        """Xóa lịch sử chat."""
        self.chat_history.clear()
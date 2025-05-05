import argparse
from dnslib.server import DNSServer, BaseResolver
from dnslib import RR, QTYPE, A, DNSRecord
import datetime
import base64
import socketio

# Подключение к веб-интерфейсу
sio = socketio.Client()

try:
    sio.connect("http://localhost:5000")
    print("[✓] Подключено к веб-интерфейсу")
except Exception as e:
    print(f"[!] Не удалось подключиться к веб-интерфейсу: {e}")

TARGET_DOMAIN = "myserver.local."
session_data = {}

# 🔍 Простая эвристика для анализа DNS-запроса
def is_suspicious_domain(labels: list[str]) -> list[str]:
    reasons = []
    if len(labels) > 5:
        reasons.append("слишком много меток в запросе")
    for label in labels:
        if len(label) > 30:
            reasons.append(f"подозрительно длинная метка: '{label[:10]}...'")
        if all(c.isalnum() or c in "-_" for c in label) and not label.isalpha():
            reasons.append(f"возможная base64 метка: '{label[:10]}...'")
    return reasons

def log_suspicious_query(ip: str, domain: str, reasons: list[str]):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[⚠️  {timestamp}] Обнаружен подозрительный запрос от {ip}: {domain}")
    for r in reasons:
        print(f"   └─ Причина: {r}")
    
    try:
        sio.emit("suspicious_log", {
            "ip": ip,
            "timestamp": timestamp,
            "domain": domain,
            "reasons": reasons
        })
    except Exception as e:
        print(f"[!] Ошибка отправки подозрительного запроса в веб: {e}")

class StealthDNSResolver(BaseResolver):
    def __init__(self, mode='full'):
        self.mode = mode

    def resolve(self, request, handler):
        qname = request.q.qname
        domain_str = str(qname)
        client_ip = handler.client_address[0]
        labels = domain_str.strip('.').split('.')

        # 🔍 Детектирование
        if self.mode in ('full', 'detect'):
            reasons = is_suspicious_domain(labels)
            if reasons:
                log_suspicious_query(client_ip, domain_str, reasons)

        # ✅ Расшифровка
        if self.mode in ('full', 'passive') and domain_str.endswith(TARGET_DOMAIN):
            try:
                subdomain = domain_str.replace("." + TARGET_DOMAIN, "").strip(".")
                parts = subdomain.split(".")

                *data_chunks, index_str, total_str, session_id = parts
                encoded_part = ''.join(data_chunks)
                index = int(index_str)
                total = int(total_str)

                if session_id not in session_data:
                    session_data[session_id] = {}
                session_data[session_id][index] = encoded_part

                fragments = session_data[session_id]
                if len(fragments) == total:
                    full_encoded = ''.join(fragments[i] for i in sorted(fragments))
                    padding = len(full_encoded) % 4
                    if padding != 0:
                        full_encoded += "=" * (4 - padding)
                    decoded = base64.urlsafe_b64decode(full_encoded.encode()).decode()
                    print(f"\n✅ [Сессия {session_id}] Расшифровано сообщение:\n{decoded}\n")
                    try:
                        sio.emit("new_message", f"[{session_id}] {decoded}")
                    except Exception as e:
                        print(f"[!] Ошибка отправки сообщения в веб: {e}")
                    del session_data[session_id]
            except Exception as e:
                print(f"[!] Ошибка разбора: {e}")

        # Ответ-заглушка
        reply = request.reply()
        reply.add_answer(RR(rname=qname, rtype=QTYPE.A, rclass=1, ttl=60, rdata=A("127.0.0.1")))
        return reply


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DNS-сервер со скрытым каналом")
    parser.add_argument('--mode', choices=['full', 'passive', 'detect'], default='full', help="Режим работы сервера")
    args = parser.parse_args()

    print(f"[*] Запуск DNS-сервера в режиме: {args.mode}")
    resolver = StealthDNSResolver(mode=args.mode)
    server = DNSServer(resolver, port=53535, address="0.0.0.0", tcp=False)
    print("[*] DNS-сервер запущен на 0.0.0.0:53535")
    server.start()

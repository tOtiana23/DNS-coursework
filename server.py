from dnslib.server import DNSServer, BaseResolver
from dnslib import RR, QTYPE, A, DNSRecord
import datetime
import base64

TARGET_DOMAIN = "myserver.local."
session_data = {}

class StealthDNSResolver(BaseResolver):
    def resolve(self, request, handler):
        qname = request.q.qname
        domain_str = str(qname)

        if domain_str.endswith(TARGET_DOMAIN):
            subdomain = domain_str.replace("." + TARGET_DOMAIN, "").strip(".")
            labels = subdomain.split(".")
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{timestamp}] Получен фрагмент: {labels}")

            try:
                *data_chunks, index_str, total_str, session_id = labels
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
                    del session_data[session_id]
            except Exception as e:
                print(f"[!] Ошибка разбора: {e}")

        # Заглушечный ответ — просто чтобы не падало
        reply = request.reply()
        reply.add_answer(RR(rname=qname, rtype=QTYPE.A, rclass=1, ttl=60, rdata=A("127.0.0.1")))
        return reply


if __name__ == "__main__":
    resolver = StealthDNSResolver()
    server = DNSServer(resolver, port=53535, address="0.0.0.0", tcp=False)
    print("[*] DNS-сервер запущен на 0.0.0.0:53535 (с расшифровкой)")
    server.start()

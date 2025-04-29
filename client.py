import base64
import dns.resolver
import uuid

MAX_LABEL_LENGTH = 63
SAFE_LABEL_CHUNK = 50  # безопасный размер одной метки

def encode_data(data: str) -> list[str]:
    """
    Функция принимает строку, кодирует её в формат Base64 
    и разбивает результат на фрагменты фиксированной длины (MAX_LABEL_LENGTH), 
    что позволяет использовать их в качестве частей DNS-имен.

    Аргументы:
    data (str): Входная строка, которую необходимо закодировать.

    Возвращает:
    list[str]: Список строк, представляющих закодированные фрагменты.
    """
    
    encoded = base64.urlsafe_b64encode(data.encode()).decode() # Переводим строку в base64
    parts = [encoded[i:i+MAX_LABEL_LENGTH] for i in range(0, len(encoded), MAX_LABEL_LENGTH)] # Разбиваем на фрагменты
    return parts

def chunk_label(label: str) -> list[str]:
    """
    Делит длинный фрагмент на несколько меток DNS, каждая ≤ SAFE_LABEL_CHUNK.
    """
    return [label[i:i+SAFE_LABEL_CHUNK] for i in range(0, len(label), SAFE_LABEL_CHUNK)]

def send_dns_query(label_chunks: list[str], domain: str):
    """
    Формирует полное доменное имя и отправляет запрос типа 'A' к локальному DNS-серверу 
    имитируя стандартный запрос на разрешение доменного имени в IP-адрес.

    Аргументы:
    #! subdomain (str): Поддомен, содержащий часть закодированных данных.
    domain (str): Доменное имя, к которому относится поддомен.

    Возвращает:
    None: Выводит результаты в консоль, но не возвращает значения.
    
    Исключения:
    При возникновении ошибок во время запроса, они перехватываются и выводятся в консоль.
    """
    full_name = ".".join(label_chunks + [domain]) # Формируем полное доменное имя
    try:
        resolver = dns.resolver.Resolver() # Создаем объект для отправки DNS запросов
        resolver.nameservers = ['127.0.0.1'] # Указываем локальный адрес сервера, который должен обработать запрос
        resolver.port = 53535 # Порт, на котором ожидается ответ от DNS-сервера
        resolver.resolve(full_name, 'A') # Отправляем запрос на разрешение полного доменного имени с типом записи 'A' (IPv4-адреса)
        print(f"[+] Sent: {full_name}") # Логируем успешную отправку
    except Exception as e:
        print(f"[!] Error for {full_name}: {e}") # Логируем ошибку, если она возникла

def send_data_via_dns(data: str, target_domain: str):
    """
    Отправляет данные через DNS-запросы, разбивая их на части и кодируя в base64.
    
    Параметры:
    data (str): Строка данных, которые необходимо отправить.
    target_domain (str): Целевой домен, на который будут отправлены DNS-запросы.
    """
    session_id = uuid.uuid4().hex[:6]
    parts = encode_data(data)
    total_parts = len(parts)
    for i, part in enumerate(parts):
        part_chunks = chunk_label(part)
        label_chunks = part_chunks + [str(i), str(total_parts), session_id]
        send_dns_query(label_chunks, target_domain)

if __name__ == "__main__":
    message = "Каждый фрагмент собирался сервером в словарь по session_id и индексу. После получения всех фрагментов выполнялась проверка полноты, восстанавливался порядок, и производилось декодирование полного сообщения. Дополнительно реализована коррекция длины строки для восстановления правильной кодировки Base64."
    target = "myserver.local"
    send_data_via_dns(message, target)

import socket
import ipaddress
import pandas as pd
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import time

def is_valid_subnet(subnet):
    """Проверяет, является ли подсеть допустимой."""
    try:
        ipaddress.ip_network(subnet)
        return True
    except ValueError:
        return False

def is_valid_ports(ports_input):
    """Проверяет, являются ли порты допустимыми."""
    ports = ports_input.split(",")
    for port in ports:
        try:
            num = int(port.strip())
            if num < 1 or num > 65535:
                return False
        except ValueError:
            return False
    return True

def get_subnet():
    """Запрашивает от пользователя подсеть и проверяет её валидность."""
    while True:
        subnet = input("Введите подсеть (например, 192.168.1.0/24): ")
        if is_valid_subnet(subnet):
            return subnet
        print("Неверный формат подсети. Попробуйте еще раз.")

def get_ports():
    """Запрашивает у пользователя порты и проверяет их валидность."""
    default_ports = [22, 3389, 5985, 5986, 445]
    while True:
        ports_input = input("Введите порты для сканирования через запятую (например, 22,3389,5985,5986,445), или нажмите Enter для использования портов по умолчанию: ")
        if ports_input.strip() == "":  # Если пользователь нажал Enter
            return default_ports  # Порты по умолчанию
        elif is_valid_ports(ports_input):
            return [int(port.strip()) for port in ports_input.split(",")]
        print("Неверный формат портов. Убедитесь, что порты находятся в диапазоне от 1 до 65535.")

def scan_port(ip, port):
    """Функция для сканирования одного порта на одном IP-адресе."""
    status = "Закрыт"
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)  # Установка таймаута меньше для быстрого сканирования
        if sock.connect_ex((str(ip), port)) == 0:
            status = "Открыт"
    return str(ip), port, status

def scan_ports(subnet, ports, total_ips, max_workers):
    results = []
    net = ipaddress.ip_network(subnet)

    start_time = time.time()  # Начальное время
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {
            executor.submit(scan_port, ip, port): (str(ip), port) 
            for ip in net.hosts() 
            for port in ports
        }

        for index, future in enumerate(as_completed(future_to_port)):
            ip, port, status = future.result()
            if status == "Открыт":
               results.append({"IP-адрес": ip, "Порт": port, "Статус порта": status})

            # Обновляем статус
            elapsed_time = time.time() - start_time
            update_scan_status(index + 1, total_ips, elapsed_time)

    return results

def update_scan_status(completed, total, elapsed_time):
    """Обновление статуса сканирования."""
    estimated_time = (elapsed_time / completed) * (total - completed) if completed > 0 else 0
    estimated_time_str = time.strftime("%H:%M:%S", time.gmtime(estimated_time))
    print(f"\rСканировано {completed}/{total} | Ожидаемое время до завершения: {estimated_time_str} | Нажмите Enter для обновления статуса...", end='')

def monitor_status_thread(total):
    """Поток для мониторинга статуса по нажатию Enter."""
    while True:
        input()  # Ждем, пока пользователь нажмет Enter
        update_scan_status(total, total, 0)  # передаем 0 для elapsed_time, так как оно не актуально

def save_to_csv(results, filename):
    """Сохраняем результаты в CSV-файл."""
    df = pd.DataFrame(results)
    df.to_csv(filename, index=False, encoding='utf-8')
if __name__ == "__main__":
    subnet = get_subnet()
    ports = get_ports()
    while True:
        try:
            max_workers = int(input("Введите количество потоков (по умолчанию 100): ") or 100)
            if max_workers < 1:
                raise ValueError
            break
        except ValueError:
            print("Пожалуйста, введите положительное целое число.")
    total_ips = sum(1 for _ in ipaddress.ip_network(subnet).hosts()) * len(ports)
    # Запускаем поток для мониторинга статуса
    status_thread = threading.Thread(target=monitor_status_thread, args=(total_ips,), daemon=True)
    status_thread.start()
    # Сканируем порты и получаем результаты
    results = scan_ports(subnet, ports, total_ips, max_workers)
    # Сохраняем результаты в CSV файл
    output_file = "scan_results.csv"
    save_to_csv(results, output_file)
    print(f"\nРезультаты сканирования сохранены в файл: {output_file}")
import json
import time
import mmh3
from collections import defaultdict
from math import log2

class HyperLogLog:
    def __init__(self, b=14):  # Оптимальне значення b для точності
        self.b = b
        self.m = 1 << b
        self.registers = [0] * self.m

    def add(self, item):
        hash_val = mmh3.hash(item, signed=False)
        index = hash_val & (self.m - 1)
        w = hash_val >> self.b
        self.registers[index] = max(self.registers[index], self._rho(w))

    def count(self):
        alpha = 0.7213 / (1 + 1.079 / self.m)
        Z = sum(2.0 ** -r for r in self.registers)
        E = alpha * self.m * self.m / Z
        return int(E)

    def _rho(self, w):
        """Рахує позицію першого встановленого біта (від 1, а не 0)."""
        if w == 0:
            return 1
        return log2(w & -w) + 1

def load_ips_from_log(file_path):
    """Завантажує IP-адреси з лог-файлу."""
    ip_addresses = []
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            for line in file:
                try:
                    log_entry = json.loads(line)
                    ip = log_entry.get("remote_addr")
                    if ip:
                        ip_addresses.append(ip)
                except json.JSONDecodeError:
                    continue  # Пропускаємо некоректні рядки
    except FileNotFoundError:
        print(f"Файл {file_path} не знайдено.")
    return ip_addresses

def count_unique_ips_set(ip_list):
    """Підраховує унікальні IP-адреси за допомогою множини (set)."""
    return len(set(ip_list))

def count_unique_ips_hyperloglog(ip_list):
    """Підраховує унікальні IP-адреси за допомогою HyperLogLog."""
    hll = HyperLogLog()
    for ip in ip_list:
        hll.add(ip)
    return hll.count()

if __name__ == "__main__":
    log_file = "lms-stage-access.log"
    ips = load_ips_from_log(log_file)
    if not ips:
        print("Не вдалося завантажити IP-адреси.")
    else:
        # Підрахунок за допомогою set
        start_time = time.time()
        exact_count = count_unique_ips_set(ips)
        exact_time = time.time() - start_time

        # Підрахунок за допомогою HyperLogLog
        start_time = time.time()
        approx_count = count_unique_ips_hyperloglog(ips)
        approx_time = time.time() - start_time

        # Виведення результатів
        print(f"{'Метод':<25}{'Точний підрахунок':<20}{'HyperLogLog':<20}")
        print(f"{'Унікальні елементи':<25}{exact_count:<20}{approx_count:<20}")
        print(f"{'Час виконання (сек.)':<25}{exact_time:<20.6f}{approx_time:<20.6f}")

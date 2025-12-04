import os
import sys
import time
import threading
import requests
import json
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP
from colorama import Fore, Back
import psutil
print("""


⠀⠀⠀⢠⣾⣷⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⣰⣿⣿⣿⣿⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⢰⣿⣿⣿⣿⣿⣿⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣤⣄⣀⣀⣤⣤⣶⣾⣿⣿⣿⡷
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠁
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠁⠀
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠏⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠏⠀⠀⠀⠀
⣿⣿⣿⡇⠀⡾⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠁⠀⠀⠀⠀⠀
⣿⣿⣿⣧⡀⠁⣀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠉⢹⠉⠙⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣀⠀⣀⣼⣿⣿⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠛⠀⠤⢀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⠿⣿⣿⣿⣿⣿⣿⣿⠿⠋⢃⠈⠢⡁⠒⠄⡀⠈⠁⠀⠀⠀⠀⠀⠀⠀
⣿⣿⠟⠁⠀⠀⠈⠉⠉⠁⠀⠀⠀⠀⠈⠆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀


""")

def log_event(message):
    log_folder = "src"
    os.makedirs(log_folder, exist_ok=True)
    timestamp = time.strftime("%Y-%m-%d_%H-%M-%S", time.localtime())
    log_file = os.path.join(log_folder, f"log_{timestamp}.txt")
    with open(log_file, "a", encoding="utf-8") as file:
        file.write(str(message) + "\n")
    print(f"[{info}]: Log kaydedildi → {log_file}")

def log_blacklist(ip):
    log_folder = "src"
    os.makedirs(log_folder, exist_ok=True)
    blacklist_file = os.path.join(log_folder, "blacklist.txt")
    with open(blacklist_file, "a", encoding="utf-8") as file:
        file.write(str(ip) + "\n")
    print(f"{warning}: IP blacklist'e eklendi → {blacklist_file}")
    
def log_error(err):
    log_folder = "srcerr"
    os.makedirs(log_folder, exist_ok=True)
    error_file = os.path.join(log_folder, "error.log")
    with open(error_file, "a", encoding="utf-8") as file:
        file.write(str(err) + "\n")
    print(f"[{error}]: Error Log saved {error_file}")
 
import numpy as np
import random

def sts():

    traffic = np.array([random.randint(50, 60) for _ in range(70)] + [random.randint(500, 600) for _ in range(80)])
    
    
    THRESHOLD_TEST = 200
    detections = np.array([1 if v > THRESHOLD_TEST else 0 for v in traffic])
    
    
    mean = np.mean(traffic[:70]) 
    std = np.std(traffic[:70])
    
    print("\n--- İstatistiksel Analiz Sonuçları ---")
    print(f"Normal Trafik Ortalaması: {round(mean, 2)}")
    print(f"Threshold Tespiti (Örnek): {np.sum(detections)} adet saldırı tespit edildi.")
    print("------------------------------------\n")

#
def ps():
    ram = psutil.virtual_memory()
    ram_used_gb = round(ram.used / (1024**3), 2)
    ram_percent = ram.percent
    
    p = f"RAM KULLANIMI: {ram_used_gb} GB"
    r = f"RAM YÜZDESİ (%): {ram_percent}"
    
    log_folder = "power"
    os.makedirs(log_folder, exist_ok=True)
    error_file = os.path.join(log_folder, "power.log")
    with open(error_file, "a", encoding="utf-8") as file:
        file.write(p + "\n")
        file.write(r + "\n")
        
    print(f"[{info}] {p}")
    print(f"[{info}] {r}")

def is_nimda_worm(packet, port=80):
    if packet.haslayer(TCP) and packet[TCP].dport == port:
        
        payload = bytes(packet[TCP].payload)
        
        return b"GET /script/root.py" in payload
    return False


def ban_ip(ip):

    print(f"[{warming}] SAHTE ENGELLEME: {ip} adresli trafiğin işlenmesi durduruldu (Ağ seviyesinde engelleme iptables/nftables gerektirir).")
    log_blacklist(ip)
THRESHOLD = 40  
info = Fore.GREEN + "info" + Fore.RESET
warning = Fore.RED + "WARNING" + Fore.RESET
error = Fore.RED + "error" + Fore.RESET
tig = "[" + Fore.GREEN + "=" * 100 + Fore.RESET + "]"
packet_count = defaultdict(int)
start_time = [time.time()]
blocked_ip = set()
blacklist = set() 
def packet_callback(packet):
    global packet_count, start_time, blocked_ip, blacklist
    
    if IP in packet:
        src_ip = packet[IP].src

        if src_ip in blocked_ip:
            print(f"[{warning}] DROP: Engellenmiş IP'den gelen paket → {src_ip}")
            return
        
        
        if src_ip in blacklist:
            print(f"[{warning}] BLACKLIST: Kara listedeki IP'den paket → {src_ip}")
            threading.Thread(target=ban_ip, args=(src_ip,)).start()
            blocked_ip.add(src_ip)
            return

        
        packet_count[src_ip] += 1
        current_time = time.time()
        time_interval = current_time - start_time[0]
        
        
        if time_interval >= 1:
            
            threading.Thread(target=analyze_and_reset, args=(current_time, time_interval)).start()

def analyze_and_reset(current_time, time_interval):
    global packet_count, start_time, blocked_ip, THRESHOLD
    
 
    
    for ip, count in list(packet_count.items()):
        packet_rate = count / time_interval
        
        if packet_rate > THRESHOLD and ip not in blocked_ip:
            
            print("["+"="*20+"]")
            print(f"[{warning}] ŞÜPHELİ TRAFİK: IP={ip}, Paket Hızı={round(packet_rate, 2)} pps")
            
            
            url = f"http://ipinfo.io/{ip}/json" 
            try:
                response = requests.get(url, timeout=3)
                data = response.json()
                print(f"[{info}] Target Lokasyon: {data.get('city', 'Bilinmiyor')}, {data.get('country', 'Bilinmiyor')}")
            except Exception as e:
                log_error(f"GeoIP Hatası: {e}")

            
            threading.Thread(target=ban_ip, args=(ip,)).start()
            blocked_ip.add(ip)
            
            log_event(f"Tespitedilen Saldırı: {ip} | Hız: {round(packet_rate, 2)} pps")

  

    
    packet_count.clear()
    start_time[0] = current_time
    
if __name__ == "__main__":
    
    print(Back.WHITE + """Caty""" + Back.RESET)
    print(f"[{info}] Cats protect you from rat")
    print(tig)
    
    
    if os.geteuid() != 0:
        print(f"[{error}] YETKİ HATASI: Bu programın çalışması için root (yönetici) yetkisi gereklidir.")
        print(tig)
        sys.exit()

    log_error("[error]Start")
    log_blacklist("[info]Start")
    log_event("[info]Start")
    
    
    threading.Thread(target=ps).start()
    
    print(f"[{info}] EŞİK (THRESHOLD): {THRESHOLD} paket/saniye")
    print(f"[{info}] Ağ trafiği izleniyor...")
    
    try:
        
        sniff(filter="ip", prn=packet_callback, store=0)
        
    except KeyboardInterrupt:
        print(f"\n[{info}] Program kullanıcı tarafından durduruldu.")
    except Exception as e:
        log_error(f"Ana Hata: {e}")
        print(f"[{error}] Beklenmedik Hata: {e}")
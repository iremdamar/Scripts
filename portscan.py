#!/usr/bin/env python3
import socket
import concurrent.futures
import ipaddress
import datetime
import sys
import os

# Terminal renkleri
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

# Yaygın portlar ve basit servis eşlemesi
COMMON_PORTS = {
    20: 'FTP Data',
    21: 'FTP Control',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    139: 'NetBIOS',
    143: 'IMAP',
    443: 'HTTPS',
    445: 'SMB',
    3389: 'RDP',
    5900: 'VNC',
    8080: 'HTTP Proxy'
}

def parse_ip_range(ip_range):
    if '-' in ip_range:
        try:
            start_ip, end_ip = ip_range.split('-')
            start_ip = ipaddress.IPv4Address(start_ip.strip())
            end_ip = ipaddress.IPv4Address(end_ip.strip())
            if end_ip < start_ip:
                print(f"{Colors.FAIL}Bitiş IP'si başlangıç IP'sinden küçük olamaz.{Colors.ENDC}")
                return None
            cur = start_ip
            ips = []
            while cur <= end_ip:
                ips.append(str(cur))
                cur += 1
            return ips
        except Exception:
            print(f"{Colors.FAIL}Geçersiz IP aralığı formatı.{Colors.ENDC}")
            return None
    else:
        try:
            ip = str(ipaddress.IPv4Address(ip_range.strip()))
            return [ip]
        except Exception:
            print(f"{Colors.FAIL}Geçersiz IP formatı.{Colors.ENDC}")
            return None

def scan_port(ip, port, timeout=1):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                try:
                    sock.settimeout(0.5)
                    banner = sock.recv(1024).decode(errors='ignore').strip()
                except:
                    banner = ''
                return (port, True, banner)
            else:
                return (port, False, '')
    except Exception:
        return (port, False, '')

def ttl_to_os(ttl):
    if ttl is None:
        return "Bilinmiyor"
    if ttl <= 64:
        return "Linux/Unix"
    elif ttl <= 128:
        return "Windows"
    elif ttl <= 255:
        return "Router/Switch Cihazı"
    return "Bilinmiyor"

def get_ttl(ip):
    import platform
    import subprocess
    system = platform.system()
    ttl = None
    try:
        if system == "Windows":
            output = subprocess.check_output(["ping", "-n", "1", ip], encoding='utf-8')
            for line in output.splitlines():
                if "TTL=" in line:
                    parts = line.split("TTL=")
                    ttl_str = parts[1].split()[0]
                    ttl = int(ttl_str)
                    break
        else:
            output = subprocess.check_output(["ping", "-c", "1", ip], encoding='utf-8')
            for line in output.splitlines():
                if "ttl=" in line.lower():
                    parts = line.lower().split("ttl=")
                    ttl_str = parts[1].split()[0]
                    ttl = int(ttl_str)
                    break
    except Exception:
        ttl = None
    return ttl

def scan_ip(ip, ports, timeout):
    print(f"{Colors.HEADER}[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Scanning {ip}...{Colors.ENDC}")
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(scan_port, ip, port, timeout): port for port in ports}
        for future in concurrent.futures.as_completed(futures):
            port, is_open, banner = future.result()
            if is_open:
                open_ports.append((port, banner))
                print(f"{Colors.OKGREEN}  [+] Port {port} ({COMMON_PORTS.get(port,'Unknown')}) açık{Colors.ENDC}")
    ttl = get_ttl(ip)
    os_guess = ttl_to_os(ttl)
    print(f"{Colors.OKCYAN}Tahmini İşletim Sistemi: {os_guess} (TTL={ttl}){Colors.ENDC}\n")
    return {
        'ip': ip,
        'open_ports': open_ports,
        'os': os_guess
    }

def generate_html_report(results, output_file):
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    html = f"""<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8" />
<title>Ağ Tarama Raporu - {now}</title>
<style>
body {{
    font-family: Arial, sans-serif;
    background-color: #f2f2f2;
    color: #333;
    padding: 20px;
}}
h1 {{
    color: #007acc;
}}
table {{
    width: 100%;
    border-collapse: collapse;
    margin-top: 20px;
}}
th, td {{
    text-align: left;
    padding: 8px;
    border-bottom: 1px solid #ddd;
}}
th {{
    background-color: #007acc;
    color: white;
}}
tr:hover {{background-color: #f5f5f5;}}
.port-open {{
    color: green;
    font-weight: bold;
}}
</style>
</head>
<body>
<h1>Ağ Tarama Raporu</h1>
<p>Tarama zamanı: {now}</p>
"""

    for res in results:
        html += f"<h2>IP: {res['ip']} - İşletim Sistemi Tahmini: {res['os']}</h2>\n"
        if len(res['open_ports']) == 0:
            html += "<p><i>Hiç açık port bulunamadı.</i></p>\n"
        else:
            html += "<table>\n<tr><th>Port</th><th>Servis</th><th>Banner</th></tr>\n"
            for port, banner in res['open_ports']:
                service = COMMON_PORTS.get(port, "Bilinmeyen")
                safe_banner = banner if banner else "-"
                html += f"<tr><td class='port-open'>{port}</td><td>{service}</td><td>{safe_banner}</td></tr>\n"
            html += "</table>\n"
    html += "</body>\n</html>"
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html)
    print(f"{Colors.OKBLUE}Rapor oluşturuldu: {output_file}{Colors.ENDC}")

def main():
    print(f"{Colors.BOLD}Ağ Tarayıcı Başlatılıyor...{Colors.ENDC}")
    while True:
        ip_input = input("Tarama yapılacak IP veya IP aralığını girin (örn: 192.168.1.1 veya 192.168.1.1-192.168.1.20): ")
        ips = parse_ip_range(ip_input)
        if ips:
            break

    while True:
        ports_input = input("Taramak istediğiniz portları virgülle girin (örnek: 22,80,443) veya boş bırakın varsayılan için: ")
        if not ports_input.strip():
            ports = [22,80,443,3389]
            break
        else:
            try:
                ports = [int(p.strip()) for p in ports_input.split(',') if p.strip().isdigit()]
                if ports:
                    break
                else:
                    print(f"{Colors.FAIL}Geçerli en az bir port giriniz.{Colors.ENDC}")
            except:
                print(f"{Colors.FAIL}Port listesi geçersiz.{Colors.ENDC}")

    while True:
        timeout_input = input("Port tarama timeout süresi saniye olarak girin (varsayılan 1): ")
        if not timeout_input.strip():
            timeout = 1.0
            break
        else:
            try:
                timeout = float(timeout_input)
                if timeout > 0:
                    break
                else:
                    print(f"{Colors.FAIL}Pozitif bir sayı giriniz.{Colors.ENDC}")
            except:
                print(f"{Colors.FAIL}Geçerli bir sayı giriniz.{Colors.ENDC}")

    output_file = input("Rapor dosya adını girin (varsayılan network_scan_report.html): ")
    if not output_file.strip():
        output_file = 'network_scan_report.html'

    print(f"\n{Colors.BOLD}Başlatılıyor: {len(ips)} IP, {len(ports)} port taranacak...{Colors.ENDC}\n")
    results = []
    for ip in ips:
        try:
            res = scan_ip(ip, ports, timeout)
            results.append(res)
        except KeyboardInterrupt:
            print("\nTarama kullanıcı tarafından iptal edildi.")
            sys.exit(0)
        except Exception as e:
            print(f"{Colors.WARNING}Hata IP {ip} için: {e}{Colors.ENDC}")

    generate_html_report(results, output_file)
    print(f"\n{Colors.BOLD}Tüm tarama işlemi tamamlandı.{Colors.ENDC}")

if __name__ == "__main__":
    main()

import socket
import ssl
import time
import re
import base64
import json
import requests

def extract_host_port_from_line(line):
    # vmess / vless
    if line.startswith("vmess://") or line.startswith("vless://"):
        try:
            b64 = line.split("://")[1]
            while len(b64) % 4 != 0:
                b64 += "="
            decoded = base64.b64decode(b64).decode()
            obj = json.loads(decoded)
            host = obj.get("add", "")
            port = obj.get("port", "")
            return host, port
        except Exception:
            return None, None

    # ss
    if line.startswith("ss://"):
        try:
            # ss://base64@host:port
            if '@' in line:
                m = re.search(r'@([^:]+):(\d+)', line)
                if m:
                    return m.group(1), m.group(2)
            else:
                b64 = line[5:]
                while len(b64) % 4 != 0:
                    b64 += '='
                decoded = base64.b64decode(b64).decode()
                m = re.search(r'@([^:]+):(\d+)', decoded)
                if m:
                    return m.group(1), m.group(2)
        except:
            pass

    # ssr
    if line.startswith("ssr://"):
        try:
            b64 = line[6:]
            while len(b64) % 4 != 0:
                b64 += "="
            decoded = base64.b64decode(b64).decode()
            parts = decoded.split(":")
            if len(parts) >= 2:
                host = parts[0]
                port = parts[1]
                return host, port
        except:
            pass

    # trojan
    if line.startswith("trojan://"):
        try:
            m = re.search(r'//[^@]+@([^:]+):(\d+)', line)
            if m:
                return m.group(1), m.group(2)
        except:
            pass

    return None, None

def extract_sni_from_line(line):
    # استخراج SNI برای Trojan
    if line.startswith("trojan://"):
        try:
            m = re.search(r'sni=([^#]+)', line)
            if m:
                return m.group(1)
        except:
            pass
    # استخراج SNI یا host برای VMess/VLESS
    elif line.startswith("vmess://") or line.startswith("vless://"):
        try:
            b64 = line.split("://")[1]
            while len(b64) % 4 != 0:
                b64 += "="
            decoded = base64.b64decode(b64).decode()
            obj = json.loads(decoded)
            return obj.get("sni", "") or obj.get("host", "")
        except:
            pass
    return None

def get_country(host):
    try:
        r = requests.get(f"http://ip-api.com/json/{host}?fields=country", timeout=5)
        if r.status_code == 200:
            return r.json().get("country", "")
    except:
        pass
    return ""

def check_tcp_ping(host, port, timeout=3):
    start = time.time()
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            end = time.time()
            return round((end - start) * 1000, 2)
    except:
        return None

def health_check_tls(host, port, sni=None, timeout=5):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, int(port)), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=sni or host) as ssock:
                ssock.do_handshake()
                return True
    except Exception as e:
        print(f"⚠️ {host}:{port} TLS Handshake FAILED with SNI {sni or host}: {str(e)}")
        return False

def test_all_configs(file_path="combined_configs.txt", skip_countries=None):
    if skip_countries is None:
        skip_countries = ["United States"]

    with open(file_path, "r", encoding="utf-8") as f:
        lines = f.read().splitlines()

    results = []
    tested = 0

    for line in lines:
        if not line or line.startswith("#"):
            continue

        host, port = extract_host_port_from_line(line)
        sni = extract_sni_from_line(line)  # استخراج SNI
        if host and port:
            country = get_country(host)
            print(f"{host} is located in: {country}")
            if country in skip_countries:
                print(f"⏭️ Skipping {host} because it's in {country}")
                continue

            tested += 1
            ping_time = check_tcp_ping(host, port)
            if ping_time is not None:
                print(f"✅ {host}:{port} OPEN - ping: {ping_time} ms")
                
                if health_check_tls(host, port, sni):
                    print(f"💚 {host}:{port} TLS Handshake OK with SNI: {sni or host}")
                    results.append((ping_time, host, port, line))
                else:
                    print(f"⚠️ {host}:{port} TLS Handshake FAILED with SNI: {sni or host}")
            else:
                print(f"❌ {host}:{port} CLOSED")

    print(f"\nDone! Tested {tested} configs.")
    return results

def save_best_configs(results, top_n=10, output_file="best_configs.txt"):
    results.sort()
    with open(output_file, "w", encoding="utf-8") as f:
        for i, (ping, host, port, line) in enumerate(results[:top_n], 1):
            f.write(f"# {i}. {host}:{port} - ping: {ping} ms\n{line}\n")
    print(f"✅ Saved top {top_n} best configs to {output_file}")

if __name__ == "__main__":
    results = test_all_configs()
    save_best_configs(results)
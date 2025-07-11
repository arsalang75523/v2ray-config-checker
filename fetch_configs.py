import requests
import base64
import json
import re
import socket
import ssl
import time

# ========= CONFIGS ===========
SUB_URLS = [
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub1.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub2.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub3.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub4.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub5.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub6.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub7.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub8.txt",
]
EXCLUDE_HOST = "elma.ns.cloudflare.com"
SKIP_COUNTRIES = ["United States"]
# =============================

def line_contains_excluded_host(line):
    if EXCLUDE_HOST in line:
        return True

    if line.startswith("vmess://") or line.startswith("vless://"):
        try:
            b64 = line.split("://")[1]
            while len(b64) % 4 != 0:
                b64 += '='
            decoded = base64.b64decode(b64).decode()
            if EXCLUDE_HOST in decoded:
                return True
        except:
            pass

    if line.startswith("ssr://"):
        try:
            b64 = line[6:]
            while len(b64) % 4 != 0:
                b64 += '='
            decoded = base64.b64decode(b64).decode()
            if EXCLUDE_HOST in decoded:
                return True
        except:
            pass

    m = re.search(r'@([^:]+):', line)
    if m and EXCLUDE_HOST in m.group(1):
        return True

    return False

def fetch_and_filter_configs():
    all_filtered_lines = []

    for url in SUB_URLS:
        print(f"Downloading subscription from {url} ...")
        try:
            response = requests.get(url, timeout=15)
            response.raise_for_status()
            content = response.text.strip()

            lines = content.splitlines()
            filtered_lines = []
            for line in lines:
                if not line.strip():
                    continue
                if not line_contains_excluded_host(line):
                    filtered_lines.append(line)

            all_filtered_lines.extend(filtered_lines)
            print(f"✅ {len(filtered_lines)} configs loaded from {url}")

        except Exception as e:
            print(f"⚠️ Failed to download from {url}: {e}")

    with open("combined_configs.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(all_filtered_lines))

    print(f"\n✅ All done. Saved total {len(all_filtered_lines)} configs to combined_configs.txt")
    return "combined_configs.txt"

def extract_host_port_from_line(line):
    if line.startswith("vmess://") or line.startswith("vless://"):
        try:
            b64 = line.split("://")[1]
            while len(b64) % 4 != 0:
                b64 += "="
            decoded = base64.b64decode(b64).decode()
            obj = json.loads(decoded)
            return obj.get("add", ""), obj.get("port", "")
        except:
            return None, None
    if line.startswith("ss://"):
        try:
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
    if line.startswith("ssr://"):
        try:
            b64 = line[6:]
            while len(b64) % 4 != 0:
                b64 += "="
            decoded = base64.b64decode(b64).decode()
            parts = decoded.split(":")
            if len(parts) >= 2:
                return parts[0], parts[1]
        except:
            pass
    if line.startswith("trojan://"):
        try:
            m = re.search(r'//[^@]+@([^:]+):(\d+)', line)
            if m:
                return m.group(1), m.group(2)
        except:
            pass
    return None, None

def extract_sni_from_line(line):
    if line.startswith("trojan://"):
        try:
            m = re.search(r'sni=([^#]+)', line)
            if m:
                return m.group(1)
        except:
            pass
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
    except:
        return False

def test_all_configs(file_path, skip_countries=None):
    if skip_countries is None:
        skip_countries = SKIP_COUNTRIES

    with open(file_path, "r", encoding="utf-8") as f:
        lines = f.read().splitlines()

    results = []
    tested = 0

    for line in lines:
        if not line or line.startswith("#"):
            continue

        host, port = extract_host_port_from_line(line)
        sni = extract_sni_from_line(line)
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
                    print(f"💚 {host}:{port} TLS OK with SNI: {sni or host}")
                    results.append((ping_time, host, port, line))
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
    file_path = fetch_and_filter_configs()
    results = test_all_configs(file_path)
    save_best_configs(results)

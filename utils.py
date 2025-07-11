# utils.py
import re
import base64
import json

def extract_host_port_from_line(line):
    """
    سعی می‌کند host و port را از کانفیگ line پیدا کند
    """
    # مثال برای vmess (base64)
    if line.startswith("vmess://"):
        try:
            decoded = base64.urlsafe_b64decode(line[8:] + '==').decode('utf-8')
            data = json.loads(decoded)
            return data.get('add'), data.get('port')
        except:
            return None, None

    # مثال برای vless / trojan / ss
    m = re.search(r'^(vless|trojan|ss)://([^@]+)@([^:/]+):(\d+)', line)
    if m:
        host = m.group(3)
        port = m.group(4)
        return host, port

    return None, None

import json
import random
from datetime import datetime, timedelta

logs = []
base_time = datetime.now()

# 1. Gerando tráfego NORMAL (95% dos dados)
for i in range(1000):
    logs.append({
        "timestamp": (base_time + timedelta(seconds=i)).isoformat(),
        "src_ip": f"192.168.1.{random.randint(10, 50)}",
        "dest_ip": "10.0.0.5",
        "dest_port": 443,
        "bytes_sent": random.randint(100, 5000),
        "status_code": 200
    })

# 2. ATAQUE: Brute Force (Muitos erros 401 do mesmo IP)
for i in range(50):
    logs.append({
        "timestamp": (base_time + timedelta(seconds=i)).isoformat(),
        "src_ip": "172.16.0.10",
        "dest_ip": "10.0.0.5",
        "dest_port": 22,
        "bytes_sent": 0,
        "status_code": 401
    })

# 3. ATAQUE: Exfiltração de Dados (Volume de bytes anômalo)
logs.append({
    "timestamp": base_time.isoformat(),
    "src_ip": "192.168.1.15",
    "dest_ip": "203.0.113.50",
    "dest_port": 443,
    "bytes_sent": 10000000, # 10MB em uma única conexão
    "status_code": 200
})

# 4. ATAQUE: Port Scanning (Um IP em várias portas)
for port in [21, 22, 23, 25, 80, 443, 8080, 3389]:
    logs.append({
        "timestamp": base_time.isoformat(),
        "src_ip": "10.0.0.99",
        "dest_ip": "10.0.0.5",
        "dest_port": port,
        "bytes_sent": 0,
        "status_code": 404
    })

with open('firewall_logs.json', 'w') as f:
    json.dump(logs, f, indent=4)

print("Dataset 'firewall_logs.json' gerado com sucesso!")
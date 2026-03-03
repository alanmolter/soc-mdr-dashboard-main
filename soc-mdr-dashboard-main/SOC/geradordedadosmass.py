import json
import random
from datetime import datetime, timedelta

logs = []
base_time = datetime.now() - timedelta(hours=2) # Simula as últimas 2 horas

# 1. TRÁFEGO NORMAL (~5.000 logs de IPs variados)
for i in range(5000):
    logs.append({
        "timestamp": (base_time + timedelta(seconds=random.randint(0, 7200))).isoformat(),
        "src_ip": f"192.168.1.{random.randint(50, 250)}",
        "dest_ip": "10.0.0.5",
        "dest_port": 443,
        "bytes_sent": random.randint(100, 2000),
        "status_code": 200
    })

# 2. INJEÇÃO DE 20 IPS MALICIOSOS (Os Vilões)

# Grupo A: Exfiltração Massiva (5 IPs) - Muita transferência de dados
for i in range(5):
    ip = f"10.0.99.{10 + i}"
    for _ in range(10):
        logs.append({
            "timestamp": (base_time + timedelta(minutes=random.randint(10, 110))).isoformat(),
            "src_ip": ip,
            "dest_ip": "203.0.113.88",
            "dest_port": 443,
            "bytes_sent": random.randint(500000, 2000000), # 0.5MB a 2MB por log
            "status_code": 200
        })

# Grupo B: Port Scanning (5 IPs) - Muitas portas diferentes
for i in range(5):
    ip = f"172.16.5.{20 + i}"
    for port in range(20, 100, 5): # Testa várias portas
        logs.append({
            "timestamp": (base_time + timedelta(minutes=random.randint(5, 30))).isoformat(),
            "src_ip": ip,
            "dest_ip": "10.0.0.5",
            "dest_port": port,
            "bytes_sent": 0,
            "status_code": 404
        })

# Grupo C: Brute Force SSH (5 IPs) - Muitos erros 401
for i in range(5):
    ip = f"185.92.10.{30 + i}"
    for _ in range(40): # 40 tentativas de login falhas cada
        logs.append({
            "timestamp": (base_time + timedelta(seconds=random.randint(0, 3600))).isoformat(),
            "src_ip": ip,
            "dest_ip": "10.0.0.5",
            "dest_port": 22,
            "bytes_sent": 150,
            "status_code": 401
        })

# Grupo D: O Caso "Alan Molter" - Probing Decimal (5 IPs)
# Padrão: 5, 500, 5000 unidades (simulado aqui por multiplicadores de bytes)
for i in range(5):
    ip = f"192.168.1.{2 + i}"
    for val in [5000, 500000, 5000000]: # 5KB, 500KB, 5MB
        logs.append({
            "timestamp": (base_time + timedelta(minutes=30 + i)).isoformat(),
            "src_ip": ip,
            "dest_ip": "10.0.0.5",
            "dest_port": 443,
            "bytes_sent": val,
            "status_code": 200
        })

with open('firewall_logs.json', 'w') as f:
    json.dump(logs, f, indent=4)

print("Dataset 'firewall_logs.json' com 20 ameaças gerado com sucesso!")
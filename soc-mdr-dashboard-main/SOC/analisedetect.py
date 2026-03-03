import pandas as pd
import os
from sklearn.ensemble import IsolationForest

# ==============================================================================
# 1. CARREGAMENTO E ENGENHARIA DE ATRIBUTOS (FEATURE ENGINEERING)
# ==============================================================================

# Lemos o arquivo JSON. O Pandas converte automaticamente o formato de texto
# para um objeto DataFrame (uma tabela altamente otimizada em memória).
json_path = os.path.join(os.path.dirname(__file__), 'firewall_logs.json')
df = pd.read_json(json_path)

# Aplicamos o 'Feature Engineering': Transformamos logs brutos em métricas de comportamento.
# Usamos o 'Named Aggregation' (disponível desde o Pandas 0.25), que permite 
# criar colunas novas com nomes claros durante o agrupamento (groupby).
features = df.groupby('src_ip').agg(
    # Soma de bytes enviados: IPs que fogem da média podem estar em Exfiltração.
    total_bytes=('bytes_sent', 'sum'), 
    
    # Contagem de portas únicas: Um IP tentando muitas portas indica Port Scanning.
    unique_ports=('dest_port', 'nunique'), 
    
    # Função Lambda: Percorre os códigos de status e soma apenas onde for 401 (Unauthorized).
    # Isso isola tentativas de Brute Force em serviços como SSH ou Web Admin.
    failed_logins=('status_code', lambda x: (x == 401).sum()) 
).reset_index()

# ==============================================================================
# 2. DETECÇÃO DE ANOMALIAS COM MACHINE LEARNING
# ==============================================================================

# O Isolation Forest é um algoritmo não supervisionado (não precisa de exemplos prévios).
# Ele "isola" observações criando árvores de decisão. Anomalias são mais fáceis 
# de isolar e, por isso, possuem caminhos mais curtos na árvore.
# 
# Parâmetros:
# - contamination: A porcentagem de dados que acreditamos ser anômala (0.03 = 3%).
# - random_state: Garante que o resultado seja o mesmo toda vez que rodarmos (Reprodutibilidade).
model = IsolationForest(contamination=0.03, random_state=42)

# fit_predict: O modelo "aprende" o padrão dos dados (fit) e imediatamente 
# classifica cada linha (predict). 
# Resultado: 1 para dados normais | -1 para anomalias.
features['anomaly_score'] = model.fit_predict(features[['total_bytes', 'unique_ports', 'failed_logins']])

# ==============================================================================
# 3. INTERPRETAÇÃO E TRIAGEM PARA O SOC
# ==============================================================================

# Usamos indexação booleana (filtro) para selecionar apenas as linhas marcadas como -1.
anomalies = features[features['anomaly_score'] == -1]

print(f"--- Foram identificados {len(anomalies)} IPs com comportamento anômalo ---")
print(anomalies)

# Iteramos sobre o DataFrame de anomalias usando .iterrows().
# Em Python, isso permite acessar cada linha como um par (índice, série de dados).
for index, row in anomalies.iterrows():
    print(f"\n[Investigação Necessária para o IP: {row['src_ip']}]")
    
    # Lógica de Triagem: Categorizando a anomalia para o analista do SOC.
    if row['failed_logins'] > 20:
        print(f" > Alerta de Segurança: Volume excessivo de falhas de login ({row['failed_logins']}).")
        
    if row['total_bytes'] > 1000000:
        print(f" > Alerta de Segurança: Volume de saída anômalo ({row['total_bytes']} bytes).")
        
    if row['unique_ports'] > 5:
        print(f" > Alerta de Segurança: Varredura de múltiplas portas detectada ({row['unique_ports']} portas).")
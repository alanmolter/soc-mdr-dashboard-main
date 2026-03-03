import streamlit as st
import pandas as pd
import requests
from sklearn.ensemble import IsolationForest
import plotly.express as px
import os

# ==============================================================================
# 1. CONFIGURAÇÕES INICIAIS E SEGURANÇA
# ==============================================================================
st.set_page_config(page_title="Redbelt - MDR Intelligence", layout="wide")

# Uso de st.secrets para ocultar a API Key
API_KEY = None
try:
    # Tenta carregar de st.secrets (desenvolvimento local ou Streamlit Cloud secrets)
    API_KEY = st.secrets.get("VT_API_KEY")
except:
    pass

# Se não encontrou em st.secrets, tenta variável de ambiente
if not API_KEY:
    API_KEY = os.getenv("VT_API_KEY")

# Se ainda não encontrou, mostra aviso
if not API_KEY:
    st.warning("⚠️ VT_API_KEY não configurada. Configure via: https://docs.streamlit.io/deploy/streamlit-cloud/deploy-your-app#add-secrets")
    API_KEY = "dummy_key"  # Permite app rodar sem VirusTotal

# ==============================================================================
# 2. INTELIGÊNCIA DE AMEAÇAS E PROCESSAMENTO
# ==============================================================================
@st.cache_data(ttl=3600)
def get_ip_reputation(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": API_KEY}
    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()
            return data['data']['attributes']['last_analysis_stats']['malicious']
        return 0
    except: return "N/A"

@st.cache_data
def process_security_data():
    json_path = os.path.join(os.path.dirname(__file__), 'firewall_logs.json')
    df = pd.read_json(json_path)
    # Garantimos que o timestamp seja lido como data para o gráfico de linha
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    features = df.groupby('src_ip').agg(
        total_bytes=('bytes_sent', 'sum'),
        unique_ports=('dest_port', 'nunique'),
        failed_logins=('status_code', lambda x: (x == 401).sum())
    ).reset_index()

    model = IsolationForest(contamination=0.03, random_state=42)
    features['anomaly_score'] = model.fit_predict(features[['total_bytes', 'unique_ports', 'failed_logins']])
    return df, features

df_raw, df_features = process_security_data()

# ==============================================================================
# 3. SIDEBAR E ESTADO DA SESSÃO
# ==============================================================================
st.sidebar.title("Navegação do SOC")
anomalies_only = df_features[df_features['anomaly_score'] == -1]
selected_ip = st.sidebar.selectbox(
    "IPs Suspeitos Identificados pelo ML:",
    options=anomalies_only['src_ip'].tolist()
)

if 'ip_to_investigate' not in st.session_state or selected_ip:
    st.session_state.ip_to_investigate = selected_ip

# ==============================================================================
# 4. PAINEL PRINCIPAL
# ==============================================================================
st.title("🛡️ MDR Intelligence Dashboard")
st.write(f"Análise de Logs e Threat Hunting - Pesquisador: **Alan Molter**")

c1, c2, c3 = st.columns(3)
c1.metric("Logs Totais", len(df_raw))
c2.metric("IPs Únicos", df_features['src_ip'].nunique())
c3.metric("Anomalias Críticas", len(anomalies_only))

st.divider()

# Bloco de Consulta VirusTotal
col_search, col_result = st.columns([2, 1])
with col_search:
    investigate_ip = st.text_input("IP para consulta VirusTotal:", value=st.session_state.ip_to_investigate)
with col_result:
    if investigate_ip:
        res = get_ip_reputation(investigate_ip)
        if isinstance(res, int) and res > 0: st.error(f"🚩 IP Malicioso! ({res} detecções)")
        elif isinstance(res, int): st.success("✅ IP sem alertas externos.")

st.divider()

# --- NOVO GRÁFICO: VOLUME DE DADOS POR IP (SÉRIE TEMPORAL) ---
st.subheader("📈 Linha do Tempo: Volume de Dados por IP")
st.markdown("""
Esta visualização é crucial para detectar **Exfiltração Lenta (Low and Slow)**. 
Picos isolados indicam transferências massivas, enquanto padrões repetitivos indicam comunicação de malware (*Beaconing*).
""")

# Criamos o gráfico de linha usando os dados brutos filtrados pelos IPs com mais tráfego
top_ips = df_features.nlargest(10, 'total_bytes')['src_ip']
df_timeline = df_raw[df_raw['src_ip'].isin(top_ips)]

fig_line = px.line(
    df_timeline, 
    x='timestamp', 
    y='bytes_sent', 
    color='src_ip',
    title="Análise de Volume Temporal (Top 10 IPs por Volume)",
    labels={'bytes_sent': 'Bytes Enviados', 'timestamp': 'Tempo'}
)
st.plotly_chart(fig_line, use_container_width=True)

# --- GRÁFICO DE DISPERSÃO (ISOLATION FOREST) ---
st.subheader("🎯 Análise Espacial de Anomalias")
fig_scatter = px.scatter(
    df_features, 
    x="total_bytes", 
    y="unique_ports", 
    color="anomaly_score",
    hover_data=["src_ip"],
    color_continuous_scale=["red", "blue"], # Correção: Nomes das cores em vez de valores
    color_continuous_midpoint=0
)
st.plotly_chart(fig_scatter, use_container_width=True)

# Tabela de Dados
st.subheader("📂 Relatório Forense de Atividades")
st.dataframe(df_features.sort_values(by="anomaly_score"), use_container_width=True)
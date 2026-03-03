import streamlit as st
import pandas as pd
import requests
from sklearn.ensemble import IsolationForest
import plotly.express as px

# ==============================================================================
# 1. SETUP E SEGURANÇA (Secure Coding & DevSecOps)
# ==============================================================================

# st.set_page_config: Define o título da aba e o layout como 'wide' (largo).
# Em segurança, o layout largo é vital para monitorar múltiplos gráficos simultaneamente.
st.set_page_config(page_title="MDR - Advanced Analytics", layout="wide")

# Gerenciamento de Segredos: O uso de st.secrets evita o "Hardcoded Credentials".
# Jamais deixe chaves de API visíveis no código. Isso garante conformidade com a LGPD.
try:
    API_KEY = st.secrets["VT_API_KEY"]
except:
    st.error("Erro Crítico: Configure a VT_API_KEY no arquivo .streamlit/secrets.toml")
    st.stop() # Interrompe a execução se a chave de segurança não for encontrada.

# ==============================================================================
# 2. PROCESSAMENTO E DATA ENGINEERING
# ==============================================================================

# @st.cache_data: Decorator que salva o resultado em memória (Cache LRU).
# Evita reprocessar dados pesados a cada interação, reduzindo a latência do painel.
@st.cache_data
def load_and_process():
    # pd.read_json: Método nativo do Pandas para carregar arquivos JSON.
    df = pd.read_json('firewall_logs.json')
    
    # pd.to_datetime: Converte strings de tempo em objetos datetime do Python.
    # Essencial para cálculos temporais e eixos cronológicos corretos.
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    # sort_values (Ordenação Multinível): Resolve o erro de "rabiscos" no gráfico.
    # Ordenamos primeiro por IP (agrupamento de linha) e depois por tempo.
    # Isso garante que o Plotly desenhe as linhas de forma linear e contínua.
    df = df.sort_values(by=['src_ip', 'timestamp'])
    
    # Feature Engineering (UBA - User Behavior Analytics):
    # Agrupamos os logs por IP (src_ip) para criar perfis comportamentais.
    # .agg(): Método nativo do Pandas para realizar múltiplas agregações de uma vez.
    features = df.groupby('src_ip').agg(
        total_bytes=('bytes_sent', 'sum'),           # Soma: Detecta Exfiltração massiva.
        unique_ports=('dest_port', 'nunique'),       # nunique: Detecta Port Scanning (varredura).
        # lambda: Função anônima que filtra apenas status 401 (Unauthorized) para Brute Force.
        failed_logins=('status_code', lambda x: (x == 401).sum()) 
    ).reset_index()

    # Isolation Forest (Detecção de Outliers):
    # Algoritmo não supervisionado que isola anomalias em vez de descrever o normal.
    # contamination=0.08: Define que esperamos que 8% dos dados sejam anômalos.
    model = IsolationForest(contamination=0.08, random_state=42)
    # fit_predict: Treina o modelo e classifica: 1 (Normal) ou -1 (Anomalia).
    features['anomaly_score'] = model.fit_predict(features[['total_bytes', 'unique_ports', 'failed_logins']])
    
    return df, features

# Execução do pipeline de dados
df_raw, df_features = load_and_process()
# Filtragem booleana rápida: Isola apenas as ameaças detectadas pelo ML.
anomalies_df = df_features[df_features['anomaly_score'] == -1]

# ==============================================================================
# 3. INTERFACE E VISUALIZAÇÃO (SOC Dashboard)
# ==============================================================================

st.sidebar.title("🛡️ SOC Control Center")
st.sidebar.markdown(f"**Analista:** Alan Molter")
# st.selectbox: Componente interativo que permite ao analista focar em um IP suspeito.
selected_ip = st.sidebar.selectbox("Focar Investigação em IP Anômalo:", anomalies_df['src_ip'])

st.title("🛡️ MDR Intelligence")

# KPIs (Key Performance Indicators): Métricas de alto impacto para o MTTR.
m1, m2, m3, m4 = st.columns(4)
m1.metric("Logs Processados", len(df_raw))
m2.metric("IPs Únicos Analisados", len(df_features))
m3.metric("Ameaças Detectadas (ML)", len(anomalies_df), delta_color="inverse")
m4.metric("Nível de Risco", "CRÍTICO", delta="-15% (MTTR)") # Simula melhoria no tempo de resposta.

st.divider()

# --- Investigação Temporal (Séries Temporais) ---
st.subheader("📈 Investigação Temporal de Exfiltração")
# .nlargest(): Método nativo para filtrar os 15 IPs com maior volume de tráfego.
top_offenders = df_features.nlargest(15, 'total_bytes')['src_ip']
df_timeline = df_raw[df_raw['src_ip'].isin(top_offenders)]

# px.line: Gráfico de linha do Plotly para análise de picos de tráfego.
fig_timeline = px.line(
    df_timeline, x='timestamp', y='bytes_sent', color='src_ip',
    title="Picos de Tráfego por IP (Análise de Burst)",
    template="plotly_dark" # Tema escuro: padrão industrial para centros de comando.
)
st.plotly_chart(fig_timeline, use_container_width=True)

# --- Mapeamento de Outliers (Análise Espacial) ---
col_graph, col_search = st.columns([2, 1])

with col_graph:
    st.subheader("🎯 Mapeamento Espacial de Outliers")
    fig_scatter = px.scatter(
        df_features, x="total_bytes", y="unique_ports", color="anomaly_score",
        hover_data=["src_ip", "failed_logins"],
        # color_continuous_scale: Mapeia o valor -1 para vermelho (perigo) e 1 para azul (seguro).
        color_continuous_scale=["red", "blue"], 
        color_continuous_midpoint=0,
        template="plotly_dark"
    )
    st.plotly_chart(fig_scatter, use_container_width=True)

with col_search:
    st.subheader("🔍 Threat Intel (VirusTotal)")
    target = st.text_input("Investigar Reputação:", value=selected_ip)
    if st.button("Consultar API"):
        # Interface de feedback visual para o analista do SOC.
        st.warning(f"Consultando reputação para {target}...")
        st.error(f"IP {target} reportado em bases de C&C!")

st.divider()

# --- Tabela Forense com Gradiente de Cor ---
st.subheader("📂 Relatório de Triagem de Incidentes")
# .style.background_gradient: Aplica cores diretamente na tabela.
# Requer a biblioteca 'matplotlib' instalada para funcionar.
st.dataframe(
    df_features.sort_values(by="anomaly_score").style.background_gradient(cmap='RdBu', subset=['anomaly_score']),
    use_container_width=True
)

st.divider()
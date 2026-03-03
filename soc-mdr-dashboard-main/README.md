# MDR Intelligence - SOC Dashboard

## 🛡️ Visão Geral
Este projeto é uma ferramenta de **Managed Detection and Response (MDR)** desenvolvida para auxiliar analistas de SOC (Security Operations Center). A aplicação processa logs de firewall, utiliza Machine Learning para detectar comportamentos anômalos e apresenta os dados em um dashboard interativo para investigação de ameaças.

## 🚀 Funcionalidades

### 1. Detecção de Anomalias (Machine Learning)
Utiliza o algoritmo **Isolation Forest** (Scikit-Learn) para identificar padrões suspeitos nos logs, focando em:
- **Exfiltração de Dados:** Detecção de volumes anômalos de bytes enviados.
- **Port Scanning:** Identificação de IPs varrendo múltiplas portas únicas.
- **Brute Force:** Monitoramento de falhas excessivas de login (Status 401).

### 2. Visualização de Dados (Dashboard)
Interface interativa construída com **Streamlit** e **Plotly**, oferecendo:
- KPIs de segurança e nível de risco.
- Gráficos de linha do tempo para análise de picos de tráfego.
- Mapeamento espacial de outliers (Scatter Plot).
- Tabela forense com gradiente de risco.

### 3. Threat Intelligence
- Integração com a API do **VirusTotal** para verificação de reputação de IPs suspeitos em tempo real.

## 📂 Estrutura do Projeto

- `analisedetect.py`: Script standalone para processamento dos logs e execução do modelo de ML.
- `dashattcompleto.py`: Dashboard principal completo com todas as funcionalidades e integração de API.
- `dashfinal.py`: Versão alternativa do dashboard com foco em UX/UI para o SOC.
- `app_seguranca.py`: Versão simplificada do dashboard para visualização rápida.
- `firewall_logs.json`: Arquivo de entrada contendo os logs brutos (necessário para execução).

## 🛠️ Pré-requisitos

Certifique-se de ter o Python instalado (3.8+) e as bibliotecas necessárias:

```bash
pip install pandas scikit-learn streamlit plotly requests
```

## ⚙️ Configuração (Segurança)

### 🔧 Ambiente Local

Para utilizar a funcionalidade de consulta ao VirusTotal, é necessário configurar a chave de API de forma segura. Crie um arquivo `.streamlit/secrets.toml` dentro da pasta `SOC`:

```toml
# .streamlit/secrets.toml (local)
VT_API_KEY = "SUA_CHAVE_VIRUSTAL_AQUI"
```

⚠️ **Importante:** Este arquivo está no `.gitignore` e nunca será enviado para o GitHub por questões de segurança.

### ☁️ Streamlit Cloud (Deploy Remoto)

1. Acesse seu app em [share.streamlit.io](https://share.streamlit.io)
2. Clique no menu de 3 pontos (**⋮**) → **Edit secrets**
3. Adicione a sua chave:
   ```toml
   VT_API_KEY = "sua_chave_api_aqui"
   ```
4. Salve as alterações

[📖 Ver documentação oficial](https://docs.streamlit.io/deploy/streamlit-cloud/deploy-your-app#add-secrets)

## ▶️ Como Executar

### Desenvolvimento Local

Navegue até a pasta `SOC` e execute:

```bash
cd SOC
streamlit run dashattcompleto.py
```

O dashboard estará acessível em `http://localhost:8501`.

## 👨‍💻 Autor
**Alan Molter** - Analista de Segurança / Desenvolvedor
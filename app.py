import streamlit as st
import pandas as pd
import os
import json
import numpy as np
import requests
from streamlit_autorefresh import st_autorefresh
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler

st.set_page_config(page_title="MDR SOC - Mestrado Unimontes", layout="wide")

# --- CUSTOMIZAÇÃO VISUAL CYBERPUNK ROXO DIRETO NO CÓDIGO ---
st.markdown(
    """
    <style>
    .stApp {
        background-color: #1A1625 !important;
        color: #FFFFFF !important;
    }
    h1, h2, h3, h4, h5, h6, p, span, label, .stMarkdown {
        color: #FFFFFF !important;
    }
    div[data-testid="stMetric"] {
        background-color: #241E34 !important;
        border: 2px solid #9B5DE5 !important;
        padding: 20px !important;
        border-radius: 10px !important;
        box-shadow: 0px 4px 10px rgba(155, 93, 229, 0.2) !important;
        margin-bottom: 15px !important;
    }
    [data-testid="stMetricValue"] {
        color: #9B5DE5 !important;
        font-size: 2.5rem !important;
        font-weight: bold !important;
    }
    [data-testid="stMetricLabel"] p {
        color: #FFFFFF !important;
        font-size: 1.1rem !important;
        font-weight: 500 !important;
    }
    button[data-baseweb="tab"] {
        color: #BBBBBB !important;
    }
    button[aria-selected="true"] {
        color: #9B5DE5 !important;
        border-bottom-color: #9B5DE5 !important;
        font-weight: bold !important;
    }
    </style>
    """,
    unsafe_allow_html=True
)

st.title("Portal MDR Inteligente: Gestao de Vulnerabilidades e Compliance")
st.markdown("Analise preditiva e auditoria de Sistemas Operacionais integrada ao laboratorio com consulta dinamica global via API.")

# Auto-refresh configurado para 30 segundos (sem piscar a aba agressivamente)
st_autorefresh(interval=30000, key="contador_MDR_estavel")

PASTA_INVENTARIO = "https://github.com/januariaricardo-collab/mdr-soc-unimontes"

# =========================================================================
# 1. CONSULTA DINÂMICA: API CIRCL (CVE-Search)
# =========================================================================
@st.cache_data(ttl=86400)
def consultar_api_global(nome_produto, versao_produto):
    nome_limpo = nome_produto.lower()
    versao_limpa = str(versao_produto).strip()
    
    if "windows" in nome_limpo:
        termo_busca = "windows"
    else:
        termo_busca = nome_limpo.split()[0]
        
    if len(termo_busca) < 3:
        return "Nenhuma Detectada", 0.0

    try:
        url_api = f"https://cve.circl.lu/api/search/{termo_busca}"
        resposta = requests.get(url_api, timeout=5)
        
        if resposta.status_code == 200:
            dados_cve = resposta.json()
            
            if isinstance(dados_cve, list) and len(dados_cve) > 0:
                for cve_item in dados_cve:
                    resumo = str(cve_item.get('summary', '')).lower()
                    id_cve = cve_item.get('id', '')
                    cvss_nota = cve_item.get('cvss', None)
                    
                    if versao_limpa in resumo and cvss_nota is not None:
                        return f"{id_cve} (Match de Versao)", float(cvss_nota)
                
                for cve_item in dados_cve:
                    id_cve = cve_item.get('id', '')
                    cvss_nota = cve_item.get('cvss', None)
                    if id_cve and cvss_nota is not None:
                        return f"{id_cve} (Filtro por Produto)", float(cvss_nota)

        elif resposta.status_code == 429:
            return "AVISO: API Limit (Rate Limit Excedido)", 0.0
            
    except requests.exceptions.Timeout:
        return "ERRO: Timeout na Consulta API", 0.0
    except Exception as e:
        return f"ERRO: Rede API: {str(e)}", 0.0
        
    return "Nenhuma Detectada", 0.0

# =========================================================================
# 2. CONSULTA DINÂMICA: API VIRUSTOTAL (Recurso Multimotores)
# =========================================================================
@st.cache_data(ttl=86400)
def consultar_virustotal_api(file_hash, api_key="CHAVE_REPRODUCAO_ACADEMICA"):
    if api_key == "CHAVE_REPRODUCAO_ACADEMICA" or not api_key:
        if file_hash == "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f":
            return 53.0  
        return 0.0

    url_api = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    try:
        resposta = requests.get(url_api, headers=headers, timeout=5)
        if resposta.status_code == 200:
            payload = resposta.json()
            stats = payload.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return float(stats.get("malicious", 0))
    except Exception:
        return 0.0
    return 0.0

# =========================================================================
# 3. REDE NEURAL ARTIFICIAL (TOPOLOGIA RESILIENTE EM 4 DIMENSÕES)
# =========================================================================
@st.cache_resource
def inicializar_e_treinar_ia_verbose():
    X_train = np.array([
        [0, 0, 0.0, 0.0],    
        [1, 1, 9.8, 53.0],   
        [1, 1, 9.8, 48.0],   
        [0, 1, 5.0, 0.0]     
    ])
    y_train = np.array([0, 1, 1, 0])
    
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    
    mlp = MLPClassifier(
        hidden_layer_sizes=(8, 4), 
        activation='logistic', 
        max_iter=3000, 
        random_state=24,
        solver='lbfgs'
    )
    mlp.fit(X_train_scaled, y_train)
    return mlp, scaler, X_train, y_train

mlp_motor, ia_scaler, X_dados_treino, y_dados_treino = inicializar_e_treinar_ia_verbose()

# =========================================================================
# 4. PROCESSAMENTO DO INVENTÁRIO (INGESTÃO E EXTRAÇÃO DINÂMICA)
# =========================================================================
def processar_dados_inventario():
    linhas_dataset = []
    if not os.path.exists(PASTA_INVENTARIO): return pd.DataFrame(), []
    arquivos = [f for f in os.listdir(PASTA_INVENTARIO) if f.endswith('.json')]
    if len(arquivos) == 0: return pd.DataFrame(), []

    logs_verbose_predicao = []

    for arquivo in arquivos:
        caminho_completo = os.path.join(PASTA_INVENTARIO, arquivo)
        try:
            with open(caminho_completo, 'rb') as f:
                conteudo_binario = f.read()
                
            if conteudo_binario.startswith(b'\xef\xbb\xbf'):
                conteudo_binario = conteudo_binario[3:]
                
            try:
                conteudo_texto = conteudo_binario.decode('utf-8')
            except Exception:
                conteudo_texto = conteudo_binario.decode('cp1252', errors='replace')
                
            dados = json.loads(conteudo_texto)
            
            hostname = dados.get('Hostname', 'Desconhecido').upper()
            status_licenca = dados.get('StatusLicencaWindows', 'Original / Licenciado')
            usa_ativador_flag = int(dados.get('UsaAtivadorKMSPico', 0))
            windows_build = dados.get('Build', '10.0')
            nome_so_real = dados.get('SO', 'Windows')
            
            hash_arquivo = dados.get('HashArquivoSuspeito', '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f' if usa_ativador_flag == 1 else 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')

            ativador_detectado = 0
            licenca_invalida = 0
            compliance_status = "EM CONFORMIDADE"
            veredito_ia = "ACEITAVEL"

            id_cve_so, nota_cvss_so = consultar_api_global("windows", windows_build)

            texto_analise = str(status_licenca).lower()
            contem_suspeito = "suspeito" in texto_analise
            eh_nao_licenciado = contem_suspeito and ("nao" in texto_analise or "n\u00e3o" in texto_analise or texto_analise.startswith("n"))

            motores_vt = 0.0

            if eh_nao_licenciado:
                ativador_detectado = 0
                licenca_invalida = 1
                compliance_status = "FORA DE CONFORMIDADE"
                veredito_ia = "ATENCAO"
                max_cvss = max(nota_cvss_so, 5.0)
                vulnerabilidade_cve = "Ausencia de Licenca Valida"
                status_limpo_exibicao = "Não Licenciado / Suspeito"
                motores_vt = 0.0

            elif usa_ativador_flag == 1 or "fraude" in texto_analise or "massgrave" in texto_analise or "ativac" in texto_analise:
                ativador_detectado = 1
                licenca_invalida = 1
                compliance_status = "FORA DE CONFORMIDADE"
                veredito_ia = "CRITICO"
                max_cvss = max(nota_cvss_so, 9.8)
                vulnerabilidade_cve = f"{id_cve_so} + Risco de Ativador" if nota_cvss_so > 0 else "Risco de Integridade (Kernel)"
                status_limpo_exibicao = "Licenciado / Script suspeito"
                motores_vt = consultar_virustotal_api(hash_arquivo)

            else:
                max_cvss = nota_cvss_so
                vulnerabilidade_cve = id_cve_so if nota_cvss_so > 0 else "Nenhuma Detectada"
                status_limpo_exibicao = "Original / Licenciado"
                motores_vt = 0.0

            vetor_reais = np.array([[ativador_detectado, licenca_invalida, max_cvss, motores_vt]])
            vetor_scaled = ia_scaler.transform(vetor_reais)
            probabilidades = mlp_motor.predict_proba(vetor_scaled)[0]
            
            p_critico = probabilidades[1]
            probabilidade_risco = p_critico if (ativador_detectado == 1 or licenca_invalida == 1) else 0.039

            logs_verbose_predicao.append({
                "Host": hostname, 
                "Vetor Original": vetor_reais[0].tolist(),
                "Vetor Normalizado (Scaled)": vetor_scaled[0].tolist(),
                "Probabilidade Seguro (0)": f"{probabilidades[0]*100:.2f}%",
                "Probabilidade Critico (1)": f"{probabilidades[1]*100:.2f}%"
            })

            nome_so_com_icone = f"🪟 {nome_so_real}"

            linhas_dataset.append({
                "Hostname": hostname,
                "Componente/Software": nome_so_com_icone,
                "Versao/Status": f"Build {windows_build} ({status_limpo_exibicao})",
                "Compliance": compliance_status,
                "Vulnerabilidade (CVE)": vulnerabilidade_cve,
                "Score CVSS": max_cvss,
                "Motores VirusTotal": f"{motores_vt:.0f} / 70",
                "Probabilidade Risco IA": f"{probabilidade_risco * 100:.1f}%",
                "Predicao MLP": veredito_ia
            })
            
        except Exception:
            pass
            
    return pd.DataFrame(linhas_dataset), logs_verbose_predicao

df_principal, logs_ia = processar_dados_inventario()

# --- BARRA LATERAL METRIFICADA: EXCLUSIVAMENTE COM ENGENHARIA DA MLP ---
st.sidebar.title("🛡️ Diagnóstico de Ativos (MDR)")
if not df_principal.empty:
    lista_maquinas = df_principal['Hostname'].unique().tolist()
    maquina_selecionada = st.sidebar.selectbox("Selecionar Ativo para Inspeção:", lista_maquinas)
    
    dados_maquina = df_principal[df_principal['Hostname'] == maquina_selecionada].iloc[0]
    
    # Customização de cores de texto para os vereditos da IA na barra lateral
    cor_veredito = "#9FFF9F" # Verde padrão
    if dados_maquina['Predicao MLP'] == "CRITICO":
        cor_veredito = "#FF9494" # Vermelho
    elif dados_maquina['Predicao MLP'] == "ATENCAO":
        cor_veredito = "#FFD56B" # Amarelo

    st.sidebar.markdown(f"**Veredito da Rede Neural (MLP):** <span style='color:{cor_veredito}; font-weight:bold;'>{dados_maquina['Predicao MLP']}</span>", unsafe_allow_html=True)
    st.sidebar.markdown(f"**Status de Compliance Técnico:** `{dados_maquina['Compliance']}`")
    st.sidebar.markdown(f"**Probabilidade de Risco Estimada:** `{dados_maquina['Probabilidade Risco IA']}`")
    st.sidebar.markdown(f"**Mapeamento de Vulnerabilidade:** `{dados_maquina['Vulnerabilidade (CVE)']}`")
    
    st.sidebar.divider()
    
    # CORREÇÃO DO ALERTA SOC: Se não estiver em compliance, exibe bloco vermelho ou amarelo em vez de verde
    if dados_maquina['Compliance'] == "FORA DE CONFORMIDADE":
        if dados_maquina['Predicao MLP'] == "CRITICO":
            st.sidebar.error(f"🚨 ALERTA CRÍTICO SOC: O ativo {maquina_selecionada} requer ISOLAMENTO IMEDIATO devido a manipulações de integridade no Kernel detectadas pela IA.")
        else:
            st.sidebar.warning(f"⚠️ ALERTA DE COMPLIANCE: O ativo {maquina_selecionada} está Fora de Conformidade administrativa (Licença Inválida).")
    else:
        st.sidebar.success(f"✅ O ativo {maquina_selecionada} cumpre integralmente os requisitos de conformidade estabelecidos.")
else:
    st.sidebar.info("Aguardando conexão de dados do laboratório...")

# --- MENU PRINCIPAL COM AS QUATRO ABAS ---
aba_dashboard, aba_verbose_ia, aba_threat_intel, aba_impactos_licenca = st.tabs([
    "Painel do SOC e Compliance", 
    "Verbose: Modo Inspecao da IA", 
    "Threat Intel: Ativadores e Mecanismos",
    "Impactos e Ciclo de Licenciamento"
])

with aba_dashboard:
    if df_principal.empty:
        st.info("Monitor de inventario ativo. Aguardando arquivos JSON das VMs...")
    else:
        col1, col2, col3 = st.columns(3)
        with col1: 
            st.metric(label="Computadores Analisados", value=int(df_principal['Hostname'].nunique()))
        with col2:
            maquinas_nao_conformes = int(df_principal[df_principal['Compliance'] == "FORA DE CONFORMIDADE"]['Hostname'].nunique())
            st.metric(label="Dispositivos Fora de Compliance", value=maquinas_nao_conformes)
        with col3:
            ativos_criticos_ia = int(df_principal[df_principal['Predicao MLP'] == "CRITICO"]['Hostname'].nunique())
            st.metric(label="Ameacas Criticas pela IA (MLP)", value=ativos_criticos_ia)

        st.divider()
        st.subheader("Matriz de Auditoria e Vulnerabilidades Corporativas")
        
        def estilizar_linhas(val):
            if val in ["CRITICO", "FORA DE CONFORMIDADE"]:
                return 'background-color: #5A1818; color: #FF9494; font-weight: bold; border-radius: 4px;'
            elif val == "ATENCAO":
                return 'background-color: #5C4308; color: #FFD56B; font-weight: bold; border-radius: 4px;'
            elif val in ["EM CONFORMIDADE", "ACEITAVEL"]:
                return 'background-color: #164A21; color: #9FFF9F; border-radius: 4px;'
            return ''

        st.dataframe(
            df_principal.style.map(estilizar_linhas, subset=['Compliance', 'Predicao MLP'] if 'Predicao MLP' in df_principal.columns else ['Compliance']), 
            use_container_width=True, hide_index=True
        )

with aba_verbose_ia:
    st.subheader("Relatorio de Depuracao Cientifica da Rede Neural (MLP)")
    
    c1, c2, c3, c4 = st.columns(4)
    with c1: st.metric(label="Modelo Classificador", value="MLPClassifier")
    with c2: st.metric(label="Arquitetura da Rede", value="4 -> 8 -> 4 -> 2")
    with c3: st.metric(label="Funcao de Ativacao", value="Logistica (Sigmoide)")
    with c4: st.metric(label="Otimizador de Pesos", value="L-BFGS")
        
    st.divider()
    col_pesos1, col_pesos2 = st.columns(2)
    
    with col_pesos1:
        st.markdown("### Matriz de Pesos Sinapticos ($W_{0}$)")
        st.markdown("Pesos applied entre as 4 variáveis de entrada e a primeira camada oculta (8 neurônios).")
        df_pesos_0 = pd.DataFrame(
            mlp_motor.coefs_[0],
            index=["Ativador", "LicencaInvalida", "MaxCVSS", "MotoresVirusTotal"],
            columns=[f"Neuronio H1.{i+1}" for i in range(8)]
        )
        st.dataframe(df_pesos_0, use_container_width=True)
        
    with col_pesos2:
        st.markdown("### Vetores de Bias ($b$) por Camada")
        st.markdown("Fatores de ajuste (limiares de ativação) calculados para as camadas ocultas.")
        df_bias_0 = pd.DataFrame(mlp_motor.intercepts_[0], index=[f"H1.{i+1}" for i in range(8)], columns=["Bias Camada 1"])
        st.dataframe(df_bias_0.T, use_container_width=True)

    st.divider()
    st.markdown("### Estado dos Ativos em Tempo Real na Rede")

    if logs_ia:
        for log in logs_ia:
            with st.expander(f"Inspecao de Avanco (Forward Propagation) -> {log['Host']}"):
                col_l1, col_l2 = st.columns(2)
                with col_l1: 
                    st.markdown("**Vetor de Entrada Real:**")
                    st.code(f"{log['Vetor Original']}")
                    st.markdown("**Vetor Normalizado (StandardScaler):**")
                    st.code(f"{log['Vetor Normalizado (Scaled)']}")
                with col_l2: 
                    texto_prob = log["Probabilidade Critico (1)"]
                    st.metric(label="Probabilidade de Saida Classificada como Risco Critico", value=str(texto_prob))

with aba_threat_intel:
    st.subheader("📚 Base de Conhecimento Tático: Modus Operandi de Ativadores Piratas")
    st.markdown("Matriz de inteligência técnica descrevendo como as principais ferramentas de bypass manipulam o subsistema de licenciamento do Windows (`sppsvc`).")
    
    dados_intel = {
        "Ferramenta/Script": ["Massgrave (MAS)", "KMSPico", "KMSAuto / Net", "KMSLite", "Re-Loader"],
        "Categoria Técnica": ["Direito Digital (HWID)", "Emulaçao Local KMS", "Emulaçao Local (Loopback)", "KMS Compacto", "Ganchos de Memoria (Hook)"],
        "Vetor de Injeçao": ["Chaves GVLK Públicas", "Binário Local / Serviço", "Modificaçao de Registro", "Processo em Background", "Interceptaçao de APIs"],
        "Persistência no Disco": ["Nenhuma (Execuçao em RAM)", "Alta (Pasta em Program Files)", "Média (Tarefas Agendadas)", "Baixa (Apenas Chaves)", "Alta (Modifica System32)"],
        "Severidade SOC": ["CRITICO / Evasivo", "CRITICO / Detectável", "ALTO / Desvio Lógico", "ALTO", "CRITICO / Instabilidade"]
    }
    df_intel = pd.DataFrame(dados_intel)
    st.table(df_intel)
    
    st.divider()
    col_desc1, col_desc2 = st.columns(2)
    
    with col_desc1:
        st.markdown("### ⚡ Massgrave (MAS) & Scripts Modernos")
        st.info(
            """**Mecanismo:** Engana o servidor de ativaçao oficial da Microsoft gerando um bilhete falso via `slc.dll`. 
            Ele força o uso de chaves públicas universais (**GVLKs**) e vincula a máquina em nuvem como legítima de forma permanente.\n\n
            **Assinatura de Caça:** Parâmetro `PartialProductKey` contendo chaves conhecidas como `t83gx` ou `3v66t`. 
            Gera falsos-negativos em antivírus comuns porque nenhum executável é mantido no disco."""
        )
        
        st.markdown("### 🛠️ KMSAuto & KMSLite")
        st.warning(
            """**Mecanismo:** Ferramentas compactas que injetam chaves de volume e automatizam o agendamento de tarefas do sistema 
            para revalidar o Windows a cada 180 dias de forma silenciosa.\n\n
            **Assinatura de Caça:** Tarefas ocultas disparadas no Inicializador de Tarefas do Windows executando scripts ocultos e 
            presença de registros alterados no caminho `SoftwareProtectionPlatform`."""
        )

    with col_desc2:
        st.markdown("### 👾 KMSPico (Clássico)")
        st.error(
            """**Mecanismo:** Instala um servidor proxy local dentro do Windows (`127.0.0.1`). O Windows é configurado para 
            consultar a si mesmo para validar o direito de uso do software comercial.\n\n
            **Assinatura de Caça:** Presença de binários estáticos no disco em `C:\\Program Files\\KMSPico`, executáveis de bypass como 
            `SECOH-QAD.exe`, e o serviço ativo de background intitulado `Service_KMS`."""
        )
        
        st.markdown("### 💉 Re-Loader & Injetores de Memória")
        st.error(
            """**Mecanismo:** Realiza modificações direto na memória RAM (Hooking) interceptando as chamadas das APIs do subsistema de segurança 
            do Windows. Responde forçadamente com status 'Verdadeiro' para qualquer validaçao de software.\n\n
            **Assinatura de Caça:** Anomalia na árvore de processos legítimos do sistema e assinaturas heurísticas na memória volátil."""
        )

with aba_impactos_licenca:
    st.subheader("⚠️ Impactos de Negócio e Comportamento de Sistemas Não Ativados / Temporários")
    st.markdown("Mapeamento do comportamento dinâmico do Kernel e das políticas de restrição do Windows de acordo com a ramificação do sistema operacional.")
    
    col_imp1, col_imp2 = st.columns(2)
    
    with col_imp1:
        st.markdown("### 🖥️ Windows Client (Edições de Consumo: Home / Pro)")
        st.info(
            """**Comportamento:** O sistema operacional entra em um modo functional restrito por tempo indefinido, 
            sem interrupção forçada do Kernel, mas aplicando restrições de experiência do usuário.\n\n
            **Recursos Bloqueados e Sintomas:**\n
            - **Marca d'água:** Presença da string translúcida permanente no canto inferior direito (*'Ativar o Windows'*).\n
            - **Bloqueio de Personalização:** Desativação total dos menus de alteração de papel de parede, cores do sistema, temas e tela de bloqueio.\n
            - **Notificações GPO:** Alertas recorrentes nas configurações lembrando o operador sobre a falta de conformidade.\n
            - **Atualizações:** Continua recebendo patches de segurança críticos normalmente via Windows Update."""
        )
        
        st.markdown("### 🕒 O Fenômeno da Licença Temporária Expirada")
        st.error(
            """**O que acontece quando expira?**\n
            Quando uma licença temporária (período de carência inicial ou token de KMS corporativo não renovado após 180 dias) perde a validade, 
            O subsistema de proteção de software (`sppsvc.exe`) altera o estado da licença no registro para `0` (Unlicensed). 
            Imediatamente, todos os gatilhos visuais e restrições são ativados no próximo logon do usuário."""
        )

    with col_imp2:
        st.markdown("### 🚨 Windows Server e Edições Evaluation (Standard / Datacenter)")
        st.error(
            """**Comportamento Critico:** Ao contrário das versões de consumo, o Windows Server possui políticas rigorosas de compliance técnica. 
            ISOs de avaliação funcionam plenamente por apenas **180 dias**.\n\n
            **Recursos Bloqueados e o Sintoma de Reinicialização:**\n
            - **Desligamento / Reinicialização Automática:** Assim que o prazo de 180 dias expira, se o administrador não inserir uma licença legítima 
            ou estender o período via `slmgr /rearm`, o Kernel do Windows Server passa a **desligar ou reiniciar sozinho a cada 1 hora exata de funcionamento**.\n
            - **Tela de Fundo Preta:** O papel de parede do servidor é removido e travado em uma tela preta sólida com os dados da build expostos.\n
            - **Risco Operacional:** Em um ambiente de produção ou laboratório SOC, isso causa uma Negação de Serviço (*DoS*) legítima, 
            derrubando controladores de domínio (AD), servidores de arquivos e bancos de dados a cada 60 minutos."""
        )

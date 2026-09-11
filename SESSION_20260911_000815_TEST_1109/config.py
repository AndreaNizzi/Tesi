import os
from sqlalchemy import create_engine
from dotenv import load_dotenv
from typing import Set


load_dotenv()

# Configurazione Connessione Database 
DB_USER = 'root'
DB_PASS = os.environ.get("DB_PASSWORD")  
DB_HOST = 'localhost'
DB_NAME = 'thesis_network'

try:
    engine = create_engine(
        f'mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_HOST}/{DB_NAME}?charset=utf8mb4'
    )
except Exception as e:
    print(f"Errore nella creazione dell'engine SQLAlchemy: {e}")
    engine = None


class Soglie:
    # --- PORTE E SERVIZI ---
    PORTE_WEB_L7 = {80, 443, 8080, 8443, 8000}
    PORTE_DNS = {53}
    PORTE_INFRASTRUTTURA_LAN = {53, 88, 137, 138, 139, 389, 445, 636}
    PORTE_ORDINARIE_WEB_DNS = PORTE_WEB_L7.union(PORTE_DNS)
    
    # Mantenere PORTE_GESTIONE come SET per la logica di controllo SQL/Python:
    PORTE_GESTIONE = {21, 22, 23, 3389, 5900, 2222}
    PORTE_GESTIONE_STR: str = "21 (FTP), 22 (SSH), 23 (Telnet), 3389 (RDP), 5900 (VNC), 2222"
    PORTE_ORDINARIE_WEB = PORTE_WEB_L7

    # --- BEACONING / C2 ---
    CV_BEACON_STRICT = 0.15
    CV_BEACON_JITTER_MAX = 0.60  
    BEACON_MIN_CONNESSIONI = 15  # Incrementato da 5 a 15 per evitare FP su Benign
    ANOMALY_SCORE_C2_MIN = 70
    BEACON_TOP_N_DEFAULT = 10
    BEACON_DOS_VOLUME_THRESHOLD = 200

    # --- ANOMALY SCORES PREDEFINITI ---
    SCORE_WHITELISTED = 10
    SCORE_DEFAULT = 0
    SCORE_MAX = 100

    # --- SCAN / BRUTEFORCE ---
    SCAN_PORTE_MIN = 15  
    EPHEMERAL_SCAN_MIN_PORTS = 25
    BRUTEFORCE_TENTATIVI_MIN = 25
    SCAN_IP_SWEEP_MIN_NONWEB = 10
    SCAN_AGGRESSIVE_PPS_MIN = 100.0
    SCAN_PROBE_MAX_PACCHETTI = 4

    # --- DOS VOLUMETRICO & SLOWLORIS ---
    MS_IN_SEC = 1000.0
    DOS_PPS_MIN = 3000.0
    DOS_L7_FLUSSI_MIN = 50
    DOS_L7_RPS_MIN = 10.0
    SLOWLORIS_FLUSSI_MIN = 50
    SLOWLORIS_DURATION_MS = 60000
    SLOWLORIS_MAX_BYTES = 1000
    DOS_PPS_MIN_FALLBACK = 1000.0
    SLOWLORIS_FLUSSI_MIN_FALLBACK = 50
    CONCENTRAZIONE_DOS_MIN = 25.0   # flussi/destinazione minimi per parlare di flood concentrato

    # --- WEB ATTACK & EXFILTRATION ---
    WEBATTACK_ENTROPIA_MAX = 4.0
    ENTROPIA_L7_SOGLIA = 7.2
    WEBATTACK_MIN_RICHIESTE_BREVI = 15
    WEBATTACK_SCORE_SATURATION = 5
    WEBATTACK_MAX_BYTES = 2000
    EXFILTRATION_BYTE_RATE_MIN = 1048576
    WEB_SCORE_MIN_FOR_PRIORITY = 0.30

    # --- CAMPIONE MINIMO E MARGINI ---
    FLUSSI_MIN_CAMPIONE_AFFIDABILE = 10
    CONFIDENZA_MARGINE_ALTO = 0.3
    CONFIDENZA_MARGINE_MEDIO = 0.15
    DENSITA_FLUSSI_ELEVATA_MIN = 500
    DEFAULT_WINDOW_SECONDS = 900.0

    # --- LIMITI OPERATIVI E CACHE ---
    LIMIT_QUERY_FLUSSI = 5000
    LIMIT_DEFAULT_QUERY = 10
    LIMIT_TRAFFIC_SUMMARY = 15
    MAX_ERR_LOG_CHARS = 200
    FLUSSO_DURATA_MIN_MS = 500
    FLUSSO_PACCHETTI_MIN = 5
    AUTO_FIX_STEP_LIMIT_DEFAULT = 100
    CACHE_TTL_SECONDS = 300

    # --- AGENT WORKFLOW ---
    MAX_DRILLDOWN_TURNS = 10
    MAX_RETRY_REPORT = 3

    # --- LIMITI CONTESTO LLM ---
    PRUNING_MAX_CHARS_DEFAULT = 4000
    PRUNING_MAX_MESSAGES_DEFAULT = 6
    PRUNING_MAX_MESSAGES_GPT_OSS = 4
    PRUNING_TOOL_CHARS_DEFAULT = 2000
    PRUNING_MAX_TOOL_CHARS_GROQ = 300
    PRUNING_TOOL_CHARS_CAP = 1500
    PRUNING_LINEE_VECCHIE_LIMIT = 20
    PRUNING_LIMITE_VECCHI_MIN = 1000
    TRONCAMENTO_TOOL_RAW_MAX = 1500
    TRONCAMENTO_FIELD_MAX_CHARS = 150
    TRONCAMENTO_LINEE_VECCHIE = 20
    TOOL_DESC_MAX_CHARS = 300
    REPORT_CONTEXT_MAX_CHARS_GPT_OSS = 3000
    REPORT_CONTEXT_MAX_CHARS_DEFAULT = 6000

    # --- SWEEP MULTI-SERVIZIO (fascia intermedia tra bruteforce singolo e scan largo) ---
    SWEEP_PORTE_MIN = 4                 # sotto questa soglia è troppo poco per parlare di sweep
    SWEEP_CONCENTRAZIONE_MAX = 0.70     # se una porta domina oltre il 70% dei flussi, non è uno sweep

# ------------------------------------------------------------------------------
# 2. ENFORCEMENT TOOL OBBLIGATORI
# ------------------------------------------------------------------------------

TOOL_OBBLIGATORI: Set[str] = {
    "get_rate_statistics",
    "get_host_port_distribution",
    "search_connection_attempts",
    "search_http_l7_anomalies",
    "detect_beaconing",
    "compute_verdict_scores",  # Deve essere eseguito come ultimo step
}
tool_chiamati: Set[str] = set()
tool_obbligatori_str = ", ".join(f"'{t}'" for t in TOOL_OBBLIGATORI)

import os
import textwrap
from sqlalchemy import create_engine
from dotenv import load_dotenv
from pydantic import BaseModel, Field
from typing import get_args, Literal
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
    PORTE_GESTIONE_SET = {21, 22, 23, 3389, 5900, 2222}
    PORTE_GESTIONE: str = "21 (FTP), 22 (SSH), 23 (Telnet), 3389 (RDP), 5900 (VNC), 2222"
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

    # --- WEB ATTACK & EXFILTRATION ---
    WEBATTACK_ENTROPIA_MAX = 4.0
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
    
# ------------------------------------------------------------------------------
# 1. ENUMERAZIONI, SCHEMI E RIGIDO INSIEME DEI VERDETTI
# ------------------------------------------------------------------------------

VerdettoEnum = Literal[
    "DOS_VOLUMETRIC",
    "SCAN_BRUTEFORCE",
    "BEACONING_C2",
    "WEB_ATTACK_EXPLOIT",
    "BENIGN",
]

VERDETTI_AMMESSI = get_args(VerdettoEnum)
verdetti_str = ", ".join(VERDETTI_AMMESSI)


class ReportForense(BaseModel):
    motivazione: str = Field(
        ...,
        description=(
            "Sintesi in 1-2 frasi basata unicamente sui dati reali dei log. "
            "Specifica n° flussi, porte, protocolli e metriche PPS/payload se presenti. "
            "NON citare mai porte o protocolli assenti dai dati."
        ),
    )
    verdetto: VerdettoEnum = Field(
        ...,
        description="Verdetto finale vincolato rigorosamente all'enumerazione ammessa.",
    )

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

# ------------------------------------------------------------------------------
# 3. DIRETTIVE DI SISTEMA E DISAMBIGUAZIONE SEMANTICA (AGGIORNATE)
# ------------------------------------------------------------------------------


DIRETTIVA_VERDETTO_TEXT = """
--- DIRETTIVA TASSATIVA SUL VERDETTO FINALE ---
1. ESEGUI 'compute_verdict_scores' ESCLUSIVAMENTE COME ULTIMO TOOL, dopo tutti gli altri tool obbligatori.
2. Il campo 'scores' che il tool restituisce contiene punteggi 0-1 già normalizzati e direttamente
   comparabili tra loro. NON tentare di ricalcolarli, verificarli o confrontarli a mano con le soglie
   viste nei log dei singoli tool — il calcolo che li produce tiene già conto di tutti i segnali rilevanti.
3. Il campo 'verdetto_suggerito' è VINCOLANTE al 100%. Il tuo VERDETTO finale deve coincidere
   esattamente con questo valore, senza eccezioni, in nessun caso.
4. È RIGOROSAMENTE VIETATO qualunque override manuale, anche se ritieni che i log mostrino
   evidenze diverse — il tool ha già visto ed elaborato tutti quei dati.
5. La MOTIVAZIONE deve spiegare, con le metriche reali del log, PERCHÉ quel verdetto è coerente
   con l'evidenza — mai proporre un verdetto alternativo o discuterne la validità.
"""

FONTE_PRIMARIA_TEXT = """
--- REGOLA DI ATTRIBUZIONE EVIDENZE (VINCOLANTE) ---
- Il campo 'pps_aggregati' / 'flussi_slowloris' conta SOLO per DOS_VOLUMETRIC.
- Il campo 'porte_uniche_contattate' conta SOLO per SCAN_BRUTEFORCE.
- Il campo 'cv' / 'anomaly_score' di detect_beaconing conta SOLO per BEACONING_C2.
- Il campo 'anomalie_l7_trovate' conta SOLO per WEB_ATTACK_EXPLOIT.
Un segnale alto in una di queste metriche NON deve MAI essere citato a supporto di una categoria diversa da quella a cui è assegnata qui.
I tool 'get_traffic_summary', 'get_flow_features' e 'resolve_host_info' forniscono SOLO contesto descrittivo e non possono da soli giustificare un verdetto.
"""

system_prompt = {
    "role": "system",
    "content": (
        "Sei un agente esperto in Network Forensics e Threat Detection.\n"
        "Il tuo compito è eseguire i tool obbligatori nell'ordine indicato ed emettere "
        "il report forense finale in formato JSON, adottando il verdetto deterministico "
        "calcolato da 'compute_verdict_scores'.\n\n"
        f"I VERDETTI CONSENTITI SONO ESCLUSIVAMENTE: [{verdetti_str}].\n\n"
        "NON usare titoli Markdown, grassetti o blocchi di codice nei campi di testo.\n\n"
        f"{DIRETTIVA_VERDETTO_TEXT}\n\n"
        f"{FONTE_PRIMARIA_TEXT}\n\n"
        "--- SCHEMA DATABASE E SEMANTICA CAMPI (ndpi_flows) ---\n"
        "- id (bigint): Identificativo univoco della connessione.\n"
        "- community_id (varchar): Hash univoco 5-tuple della connessione di rete.\n"
        "- src_ip / dst_ip (varchar): IP sorgente e destinazione.\n"
        "- src_port / dst_port (int): Porte logiche sorgente e destinazione.\n"
        "- protocol (int): Protocollo di trasporto L4 (6=TCP, 17=UDP).\n"
        "- timestamp_start (timestamp): Ora di inizio del flusso di rete.\n"
        "- duration_ms (double): Durata della connessione in MILLISECONDI.\n"
        "- total_bytes, total_fwd_bytes, total_bwd_bytes (bigint): Volumi di dati scambiati.\n"
        "- fwd_packets, bwd_packets (bigint): Conteggio pacchetti inviati/ricevuti.\n"
        "- packet_rate (double): Frequenza media pacchetti/secondo (PPS) del flusso.\n"
        "- byte_rate (double): Velocita' di trasferimento in Byte/secondo.\n"
        "- iat_flow_avg / iat_flow_stddev (double): Media e deviazione standard dell'Inter-Arrival Time.\n"
        "- tcp_flags (int): Flag TCP.\n"
        "- ndpi_hostname (varchar): Nome di dominio/host estratto da nDPI.\n"
        "- payload_entropy (double): Entropia del payload.\n"
        "- app_hierarchy (varchar): Classificazione del protocollo applicativo.\n"
        "- infra_provider (varchar): Cloud Provider o ASN della destinazione.\n"
        "- tls_version, tls_cipher_suite, tls_ja4, tls_issuer_dn (varchar): Impronte TLS.\n\n"
        "\n--- PIANO D'AZIONE RIGIDO (SEQUENZA OBBLIGATORIA) ---\n"
        "Passo 1: get_rate_statistics\n"
        "Passo 2: get_host_port_distribution\n"
        "Passo 3: search_connection_attempts\n"
        "Passo 4: search_http_l7_anomalies\n"
        "Passo 5: detect_beaconing\n"
        "Passo 6: compute_verdict_scores COME ULTIMO STEP (mai prima)\n"
        "Passo 7: genera il report JSON usando ESATTAMENTE 'verdetto_suggerito' come 'verdetto'\n\n"
        f"Prima di rispondere devi aver eseguito: {tool_obbligatori_str}.\n"
    ),
}

sys_instruction_report = (
    "Sei un analista forense che formatta un report a partire da un verdetto già deciso.\n\n"
    "REGOLE TASSATIVE:\n"
    "1. NON menzionare porte, IP o protocolli assenti dalle EVIDENZE OGGETTIVE.\n"
    f"2. VERDETTI AMMESSI: [{verdetti_str}].\n"
    "3. Il campo 'verdetto' DEVE essere identico, carattere per carattere, al valore "
    "'VERDETTO SUGGERITO DAI TOOL' fornito nel prompt utente. Non è una proposta, è un dato vincolante.\n"
    "4. Se il verdetto è WEB_ATTACK_EXPLOIT, è VIETATO citare exploit specifici (SQLi/XSS/RCE) — "
    "usa solo 'anomalia applicativa HTTP'.\n"
    f"{FONTE_PRIMARIA_TEXT}\n"
)

FOCUS_CATEGORIE = {
    "cat_a": (
        "PIANO D'AZIONE INVESTIGATIVO: ISPEZIONE TRAFFICO WEB/APPLICATIVO\n- "
        "Ambito prioritario: Focus sui servizi Web (dst_port: 80, 443, 8080, 8443) e anomalie L7.\n- "
        "Tool suggeriti: Utilizza obbligatoriamente 'search_http_l7_anomalies'.\n- "
        "REQUISITO WEB ATTACK: Cerca concentrazioni di richieste brevi (<2000 byte) a bassa entropia "
        "tramite 'search_http_l7_anomalies'. NON cercare o citare firme di exploit specifiche (SQLi/XSS/RCE) "
        "poiché il DB non ha URI o body. Usa sempre la dicitura generica 'anomalia applicativa HTTP'."
    ),
    "cat_b": (
        "PIANO D'AZIONE INVESTIGATIVO: VALUTAZIONE CARICO E SESSIONI\n- "
        "Ambito prioritario: Focus su volume (total_bytes), frequenza (packet_rate), durata e concentrazione di connessioni.\n- "
        "REGOLA DOS: L'attribuzione tra volume e anomalia Web viene gestita automaticamente da compute_verdict_scores."
    ),
    "cat_c": (
        "PIANO D'AZIONE INVESTIGATIVO: MAPPATURA ENDPOINT E ACCESSI\n- "
        "Ambito prioritario: Focus su porte di gestione (22, 3389, 21), scansione di PORTE DESTINAZIONE MULTIPLE e tentativi di login.\n- "
        "DISTINZIONE FONDAMENTALE: Le porte SORGENTE dinamiche/casuali verso un'unica porta DESTINAZIONE indicano un attacco o traffico verso un servizio "
        "(DoS/Web), NON uno SCAN_BRUTEFORCE. Lo Scan richiede multiple PORTE DESTINAZIONE distinte."
    ),
    "cat_d": (
        "PIANO D'ACTION INVESTIGATIVO: METRICHE TEMPORALI E CICLICITÀ\n- "
        "Ambito prioritario: Focus sulle metriche IAT e rilevamento beaconing (detect_beaconing).\n- "
        "Segui la classificazione restituita dal tool deterministico."
    ),
    "cat_e": (
        "PIANO D'ACTION INVESTIGATIVO: ESPLORAZIONE GLOBALE\n- "
        "Esplora i dati bilanciando rate, porte e payload L7 senza dare nulla per scontato."
    ),
}

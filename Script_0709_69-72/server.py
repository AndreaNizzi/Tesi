
import json
import time
import functools
import datetime
import ipaddress
import urllib.parse
import re
from typing import Union, Optional, Dict, Any, Tuple
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP
from sqlalchemy import text

import config

load_dotenv()

mcp = FastMCP("DPI-Network-Analyzer")

# =====================================================================
# SISTEMA DI CACHING E DEDUPLICAZIONE MCP
# =====================================================================

execution_cache: Dict[str, Dict[str, Any]] = {}
CACHE_TTL_SECONDS = config.Soglie.CACHE_TTL_SECONDS

DOMINI_WHITELIST_BEACONING = [
    "hotjar.com", "ioam.de", "google.com", "googleapis.com",
    "cloudflare.com", "mozilla.org", "akamaized.net", "facebook.com",
    "googleadservices.com", "googlesyndication.com", "googletagservices.com",
    "digicert.com", "amazontrust.com", "cloudfront.net", "rubiconproject.com",
    "quantserve.com", "usertrust.com", "symcd.com"
]

DOMINI_WHITELIST_L7 = [
    "akamai", "akamaized.net", "comodo.com", "digicert.com", 
    "sectigo.com", "letsencrypt.org", "godaddy.com", "microsoft.com",
    "apple.com", "canonical.com", "ubuntu.com", "google.com"
]

# 1 _detect_beaconing_raw
def _is_whitelisted(hostname: str, whitelist: list[str]) -> bool:
    if not hostname:
        return False
    hostname = hostname.lower().rstrip(".")
    return any(hostname == d or hostname.endswith("." + d) for d in whitelist)

def _is_l7_whitelisted(app_hierarchy: str, hostname: str) -> bool:
    app = (app_hierarchy or "").lower()
    host = (hostname or "").lower()
    
    # Check protocolli OCSP / CRL / Telemetria
    if "ocsp" in app or "crl" in app:
        return True
        
    # Check domini noti CDN / Certificate Authorities
    return any(dom in host for dom in DOMINI_WHITELIST_L7)

# 1 _detect_beaconing_raw
def _compute_anomaly_score(
    cv: float, 
    totale_connessioni: int, 
    is_whitelisted: bool, 
    dst_ip: str,
    dst_port: int = 0
) -> Tuple[int, list]:
    tag_list = []
    s = config.Soglie

    if is_whitelisted:
        tag_list.append("WHITELISTED_SERVICE")
        return s.SCORE_WHITELISTED, tag_list

    if _is_ip_privato(dst_ip):
        tag_list.append("INTERNAL_LAN_KEEPALIVE")
        return s.SCORE_DEFAULT, tag_list

    # FIX CASO 016/046: Gestione progressiva del CV con tolleranza al Jitter fino a CV <= 1.2
    if totale_connessioni >= s.BEACON_MIN_CONNESSIONI:
        if cv <= 0.6:
            score = s.ANOMALY_SCORE_C2_MIN + 30  # ~100
            tag_list.append("CONFIRMED_BEACONING_C2")
            return score, tag_list
        elif 0.6 < cv <= 1.2:
            # Score decrescente dinamico da 80 a 50
            moles_score = int(80 - ((cv - 0.6) / 0.6) * 30)
            
            # Porta non standard (>1024 e non web standard) alza il sospetto
            if dst_port > 1024 and dst_port not in (8080, 8443):
                moles_score = min(100, moles_score + 15)
                
            tag_list.append("SUSPECTED_BEACONING_JITTER")
            return moles_score, tag_list

    return s.SCORE_DEFAULT, tag_list

# 1 mcp_cache_guard
def pulisci_cache_scaduta():
    """Elimina dalla memoria tutte le chiavi più vecchie di CACHE_TTL_SECONDS."""
    ora_attuale = time.time()
    chiavi_da_eliminare = [
        k for k, v in execution_cache.items() 
        if ora_attuale - v["timestamp"] > CACHE_TTL_SECONDS
    ]
    for k in chiavi_da_eliminare:
        del execution_cache[k]

# 15 server
def mcp_cache_guard(func):
    """
    Decoratore che intercetta l'esecuzione del tool.
    Se la query è gia+ stata fatta, restituisce il risultato precedente.
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        pulisci_cache_scaduta()
        
        tool_name = func.__name__

        payload_parametri: Dict[str, Any] = dict(kwargs)
        if args:
            payload_parametri["_positional_args"] = list(args)

        # Garantisce che offset e limit differenti generino SEMPRE chiavi di cache distinte
        params_copy = dict(kwargs)
        if args:
            params_copy["_args"] = list(args)

        # Normalizza offset e limit se presenti per evitare falsi positivi di deduplicazione
        offset_val = params_copy.get("offset", 0)
        limit_val = params_copy.get("limit", 50)
        params_copy["_pagination_sig"] = f"off:{offset_val}_lim:{limit_val}"

        cache_key = f"{tool_name}:{json.dumps(params_copy, sort_keys=True, default=str)}"
            
        current_time = time.time()

        if cache_key in execution_cache:
            cache_entry = execution_cache[cache_key]
            if current_time - cache_entry["timestamp"] < CACHE_TTL_SECONDS:
                risultato_precedente = cache_entry["response"]
                
                return (
                    f"[AVVISO MCP - CHIAMATA DUPLICATA]: Hai gia' eseguito il tool '{tool_name}' "
                    f"con i medesimi parametri in questo ciclo investigativo.\n"
                    f"Sotto trovi il RISULTATO PRECEDENTE gia' estratto dal database:\n\n"
                    f"{risultato_precedente}\n\n"
                    f"[ISTRUZIONE PER L'AGENTE]: NON rieseguire questa query con gli stessi parametri. "
                    f"Sintetizza i dati sopra oppure cambia i parametri temporali / invoca un tool di drill-down diverso."
                )

        result = func(*args, **kwargs)

        if isinstance(result, str) and not result.startswith("[ERRORE TOOL]"):
            execution_cache[cache_key] = {
                "timestamp": current_time,
                "response": result
            }

        return result
    return wrapper

# 1 get_flow_features, 1 analyze_dpi_details, 1 query_by_rate, 1  get_traffic_summary, 1 get_aggregated_traffic_summar, 1 analizza_connessione_by_community_id
def arricchisci_protocollo(proto_num: int) -> str:
    mapping = {1: "1 (ICMP)", 6: "6 (TCP)", 17: "17 (UDP)"}
    return mapping.get(proto_num, f"{proto_num} (Sconosciuto)")
# 2 calcola_durata_finestra_reale, 2 search_connection_attempts, 2 get_flow_features, 2 get_top_talkers, 
# 2 analyze_dpi_detail, 2 resolve_host_info, 2 query_by_rate, 2 inspect_http_requests, 
# 2 get_traffic_summary, 2 get_aggregated_traffic_summary, 2 _detect_beaconing_raw, 
# 2 _search_http_l7_anomalies_raw, 2 _get_rate_statistics_raw, 2 _get_host_port_distribution_raw
def normalizza_data(data_str: str, is_end: bool = False) -> str:
    """
    Se l'LLM omette l'orario (es. 'YYYY-MM-DD'), aggiunge le ore/minuti/secondi.
    """
    data_str = data_str.strip()
    if len(data_str) == 10:
        return data_str + (" 23:59:59" if is_end else " 00:00:00")
    return data_str
# 1 get_traffic_summary, 1 get_aggregated_traffic_summary, 1 _get_rate_statistics_raw
def calcola_durata_finestra_reale(start_time: str, end_time: str) -> float:
    start_norm = normalizza_data(start_time, is_end=False)
    end_norm = normalizza_data(end_time, is_end=True)

    try:
        dt_s = datetime.fromisoformat(start_norm.replace('Z', '+00:00'))
        dt_e = datetime.fromisoformat(end_norm.replace('Z', '+00:00'))
        return max((dt_e - dt_s).total_seconds(), 1.0)
    except Exception:
        return config.Soglie.DEFAULT_WINDOW_SECONDS

def _is_ip_privato(ip_str: Optional[str]) -> bool:
    """Verifica se un indirizzo IP fa parte di subnet private/LAN (RFC 1918 / Loopback)."""
    if not ip_str or str(ip_str).strip().lower() in ("none", "null", "", "n/a"):
        return False
    try:
        return ipaddress.ip_address(str(ip_str).strip()).is_private
    except ValueError:
        return False

# ==============================================================================
# COSTANTI DI DESCRIZIONE (DINAMICHE DA CONFIG)
# ==============================================================================

DESC_SEARCH_CONNECTION_ATTEMPTS = f"""
Rileva tentativi di connessione e scansioni di rete (Port Scan, Network Sweep, Brute Force).

PARAMETRI FONDAMENTALI:
- ip_target: IP dell'host sotto indagine (RACCOMANDATO: inserire sempre l'IP target).
- target_port: Specifica una porta per analizzare tentativi di Brute Force mirati.

METRICHE E SOGLIE DI VALUTAZIONE (valutazione_mcp):
- Port Scan ad Alto Volume: porte_distinte >= {config.Soglie.SCAN_PORTE_MIN} -> 'SOSPETTO_PORTSCAN'
- Port Scan Lento/Stealth: porte_distinte >= 2 -> 'SOSPETTO_PORTSCAN_LOW_VOLUME'
- Brute Force: tentativi_totali >= {config.Soglie.BRUTEFORCE_TENTATIVI_MIN} su porte di gestione -> 'SOSPETTO_BRUTEFORCE'
- Brute Force Lento: tentativi_totali >= 2 su porte di gestione -> 'SOSPETTO_BRUTEFORCE_LOW_VOLUME'
"""

DESC_GET_FLOW_FEATURES = f"""
Estrae le metriche temporali e statistiche avanzate (IAT, Entropia, Flag TCP) dei flussi del target.

METRICHE E INTERPRETAZIONE:
- iat_flow_avg / iat_flow_stddev (Inter-Arrival Time):
    * stddev molto bassa + avg costante -> Automatismo matematico / Botnet / C2.
- FLAG_SLOWLORIS_SUSPECT:
    * True -> Connessione HTTP/HTTPS attiva per >= {config.Soglie.SLOWLORIS_DURATION_MS // int(config.Soglie.MS_IN_SEC)}s con volume trasferito < {config.Soglie.SLOWLORIS_MAX_BYTES} B (Slow HTTP DoS).
- duration_ms: Ordina per flussi a più lunga durata per evidenziare connessioni persistenti.

QUANDO USARLO:
Usare per un'analisi comportamentale approfondita dopo aver identificato l'IP coinvolto in un'anomalia.
"""

DESC_GET_TOP_TALKERS = f"""
Identifica gli host sorgente che generano il maggior traffico nella rete (Top Talkers).

PARAMETRI E SOGLIE RACCOMANDATE:
- top_n: Numero di host da restituire (default {config.Soglie.BEACON_TOP_N_DEFAULT}, max 50).
- criterion: 
    * 'bytes'   -> Identifica sorgenti di esfiltrazione o trasferimenti di grandi file.
    * 'packets' -> Identifica sorgenti di Port Scanning, Brute Force o SYN Flood.

QUANDO USARLO:
Trattalo come step iniziale nelle indagini generiche o non mirate, per isolare gli IP che monopolizzano la rete.
"""

DESC_ANALYZE_DPI_DETAILS = f"""
Esegue un'analisi profonda Deep Packet Inspection (DPI/L7) sui flussi del target.

METRICHE RESTITUITE E INTERPRETAZIONE:
- payload_entropy: Valore da 0.0 a 8.0.
    * > 7.0: Indicatore di traffico cifrato malevolo, obfuscation o esfiltrazione.
    * <= {config.Soglie.WEBATTACK_ENTROPIA_MAX}: Tipico di testo in chiaro o traffico applicativo non cifrato.
- tls_version / tls_cipher_suite: Permette di individuare cifrati deboli o agenti C2 che usano suite obsolete.
- app_hierarchy / ndpi_hostname: Mostra il protocollo applicativo reale e la destinazione SNI/DNS.

QUANDO USARLO:
Usalo dopo aver isolato un IP sospetto per analizzarne i dettagli applicativi e rilevare anomalie L7.
"""

DESC_RESOLVE_HOST_INFO = f"""
Riconnette l'IP target a nomi di dominio (ndpi_hostname/SNI) e Service Provider Cloud (infra_provider).

METRICHE RESTITUITE E INTERPRETAZIONE:
- infra_provider: Indica l'infrastruttura di hosting (es. AWS, Cloudflare, DigitalOcean). Utile per rilevare nodi C2 su cloud pubblici.
- ndpi_hostname: Dominio richiesto durante l'handshake.

QUANDO USARLO:
Usalo durante il profiling dell'host per capire a quali servizi/domini esterni si collega l'IP analizzato.
"""

DESC_QUERY_BY_RATE = f"""
Isola e filtra i flussi la cui frequenza supera una specifica soglia di sicurezza.

PARAMETRI E SOGLIE CONSIGLIATE:
- metric: 'packet_rate' (pacchetti/sec) o 'byte_rate' (byte/sec).
- threshold (Soglie raccomandate):
    * metric='packet_rate' e threshold={config.Soglie.DOS_PPS_MIN} -> Trova flussi ad altissimo impatto (DoS Flood).
    * metric='packet_rate' e threshold={config.Soglie.SCAN_AGGRESSIVE_PPS_MIN} -> Trova flussi di scansione aggressiva.
    * metric='byte_rate'   e threshold={config.Soglie.EXFILTRATION_BYTE_RATE_MIN} ({config.Soglie.EXFILTRATION_BYTE_RATE_MIN // (1024 * 1024)} MB/s) -> Trova flussi con esfiltrazione dati massiva.
    
QUANDO USARLO:
Usare DOPO 'get_rate_statistics' per estrarre l'elenco esatto dei flussi responsabili del picco di traffico.
"""

DESC_INSPECT_HTTP_REQUESTS = f"""
Estrae la telemetria L7/HTTP (porte {config.Soglie.PORTE_ORDINARIE_WEB_DNS}) per l'host target.

METRICHE E INTERPRETAZIONE:
- payload_entropy: Valore da 0.0 a 8.0.
    * Entropy > 7.0: Payload cifrato, compresso o exfiltration di dati.
    * Entropy <= {config.Soglie.WEBATTACK_ENTROPIA_MAX}: Tipico di testo in chiaro o richieste Web standard/non cifrate.
- total_bytes: Distingue richieste vuote/scansioni da esfiltrazione/upload.

LIMITAZIONE TECNICA FONDAMENTALE:
Il database NON registra URI completi, header HTTP, o parametri GET/POST.
"""

DESC_GET_TRAFFIC_SUMMARY = f"""
Sintesi volumetrica del traffico (L3/L4) per un IP target.

METRICHE RESTITUITE:
- pps_complessivi: Pacchetti al secondo aggregati. (>{config.Soglie.DOS_PPS_MIN} PPS indica attacco volumetrico/DoS).
- totale_flussi_reali: Conteggio totale flussi (>{config.Soglie.DENSITA_FLUSSI_ELEVATA_MIN} indica Connection Exhaustion o Scanning).

QUANDO USARLO:
Usare come primissimo step per escludere o confermare attacchi volumetrici (DDoS/SYN Flood).
"""

DESC_GET_AGGREGATED_TRAFFIC_SUMMARY = f"""
PASSO FONDAMENTALE DI TRIAGE: Raggruppa il traffico per (dst_ip, dst_port, protocollo, app).
Bypassa i limiti di campionamento dei singoli flussi.

METRICHE E INTERPRETAZIONE:
- totale_flussi: Elevato (>{config.Soglie.DENSITA_FLUSSI_ELEVATA_MIN}) verso una sola porta -> Possibile Port Scan o Syn Flood.
- bytes_per_sec: Volume di banda occupato.
- packets_per_sec_aggregati_porta:
    * > {config.Soglie.DOS_PPS_MIN} PPS: Attacco volumetrico/DoS in corso su quella porta.
    * < {config.Soglie.BEACON_TOP_N_DEFAULT} PPS: Traffico standard o comunicazioni a basso volume.

QUANDO USARLO: All'inizio dell'analisi per identificare quali porte o IP remoti concentrano il traffico.
"""

DESC_COMPUTE_VERDICT_SCORES = f"""
Calcola i punteggi deterministici (0-1) per ogni categoria di minaccia ed applica la gerarchia forense aziendale (precedenze qualitative L7/Beaconing).
Restituisce il 'candidato_predominante' vincolante e il livello di confidenza.
ELIMINA totalmente l'arbitraggio dell'analista e l'override manuale.
"""

DESC_DETECT_BEACONING = f"""
Rileva comunicazioni cicliche e persistenti (Heartbeat/Beaconing) verso C2 o Botnet.

METRICHE RESTITUITE:
- cv (Coefficient of Variation = std_sec / avg_sec):
    * cv < {config.Soglie.CV_BEACON_STRICT}: periodicita' matematica (Script/Botnet).
    * {config.Soglie.CV_BEACON_STRICT} <= cv < {config.Soglie.CV_BEACON_JITTER_MAX}: periodicita' con jitter.
    * cv >= {config.Soglie.CV_BEACON_JITTER_MAX}: non periodico (traffico umano/casuale).
    * cv = 999.0: intervallo medio ~0 (richieste quasi-simultanee/burst), NON è beaconing
      periodico — valuta come possibile prefetch/batch di risorse (es. OCSP/CDN), non come C2.
- anomaly_score: punteggio 0-100.
    * >= {config.Soglie.ANOMALY_SCORE_C2_MIN}: soglia minima per considerare C2 reale.
- Richiede almeno {config.Soglie.BEACON_MIN_CONNESSIONI} connessioni per essere affidabile
  (sotto questa soglia il cv non è statisticamente robusto).

REGOLE INTERPRETATIVE:
- Se 'WHITELISTED_SERVICE' è nei tag, l'anomalia è un falso positivo noto
  (es. Google, Cloudflare, Analytics, OCSP).
- Se 'HIGH_VOLUME_DOS_SUSPECT' è nei tag (>= {config.Soglie.BEACON_DOS_VOLUME_THRESHOLD} connessioni),
  è un segnale INFORMATIVO di volume elevato — NON esclude di per sé il beaconing (un C2 molto
  chiacchierone può avere sia volume alto sia cv basso). Valuta entrambi i segnali insieme;
  la scelta tra BEACONING_C2 e DOS_VOLUMETRIC come verdetto finale spetta a compute_verdict_scores,
  non a questo tool.
"""

DESC_SEARCH_HTTP_L7 = f"""
Ispeziona flussi Web (porte 80/443/8080/8443) per rilevare concentrazioni anomale di
richieste HTTP sospette.

METRICHE:
- payload_entropy: {config.Soglie.WEBATTACK_ENTROPIA_MAX} o meno = testo in chiaro
  (compatibile con exploit HTTP classici, MA da solo NON prova un exploit specifico).
- anomalie_l7_trovate: conteggio di coppie (dst_ip, dst_port) con almeno
  {config.Soglie.WEBATTACK_MIN_RICHIESTE_BREVI} richieste brevi (<{config.Soglie.WEBATTACK_MAX_BYTES} byte) a bassa entropia
  concentrate sullo stesso endpoint.

LIMITAZIONE STRUTTURALE: il DB non contiene URI, header o body. Questo tool NON PUÒ confermare
SQLi/XSS/Path Traversal/RCE specifici. 'anomalie_l7_trovate' indica CONCENTRAZIONE ANOMALA di
richieste HTTP sospette per pattern strutturale (entropia + frequenza), non firme di exploit.
Non menzionare tipologie di exploit specifiche nella motivazione finale — usa "anomalia
applicativa HTTP" generica.

REGOLA DI PRIORITÀ INTERPRETATIVA: se sono presenti sia anomalie L7 sia una cadenza periodica
regolare (confermata da detect_beaconing), il verdetto PRIMARIO deve essere BEACONING_C2, non
WEB_ATTACK_EXPLOIT. Un volume/rate elevato su porta web, da solo, è terreno di DOS_VOLUMETRIC,
non di WEB_ATTACK_EXPLOIT.

QUANDO USARLO: fonte primaria per WEB_ATTACK_EXPLOIT (vedi FONTE PRIMARIA PER CATEGORIA nel
system prompt).
"""

DESC_GET_RATE_STATISTICS = f"""
Calcola le statistiche generali sul rate di trasmissione (PPS e BPS) nella finestra temporale.

METRICHE RESTITUITE E INTERPRETAZIONE:
- pps_aggregati: Frequenza globale dei pacchetti. Valori > {config.Soglie.DOS_PPS_MIN} PPS
  indicano un attacco volumetrico/DoS.
- flussi_slowloris: Numero di sessioni HTTP lente e persistenti
  (duration_ms >= {config.Soglie.SLOWLORIS_DURATION_MS}, total_bytes < {config.Soglie.SLOWLORIS_MAX_BYTES}).
  Un valore >= {config.Soglie.SLOWLORIS_FLUSSI_MIN} conferma un attacco DoS applicativo di tipo Slowloris.
- flussi_oltre_soglia_pps: Conteggio di singoli flussi ad altissima frequenza (es. SYN flood / UDP flood).

QUANDO USARLO: fonte primaria per DOS_VOLUMETRIC (vedi FONTE PRIMARIA PER CATEGORIA nel
system prompt) — step iniziale per classificare anomalie di tipo DoS/DDoS (Volumetrico vs Slowloris).
"""

DESC_GET_HOST_PORT_DISTRIBUTION = f"""
Analizza la dispersione delle connessioni OUTBOUND su IP e porte per rilevare Port Scan o Network Sweep.
Filtra automaticamente le conversazioni dati ed esclude l'effetto flood/L7 per evitare falsi positivi.

REGOLE INTERPRETATIVE:
- porte_uniche_contattate >= {config.Soglie.SCAN_PORTE_MIN}: PORT_SCANNING confermato (rilevate porte probe-like <= 4 pkt/flusso in outbound).
- ip_non_web_unici > {config.Soglie.SCAN_IP_SWEEP_MIN_NONWEB}: NETWORK_SWEEP in corso.
- porte_uniche_contattate <= 1 e totale_flussi elevati: traffico concentrato su un singolo servizio (candidato DoS o Beaconing, non Scan).

QUANDO USARLO: fonte primaria per confermare SCAN_BRUTEFORCE (vedi FONTE PRIMARIA PER CATEGORIA nel system prompt).
"""

DESC_ANALIZZA_CONNESSIONE = f"""
Analizza il dettaglio L7 di una connessione tramite il suo community_id.

IMPORTANTE:
- Usare SOLO community_id reali scritti in formato Hash/Stringa univoca ritornati dai tool precedenti (es. '1:8f9a2b...').
- NON inventare o costruire il community_id concatenando IP e porte a mano. Se non lo possiedi, usa 'analyze_dpi_details' o 'get_flow_features'.

NOTE SULLE METRICHE WEB/EXPLOIT:
- payload_entropy: misura la casualita' del payload (0.0 - 8.0).
  * ATTENZIONE: Gli attacchi Web tradizionali hanno spesso entropia BASSA (<= {config.Soglie.WEBATTACK_ENTROPIA_MAX}).
  * Ricorda che il DB non include URI complete o parametri della richiesta: valuta il rischio basandoti su frequenza, dimensione del payload ed entropia.
"""

# ==============================================================================
# FUNZIONI TOOL MCP
# ==============================================================================

@mcp.tool(description=DESC_GET_FLOW_FEATURES)
@mcp_cache_guard
def get_flow_features(ip: str, start_time: str, end_time: str) -> str:
    """Estrae metriche avanzate (IAT, Entropia, Slowloris) dei flussi del target."""
    start_time = normalizza_data(start_time, is_end=False)
    end_time = normalizza_data(end_time, is_end=True)

    query = text("""
        SELECT community_id, src_ip, dst_ip, dst_port, protocol, duration_ms, 
               total_bytes, total_fwd_bytes, total_bwd_bytes, fwd_packets, bwd_packets,
               packet_rate, byte_rate, iat_flow_avg, iat_flow_stddev, payload_entropy, tcp_flags
        FROM ndpi_flows
        WHERE (src_ip = :ip OR dst_ip = :ip)
          AND timestamp_start BETWEEN :start AND :end
        ORDER BY duration_ms DESC
        LIMIT 20;
    """)
    try:
        t_inizio_sql = time.perf_counter()

        with config.engine.connect() as connection:
            result = connection.execute(query, {"ip": ip, "start": start_time, "end": end_time})
            flussi = [dict(row) for row in result.mappings().fetchall()]
            
            t_sql_puro = time.perf_counter() - t_inizio_sql

            slowloris_count = 0
            s = config.Soglie
            for f in flussi:
                f["protocol"] = arricchisci_protocollo(int(f["protocol"]))
                
                duration_ms = float(f.get("duration_ms", 0) or 0)
                dst_port = int(f.get("dst_port", 0) or 0)
                tot_bytes = float(f.get("total_bytes", 0) or 0)
                
                if dst_port in s.PORTE_ORDINARIE_WEB_DNS and duration_ms >= s.SLOWLORIS_DURATION_MS and tot_bytes < s.SLOWLORIS_MAX_BYTES:
                    f["FLAG_SLOWLORIS_SUSPECT"] = True
                    f["ANOMALY_NOTE"] = f"ALERT: Connessione HTTP/HTTPS attiva per oltre {int(s.SLOWLORIS_DURATION_MS // s.MS_IN_SEC)}s a volume ridotto. Impronta tipica di Slowloris/Slow-Rate DoS."
                    slowloris_count += 1
                else:
                    f["FLAG_SLOWLORIS_SUSPECT"] = False

            risposta_finale = {
                "sintesi_smart": {
                    "stato": "ANOMALIA_RILEVATA" if slowloris_count > 0 else "NORMALE",
                    "flussi_slowloris_confermati": slowloris_count,
                    "diagnosi": f"Rilevati {slowloris_count} flussi con impronta Slowloris/Slow HTTP DoS." 
                               if slowloris_count > 0 else "Nessuna anomalia temporale o Slowloris rilevata nei flussi principali."
                },
                "tempo_sql_reale_sec": round(t_sql_puro, 6),
                "totale_flussi_analizzati": len(flussi),
                "campione_flussi": flussi
            }

            return json.dumps(risposta_finale, indent=2, default=str)
    except Exception as e:
        return f"[ERRORE TOOL]: Errore nell'estrazione delle flow features: {str(e)}"

@mcp.tool(description=DESC_GET_TOP_TALKERS)
@mcp_cache_guard
def get_top_talkers(
    start_time: str,
    end_time: str,
    top_n: int = config.Soglie.BEACON_TOP_N_DEFAULT,
    criterion: str = "bytes",
) -> str:
    """Identifica gli host sorgente che generano il maggior traffico nella rete."""
    start_time = normalizza_data(start_time, is_end=False)
    end_time = normalizza_data(end_time, is_end=True)

    try:
        top_n_int = min(max(int(top_n), 1), 50)
    except (ValueError, TypeError):
        top_n_int = config.Soglie.BEACON_TOP_N_DEFAULT

    if criterion not in ["bytes", "packets"]:
        return "[ERRORE TOOL]: il criterio deve essere 'bytes' o 'packets'."

    espr_volume = (
        "total_bytes"
        if criterion == "bytes"
        else "(fwd_packets + bwd_packets)"
    )

    query = text(f"""
        SELECT src_ip, 
               SUM({espr_volume}) as volume_totale, 
               COUNT(*) as flussi_totali
        FROM ndpi_flows
        WHERE timestamp_start BETWEEN :start AND :end
        GROUP BY src_ip
        ORDER BY volume_totale DESC
        LIMIT :top_n;
    """)
    try:
        t_inizio_sql = time.perf_counter()

        with config.engine.connect() as connection:
            result = connection.execute(
                query,
                {
                    "start": start_time,
                    "end": end_time,
                    "top_n": top_n_int,
                },
            )
            host = [dict(row) for row in result.mappings().fetchall()]

            t_sql_puro = time.perf_counter() - t_inizio_sql

            risposta_finale = {
                "sintesi_smart": {
                    "criterio_usato": criterion,
                    "totale_top_talkers_trovati": len(host),
                },
                "tempo_sql_reale_sec": round(t_sql_puro, 6),
                "top_talkers": host,
            }

            return json.dumps(risposta_finale, indent=2, default=str)
    except Exception as e:
        return f"[ERRORE TOOL]: Errore nel calcolo dei Top Talkers: {str(e)}"

@mcp.tool(description=DESC_ANALYZE_DPI_DETAILS)
@mcp_cache_guard
def analyze_dpi_details(ip: str, start_time: str, end_time: str) -> str:
    """Esegue un'analisi profonda Deep Packet Inspection sui flussi del target."""
    start_time = normalizza_data(start_time, is_end=False)
    end_time = normalizza_data(end_time, is_end=True)

    query = text("""
        SELECT community_id, src_ip, src_port, dst_ip, dst_port, protocol, app_hierarchy, 
               ndpi_hostname, payload_entropy, infra_provider, tls_version, tls_cipher_suite
        FROM ndpi_flows
        WHERE (src_ip = :ip OR dst_ip = :ip)
          AND timestamp_start BETWEEN :start AND :end
        ORDER BY 
          CASE WHEN dst_port IN (80, 443, 8080) OR src_port IN (80, 443, 8080) THEN 0 ELSE 1 END,
          timestamp_start DESC
        LIMIT 20;
    """)
    try:
        t_inizio_sql = time.perf_counter()

        with config.engine.connect() as connection:
            result = connection.execute(query, {"ip": ip, "start": start_time, "end": end_time})
            flussi = [dict(row) for row in result.mappings().fetchall()]

            t_sql_puro = time.perf_counter() - t_inizio_sql
            
            flussi_alta_entropia = 0
            for f in flussi:
                f["protocol"] = arricchisci_protocollo(int(f["protocol"]))
                if (f.get("payload_entropy") or 0.0) > 7.0:
                    flussi_alta_entropia += 1
            
            risposta_finale = {
                "sintesi_smart": {
                    "flussi_analizzati": len(flussi),
                    "flussi_entropia_elevata": flussi_alta_entropia,
                    "avviso_sicurezza": "Possibile cifratura/obfuscation sospetta nel payload." if flussi_alta_entropia > 0 else "Nessuna anomalia critica di entropia."
                },
                "tempo_sql_reale_sec": round(t_sql_puro, 6),
                "dpi_details": flussi
            }

            return json.dumps(risposta_finale, indent=2, default=str)
    except Exception as e:
        return f"[ERRORE TOOL]: Errore nell'ispezione DPI di dettaglio: {str(e)}"

@mcp.tool(description=DESC_RESOLVE_HOST_INFO)
@mcp_cache_guard
def resolve_host_info(ip: str, start_time: str, end_time: str) -> str:
    """Riconnette l'IP target a nomi di dominio e Service Provider Cloud."""
    start_time = normalizza_data(start_time, is_end=False)
    end_time = normalizza_data(end_time, is_end=True)

    query = text(f"""
        SELECT DISTINCT ndpi_hostname, infra_provider
        FROM ndpi_flows
        WHERE (src_ip = :ip OR dst_ip = :ip) 
        AND timestamp_start BETWEEN :start AND :end
        AND (ndpi_hostname IS NOT NULL OR infra_provider IS NOT NULL)
        LIMIT {config.Soglie.LIMIT_DEFAULT_QUERY};
    """)
    try:
        t_inizio_sql = time.perf_counter()

        with config.engine.connect() as connection:
            result = connection.execute(query, {"ip": ip, "start": start_time, "end": end_time})
            info = [dict(row) for row in result.mappings().fetchall()]

            t_sql_puro = time.perf_counter() - t_inizio_sql

            risposta_finale = {
                "sintesi_smart": {
                    "associazioni_trovate": len(info)
                },
                "tempo_sql_reale_sec": round(t_sql_puro, 6),
                "host_info": info
            }

            return json.dumps(risposta_finale, indent=2, default=str)
    except Exception as e:
        return f"[ERRORE TOOL]: Errore nella risoluzione delle info host: {str(e)}"

@mcp.tool(description=DESC_QUERY_BY_RATE)
@mcp_cache_guard
def query_by_rate(
    threshold: float, 
    start_time: str, 
    end_time: str, 
    metric: str = "packet_rate",
    ip_address: Optional[str] = None
) -> str:
    """Isola e filtra i flussi la cui frequenza supera una specifica soglia."""
    start_time = normalizza_data(start_time, is_end=False)
    end_time = normalizza_data(end_time, is_end=True)

    if metric not in ["packet_rate", "byte_rate"]:
        return "[ERRORE TOOL]: La metrica deve essere 'packet_rate' o 'byte_rate'."

    sql_where = f"WHERE {metric} > :threshold AND timestamp_start BETWEEN :start AND :end"
    params = {"threshold": threshold, "start": start_time, "end": end_time}

    if ip_address:
        sql_where += " AND (src_ip = :ip OR dst_ip = :ip)"
        params["ip"] = ip_address.strip()

    query_count = text(f"""
        SELECT 
            COUNT(*) as totale_flussi_sopra_soglia, 
            SUM(total_bytes) as byte_totali, 
            SUM(fwd_packets + bwd_packets) as pacchetti_totali 
        FROM ndpi_flows {sql_where};
    """)
    
    query_top = text(f"""
        SELECT community_id, src_ip, dst_ip, dst_port, protocol, packet_rate, byte_rate, duration_ms 
        FROM ndpi_flows {sql_where} 
        ORDER BY {metric} DESC 
        LIMIT 3;
    """)

    try:
        t_inizio_sql = time.perf_counter()
        with config.engine.connect() as connection:
            res_count_raw = connection.execute(query_count, params).mappings().fetchone()
            res_count = dict(res_count_raw) if res_count_raw else {}

            res_top = connection.execute(query_top, params)
            flussi = [dict(row) for row in res_top.mappings().fetchall()]
            t_sql_puro = time.perf_counter() - t_inizio_sql

            for f in flussi:
                f["protocol"] = arricchisci_protocollo(int(f["protocol"]))

            tot_anomali = res_count.get("totale_flussi_sopra_soglia", 0)

            sintesi_testo = (
                f"Trovati {tot_anomali} flussi superiori alla soglia {metric} > {threshold}."
                if tot_anomali > 0 else
                f"Nessun flusso supera la soglia specificata ({metric} > {threshold})."
            )

            risposta_finale = {
                "sintesi_smart": {
                    "flussi_rilevati": tot_anomali,
                    "esito": sintesi_testo
                },
                "totali_aggregati": {
                    "byte_totali": float(res_count.get("byte_totali") or 0),
                    "pacchetti_totali": int(res_count.get("pacchetti_totali") or 0)
                },
                "campione_top_3": flussi,
                "tempo_sql_sec": round(t_sql_puro, 4)
            }

            return json.dumps(risposta_finale, indent=2, default=str)
    except Exception as e:
        return f"[ERRORE TOOL]: Errore nell'analisi volumetrica: {str(e)}"

@mcp.tool(description=DESC_INSPECT_HTTP_REQUESTS)
@mcp_cache_guard
def inspect_http_requests(
    ip_target: str,
    start_time: str,
    end_time: str,
    limit: int = config.Soglie.LIMIT_DEFAULT_QUERY,
    offset: int = 0
) -> str:
    """Estrae la telemetria L7/HTTP per l'host target."""
    porte_web_str = ", ".join(map(str, config.Soglie.PORTE_WEB_L7))
    
    query = text(f"""
        SELECT 
            f.community_id, 
            f.src_ip, 
            f.src_port, 
            f.dst_ip, 
            f.dst_port,
            f.ndpi_hostname, 
            f.app_hierarchy, 
            f.payload_entropy, 
            f.total_bytes,
            f.fwd_packets,
            f.bwd_packets
        FROM ndpi_flows f
        WHERE (f.src_ip = :ip OR f.dst_ip = :ip)
        AND f.timestamp_start BETWEEN :start_time AND :end_time
        AND (f.dst_port IN ({porte_web_str}) OR f.src_port IN ({porte_web_str}))
        ORDER BY f.total_bytes DESC
        LIMIT :limit OFFSET :offset;
    """)
    
    params = {
        "ip": ip_target,
        "start_time": normalizza_data(start_time, is_end=False),
        "end_time": normalizza_data(end_time, is_end=True),
        "limit": min(int(limit), 10),
        "offset": int(offset)
    }
    
    try:
        with config.engine.connect() as connection:
            result = connection.execute(query, params)
            dettagli = [dict(row) for row in result.mappings().fetchall()]
            
        return json.dumps({
            "sintesi_smart": {
                "totale_richieste_ispezionate": len(dettagli),
                "nota": "Estratto un campione rappresentativo ristretto per preservare il contesto LLM."
            },
            "richieste_top_bytes": dettagli
        }, indent=2, default=str)
    except Exception as e:
        return json.dumps({"errore_sql": str(e)})
    
@mcp.tool(description=DESC_GET_TRAFFIC_SUMMARY)
@mcp_cache_guard
def get_traffic_summary(
    ip_target: str,
    start_time: str,
    end_time: str,
    limit: Union[int, str] = config.Soglie.LIMIT_DEFAULT_QUERY,
) -> str:
    """Sintesi volumetrica del traffico (L3/L4) per un IP target."""
    start_norm = normalizza_data(start_time, is_end=False)
    end_norm = normalizza_data(end_time, is_end=True)

    try:
        limit_int = min(int(limit), config.Soglie.LIMIT_TRAFFIC_SUMMARY)
    except ValueError:
        limit_int = config.Soglie.LIMIT_DEFAULT_QUERY

    durata_finestra_sec = calcola_durata_finestra_reale(start_time, end_time)

    query = text(f"""
        SELECT community_id, src_ip, src_port, dst_ip, dst_port, protocol, 
               duration_ms, total_bytes, packet_rate, app_hierarchy,
               COUNT(*) OVER() as totale_flussi_reali,
               SUM(total_bytes) OVER() as bytes_totali_finestra,
               SUM((duration_ms / {config.Soglie.MS_IN_SEC}) * packet_rate) OVER() as pacchetti_totali_stimati_finestra
        FROM ndpi_flows 
        WHERE (src_ip = :ip OR dst_ip = :ip)
          AND timestamp_start BETWEEN :start AND :end
        ORDER BY timestamp_start DESC, total_bytes DESC 
        LIMIT :limit_val;
    """)
    try:
        t_inizio_sql = time.perf_counter()

        with config.engine.connect() as connection:
            result = connection.execute(query, {
                "ip": ip_target, 
                "start": start_norm, 
                "end": end_norm,
                "limit_val": limit_int
            })
            flussi = [dict(row) for row in result.mappings().fetchall()]
            t_sql_puro = time.perf_counter() - t_inizio_sql

            totale_reali = flussi[0]["totale_flussi_reali"] if flussi else 0
            bytes_totali = float(flussi[0]["bytes_totali_finestra"]) if flussi and flussi[0]["bytes_totali_finestra"] is not None else 0.0
            packets_totali = float(flussi[0]["pacchetti_totali_stimati_finestra"]) if flussi and flussi[0]["pacchetti_totali_stimati_finestra"] is not None else 0.0

            bps_globali = round(bytes_totali / durata_finestra_sec, 2)
            pps_globali = round(packets_totali / durata_finestra_sec, 2)

            for f in flussi:
                f["protocol"] = arricchisci_protocollo(int(f["protocol"]))
                f.pop("totale_flussi_reali", None)
                f.pop("bytes_totali_finestra", None)
                f.pop("pacchetti_totali_stimati_finestra", None)

            s = config.Soglie
            if pps_globali > s.DOS_PPS_MIN:
                diagnosi = f"CRITICO: Volume pacchetti globale elevato (>{s.DOS_PPS_MIN} PPS). Possibile DOS_VOLUMETRIC."
            elif totale_reali > config.Soglie.DENSITA_FLUSSI_ELEVATA_MIN:
                diagnosi = f"ATTENZIONE: Elevata densita' di flussi (>{config.Soglie.DENSITA_FLUSSI_ELEVATA_MIN}). Verificare se Connection Exhaustion o Scan."
            elif totale_reali == 0:
                diagnosi = "PULITO: Nessun flusso rilevato per l'host nella finestra."
            else:
                diagnosi = "REGOLARE: Volumi complessivi nella norma."

            risposta_finale = {
                "sintesi_smart": {
                    "stato": (
                        "ANOMALO"
                        if (
                            pps_globali > s.DOS_PPS_MIN
                            or totale_reali > s.DENSITA_FLUSSI_ELEVATA_MIN
                        )
                        else "NORMALE"
                    ),
                    "diagnosi_preliminare": diagnosi,
                    "pps_complessivi": pps_globali,
                    "totale_flussi_reali": totale_reali,
                },
                "campione_flussi_recenti": flussi,
                "tempo_sql_sec": round(t_sql_puro, 4),
            }

            return json.dumps(risposta_finale, indent=2, default=str)
    except Exception as e:
        return f"[ERRORE TOOL]: Errore nel recupero della sintesi del traffico: {str(e)}"

@mcp.tool(description=DESC_GET_AGGREGATED_TRAFFIC_SUMMARY)
@mcp_cache_guard
def get_aggregated_traffic_summary(ip_target: str, start_time: str, end_time: str) -> str:
    """Raggruppa il traffico per (dst_ip, dst_port, protocollo, app)."""
    start_norm = normalizza_data(start_time, is_end=False)
    end_norm = normalizza_data(end_time, is_end=True)
    durata_finestra_sec = calcola_durata_finestra_reale(start_time, end_time)

    query = text(f"""
        SELECT 
            dst_ip, 
            dst_port, 
            protocol, 
            app_hierarchy,
            COUNT(*) as totale_flussi, 
            SUM(total_bytes) as byte_totali,
            ROUND(SUM(total_bytes) / :durata_sec, 2) as bytes_per_sec,
            ROUND(AVG(packet_rate), 2) as packet_rate_medio_per_flusso,
            ROUND(
                SUM(CASE WHEN duration_ms > 0 THEN (duration_ms / {config.Soglie.MS_IN_SEC}) * packet_rate ELSE 1 END) / :durata_sec, 
                2
            ) as packets_per_sec_aggregati_porta
        FROM ndpi_flows
        WHERE (src_ip = :ip OR dst_ip = :ip)
        AND timestamp_start BETWEEN :start AND :end
        GROUP BY dst_ip, dst_port, protocol, app_hierarchy
        ORDER BY totale_flussi DESC
        LIMIT {config.Soglie.LIMIT_DEFAULT_QUERY};
    """)
    try:
        t_inizio_sql = time.perf_counter()

        with config.engine.connect() as connection:
            result = connection.execute(query, {
                "ip": ip_target, 
                "start": start_norm, 
                "end": end_norm,
                "durata_sec": durata_finestra_sec
            })
            righe = [dict(row) for row in result.mappings().fetchall()]
            t_sql_puro = time.perf_counter() - t_inizio_sql

            for r in righe:
                r["protocol"] = arricchisci_protocollo(int(r["protocol"]))

            porte_impattate = list(set(r["dst_port"] for r in righe))
            tot_flussi_aggregati = sum(r["totale_flussi"] for r in righe)

            risposta = {
                "sintesi_smart": {
                    "porte_target_distinte": len(porte_impattate),
                    "totale_flussi_raggruppati": tot_flussi_aggregati,
                    "top_porta_destinazione": righe[0]["dst_port"] if righe else None
                },
                "aggregazione_per_servizio": righe,
                "tempo_sql_sec": round(t_sql_puro, 4)
            }
            return json.dumps(risposta, indent=2, default=str)
    except Exception as e:
        return f"[ERRORE TOOL]: Errore nel recupero della sintesi aggregata: {str(e)}"



def _calcola_scores_da_evidenze(
    rate_stats: dict,
    port_dist: dict,
    beacon: dict,
    l7: dict,
    conn_attempts: dict,
) -> dict:
    s = config.Soglie

    # 0. ESTRAZIONE DATI BASE
    mk = rate_stats.get("metriche_chiave") or {}
    totale_flussi = int(mk.get("totale_flussi") or 0)
    flussi_web = int(mk.get("flussi_web_totali") or 0)
    
    pps = float(mk.get("pps_aggregati") or 0.0)
    burst_pps = float(mk.get("burst_pps") or pps)
    effective_pps = max(pps, burst_pps)

    web_rps = float(mk.get("web_rps") or 0.0)
    burst_web_rps = float(mk.get("burst_web_rps") or web_rps)
    effective_web_rps = max(web_rps, burst_web_rps)

    flussi_slow = int(mk.get("flussi_slowloris") or 0)

    # Indicators L7
    l7_ss = l7.get("sintesi_smart") or {}
    anomalie_l7 = int(l7_ss.get("anomalie_l7_trovate") or 0)
    sospetto_web_bf = l7_ss.get("sospetto_web_bruteforce", False)

    # Estrazione max tentativi per IP per controlli L7
    max_tentativi_per_ip = int(l7_ss.get("max_tentativi_per_ip") or 0)

    # FIX 29: Estrarre o calcolare i flussi sulla porta 53 (DNS)
    port_ss = port_dist.get("sintesi_smart") or {}
    distribuzione_top = port_ss.get("distribuzione_top") or []
    flussi_p53 = sum(p.get("num_flussi", 0) for p in distribuzione_top if p.get("dst_port") == 53)

    # 1. DOS VOLUMETRIC / SLOWLORIS / GOLDENEYE / HULK
    dos_pps_score = min(1.0, effective_pps / getattr(s, "DOS_PPS_MIN", 3000.0))
    if effective_pps < 300.0:
        dos_pps_score = 0.0

    dos_l7_score = 0.0
    
    # FIX 29: Check e gestione dedicata per Infrastruttura e traffico DNS
    is_dns_traffic = (flussi_p53 / max(totale_flussi, 1) > 0.8) if totale_flussi > 0 else False

    if is_dns_traffic:
        # Se è prevalentemente traffico DNS, serve un burst PPS reale per scattare come DoS
        if burst_pps >= 300.0 or totale_flussi >= 20000:
            dos_l7_score = 0.95
    else:
        # Logica originale DoS L7
        if flussi_web >= 500 or totale_flussi >= 2000:
            dos_l7_score = 0.95
        elif flussi_web >= 150 and effective_web_rps >= 3.0 and not sospetto_web_bf:
            dos_l7_score = 0.95

    dos_slow_score = 0.0
    slow_min = getattr(s, "SLOWLORIS_FLUSSI_MIN", 10)
    if flussi_slow >= slow_min or (flussi_web >= 50 and flussi_slow >= 5):
        dos_slow_score = 0.95

    dos_score = max(dos_pps_score, dos_l7_score, dos_slow_score)

    # 2. BEACONING C2 / BOT
    beacon_score = 0.0
    top_candidati = beacon.get("candidati_top") or []
    sintesi_beacon = beacon.get("sintesi_smart") or {}

    if sintesi_beacon.get("beaconing_c2_rilevato"):
        beacon_score = 1.0
    elif len(top_candidati) > 0:
        max_cand_score = max([float(c.get("anomaly_score") or 0) for c in top_candidati], default=0)
        min_cv = min([float(c.get("cv") if c.get("cv") is not None else 999.0) for c in top_candidati], default=999.0)
        
        if max_cand_score >= 50 or min_cv < 0.20:
            beacon_score = 0.95

    # 3. SCAN & BRUTEFORCE
    porte_uniche_total = int(port_ss.get("porte_uniche_contattate") or 0)
    sospetto_scan = port_ss.get("sospetto_portscan", False)
    porte_target_bruteforce = port_ss.get("porte_target_bruteforce") or []

    scan_score = 0.0
    if porte_uniche_total >= getattr(s, "SCAN_PORTE_MIN", 15) and sospetto_scan:
        scan_score = 0.95

    # FIX 21: Evita che DoS a porte dinamiche/casuali scatti erroneamente come PortScan
    if porte_uniche_total < 50 and (burst_pps >= 15.0 or totale_flussi >= 1500 or dos_l7_score >= 0.85):
        scan_score = 0.0

    porte_gestione = getattr(s, "PORTE_GESTIONE_SET", {21, 22, 23, 3389, 5900, 2222})
    has_valid_bf_port = any(int(p) in porte_gestione for p in porte_target_bruteforce)

    tentativi_conn = conn_attempts.get("tentativi_connessione") or []
    has_single_port_bf = False
    for t in tentativi_conn:
        tentativi = int(t.get("tentativi_totali") or 0)
        porta = int(t.get("dst_port") or 0)
        if porta in porte_gestione and tentativi >= getattr(s, "BRUTEFORCE_TENTATIVI_MIN", 25):
            has_single_port_bf = True
            break

    if has_valid_bf_port or has_single_port_bf:
        scan_score = max(scan_score, 0.90)

    # 4. WEB ATTACK & EXPLOIT
    if flussi_web >= 40 and porte_uniche_total <= 3 and dos_score < 0.85:
        sospetto_web_bf = True
        scan_score = 0.0

    web_score = 0.0
    # FIX 24: Richiedi anomalie L7 reali per evitare falsi positivi da PortScan Stealth
    if sospetto_web_bf:
        if anomalie_l7 > 0 or max_tentativi_per_ip >= 150:
            web_score = 0.95
        else:
            web_score = 0.0
    elif anomalie_l7 >= 3 and flussi_web < 500:
        web_score = 0.95
    elif anomalie_l7 >= 1 and flussi_web < 300:
        web_score = 0.85
    elif flussi_web >= 40 and porte_uniche_total <= 3 and dos_score < 0.85:
        web_score = 0.90

    # 5. GERARCHIA ED ESCLUSIONE MUTUA
    # FIX 27: Il PortScan Massivo ha priorità sul DoS Volumetrico
    if scan_score >= 0.85 and porte_uniche_total >= 100:
        dos_score = 0.0
        web_score = 0.0

    elif dos_score >= 0.85:
        web_score = 0.0
        scan_score = 0.0

    elif web_score >= 0.90 and porte_uniche_total <= 3:
        scan_score = 0.0

    elif scan_score >= 0.95:
        web_score = 0.0

    # Gestione C2 / Bot
    if beacon_score >= 0.85 and totale_flussi < 1000 and dos_score < 0.95:
        dos_score = 0.0
        web_score = 0.0
        scan_score = 0.0

    # Cut-off rumore di fondo
    dos_score = 0.0 if dos_score < 0.30 else dos_score
    web_score = 0.0 if web_score < 0.30 else web_score
    scan_score = 0.0 if scan_score < 0.30 else scan_score
    beacon_score = 0.0 if beacon_score < 0.30 else beacon_score

    scores_map = {
        "BEACONING_C2": beacon_score,
        "DOS_VOLUMETRIC": dos_score,
        "WEB_ATTACK_EXPLOIT": web_score,
        "SCAN_BRUTEFORCE": scan_score,
    }

    max_categoria = max(scores_map, key=scores_map.get)
    max_valore = scores_map[max_categoria]

    if max_valore >= 0.50:
        verdetto = max_categoria
        score_dominante = max_valore
    else:
        verdetto = "BENIGN"
        score_dominante = 0.0

    return {
        "status": "success",
        "verdetto_suggerito": verdetto,
        "score_dominante": round(score_dominante, 2),
        "scores": {
            "dos_score": round(dos_score, 2),
            "web_score": round(web_score, 2),
            "scan_score": round(scan_score, 2),
            "beacon_score": round(beacon_score, 2),
        },
        "metriche_chiave": {
            "totale_flussi": totale_flussi,
            "flussi_web": flussi_web,
            "anomalie_l7": anomalie_l7,
            "porte_uniche_total": porte_uniche_total,
            "sospetto_web_bruteforce": sospetto_web_bf,
        },
    }

@mcp.tool(description=DESC_COMPUTE_VERDICT_SCORES)
@mcp_cache_guard
def compute_verdict_scores(ip_target: str, start_time: str, end_time: str) -> str:
    """Wrapper MCP: fetch dei dati via tool _raw + delega del calcolo alla funzione pura."""
    try:
        rate_stats = _get_rate_statistics_raw(start_time, end_time, ip_target) or {}
        port_dist = _get_host_port_distribution_raw(ip_target, start_time, end_time) or {}
        beacon = _detect_beaconing_raw(ip_target, start_time, end_time) or {}
        l7 = _search_http_l7_anomalies_raw(ip_target, start_time, end_time) or {}
        
        conn_attempts = _search_connection_attempts_raw(
            start_time, 
            end_time, 
            ip_target=ip_target, 
            include_web_ports=True
        ) or {}

        risultato = _calcola_scores_da_evidenze(rate_stats, port_dist, beacon, l7, conn_attempts)
        risultato["ip_target"] = ip_target
        return json.dumps(risultato, ensure_ascii=False)

    except Exception as e:
        return json.dumps({"status": "error", "message": f"Errore calcolo verdict scores: {str(e)}"})

def _detect_beaconing_raw(
    ip_target: str,
    start_time: str,
    end_time: str,
    dst_ip: Optional[str] = None,
    top_n: Optional[int] = None,
) -> dict:
    top_n_val = top_n or config.Soglie.BEACON_TOP_N_DEFAULT

    start_norm = normalizza_data(start_time, is_end=False)
    end_norm = normalizza_data(end_time, is_end=True)

    if not dst_ip or str(dst_ip).strip().lower() in ("none", "null", ""):
        dst_ip_clean = None
    else:
        dst_ip_clean = dst_ip.strip()

    min_intervals = 1 if dst_ip_clean else max(1, config.Soglie.BEACON_MIN_CONNESSIONI - 1)
    dst_filter = "AND n.dst_ip = :dst_ip" if dst_ip_clean else ""
    limit_n = max(1, min(int(top_n_val), 50))

    order_clause = "CASE WHEN dst_ip = :dst_ip THEN 0 ELSE 1 END," if dst_ip_clean else ""

    query_str = f"""
        WITH timed_flows AS (
            SELECT
                n.dst_ip,
                n.dst_port,
                n.ndpi_hostname,
                TIMESTAMPDIFF(
                    SECOND,
                    LAG(n.timestamp_start) OVER (
                        PARTITION BY n.dst_ip, n.dst_port
                        ORDER BY n.timestamp_start
                    ),
                    n.timestamp_start
                ) AS delta_time
            FROM ndpi_flows AS n
            WHERE (n.src_ip = :ip OR n.dst_ip = :ip)
            AND n.timestamp_start BETWEEN :start AND :end
            {dst_filter}
        ),
        beaconing_stats AS (
            SELECT
                dst_ip,
                dst_port,
                MAX(ndpi_hostname) as hostname,
                COUNT(*) as intervalli_validi,
                AVG(delta_time) as intervallo_medio,
                STDDEV(delta_time) as dev_std,
                CASE
                    WHEN AVG(delta_time) > 0 THEN STDDEV(delta_time) / AVG(delta_time)
                    ELSE 999.0
                END as cv_calcolato
            FROM timed_flows
            WHERE delta_time IS NOT NULL
            GROUP BY dst_ip, dst_port
            HAVING intervalli_validi >= :min_intervals
        )
        SELECT dst_ip, dst_port, (intervalli_validi + 1) as totale_connessioni,
               ROUND(intervallo_medio, 1) as avg_sec,
               ROUND(dev_std, 1) as std_sec,
               ROUND(cv_calcolato, 3) as cv,
               hostname
        FROM beaconing_stats
        ORDER BY
            {order_clause}
            cv_calcolato ASC,
            totale_connessioni DESC
        LIMIT :top_n;
    """

    params = {
        "ip": ip_target,
        "start": start_norm,
        "end": end_norm,
        "min_intervals": min_intervals,
        "top_n": limit_n,
    }
    if dst_ip_clean:
        params["dst_ip"] = dst_ip_clean

    t_inizio_sql = time.perf_counter()
    with config.engine.connect() as connection:
        result = connection.execute(text(query_str), params)
        righe = [dict(row) for row in result.mappings().fetchall()]
        t_sql_puro = time.perf_counter() - t_inizio_sql

    if not righe:
        return {
            "sintesi_smart": {
                "beaconing_c2_rilevato": False,
                "esito": "Nessuna cadenza temporale regolare trovata."
            },
            "candidati_top": [],
            "tempo_sql_sec": round(t_sql_puro, 4)
        }

    risultati = []
    has_c2_candidate = False

    for riga in righe:
        dst_ip_val = riga.get("dst_ip")
        dst_port = int(riga.get("dst_port") or 0)
        totale_connessioni = int(riga.get("totale_connessioni") or 0)
        avg_sec = float(riga.get("avg_sec") or 0.0)
        cv = float(riga.get("cv") if riga.get("cv") is not None else 999.0)
        hostname = str(riga.get("hostname") or "").lower()

        is_whitelisted = _is_whitelisted(hostname, DOMINI_WHITELIST_BEACONING)
        
        anomaly_score, tag_list = _compute_anomaly_score(
            cv, totale_connessioni, is_whitelisted, dst_ip_val
        )

        if "CONFIRMED_BEACONING_C2" in tag_list:
            has_c2_candidate = True

        risultati.append({
            "dst_ip": dst_ip_val,
            "dst_port": dst_port,
            "hostname": hostname if hostname else "N/A",
            "totale_connessioni": totale_connessioni,
            "intervallo_medio_sec": avg_sec,
            "cv": cv,
            "anomaly_score": anomaly_score,
            "tags": tag_list
        })

    return {
        "sintesi_smart": {
            "beaconing_c2_rilevato": has_c2_candidate,
            "diagnosi": (
                f"ALLERTA C2: Trovata cadenza periodica regolare (CV < {config.Soglie.CV_BEACON_JITTER_MAX})."
                if has_c2_candidate else
                "Nessuna minaccia C2 rilevante."
            )
        },
        "candidati_top": risultati,
        "tempo_sql_sec": round(t_sql_puro, 4)
    }

def _search_http_l7_anomalies_raw(
    ip_target: str,
    start_time: str,
    end_time: str,
    limit: int = config.Soglie.LIMIT_DEFAULT_QUERY,
) -> dict:
    porte_web_extended = set(config.Soglie.PORTE_WEB_L7).union({444, 8443, 4433, 80, 443})
    porte_web_str = ", ".join(map(str, porte_web_extended))

    query = text(f"""
        SELECT 
            community_id, src_ip, src_port, dst_ip, dst_port,
            app_hierarchy, ndpi_hostname, payload_entropy, 
            fwd_packets, bwd_packets, total_bytes, duration_ms, timestamp_start
        FROM ndpi_flows
        WHERE (src_ip = :ip OR dst_ip = :ip)
        AND timestamp_start BETWEEN :start_time AND :end_time
        AND (
            dst_port IN ({porte_web_str})       
            OR src_port IN ({porte_web_str})
            OR app_hierarchy LIKE '%SSL%'
            OR app_hierarchy LIKE '%TLS%'
            OR app_hierarchy LIKE '%HTTP%'
        )
        ORDER BY timestamp_start ASC;
    """)
    
    params = {
        "ip": ip_target,
        "start_time": normalizza_data(start_time, is_end=False),
        "end_time": normalizza_data(end_time, is_end=True),
    }

    t_inizio_sql = time.perf_counter()
    with config.engine.connect() as connection:
        result = connection.execute(query, params)
        flussi = [dict(row) for row in result.mappings().fetchall()]
        t_sql_puro = time.perf_counter() - t_inizio_sql

    if not flussi:
        return {
            "sintesi_smart": {
                "anomalie_l7_trovate": 0,
                "flussi_web_esaminati": 0,
                "target_colpiti_count": 0,
                "sospetto_web_bruteforce": False,
                "esito": "Nessun traffico HTTP/L7 trovato nella finestra temporale.",
            },
            "campione_anomalie": [],
            "tempo_sql_sec": round(t_sql_puro, 4),
        }

    sqli_xss_patterns = [
        "<script", "%3cscript", "javascript:", "onerror=", "onload=", "<img", "%3cimg", "<svg", "%3csvg",
        "alert(", "eval(", "union select", "union%20select", "drop table", "xp_cmdshell",
        "' or '1'='1", "%27%20or%20", "' or 1=1", "%27or1=1", "select ", "%20select%20",
        "insert into", "benchmark(", "sleep(", "../", "..\\", "%2e%2e%2f", "etc/passwd",
        "wp-login"
    ]

    richieste_sospette = []
    flussi_web_non_whitelisted = 0
    req_per_sorgente = {}
    target_per_sorgente = {}

    for f in flussi:
        if _is_l7_whitelisted(f.get("app_hierarchy"), f.get("ndpi_hostname")):
            continue
            
        flussi_web_non_whitelisted += 1
        src = f.get("src_ip")
        dst = f.get("dst_ip")
        
        req_per_sorgente[src] = req_per_sorgente.get(src, 0) + 1
        if src not in target_per_sorgente:
            target_per_sorgente[src] = set()
        if dst:
            target_per_sorgente[src].add(dst)

        payload_ent = f.get("payload_entropy")
        is_entropy_suspicious = (payload_ent is not None and payload_ent > 7.2)
        
        app_h = str(f.get("app_hierarchy") or "").lower()
        hostname = str(f.get("ndpi_hostname") or "").lower()
        target_text_raw = f"{hostname} {app_h}"
        
        # FIX: Decodifica URL protetta
        target_text_unquoted = urllib.parse.unquote_plus(urllib.parse.unquote(target_text_raw)).lower()
        
        is_signature_match = any(
            pattern in target_text_raw or pattern in target_text_unquoted 
            for pattern in sqli_xss_patterns
        )

        if is_entropy_suspicious or is_signature_match:
            richieste_sospette.append(f)

    max_richieste_src = max(req_per_sorgente.values()) if req_per_sorgente else 0
    is_massive_flood = len(flussi) > 300

    sospetto_web_bruteforce = False
    if not is_massive_flood:
        for src_ip, count in req_per_sorgente.items():
            distinct_targets = len(target_per_sorgente.get(src_ip, set()))
            if count >= 40 and distinct_targets <= 3:
                sospetto_web_bruteforce = True
                break

    totale_flussi_anomali = len(richieste_sospette)
    target_colpiti = len(set(f["dst_ip"] for f in richieste_sospette if f.get("dst_ip"))) if richieste_sospette else 0

    return {
        "sintesi_smart": {
            "anomalie_l7_trovate": totale_flussi_anomali,
            "flussi_web_esaminati": len(flussi),
            "sospetto_web_bruteforce": sospetto_web_bruteforce,
            "max_tentativi_per_ip": max_richieste_src,
            "target_colpiti_count": target_colpiti,
            "esito": f"RILEVATI {totale_flussi_anomali} flussi anomali HTTP/L7 su {len(flussi)} flussi Web.",
        },
        "campione_anomalie": richieste_sospette[:limit],
        "tempo_sql_sec": round(t_sql_puro, 4),
    }

def _get_rate_statistics_raw(
    start_time: str,
    end_time: str,
    ip_address: Optional[str] = None,
    ip_target: Optional[str] = None,
) -> dict:
    target_ip = (ip_target or ip_address or "").strip()

    start_norm = normalizza_data(start_time, is_end=False)
    end_norm = normalizza_data(end_time, is_end=True)
    durata_sec = calcola_durata_finestra_reale(start_time, end_time)

    porte_web_str = ", ".join(map(str, config.Soglie.PORTE_WEB_L7))

    web_cond_sql = f"""(
        dst_port IN ({porte_web_str}) 
        OR src_port IN ({porte_web_str}) 
        OR app_hierarchy LIKE '%HTTP%' 
        OR app_hierarchy LIKE '%SSL%'
        OR app_hierarchy LIKE '%TLS%'
        OR app_hierarchy LIKE '%Web%'
    )"""

    where_conditions = ["timestamp_start BETWEEN :start AND :end"]
    params = {
        "start": start_norm,
        "end": end_norm,
        "dos_pps_min": config.Soglie.DOS_PPS_MIN,
        "slowloris_dur": config.Soglie.SLOWLORIS_DURATION_MS,
        "slowloris_bytes": config.Soglie.SLOWLORIS_MAX_BYTES,
    }

    if target_ip:
        where_conditions.append("(src_ip = :ip OR dst_ip = :ip)")
        params["ip"] = target_ip

    where_clause = " WHERE " + " AND ".join(where_conditions)

    sql_text = f"""
        SELECT 
            AVG(packet_rate) as avg_packet_rate, 
            MAX(CASE WHEN duration_ms >= {config.Soglie.FLUSSO_DURATA_MIN_MS} AND (fwd_packets + bwd_packets) > {config.Soglie.FLUSSO_PACCHETTI_MIN} THEN packet_rate ELSE 0 END) as max_packet_rate,
            STDDEV(packet_rate) as stddev_packet_rate,
            AVG(byte_rate) as avg_byte_rate,
            MAX(byte_rate) as max_byte_rate,
            COUNT(*) as totale_flussi,
            SUM(total_bytes) as byte_totali_aggregati,
            SUM(CASE 
                WHEN duration_ms > 0 THEN (duration_ms / {config.Soglie.MS_IN_SEC}) * packet_rate 
                ELSE (fwd_packets + bwd_packets) 
            END) as pacchetti_totali_aggregati,
            SUM(CASE WHEN packet_rate >= :dos_pps_min THEN 1 ELSE 0 END) as flussi_sopra_soglia_pps,
            SUM(CASE WHEN {web_cond_sql} THEN 1 ELSE 0 END) as flussi_web_totali,
            SUM(CASE WHEN {web_cond_sql} 
                THEN (CASE WHEN duration_ms > 0 THEN (duration_ms / {config.Soglie.MS_IN_SEC}) * packet_rate ELSE (fwd_packets + bwd_packets) END)
                ELSE 0 END) as pkts_web_totali,
            SUM(CASE WHEN duration_ms >= :slowloris_dur AND total_bytes < :slowloris_bytes AND {web_cond_sql} THEN 1 ELSE 0 END) as flussi_slowloris_attivi,
            SUM(CASE WHEN bwd_packets = 0 THEN 1 ELSE 0 END) as flussi_senza_bwd_pkt,
            TIMESTAMPDIFF(
                SECOND, 
                MIN(CASE WHEN {web_cond_sql} THEN timestamp_start ELSE NULL END), 
                MAX(CASE WHEN {web_cond_sql} THEN timestamp_start ELSE NULL END)
            ) as durata_burst_web_sec,
            TIMESTAMPDIFF(SECOND, MIN(timestamp_start), MAX(timestamp_start)) as durata_burst_sec
        FROM ndpi_flows
        {where_clause};
    """

    t_inizio_sql = time.perf_counter()
    raw_stats = {}
    try:
        with config.engine.connect() as connection:
            result = connection.execute(text(sql_text), params)
            riga_raw = result.mappings().fetchone()
            t_sql_puro = time.perf_counter() - t_inizio_sql
            raw_stats = dict(riga_raw) if riga_raw else {}
    except Exception as err_sql:
        print(f"[ERRORE SQL in _get_rate_statistics_raw]: {err_sql}")
        t_sql_puro = time.perf_counter() - t_inizio_sql

    max_pps = float(raw_stats.get("max_packet_rate") or 0.0)
    totale_flussi = int(raw_stats.get("totale_flussi") or 0)
    flussi_web = int(raw_stats.get("flussi_web_totali") or 0)
    flussi_slow = int(raw_stats.get("flussi_slowloris_attivi") or 0)
    flussi_high_rate = int(raw_stats.get("flussi_sopra_soglia_pps") or 0)
    pkts_totali = float(raw_stats.get("pacchetti_totali_aggregati") or 0.0)

    durata_burst = float(raw_stats.get("durata_burst_sec") or 0.0)
    eff_durata_burst = max(1.0, durata_burst)
    eff_durata_finestra = max(1.0, float(durata_sec))

    global_pps = round(pkts_totali / eff_durata_finestra, 2)
    burst_pps = round(pkts_totali / eff_durata_burst, 2)
    flussi_per_sec = round(totale_flussi / eff_durata_finestra, 2)
    burst_flussi_per_sec = round(totale_flussi / eff_durata_burst, 2)

    durata_burst_web = float(raw_stats.get("durata_burst_web_sec") or 0.0)
    eff_durata_burst_web = max(1.0, durata_burst_web)   
    web_rps = round(flussi_web / eff_durata_finestra, 2)
    burst_web_rps = round(flussi_web / eff_durata_burst_web, 2)

    s = config.Soglie
    dos_l7_flussi_min = getattr(s, "DOS_L7_FLUSSI_MIN", 20)
    dos_l7_rps_min = getattr(s, "DOS_L7_RPS_MIN", 0.02)
    dos_pps_min = getattr(s, "DOS_PPS_MIN", 3000.0)

    sospetto_volumetrico = (
        global_pps >= dos_pps_min
        or burst_pps >= dos_pps_min
        or flussi_high_rate > 0
        or (
            flussi_web >= dos_l7_flussi_min 
            and (web_rps >= dos_l7_rps_min or burst_web_rps >= dos_l7_rps_min)
        )
    )
    sospetto_slowloris = flussi_slow >= getattr(s, "SLOWLORIS_FLUSSI_MIN", 25)

    if sospetto_volumetrico:
        esito_smart = f"CRITICO: Rilevato traffico ad alto rate/flood (Burst PPS: {burst_pps}, Web RPS: {burst_web_rps}). Candidato per DOS_VOLUMETRIC."
    elif sospetto_slowloris:
        esito_smart = f"ATTENZIONE: Rilevate {flussi_slow} sessioni persistenti lente. Candidato per DOS_VOLUMETRIC (Slowloris)."
    else:
        esito_smart = "NORMALE: Volumi e frequenze pacchetti rientrano nei parametri regolari."

    return {
        "sintesi_smart": {
            "stato_anomalia": (
                "ANOMALIA_RILEVATA"
                if (sospetto_volumetrico or sospetto_slowloris)
                else "NORMALE"
            ),
            "diagnosi_preliminare": esito_smart,
        },
        "metriche_chiave": {
            "pps_aggregati": global_pps,
            "burst_pps": burst_pps,
            "totale_flussi": totale_flussi,
            "flussi_web_totali": flussi_web,
            "flussi_per_sec": flussi_per_sec,
            "burst_flussi_per_sec": burst_flussi_per_sec,
            "web_rps": web_rps,
            "burst_web_rps": burst_web_rps,
            "flussi_oltre_soglia_pps": flussi_high_rate,
            "flussi_slowloris": flussi_slow,
            "max_pps_singolo_flusso": round(max_pps, 2),
            "durata_burst_sec": durata_burst,
            "durata_burst_web_sec": durata_burst_web,
        },
        "tempo_sql_sec": round(t_sql_puro, 4),
    }

def _get_host_port_distribution_raw(
    ip_target: str,
    start_time: str,
    end_time: str,
) -> dict:
    query = text("""
        SELECT 
            dst_port,
            COUNT(*) as num_flussi,
            COUNT(DISTINCT src_ip) as sorgenti_distinte
        FROM ndpi_flows
        WHERE (dst_ip = :ip OR src_ip = :ip)
        AND timestamp_start BETWEEN :start_time AND :end_time
        GROUP BY dst_port
        ORDER BY num_flussi DESC;
    """)
    
    params = {
        "ip": ip_target,
        "start_time": normalizza_data(start_time, is_end=False),
        "end_time": normalizza_data(end_time, is_end=True),
    }

    t_inizio_sql = time.perf_counter()
    with config.engine.connect() as connection:
        result = connection.execute(query, params)
        distribuzione = [dict(row) for row in result.mappings().fetchall()]
        t_sql_puro = time.perf_counter() - t_inizio_sql

    porte_uniche = len(distribuzione)
    porte_probe = [p for p in distribuzione if p["num_flussi"] <= 3]
    
    porte_target_bf = [
        p["dst_port"] for p in distribuzione 
        if p["num_flussi"] >= 50 and p["dst_port"] not in (80, 443, 8080)
    ]

    # PortScan richiede almeno 15 porte uniche contattate con basso volume di flussi per porta
    sospetto_scan = (porte_uniche >= getattr(config.Soglie, "SCAN_PORTE_MIN", 15) and len(porte_probe) >= 8)
    sospetto_bruteforce = len(porte_target_bf) > 0

    return {
        "sintesi_smart": {
            "stato": "ANOMALIA_RILEVATA" if (sospetto_scan or sospetto_bruteforce) else "NORMALE",
            "porte_uniche_contattate": porte_uniche,
            "porte_probe_count": len(porte_probe),
            "sospetto_portscan": sospetto_scan,
            "sospetto_bruteforce": sospetto_bruteforce,
            "porte_target_bruteforce": porte_target_bf,
            "distribuzione_top": distribuzione[:10],
        },
        "tempo_sql_sec": round(t_sql_puro, 4),
    }

def _search_connection_attempts_raw(
    start_time: str,
    end_time: str,
    ip_target: Optional[str] = None,
    target_port: Optional[int] = None,
    ip_address: Optional[str] = None,
    include_web_ports: bool = True,
) -> dict:
    try:
        start_norm = normalizza_data(start_time, is_end=False)
        end_norm = normalizza_data(end_time, is_end=True)
        target_ip = (ip_target or ip_address or "").strip()

        params = {"start": start_norm, "end": end_norm}
        where_conds = ["timestamp_start BETWEEN :start AND :end"]

        # 1. COSTRUZIONE QUERY SQL
        if target_port is not None:
            params["target_port"] = int(target_port)
            where_conds.append("dst_port = :target_port")
            select_clause = "src_ip, dst_ip, dst_port, COUNT(*) as tentativi_totali, 1 as porte_distinte"
        else:
            if not include_web_ports:
                porte_escluse_raw = getattr(config.Soglie, "PORTE_ORDINARIE_WEB_DNS", {80, 443, 8080, 53})
                if isinstance(porte_escluse_raw, str):
                    porte_valide = re.findall(r"\d+", porte_escluse_raw)
                else:
                    porte_valide = [str(p) for p in porte_escluse_raw]

                if porte_valide:
                    porte_str = ",".join(porte_valide)
                    where_conds.append(f"(dst_port IS NULL OR dst_port NOT IN ({porte_str}))")

            select_clause = "src_ip, dst_ip, dst_port, COUNT(*) as tentativi_totali, COUNT(DISTINCT dst_port) as porte_distinte"

        if target_ip:
            where_conds.append("(src_ip = :ip OR dst_ip = :ip)")
            params["ip"] = target_ip

        where_clause = " WHERE " + " AND ".join(where_conds)
        group_clause = "GROUP BY src_ip, dst_ip, dst_port"

        sql_text = f"""
            SELECT 
                {select_clause}
            FROM ndpi_flows
            {where_clause}
            {group_clause}
            ORDER BY tentativi_totali DESC, porte_distinte DESC
            LIMIT 50;
        """

        # 2. ESECUZIONE QUERY
        t_inizio_sql = time.perf_counter()
        with config.engine.connect() as connection:
            result = connection.execute(text(sql_text), params)
            risultati = [dict(row) for row in (result.mappings().fetchall() if hasattr(result, "mappings") else result.fetchall())]

        t_sql_puro = time.perf_counter() - t_inizio_sql
        s = config.Soglie
        sospetti_count = 0

        # 3. PARSING SICURO DELLE PORTE DA CONFIGURAZIONE
        def _estrai_porte_set(valore_raw, fallback_set: set) -> set:
            if isinstance(valore_raw, str):
                numeri = re.findall(r"\d+", valore_raw)
                return {int(n) for n in numeri} if numeri else fallback_set
            elif isinstance(valore_raw, (set, list, tuple)):
                return {int(p) for p in valore_raw if str(p).isdigit()}
            return fallback_set

        porte_infra_estese = _estrai_porte_set(
            getattr(s, "PORTE_INFRASTRUTTURA_LAN", None),
            {53, 88, 135, 137, 138, 139, 389, 445, 3268, 3269}
        )

        porte_gestione = _estrai_porte_set(
            getattr(s, "PORTE_GESTIONE", None),
            {21, 22, 23, 3389, 5900, 2222}
        )

        # 4. VALUTAZIONE DEI FLUSSI
        for riga in risultati:
            porta = int(riga.get("dst_port") or 0)
            tentativi = int(riga.get("tentativi_totali") or 0)
            porte_distinte = int(riga.get("porte_distinte") or 1)

            if porta in porte_infra_estese or porta > 32768:
                riga["valutazione_mcp"] = "TRAFFICO_ORDINARIO_LAN"
            elif porte_distinte >= getattr(s, "SCAN_PORTE_MIN", 15):
                riga["valutazione_mcp"] = "SOSPETTO_PORTSCAN"
                sospetti_count += 1
            elif porte_distinte >= 3 and target_port is None:
                riga["valutazione_mcp"] = "SOSPETTO_PORTSCAN_LOW_VOLUME"
                sospetti_count += 1
            elif porta in porte_gestione and tentativi >= getattr(s, "BRUTEFORCE_TENTATIVI_MIN", 25):
                riga["valutazione_mcp"] = "SOSPETTO_BRUTEFORCE"
                sospetti_count += 1
            else:
                riga["valutazione_mcp"] = "TRAFFICO_ORDINARIO"

        return {
            "sintesi_smart": {
                "stato": "ANOMALIA_RILEVATA" if sospetti_count > 0 else "NORMALE",
                "pattern_sospetti_rilevati": sospetti_count,
                "esito": f"Rilevati {sospetti_count} pattern sospetti." if sospetti_count > 0 else "Nessun attacco aggressivo rilevato.",
                "target_analizzato": target_ip if target_ip else "TUTTI_GLI_HOST",
                "target_port_analizzata": target_port if target_port is not None else "TUTTE_LE_PORTE",
            },
            "tempo_sql_reale_sec": round(t_sql_puro, 6),
            "totale_coppie_ip_rilevate": len(risultati),
            "tentativi_connessione": risultati,
        }

    except Exception as e:
        print(f"\n[CRITICAL ERROR search_connection_attempts]: {type(e).__name__} -> {str(e)}\n")
        return {
            "sintesi_smart": {
                "stato": "ERRORE_ESECUZIONE",
                "pattern_sospetti_rilevati": 0,
                "esito": f"Errore interno SQL: {str(e)}",
                "target_analizzato": ip_target or "SCONOSCIUTO",
            },
            "tempo_sql_reale_sec": 0.0,
            "totale_coppie_ip_rilevate": 0,
            "tentativi_connessione": [],
        }
    

@mcp.tool(description=DESC_SEARCH_CONNECTION_ATTEMPTS)
@mcp_cache_guard
def search_connection_attempts(
    start_time: str,
    end_time: str,
    ip_target: Optional[str] = None,
    target_port: Optional[int] = None,
    ip_address: Optional[str] = None,
) -> str:
    raw_res = _search_connection_attempts_raw(
        start_time=start_time,
        end_time=end_time,
        ip_target=ip_target,
        target_port=target_port,
        ip_address=ip_address,
    )
    if not raw_res:
        return "[ERRORE TOOL]: Errore nell'esecuzione della ricerca dei tentativi di connessione."
    
    return json.dumps(raw_res, indent=2, default=str)


# =====================================================================
# CATEGORIA A: ANALISI COMPORTAMENTALE (Beaconing & HTTP L7)
# =====================================================================

@mcp.tool(description=DESC_DETECT_BEACONING)
@mcp_cache_guard
def detect_beaconing(
    ip_target: str,
    start_time: str,
    end_time: str,
    dst_ip: str = "",
    top_n: int = config.Soglie.BEACON_TOP_N_DEFAULT,
) -> str:
    """Wrapper MCP: chiama la logica raw e la serializza."""
    try:
        return json.dumps(_detect_beaconing_raw(ip_target, start_time, end_time, dst_ip, top_n), indent=2, default=str)
    except Exception as e:
        return f"[ERRORE TOOL]: Errore durante l'analisi di beaconing: {str(e)}"

@mcp.tool(description=DESC_SEARCH_HTTP_L7)
@mcp_cache_guard
def search_http_l7_anomalies(
    ip_target: str,
    start_time: str,
    end_time: str,
    limit: int = config.Soglie.LIMIT_DEFAULT_QUERY,
) -> str:
    """Wrapper MCP: chiama la logica raw e la serializza."""
    try:
        return json.dumps(_search_http_l7_anomalies_raw(ip_target, start_time, end_time, limit),
                          indent=2, default=str)
    except Exception as e:
        return json.dumps({"errore_sql": str(e)})

# =====================================================================
# CATEGORIA B: MONITORAGGIO VOLUMETRICO (Anomalia Rate / DoS)
# =====================================================================

@mcp.tool(description=DESC_GET_RATE_STATISTICS)
@mcp_cache_guard
def get_rate_statistics(
    start_time: str,
    end_time: str,
    ip_address: Optional[str] = None,
    ip_target: Optional[str] = None,
) -> str:
    """Wrapper MCP: chiama la logica raw e la serializza."""
    try:
        return json.dumps(
            _get_rate_statistics_raw(
                start_time, end_time, ip_address=ip_address, ip_target=ip_target
            ),
            indent=2,
            default=str,
        )
    except Exception as e:
        return f"[ERRORE TOOL]: Errore nel calcolo delle statistiche: {str(e)}"

# =====================================================================
# CATEGORIA C: INVESTIGAZIONE ENDPOINT (Top Talker & Host Profiling)
# =====================================================================

@mcp.tool(description=DESC_GET_HOST_PORT_DISTRIBUTION)
@mcp_cache_guard
def get_host_port_distribution(
    ip_target: str, start_time: str, end_time: str
) -> str:
    """Wrapper MCP: chiama la logica raw e la serializza."""
    try:
        return json.dumps(
            _get_host_port_distribution_raw(ip_target, start_time, end_time),
            indent=2,
            default=str,
        )
    except Exception as e:
        return f"[ERRORE TOOL]: Errore nell'analisi della distribuzione porte: {str(e)}"

# =====================================================================
# CATEGORIA D: ANALISI COMPORTAMENTALE (Brute Force / Infiltration)
# =====================================================================

@mcp.tool(description=DESC_ANALIZZA_CONNESSIONE)
@mcp_cache_guard
def analizza_connessione_by_community_id(cid: str) -> str:
    """Esegue il drill-down atomico su un singolo flusso conoscendo il suo community_id."""
    cid_clean = str(cid).strip()

    query = text("""
        SELECT community_id, src_ip, src_port, dst_ip, dst_port, protocol, duration_ms,
               total_bytes, packet_rate, payload_entropy, app_hierarchy, ndpi_hostname, infra_provider
        FROM ndpi_flows 
        WHERE community_id = :cid
        LIMIT 1;
    """)
    try:
        t_inizio_sql = time.perf_counter()

        with config.engine.connect() as connection:
            result = connection.execute(query, {"cid": cid_clean})
            riga_raw = result.mappings().fetchone()
            t_sql_puro = time.perf_counter() - t_inizio_sql

            if not riga_raw:
                return f"[ERRORE TOOL]: Nessun flusso di dettaglio trovato per il community_id: {cid_clean}."

            flusso = dict(riga_raw)

            if flusso.get("protocol") is not None:
                flusso["protocol"] = arricchisci_protocollo(int(flusso["protocol"]))

            payload_ent = float(flusso.get("payload_entropy") or 0.0)

            risposta_strutturata = {
                "sintesi_smart": {
                    "community_id_trovato": True,
                    "valutazione_entropia": "CRITICA (> 7.0)" if payload_ent > 7.0 else "NORMALE",
                    "note": "Payload fortemente cifrato o cifratura non standard." if payload_ent > 7.0 else "Parametri del flusso nei limiti della norma."
                },
                "tempo_sql_reale_sec": round(t_sql_puro, 6),
                "dettaglio_flusso": flusso
            }

            return json.dumps(risposta_strutturata, indent=2, default=str)
    except Exception as e:
        return f"[ERRORE TOOL]: Errore nel Drill-Down per community_id: {str(e)}"


if __name__ == "__main__":
    mcp.run(transport='stdio')
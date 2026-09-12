
import json
import time
import functools
import datetime
import ipaddress
import re
from typing import Union, Optional, Dict, Any, Tuple
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP
from sqlalchemy import text

import config, prompts

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


def _is_l7_whitelisted(app_hierarchy: str, hostname: str) -> bool:
    app = (app_hierarchy or "").lower()
    host = (hostname or "").lower()
    
    # Check protocolli OCSP / CRL / Telemetria
    if "ocsp" in app or "crl" in app:
        return True
        
    # Check domini noti CDN / Certificate Authorities
    return any(dom in host for dom in DOMINI_WHITELIST_L7)


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




@mcp.tool(description=prompts.DESC_GET_FLOW_FEATURES)
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
                
                if dst_port in s.PORTE_WEB_L7 and duration_ms >= s.SLOWLORIS_DURATION_MS and tot_bytes < s.SLOWLORIS_MAX_BYTES:
                    f["FLAG_SLOWLORIS_SUSPECT"] = True
                    f["ANOMALY_NOTE"] = f"ALERT: Connessione HTTP/HTTPS attiva per oltre {int(s.SLOWLORIS_DURATION_MS // s.MS_IN_SEC)}s a volume ridotto. Impronta tipica di Slowloris/Slow-Rate DoS."
                    slowloris_count += 1
                else:
                    f["FLAG_SLOWLORIS_SUSPECT"] = False

            risposta_finale = {
                "sintesi_smart": {
                    "stato": "ANOMALIA_RILEVATA" if slowloris_count >= config.Soglie.SLOWLORIS_FLUSSI_MIN else "NORMALE",
                    "flussi_slowloris_confermati": slowloris_count,
                    "diagnosi": (
                        f"Rilevati {slowloris_count} flussi con impronta Slowloris/Slow HTTP DoS "
                        f"(soglia per override DoS: {config.Soglie.SLOWLORIS_FLUSSI_MIN} — questo conteggio "
                        "NON la raggiunge, quindi da solo non giustifica DOS_VOLUMETRIC: valuta "
                        "WEB_ATTACK_EXPLOIT se c'è concentrazione su pochi target applicativi)."
                        if 0 < slowloris_count < config.Soglie.SLOWLORIS_FLUSSI_MIN
                        else f"Rilevati {slowloris_count} flussi con impronta Slowloris/Slow HTTP DoS."
                    ) if slowloris_count > 0 else "Nessuna anomalia temporale o Slowloris rilevata nei flussi principali."
                },
                "tempo_sql_reale_sec": round(t_sql_puro, 6),
                "totale_flussi_analizzati": len(flussi),
                "campione_flussi": flussi
            }

            return json.dumps(risposta_finale, indent=2, default=str)
    except Exception as e:
        return f"[ERRORE TOOL]: Errore nell'estrazione delle flow features: {str(e)}"

@mcp.tool(description=prompts.DESC_GET_TOP_TALKERS)
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

@mcp.tool(description=prompts.DESC_ANALYZE_DPI_DETAILS)
@mcp_cache_guard
def analyze_dpi_details(ip: str, start_time: str, end_time: str) -> str:
    """Esegue un'analisi profonda Deep Packet Inspection sui flussi del target."""
    start_time = normalizza_data(start_time, is_end=False)
    end_time = normalizza_data(end_time, is_end=True)

    query = text("""
        SELECT community_id, src_ip, src_port, dst_ip, dst_port, protocol, app_hierarchy, 
            ndpi_hostname, payload_entropy, infra_provider, tls_version, tls_cipher_suite,
            fwd_packets, bwd_packets
        FROM ndpi_flows
        WHERE (src_ip = :ip OR dst_ip = :ip)
          AND timestamp_start BETWEEN :start AND :end
        ORDER BY payload_entropy DESC, fwd_packets DESC
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

@mcp.tool(description=prompts.DESC_RESOLVE_HOST_INFO)
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




@mcp.tool(description=prompts.DESC_QUERY_BY_RATE)
@mcp_cache_guard
def query_by_rate(
    threshold: float,
    start_time: str,
    end_time: str,
    metric: str = "packet_rate",
    ip_address: Optional[str] = None,
) -> str:
    """Isola e filtra i flussi la cui frequenza supera una specifica soglia."""
    start_norm = normalizza_data(start_time, is_end=False)
    end_norm = normalizza_data(end_time, is_end=True)

    if metric not in ["packet_rate", "byte_rate"]:
        return "[ERRORE TOOL]: La metrica deve essere 'packet_rate' o 'byte_rate'."

    sql_where = (
        f"WHERE {metric} > :threshold AND timestamp_start BETWEEN :start AND :end"
    )
    params = {"threshold": threshold, "start": start_norm, "end": end_norm}

    if ip_address:
        sql_where += " AND (src_ip = :ip OR dst_ip = :ip)"
        params["ip"] = ip_address.strip()

    # Query con la corretta aggregazione bidirezionale dei byte e dei pacchetti
    query_count = text(f"""
        SELECT 
            COUNT(*) as totale_flussi_sopra_soglia, 
            COALESCE(SUM(total_fwd_bytes + total_bwd_bytes), 0) as byte_totali, 
            COALESCE(SUM(fwd_packets + bwd_packets), 0) as pacchetti_totali 
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
            res_count_raw = (
                connection.execute(query_count, params).mappings().fetchone()
            )
            res_count = dict(res_count_raw) if res_count_raw else {}

            res_top = connection.execute(query_top, params)
            flussi = [dict(row) for row in res_top.mappings().fetchall()]
            t_sql_puro = time.perf_counter() - t_inizio_sql

            for f in flussi:
                f["protocol"] = arricchisci_protocollo(int(f["protocol"]))

            tot_anomali = res_count.get("totale_flussi_sopra_soglia", 0)

            sintesi_testo = (
                f"Trovati {tot_anomali} flussi superiori alla soglia {metric} > {threshold}."
                if tot_anomali > 0
                else f"Nessun flusso supera la soglia specificata ({metric} > {threshold})."
            )

            risposta_finale = {
                "sintesi_smart": {
                    "flussi_rilevati": tot_anomali,
                    "esito": sintesi_testo,
                },
                "totali_aggregati": {
                    "byte_totali": float(res_count.get("byte_totali") or 0),
                    "pacchetti_totali": int(
                        res_count.get("pacchetti_totali") or 0
                    ),
                },
                "campione_top_3": flussi,
                "tempo_sql_sec": round(t_sql_puro, 4),
            }

            return json.dumps(risposta_finale, indent=2, default=str)
    except Exception as e:
        return f"[ERRORE TOOL]: Errore nell'analisi volumetrica: {str(e)}"

@mcp.tool(description=prompts.DESC_INSPECT_HTTP_REQUESTS)
@mcp_cache_guard
def inspect_http_requests(
    ip_target: str,
    start_time: str,
    end_time: str,
    limit: int = config.Soglie.LIMIT_DEFAULT_QUERY,
    offset: int = 0,
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
        ORDER BY f.fwd_packets DESC, f.duration_ms DESC
        LIMIT :limit OFFSET :offset;
    """)

    # Usa la costante di configurazione per il cap massimo invece del magic number 10
    max_limit = getattr(config.Soglie, "LIMIT_HTTP_INSPECT", 10)

    params = {
        "ip": ip_target.strip(),
        "start_time": normalizza_data(start_time, is_end=False),
        "end_time": normalizza_data(end_time, is_end=True),
        "limit": min(int(limit), max_limit),
        "offset": int(offset),
    }

    try:
        with config.engine.connect() as connection:
            result = connection.execute(query, params)
            dettagli = [dict(row) for row in result.mappings().fetchall()]

        return json.dumps(
            {
                "sintesi_smart": {
                    "totale_richieste_ispezionate": len(dettagli),
                    "nota": "Estratto un campione rappresentativo per preservare il contesto LLM.",
                },
                "richieste_top_bytes": dettagli,
            },
            indent=2,
            default=str,
        )
    except Exception as e:
        return json.dumps({"errore_sql": str(e)})

@mcp.tool(description=prompts.DESC_GET_TRAFFIC_SUMMARY)
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

    durata_finestra_sec = max(
        calcola_durata_finestra_reale(start_time, end_time), 1.0
    )

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
            result = connection.execute(
                query,
                {
                    "ip": ip_target.strip(),
                    "start": start_norm,
                    "end": end_norm,
                    "limit_val": limit_int,
                },
            )
            flussi = [dict(row) for row in result.mappings().fetchall()]
            t_sql_puro = time.perf_counter() - t_inizio_sql

            totale_reali = flussi[0]["totale_flussi_reali"] if flussi else 0
            bytes_totali = (
                float(flussi[0]["bytes_totali_finestra"])
                if flussi and flussi[0]["bytes_totali_finestra"] is not None
                else 0.0
            )
            packets_totali = (
                float(flussi[0]["pacchetti_totali_stimati_finestra"])
                if flussi and flussi[0]["pacchetti_totali_stimati_finestra"] is not None
                else 0.0
            )

            bps_globali = round(bytes_totali / durata_finestra_sec, 2)
            pps_globali = round(packets_totali / durata_finestra_sec, 2)

            for f in flussi:
                f["protocol"] = arricchisci_protocollo(int(f["protocol"]))
                f.pop("totale_flussi_reali", None)
                f.pop("bytes_totali_finestra", None)
                f.pop("pacchetti_totali_stimati_finestra", None)

            s = config.Soglie
            if pps_globali > s.DOS_PPS_MIN:
                diagnosi = (
                    f"CRITICO: Volume pacchetti globale elevato (>{s.DOS_PPS_MIN} PPS). Possibile DOS_VOLUMETRIC. "
                    "Non sono necessarie ulteriori ispezioni granulari sui singoli pacchetti/flussi VPN: "
                    "procedi a compute_verdict_scores con questa evidenza."
                )
            elif totale_reali > config.Soglie.DENSITA_FLUSSI_ELEVATA_MIN:
                diagnosi = (
                    f"ATTENZIONE: Elevata densita' di flussi (>{config.Soglie.DENSITA_FLUSSI_ELEVATA_MIN}). "
                    "Verificare se Connection Exhaustion o Scan. Se RPS/PPS sono concentrati, evita ispezioni "
                    "granulari ridondanti e procedi alla valutazione."
                )
            elif totale_reali == 0:
                diagnosi = "PULITO: Nessun flusso rilevato per l'host nella finestra."
            else:
                diagnosi = "REGOLARE: Volumi complessivi nella norma."

            risposta_finale = {
                "sintesi_smart": {
                    "stato": ("ANOMALO" if (pps_globali > s.DOS_PPS_MIN or totale_reali > s.DENSITA_FLUSSI_ELEVATA_MIN) else "NORMALE"),
                    "diagnosi_preliminare": diagnosi,
                    "pps_complessivi": pps_globali,
                    "totale_flussi_reali": totale_reali,
                    "totale_flussi_nella_finestra": totale_reali
                },
                "campione_flussi_recenti": flussi, 
                "tempo_sql_sec": round(t_sql_puro, 4),
            }
            return json.dumps(risposta_finale, indent=2, default=str)
    except Exception as e:
        return f"[ERRORE TOOL]: Errore nel recupero della sintesi del traffico: {str(e)}"
    
@mcp.tool(description=prompts.DESC_GET_AGGREGATED_TRAFFIC_SUMMARY)
@mcp_cache_guard
def get_aggregated_traffic_summary(
    ip_target: str, start_time: str, end_time: str
) -> str:
    """Raggruppa il traffico per (dst_ip, dst_port, protocollo, app)."""
    start_norm = normalizza_data(start_time, is_end=False)
    end_norm = normalizza_data(end_time, is_end=True)

    # Protezione divisione per zero in SQL
    durata_finestra_sec = max(
        calcola_durata_finestra_reale(start_time, end_time), 1.0
    )

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
            result = connection.execute(
                query,
                {
                    "ip": ip_target.strip(),
                    "start": start_norm,
                    "end": end_norm,
                    "durata_sec": durata_finestra_sec,
                },
            )
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
                    "top_porta_destinazione": (
                        righe[0]["dst_port"] if righe else None
                    ),
                },
                "aggregazione_per_servizio": righe,
                "tempo_sql_sec": round(t_sql_puro, 4),
            }
            return json.dumps(risposta, indent=2, default=str)
    except Exception as e:
        return f"[ERRORE TOOL]: Errore nel recupero della sintesi aggregata: {str(e)}"





def _calcola_scores_da_evidenze(
    rate_stats: dict | None,
    port_dist: dict | None,
    beacon: dict | None,
    l7: dict | None,
    conn_attempts: dict | None,
) -> dict:

    # 1. SANITIZZAZIONE INPUT CONTRO ERRORE NoneType
    rate_stats = rate_stats or {}
    port_dist = port_dist or {}
    beacon = beacon or {}
    l7 = l7 or {}
    conn_attempts = conn_attempts or {}

    def _is_private_ip(ip_str: str) -> bool:
        try:
            return ipaddress.ip_address(ip_str).is_private
        except Exception:
            return False

    def _eval_scan_and_bruteforce(
        conn_attempts: dict | None, 
        port_ss: dict, 
        s, 
        web_attack_score: float = 0.0
    ) -> tuple[float, list[str]]:
        conn_attempts = conn_attempts or {}
        note = []
        porte_gestione = getattr(s, "PORTE_GESTIONE", {21, 22, 23, 3389, 5900, 2222})
        porte_web = getattr(s, "PORTE_WEB_L7", {80, 443, 8080, 8443, 8000})
        porte_infra_lan = getattr(s, "PORTE_INFRASTRUTTURA_LAN", {53, 88, 137, 138, 139, 389, 445, 636})

        porte_target_bruteforce = port_ss.get("porte_target_bruteforce") or []
        porte_uniche_total = int(port_ss.get("porte_uniche_contattate") or 0)
        sospetto_scan = port_ss.get("sospetto_portscan", False)
        distribuzione_top = port_ss.get("distribuzione_top") or []

        has_valid_bf_port = any(int(p) in porte_gestione for p in porte_target_bruteforce)
        tentativi_conn = conn_attempts.get("tentativi_connessione") or []
        has_single_port_bf = False

        for t in tentativi_conn:
            tentativi = int(t.get("tentativi_totali") or 0)
            porta = int(t.get("dst_port") or 0)
            if porta in porte_gestione and tentativi >= getattr(s, "BRUTEFORCE_TENTATIVI_MIN", 25):
                has_single_port_bf = True
                break

        scan_score = 0.0
        if porte_uniche_total >= getattr(s, "SCAN_PORTE_MIN", 15) and sospetto_scan:
            scan_score = 0.95
            note.append("Port Scan L4 rilevato su ampie fasce di porte.")

        if has_valid_bf_port or has_single_port_bf:
            scan_score = max(scan_score, 0.95)
            note.append("Pattern Brute Force L4 rilevato su porte di gestione (SSH/FTP/RDP).")

        # --- SWEEP MULTI-SERVIZIO A BASSO VOLUME ---
        sweep_porte_min = getattr(s, "SWEEP_PORTE_MIN", 4)
        sweep_conc_max = getattr(s, "SWEEP_CONCENTRAZIONE_MAX", 0.70)

        if scan_score < 0.85 and sweep_porte_min <= porte_uniche_total < getattr(s, "SCAN_PORTE_MIN", 15) and distribuzione_top:
            categorie_toccate = set()
            for riga in distribuzione_top:
                porta = int(riga.get("dst_port") or 0)
                if porta in porte_web:
                    categorie_toccate.add("WEB")
                elif porta in porte_gestione:
                    categorie_toccate.add("GESTIONE")
                elif porta in porte_infra_lan:
                    categorie_toccate.add("INFRA_LAN")
                else:
                    categorie_toccate.add("ALTRO")

            flussi_per_porta = [int(r.get("num_flussi") or 0) for r in distribuzione_top]
            totale_flussi_top = sum(flussi_per_porta) or 1
            concentrazione = (max(flussi_per_porta) if flussi_per_porta else 0) / totale_flussi_top

            categorie_rilevanti = categorie_toccate - {"INFRA_LAN"}
            sweep_flussi_min = getattr(s, "SWEEP_FLUSSI_MIN_ASSOLUTI", 50)

            if (
                len(categorie_rilevanti) >= 2
                and concentrazione <= sweep_conc_max
                and totale_flussi_top >= sweep_flussi_min
            ):
                scan_score = max(scan_score, 0.85)
                note.append(
                    f"Rilevato sweep multi-servizio su {porte_uniche_total} porte eterogenee "
                    f"({', '.join(sorted(categorie_rilevanti))}), {totale_flussi_top} flussi totali, "
                    f"nessuna porta dominante (concentrazione max {concentrazione:.0%})."
                )

        # --- CORREZIONE DISAMBIGUAZIONE ---
        if web_attack_score >= 0.70 and not (has_valid_bf_port or has_single_port_bf):
            if porte_uniche_total < 20:
                scan_score = min(scan_score, 0.40)
                note.append("Portscan marginale/rumore L4 depotenziato in presenza di Web Attack L7 concentrato.")

        return scan_score, note

    def _eval_dos_scores(mk: dict, l7_ss: dict, flussi_p53: int, s, web_attack_score: float = 0.0) -> tuple[float, list[str]]:
        note = []
        totale_flussi = int(mk.get("totale_flussi") or 0)
        flussi_web = int(mk.get("flussi_web_totali") or 0)
        destinazioni_web = int(mk.get("destinazioni_web_distinte") or 0)
        concentrazione_web = (flussi_web / destinazioni_web) if destinazioni_web > 0 else 0.0
        concentrazione_dos_min = getattr(s, "CONCENTRAZIONE_DOS_MIN", 25.0)

        sospetto_web_bf_locale = bool(l7_ss.get("sospetto_web_bruteforce", False))

        pps = float(mk.get("pps_aggregati") or 0.0)
        burst_pps = float(mk.get("burst_pps") or pps)
        effective_pps = max(pps, burst_pps)

        web_rps = float(mk.get("web_rps") or 0.0)
        burst_web_rps = float(mk.get("burst_web_rps") or web_rps)
        effective_web_rps = max(web_rps, burst_web_rps)

        flussi_slow = int(mk.get("flussi_slowloris") or 0)
        max_tentativi_ip = int(l7_ss.get("max_tentativi_per_ip") or 0)

        pacchetti_totali = int(mk.get("pacchetti_totali_stimati") or 0)

        dos_pps_score = min(1.0, effective_pps / getattr(s, "DOS_PPS_MIN", 3000.0)) if effective_pps >= getattr(s, "DOS_PPS_MIN", 3000.0) else 0.0
        dos_l7_score = 0.0
        dos_slow_score = 0.0

        is_dns_traffic = (flussi_p53 / max(totale_flussi, 1) > 0.8) if totale_flussi > 0 else False

        if is_dns_traffic:
            if burst_pps >= 300.0 or totale_flussi >= 20000:
                dos_l7_score = 0.95
                note.append("Rilevato DNS Flood / Amplification DoS.")
        else:
            # --- GUARDRAIL GOLDENEYE / DoS L7 CONCENTRATO ---
            is_goldeneye_pattern = (
                flussi_web >= 100 
                and max_tentativi_ip >= 100 
                and destinazioni_web == 1
                and effective_web_rps >= getattr(s, "DOS_GOLDENEYE_RPS_MIN", 5.0)  # <-- NUOVO
            )

            volume_elevato = (
                flussi_web >= 1000 
                or max_tentativi_ip >= 1000 
                or effective_web_rps >= 10.0 
                or pacchetti_totali >= 5000
                or is_goldeneye_pattern
            )

            concentrazione_ok = (concentrazione_web >= concentrazione_dos_min) or (totale_flussi < 100 and pacchetti_totali >= 5000) or is_goldeneye_pattern

            if volume_elevato and concentrazione_ok:
                dos_l7_score = 0.95
                if is_goldeneye_pattern:
                    note.append(
                        f"Rilevato pattern DoS L7 (GoldenEye / HTTP Flood): {max_tentativi_ip} "
                        f"connessioni/richieste concentrate su un unico target web ({flussi_web} flussi totali)."
                    )
                else:
                    note.append(
                        f"Elevata saturazione HTTP/DoI concentrata ({flussi_web} flussi web, "
                        f"{pacchetti_totali} pacchetti totali su {destinazioni_web} destinazioni): identificato DoS L7 / Volumetrico."
                    )
            elif volume_elevato and not concentrazione_ok:
                note.append(
                    f"Volume HTTP/pacchetti elevato ({flussi_web} flussi, {pacchetti_totali} pkts) ma distribuito su "
                    f"{destinazioni_web} destinazioni: compatibile con browsing intenso. Score DoS non assegnato."
                )

        slow_min = getattr(s, "SLOWLORIS_FLUSSI_MIN", 100)
        if (flussi_slow >= slow_min or (flussi_web >= 500 and flussi_slow >= 50)):
            dos_slow_score = 0.95
            note.append("Rilevata impronta Slowloris / Slow HTTP DoS.")

        ratio_porte_effimere = float(mk.get("ratio_porte_effimere") or 0.0)
        porte_sorgente_uniche = int(mk.get("porte_sorgente_uniche") or 0)
        dos_effimere_score = 0.0

        pps_floor_ok = effective_pps >= getattr(s, "DOS_PPS_MIN_FALLBACK", 1000.0)

        if (
            dos_l7_score < 0.90
            and web_attack_score < 0.70
            and not is_dns_traffic          # <-- NUOVO: ratio porte effimere è intrinseco a DNS/UDP normale
            and (
                (ratio_porte_effimere >= getattr(s, "RATIO_PORTE_EFFIMERE_MIN", 0.70)
                and porte_sorgente_uniche >= getattr(s, "PORTE_SORGENTE_UNICHE_MIN", 100)
                and pps_floor_ok)          # <-- NUOVO: serve anche un volume PPS reale, non solo il ratio
                or (pacchetti_totali >= 5000 and totale_flussi < 500 and pps_floor_ok)
            )
        ):
            dos_effimere_score = 0.95
            note.append(
                f"Rilevato pattern volumetrico compresso da nDPI ({porte_sorgente_uniche} porte src uniche "
                f"su {totale_flussi} flussi, ratio {ratio_porte_effimere:.0%}, PPS effettivo {effective_pps:.1f}): "
                "pattern DoS Volumetrico confermato."
            )

        final_dos = max(dos_pps_score, dos_l7_score, dos_slow_score, dos_effimere_score)
        return min(final_dos, 0.95), note

    def _eval_beacon_score(beacon: dict, dos_score: float, mk: dict) -> tuple[float, list[str]]:
        note = []
        top_candidati = beacon.get("candidati_top") or []
        sintesi_beacon = beacon.get("sintesi_smart") or {}

        candidati_esterni = [
            c for c in top_candidati 
            if (ip := (c.get("dst_ip") or c.get("ip_dst") or c.get("ip_target") or c.get("ip") or "")) 
            and not _is_private_ip(ip)
        ]

        has_beacon_flag = sintesi_beacon.get("beaconing_c2_rilevato", False)
        bot_count = int(sintesi_beacon.get("bot_traffic_count") or 0)

        raw_beacon_score = 0.0
        if candidati_esterni:
            max_cand_score = max([float(c.get("anomaly_score") or 0) for c in candidati_esterni], default=0.0)
            min_cv = min([float(c.get("cv") if c.get("cv") is not None else 999.0) for c in candidati_esterni], default=999.0)
            
            has_c2_port = any(int(c.get("dst_port") or 0) in {8080, 8443, 444, 1080} for c in candidati_esterni)
            tot_connessioni = max([int(c.get("totale_connessioni") or 0) for c in candidati_esterni], default=0)

            if (max_cand_score >= 50 or min_cv <= 1.50) or (has_c2_port and tot_connessioni >= 15):
                raw_beacon_score = 0.95
                note.append(f"Rilevato traffico di Beaconing C2/Jitter verso IP esterni (CV: {min_cv}, Connessioni: {tot_connessioni}).")
        elif has_beacon_flag or bot_count > 0:
            raw_beacon_score = 0.95
            note.append("Rilevato traffico compatibile con Botnet / Beaconing C2.")

        totale_flussi = int(mk.get("totale_flussi") or 0)
        if dos_score >= 0.95 and totale_flussi >= 10000 and not has_beacon_flag:
            raw_beacon_score = min(raw_beacon_score, 0.30)

        return raw_beacon_score, note

    def _tie_break_evidenze(vincitori: list[str], mk: dict, port_ss: dict, l7_ss: dict, s) -> str | None:
        pps_effettivo = max(float(mk.get("pps_aggregati") or 0), float(mk.get("burst_pps") or 0))
        web_rps = max(float(mk.get("web_rps") or 0), float(mk.get("burst_web_rps") or 0))
        porte_uniche = int(port_ss.get("porte_uniche_contattate") or 0)
        totale_flussi = int(mk.get("totale_flussi") or 0)

        # --- GUARDRAIL VITTIMA DDoS ---
        # Se il traffico e' concentrato su UNA porta dominante (>60% dei flussi totali)
        # mentre le restanti porte hanno pochissimi flussi ciascuna, e' la firma di un
        # flood ricevuto (porte "sporcate" dal rumore dell'attacco), non di uno scan
        # iniziato dall'host. In questo caso il conteggio grezzo delle porte va
        # fortemente sconto come evidenza di SCAN_BRUTEFORCE.
        distribuzione_top = port_ss.get("distribuzione_top") or []
        flussi_per_porta = [int(r.get("num_flussi") or 0) for r in distribuzione_top]
        concentrazione_max_porta = (max(flussi_per_porta) / totale_flussi) if (flussi_per_porta and totale_flussi > 0) else 0.0
        is_probabile_vittima_flood = concentrazione_max_porta >= 0.50 and porte_uniche >= 15

        forza = {}
        if "DOS_VOLUMETRIC" in vincitori:
            forza["DOS_VOLUMETRIC"] = max(
                pps_effettivo / getattr(s, "DOS_PPS_MIN_FALLBACK", 1000.0),  # <-- usa la soglia fallback, più realistica
                web_rps / getattr(s, "DOS_L7_RPS_MIN", 10.0),
            )
        if "SCAN_BRUTEFORCE" in vincitori:
            forza_scan = porte_uniche / max(getattr(s, "SCAN_PORTE_MIN", 15), 1)
            if is_probabile_vittima_flood:
                forza_scan *= 0.3   # penalizza pesantemente: molto probabile rumore da flood, non scan reale
            forza["SCAN_BRUTEFORCE"] = forza_scan
        if "WEB_ATTACK_EXPLOIT" in vincitori:
            login_endpoint_targeted = bool(l7_ss.get("login_endpoint_targeted", False))
            target_colpiti = int(l7_ss.get("target_colpiti_count") or 0)
            if login_endpoint_targeted:
                forza["WEB_ATTACK_EXPLOIT"] = 1.2
            elif target_colpiti in (1, 2, 3) and target_colpiti > 0:
                forza["WEB_ATTACK_EXPLOIT"] = 1.05
            else:
                forza["WEB_ATTACK_EXPLOIT"] = 0.5
        if "BEACONING_C2" in vincitori:
            forza["BEACONING_C2"] = 0.8

        if not forza:
            return None

        max_forza = max(forza.values())
        if max_forza < 1.0:
            return None

        top_candidati = [k for k, v in forza.items() if v == max_forza]
        altri_valori = [v for k, v in forza.items() if k not in top_candidati]

        # --- MARGINE DI DOMINANZA ---
        # Il vincitore deve superare il secondo candidato di almeno il 50%, non solo
        # superare la propria soglia assoluta: altrimenti un pareggio "quasi vero"
        # (es. 1.06 vs 0.95) viene deciso con falsa sicurezza.
        MARGINE_MIN = 1.50
        e_dominante = (not altri_valori) or (max_forza >= max(altri_valori) * MARGINE_MIN)

        if len(top_candidati) == 1 and e_dominante:
            return top_candidati[0]

        return None

    # --- CALCOLO EFFETTIVO DEGLI SCORE ---
    s = config.Soglie
    note_logiche = []

    mk = rate_stats.get("metriche_chiave") or {}
    l7_ss = l7.get("sintesi_smart") or {}
    port_ss = port_dist.get("sintesi_smart") or {}
    distribuzione_top = port_ss.get("distribuzione_top") or []

    totale_flussi = int(mk.get("totale_flussi") or 0)
    flussi_p53 = sum(p.get("num_flussi", 0) for p in distribuzione_top if p.get("dst_port") == 53)

    # 1. Calcolo Valori L7 (Web Attack / Exploit)
    anomalie_l7 = int(l7_ss.get("anomalie_l7_trovate") or 0)
    sospetto_web_bf = l7_ss.get("sospetto_web_bruteforce", False)
    max_tentativi_ip = int(l7_ss.get("max_tentativi_per_ip") or 0)
    early_stop_exploit = l7_ss.get("early_stop_web_exploit", False)
    login_endpoint_targeted = bool(l7_ss.get("login_endpoint_targeted", False))
    porte_uniche_total = int(port_ss.get("porte_uniche_contattate") or 0)
    flussi_web = int(mk.get("flussi_web_totali") or 0)
    destinazioni_web = int(mk.get("destinazioni_web_distinte") or 0)
    web_rps_top = float(mk.get("web_rps") or 0.0)
    burst_web_rps_top = float(mk.get("burst_web_rps") or web_rps_top)
    effective_web_rps_top = max(web_rps_top, burst_web_rps_top)

    is_goldeneye_pattern = (
        flussi_web >= 100 
        and max_tentativi_ip >= 100 
        and destinazioni_web == 1
        and effective_web_rps_top >= getattr(s, "DOS_GOLDENEYE_RPS_MIN", 5.0)
    )
    is_volumetric_dos_l7 = flussi_web >= 1000 or max_tentativi_ip >= 1000 or is_goldeneye_pattern

    is_web_bruteforce_active = (sospetto_web_bf or max_tentativi_ip >= 200) and not is_volumetric_dos_l7

    web_attack_score = 0.0

    if anomalie_l7 > 0 or early_stop_exploit:
        web_attack_score = 0.95
        note_logiche.append(f"Rilevate {anomalie_l7} anomalie L7/HTTP (XSS/SQLi/Path Traversal).")
    elif is_web_bruteforce_active and porte_uniche_total < 20:
        if login_endpoint_targeted:
            web_attack_score = 0.95
            note_logiche.append(f"Rilevato Web Brute Force mirato a endpoint di login ({max_tentativi_ip} req/IP).")
        elif is_web_bruteforce_active and (porte_uniche_total < 20 or destinazioni_web <= 3):
            web_attack_score = 0.75
            note_logiche.append(
                f"Rilevato Web Brute Force a basso volume ({max_tentativi_ip} req/IP), "
                "senza endpoint di login identificabile."
            )

    # 2. Calcolo Altri Score
    scan_score, note_scan = _eval_scan_and_bruteforce(conn_attempts, port_ss, s, web_attack_score)
    note_logiche.extend(note_scan)

    dos_score, note_dos = _eval_dos_scores(mk, l7_ss, flussi_p53, s, web_attack_score)
    note_logiche.extend(note_dos)

    beacon_score, note_beacon = _eval_beacon_score(beacon, dos_score, mk)
    note_logiche.extend(note_beacon)

    # Dizionario Punteggi
    scores_dict = {
        "WEB_ATTACK_EXPLOIT": web_attack_score,
        "SCAN_BRUTEFORCE": scan_score,
        "DOS_VOLUMETRIC": dos_score,
        "BEACONING_C2": beacon_score,
    }

    # Determinazione Suggerimento per l'LLM (Tie-Breaking Euristico)
    max_val = max(scores_dict.values())
    vincitori: list[str] = []
    conflitto_a_pari_merito: list[str] = []

    if max_val >= 0.5:
        vincitori = [k for k, v in scores_dict.items() if v == max_val]
        if len(vincitori) == 1:
            vincitore_assoluto = vincitori[0]
        else:
            conflitto_a_pari_merito = vincitori
            esito_tie = _tie_break_evidenze(vincitori, mk, port_ss, l7_ss, s)
            if esito_tie is None:
                vincitore_assoluto = "CONFLITTO_IRRISOLTO"
                note_logiche.append(
                    f"CONFLITTO A PARI MERITO tra {vincitori} (score {max_val}) NON risolvibile dalle evidenze "
                    "grezze disponibili: nessun candidato supera realmente la propria soglia di riferimento. "
                    "Nessun suggerimento di default — decidi tu sulla base dei dati grezzi."
                )
            else:
                vincitore_assoluto = esito_tie
                note_logiche.append(
                    f"CONFLITTO A PARI MERITO tra {vincitori} (score {max_val}) risolto dalle evidenze grezze "
                    f"a favore di {vincitore_assoluto} (PPS/RPS effettivi vs soglie, porte contattate)."
                )
    else:
        vincitore_assoluto = "BENIGN"

    return {
        "DOS_VOLUMETRIC": scores_dict["DOS_VOLUMETRIC"],
        "SCAN_BRUTEFORCE": scores_dict["SCAN_BRUTEFORCE"],
        "BEACONING_C2": scores_dict["BEACONING_C2"],
        "WEB_ATTACK_EXPLOIT": scores_dict["WEB_ATTACK_EXPLOIT"],
        "verdetto_suggerito_euristica": vincitore_assoluto,
        "conflitto_a_pari_merito": conflitto_a_pari_merito,
        "note_logiche": note_logiche,
        "avviso_per_llm": "Questi score sono un calcolo euristico di supporto. L'LLM ha l'autonomia di confermare o ribaltare il verdetto analizzando le evidenze dettagliate."
    }

@mcp.tool(description=prompts.DESC_COMPUTE_VERDICT_SCORES)
@mcp_cache_guard
def compute_verdict_scores(ip_target: str, start_time: str, end_time: str) -> str:
    """Wrapper MCP: fetch dei dati via tool _raw + delega del calcolo alla funzione pura."""
    try:
        rate_stats = _get_rate_statistics_raw(start_time, end_time, ip_target) or {}
        port_dist = _get_host_port_distribution_raw(ip_target, start_time, end_time) or {}
        beacon = _detect_beaconing_raw(ip_target, start_time, end_time) or {}
        l7 = _search_http_l7_anomalies_raw(ip_target, start_time, end_time) or {}

        conn_attempts = (
            _search_connection_attempts_raw(
                start_time,
                end_time,
                ip_target=ip_target,
                include_web_ports=True,
            )
            or {}
        )

        risultato = _calcola_scores_da_evidenze(
            rate_stats, port_dist, beacon, l7, conn_attempts
        )
        risultato["ip_target"] = ip_target
        return json.dumps(risultato, ensure_ascii=False)

    except Exception as e:
        return json.dumps(
            {"status": "error", "message": f"Errore calcolo verdict scores: {str(e)}"},
            ensure_ascii=False,
        )




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

        if target_port is not None:
            params["target_port"] = int(target_port)
            where_conds.append("dst_port = :target_port")
            select_clause = "src_ip, dst_ip, dst_port, COUNT(*) as tentativi_totali, 1 as porte_distinte"
        else:
            if not include_web_ports:
                porte_escluse_raw = getattr(
                    config.Soglie, "PORTE_ORDINARIE_WEB_DNS", {80, 443, 8080, 53}
                )
                if isinstance(porte_escluse_raw, str):
                    porte_valide = re.findall(r"\d+", porte_escluse_raw)
                else:
                    porte_valide = [str(p) for p in porte_escluse_raw]

                if porte_valide:
                    porte_str = ",".join(porte_valide)
                    where_conds.append(f"(dst_port IS NULL OR dst_port NOT IN ({porte_str}))")

            # FIX GROUP BY: Usiamo MAX(dst_port) per evitare errori SQL FULL_GROUP_BY
            select_clause = "src_ip, dst_ip, MAX(dst_port) as dst_port, COUNT(*) as tentativi_totali, COUNT(DISTINCT dst_port) as porte_distinte"

        if target_ip:
            where_conds.append("(src_ip = :ip OR dst_ip = :ip)")
            params["ip"] = target_ip

        where_clause = " WHERE " + " AND ".join(where_conds)
        group_clause = "GROUP BY src_ip, dst_ip"

        sql_text = f"""
            SELECT 
                {select_clause}
            FROM ndpi_flows
            {where_clause}
            {group_clause}
            ORDER BY tentativi_totali DESC, porte_distinte DESC
            LIMIT 50;
        """

        t_inizio_sql = time.perf_counter()
        with config.engine.connect() as connection:
            result = connection.execute(text(sql_text), params)
            risultati = [
                dict(row)
                for row in (
                    result.mappings().fetchall()
                    if hasattr(result, "mappings")
                    else result.fetchall()
                )
            ]

        t_sql_puro = time.perf_counter() - t_inizio_sql
        s = config.Soglie
        sospetti_count = 0

        def _estrai_porte_set(valore_raw, fallback_set: set) -> set:
            if isinstance(valore_raw, str):
                numeri = re.findall(r"\d+", valore_raw)
                return {int(n) for n in numeri} if numeri else fallback_set
            elif isinstance(valore_raw, (set, list, tuple)):
                return {int(p) for p in valore_raw if str(p).isdigit()}
            return fallback_set

        porte_infra_estese = _estrai_porte_set(
            getattr(s, "PORTE_INFRASTRUTTURA_LAN", None),
            {53, 88, 135, 137, 138, 139, 389, 445, 3268, 3269},
        )

        porte_gestione = _estrai_porte_set(
            getattr(s, "PORTE_GESTIONE", None),
            {21, 22, 23, 3389, 5900, 2222},
        )

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
                "esito": (
                    f"Rilevati {sospetti_count} pattern sospetti."
                    if sospetti_count > 0
                    else "Nessun attacco aggressivo rilevato."
                ),
                "target_analizzato": target_ip if target_ip else "TUTTI_GLI_HOST",
                "target_port_analizzata": (
                    target_port if target_port is not None else "TUTTE_LE_PORTE"
                ),
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
    
def _detect_beaconing_raw(
    ip_target: str,
    start_time: str,
    end_time: str,
    dst_ip: Optional[str] = None,
    top_n: Optional[int] = None,
) -> dict:
    
    def _is_whitelisted(hostname: str, whitelist: list[str]) -> bool:
        if not hostname:
            return False
        hostname = hostname.lower().rstrip(".")
        return any(hostname == d or hostname.endswith("." + d) for d in whitelist)

    def _compute_anomaly_score(
        cv: float, 
        totale_connessioni: int, 
        is_whitelisted: bool, 
        dst_ip: str,
        dst_port: int = 0,
        infra_provider: Optional[str] = None,
    ) -> Tuple[int, list]:
        tag_list = []
        s = config.Soglie

        if is_whitelisted:
            tag_list.append("WHITELISTED_SERVICE")
            return s.SCORE_WHITELISTED, tag_list

        if _is_ip_privato(dst_ip):
            tag_list.append("INTERNAL_LAN_KEEPALIVE")
            return s.SCORE_DEFAULT, tag_list

        # Infrastruttura nota (CDN/cloud reputato) + jitter debole (CV > soglia C2 stretta):
        # e' molto più probabile un refresh periodico applicativo (news, widget, polling)
        # che un impianto C2, a meno che il pattern sia già CONFIRMED (CV <= 0.6, gestito
        # nel ramo sotto prima di questo controllo se vuoi dare priorità al CV stretto).
        PROVIDER_REPUTATI = {"cloudflare", "akamai", "edgecast", "aws", "google", "fastly", "amazon"}
        is_reputable_infra = bool(infra_provider) and any(
            p in infra_provider.lower() for p in PROVIDER_REPUTATI
        )
        if is_reputable_infra and cv > s.CV_BEACON_JITTER_MAX:
            tag_list.append("REPUTABLE_INFRA_WEAK_JITTER")
            return s.SCORE_DEFAULT, tag_list

        if totale_connessioni >= s.BEACON_MIN_CONNESSIONI:
            if cv <= 0.6:
                score = s.ANOMALY_SCORE_C2_MIN + 30
                tag_list.append("CONFIRMED_BEACONING_C2")
                return score, tag_list
            elif 0.6 < cv <= 1.2:
                moles_score = int(80 - ((cv - 0.6) / 0.6) * 30)
                
                if dst_port > 1024 and dst_port not in (8080, 8443):
                    moles_score = min(100, moles_score + 15)
                    
                tag_list.append("SUSPECTED_BEACONING_JITTER")
                return moles_score, tag_list

        return s.SCORE_DEFAULT, tag_list

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
                n.src_ip,
                n.dst_ip,
                n.dst_port,
                n.ndpi_hostname,
                n.infra_provider,
                TIMESTAMPDIFF(
                    SECOND,
                    LAG(n.timestamp_start) OVER (
                        PARTITION BY n.src_ip, n.dst_ip, n.dst_port
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
                MAX(infra_provider) as infra_provider,
                COUNT(*) as intervalli_validi,
                AVG(delta_time) as intervallo_medio,
                STDDEV(delta_time) as dev_std,
                CASE
                    WHEN AVG(delta_time) > 0 THEN STDDEV(delta_time) / AVG(delta_time)
                    ELSE 999.0
                END as cv_calcolato
            FROM timed_flows
            WHERE delta_time IS NOT NULL AND delta_time > 0
            GROUP BY dst_ip, dst_port
            HAVING intervalli_validi >= :min_intervals
        )
        SELECT 
            dst_ip, 
            dst_port, 
            (intervalli_validi + 1) as totale_connessioni,
            ROUND(intervallo_medio, 1) as avg_sec,
            ROUND(dev_std, 1) as std_sec,
            ROUND(cv_calcolato, 3) as cv,
            hostname,
            infra_provider
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
        infra_provider = str(riga.get("infra_provider") or "")

        is_whitelisted = _is_whitelisted(hostname, DOMINI_WHITELIST_BEACONING)
        
        anomaly_score, tag_list = _compute_anomaly_score(
            cv, totale_connessioni, is_whitelisted, dst_ip_val, dst_port, infra_provider
        )

        is_internal_keepalive = "INTERNAL_LAN_KEEPALIVE" in tag_list

        # MODIFICA QUI: Riconosci il Beaconing con Jitter tra i candidati C2
        if not is_whitelisted and not is_internal_keepalive:
            if (
                "CONFIRMED_BEACONING_C2" in tag_list 
                or "SUSPECTED_BEACONING_JITTER" in tag_list 
                or anomaly_score >= 50 
                or cv <= 1.50
            ):
                has_c2_candidate = True

        risultati.append({
            "dst_ip": dst_ip_val,
            "dst_port": dst_port,
            "hostname": hostname if hostname else "N/A",
            "infra_provider": infra_provider if infra_provider else "N/A",
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

@mcp.tool(description=prompts.DESC_DETECT_BEACONING)
@mcp_cache_guard
def detect_beaconing(
    ip_target: str,
    start_time: str,
    end_time: str,
    dst_ip: str = "",
    top_n: int = config.Soglie.BEACON_TOP_N_DEFAULT,
) -> str:
    try:
        return json.dumps(
            _detect_beaconing_raw(ip_target, start_time, end_time, dst_ip, top_n),
            indent=2,
            default=str,
        )
    except Exception as e:
        return json.dumps({"status": "error", "message": f"Errore durante l'analisi di beaconing: {str(e)}"})

def _search_http_l7_anomalies_raw(
    ip_target: str,
    start_time: str,
    end_time: str,
    limit: int = config.Soglie.LIMIT_DEFAULT_QUERY,
) -> dict:
    porte_web_extended = set(config.Soglie.PORTE_WEB_L7).union(
        {444, 8443, 4433, 80, 443}
    )
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
                "http_req_rate": 0.0,
                "login_endpoint_targeted": False,
                "early_stop_web_exploit": False,
                "esito": "Nessun traffico HTTP/L7 trovato nella finestra temporale.",
            },
            "campione_anomalie": [],
            "tempo_sql_sec": round(t_sql_puro, 4),
        }

    http_login_patterns = ["login", "auth", "signin", "admin", "wp-login"]

    richieste_sospette = []
    flussi_web_non_whitelisted = 0
    req_per_sorgente = {}
    target_per_sorgente = {}
    has_login_endpoint = False

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

        fwd_p = f.get("fwd_packets") or 0
        bwd_p = f.get("bwd_packets") or 0
        is_volume_anomalous = (fwd_p > 100 and bwd_p == 0)

        hostname = str(f.get("ndpi_hostname") or "").lower()
        if any(pat in hostname for pat in http_login_patterns):
            has_login_endpoint = True

        if is_entropy_suspicious or is_volume_anomalous:
            motivi = []
            if is_entropy_suspicious:
                motivi.append("ENTROPIA_ELEVATA")
            if is_volume_anomalous:
                motivi.append("TRAFFICO_ASIMMETRICO")
            
            f["motivo_anomalia"] = " + ".join(motivi)
            richieste_sospette.append(f)

    max_richieste_src = max(req_per_sorgente.values()) if req_per_sorgente else 0

    durata_finestra = max(1.0, calcola_durata_finestra_reale(start_time, end_time))
    http_req_rate = round(max_richieste_src / durata_finestra, 2)

    sospetto_web_bruteforce = False
    for src_ip, count in req_per_sorgente.items():
        distinct_targets = len(target_per_sorgente.get(src_ip, set()))
        if count >= 30 and distinct_targets <= 3:
            sospetto_web_bruteforce = True
            break

    totale_flussi_anomali = len(richieste_sospette)
    target_colpiti = (
        len(set(f["dst_ip"] for f in richieste_sospette if f.get("dst_ip")))
        if richieste_sospette
        else 0
    )

    # Regola PRIORITÀ 1: Condizione per attivare l'Early Stop Web Exploit
    early_stop_web_exploit = totale_flussi_anomali > 0

    return {
        "sintesi_smart": {
            "anomalie_l7_trovate": totale_flussi_anomali,
            "flussi_web_esaminati": len(flussi),
            "sospetto_web_bruteforce": sospetto_web_bruteforce,
            "max_tentativi_per_ip": max_richieste_src,
            "target_colpiti_count": target_colpiti,
            "http_req_rate": http_req_rate,
            "login_endpoint_targeted": has_login_endpoint,
            "early_stop_web_exploit": early_stop_web_exploit,
            "esito": f"RILEVATI {totale_flussi_anomali} flussi anomali HTTP/L7 su {len(flussi)} flussi Web.",
        },
        "campione_anomalie": richieste_sospette[:limit],
        "tempo_sql_sec": round(t_sql_puro, 4),
    }

@mcp.tool(description=prompts.DESC_SEARCH_HTTP_L7)
@mcp_cache_guard
def search_http_l7_anomalies(
    ip_target: str,
    start_time: str,
    end_time: str,
    limit: int = config.Soglie.LIMIT_DEFAULT_QUERY,
) -> str:
    try:
        return json.dumps(
            _search_http_l7_anomalies_raw(ip_target, start_time, end_time, limit),
            indent=2,
            default=str,
        )
    except Exception as e:
        return json.dumps({"status": "error", "message": f"Errore ricerca anomalie HTTP L7: {str(e)}"})

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

    # Definizione delle condizioni base per il traffico Web
    web_cond_base = f"""(
        dst_port IN ({porte_web_str}) 
        OR src_port IN ({porte_web_str}) 
        OR app_hierarchy LIKE '%HTTP%' 
        OR app_hierarchy LIKE '%SSL%'
        OR app_hierarchy LIKE '%TLS%'
        OR app_hierarchy LIKE '%Web%'
    )"""

    # Esclusione attiva dei servizi legittimi in Whitelist per prevenire falsi DoS L7
    web_cond_sql = f"""(
        {web_cond_base}
        AND NOT (app_hierarchy LIKE '%Google%' OR app_hierarchy LIKE '%Cloudflare%' OR app_hierarchy LIKE '%CDN%')
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
            COUNT(DISTINCT src_port) as porte_sorgente_uniche,
            SUM(total_bytes) as byte_totali_aggregati,
            SUM(CASE 
                WHEN duration_ms > 0 THEN (duration_ms / {config.Soglie.MS_IN_SEC}) * packet_rate 
                ELSE (fwd_packets + bwd_packets) 
            END) as pacchetti_totali_aggregati,
            SUM(CASE WHEN packet_rate >= :dos_pps_min THEN 1 ELSE 0 END) as flussi_sopra_soglia_pps,
            SUM(CASE WHEN {web_cond_sql} THEN 1 ELSE 0 END) as flussi_web_totali,
            COUNT(DISTINCT CASE WHEN {web_cond_sql} THEN dst_ip ELSE NULL END) as destinazioni_web_distinte,
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
    destinazioni_web = int(raw_stats.get("destinazioni_web_distinte") or 0)
    # Se non ci sono destinazioni web (nessun flusso web), evita divisione per zero:
    # in quel caso non c'e' comunque nulla da segnalare come DoS L7.
    concentrazione_web = (flussi_web / destinazioni_web) if destinazioni_web > 0 else 0.0

    flussi_slow = int(raw_stats.get("flussi_slowloris_attivi") or 0)
    flussi_high_rate = int(raw_stats.get("flussi_sopra_soglia_pps") or 0)
    pkts_totali = float(raw_stats.get("pacchetti_totali_aggregati") or 0.0)
    porte_sorgente_uniche = int(raw_stats.get("porte_sorgente_uniche") or 0)
    ratio_porte_effimere = round(porte_sorgente_uniche / max(totale_flussi, 1), 3)

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
    concentrazione_dos_min = getattr(s, "CONCENTRAZIONE_DOS_MIN", 25.0)

    # FIX: il conteggio grezzo (flussi_web >= 500) NON basta piu' da solo.
    # Un host che naviga tanto genera facilmente >500 flussi web, ma spalmati
    # su decine/centinaia di destinazioni distinte (concentrazione bassa).
    # Un vero flood L7 concentra le richieste su POCHE destinazioni.
    flood_l7_concentrato = (
        flussi_web >= dos_l7_flussi_min
        and concentrazione_web >= concentrazione_dos_min
        and (web_rps >= dos_l7_rps_min or burst_web_rps >= dos_l7_rps_min)
    )

    sospetto_volumetrico = (
        global_pps >= dos_pps_min
        or burst_pps >= dos_pps_min
        or flussi_high_rate >= getattr(s, "FLUSSI_HIGH_RATE_MIN", 3)
        or (flussi_web >= 500 and concentrazione_web >= concentrazione_dos_min)
        or flood_l7_concentrato
    )

    sospetto_slowloris = flussi_slow >= getattr(s, "SLOWLORIS_FLUSSI_MIN", 25)

    if sospetto_volumetrico:
        esito_smart = (
            f"CRITICO: Rilevato traffico ad alto rate/flood (Burst PPS: {burst_pps}, Web RPS: {burst_web_rps}). "
            "Candidato per DOS_VOLUMETRIC / DoS L7. Non sprecare turni ad ispezionare singoli pacchetti o flussi "
            "VPN/HTTP leciti: la saturazione volumetrica/RPS è sufficiente. Procedi a compute_verdict_scores."
        )
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
            "pacchetti_totali_stimati": int(pkts_totali),   # <-- NUOVO
            "flussi_web_totali": flussi_web,
            "destinazioni_web_distinte": destinazioni_web,
            "concentrazione_flussi_per_destinazione_web": round(concentrazione_web, 2),
            "porte_sorgente_uniche": porte_sorgente_uniche,
            "ratio_porte_effimere": ratio_porte_effimere,
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

@mcp.tool(description=prompts.DESC_GET_RATE_STATISTICS)
@mcp_cache_guard
def get_rate_statistics(
    start_time: str,
    end_time: str,
    ip_address: Optional[str] = None,
    ip_target: Optional[str] = None,
) -> str:
    try:
        res = _get_rate_statistics_raw(
            start_time, end_time, ip_address=ip_address, ip_target=ip_target
        )
        return json.dumps(res, indent=2, default=str)
    except Exception as e:
        return json.dumps({"status": "error", "message": f"Errore nel calcolo delle statistiche: {str(e)}"})


def _get_host_port_distribution_raw(
    ip_target: str,
    start_time: str,
    end_time: str,
) -> dict:
    query = text("""
        SELECT 
            dst_port,
            COUNT(*) as num_flussi,
            COUNT(DISTINCT dst_ip) as destinazioni_distinte,
            COALESCE(SUM(fwd_packets + bwd_packets), 0) as pacchetti_totali,
            COALESCE(SUM(total_fwd_bytes + total_bwd_bytes), 0) as bytes_totali,
            AVG(fwd_packets + bwd_packets) as pacchetti_medi_per_flusso
        FROM ndpi_flows
        WHERE (src_ip = :ip OR dst_ip = :ip)   -- CORREZIONE: Includi sia INBOUND che OUTBOUND
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
    
    # Rilevamento Porte Probe
    porte_probe = [
        row["dst_port"] for row in distribuzione 
        if row["num_flussi"] <= 3 or (row["pacchetti_medi_per_flusso"] is not None and float(row["pacchetti_medi_per_flusso"]) <= 2.5)
    ]
    
    porte_target_bf = [
        p["dst_port"] for p in distribuzione 
        if p["num_flussi"] >= 50 and p["dst_port"] not in (80, 443, 8080)
    ]

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

@mcp.tool(description=prompts.DESC_GET_HOST_PORT_DISTRIBUTION)
@mcp_cache_guard
def get_host_port_distribution(
    ip_target: str, start_time: str, end_time: str
) -> str:
    try:
        return json.dumps(
            _get_host_port_distribution_raw(ip_target, start_time, end_time),
            indent=2,
            default=str,
        )
    except Exception as e:
        return json.dumps({"status": "error", "message": f"Errore nell'analisi della distribuzione porte: {str(e)}"})


# =====================================================================
# Tool MCP Implementati
# =====================================================================

@mcp.tool(description=prompts.DESC_SEARCH_CONNECTION_ATTEMPTS)
@mcp_cache_guard
def search_connection_attempts(
    start_time: str,
    end_time: str,
    ip_target: Optional[str] = None,
    target_port: Optional[int] = None,
    ip_address: Optional[str] = None,
    include_web_ports: bool = True,
) -> str:
    try:
        raw_res = _search_connection_attempts_raw(
            start_time=start_time,
            end_time=end_time,
            ip_target=ip_target,
            target_port=target_port,
            ip_address=ip_address,
            include_web_ports=include_web_ports,
        )
        if not raw_res:
            return json.dumps({"status": "error", "message": "Nessun risultato restituito dalla ricerca."})
        return json.dumps(raw_res, indent=2, default=str)
    except Exception as e:
        return json.dumps({"status": "error", "message": f"Errore nell'esecuzione della ricerca: {str(e)}"})











@mcp.tool(description=prompts.DESC_ANALIZZA_CONNESSIONE)
@mcp_cache_guard
def analizza_connessione_by_community_id(cid: str) -> str:
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
                return json.dumps({
                    "status": "error", 
                    "message": f"Nessun flusso di dettaglio trovato per il community_id: {cid_clean}."
                })

            flusso = dict(riga_raw)

            if flusso.get("protocol") is not None:
                try:
                    flusso["protocol"] = arricchisci_protocollo(int(flusso["protocol"]))
                except (ValueError, TypeError):
                    pass

            payload_ent = float(flusso.get("payload_entropy") or 0.0)
            soglia_ent = config.Soglie.WEBATTACK_ENTROPIA_MAX

            risposta_strutturata = {
                "sintesi_smart": {
                    "community_id_trovato": True,
                    "valutazione_entropia": f"CRITICA (> {soglia_ent})" if payload_ent > soglia_ent else "NORMALE",
                    "note": "Payload fortemente cifrato o cifratura non standard." if payload_ent > soglia_ent else "Parametri del flusso nei limiti della norma."
                },
                "tempo_sql_reale_sec": round(t_sql_puro, 6),
                "dettaglio_flusso": flusso
            }

            return json.dumps(risposta_strutturata, indent=2, default=str)
    except Exception as e:
        return json.dumps({"status": "error", "message": f"Errore nel Drill-Down per community_id: {str(e)}"})
    
if __name__ == "__main__":
    mcp.run(transport='stdio')
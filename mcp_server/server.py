"""
server.py — Server MCP (FastMCP) che espone i tool di analisi del traffico di
rete come funzioni chiamabili dall'LLM tramite protocollo MCP su stdio.

COSA FA:
- Definisce ogni tool MCP (get_rate_statistics, get_host_port_distribution,
  search_connection_attempts, search_http_l7_anomalies, detect_beaconing,
  compute_verdict_scores, ecc.) come funzione decorata con @mcp.tool, con
  cache di deduplicazione (@mcp_cache_guard) per evitare query SQL ripetute
  con parametri identici nella stessa finestra di analisi.
- Interroga direttamente il database (tabella ndpi_flows) via SQLAlchemy e
  restituisce risultati in JSON con una sezione "sintesi_smart" pensata per
  essere letta rapidamente dall'LLM.
- compute_verdict_scores calcola un punteggio euristico deterministico
  (_calcola_scores_da_evidenze) a partire dagli altri tool, applicando le
  soglie statiche definite in config.Soglie.

DA CHI VIENE CHIAMATO:
- Avviato come sottoprocesso stdio da client.py e test_suite.py tramite
  StdioServerParameters(command=sys.executable, args=["server.py"]).
- Non viene mai importato direttamente: comunica solo via protocollo MCP.

ATTENZIONE - stdout riservato al protocollo: questo processo comunica con il
client via stdio, quindi stdout è il canale del protocollo MCP. Non usare mai
print() in questo file per log/debug: usa stderr (o niente), altrimenti si
rischia di corrompere il framing JSON-RPC dello stdio transport.
"""
import json
import time
import sys
import functools
import datetime
import ipaddress
import re
from typing import Union, Optional, Dict, Any, Tuple
from collections import defaultdict
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
    
    # Check protocolli OCSP / CRL 
    if "ocsp" in app or "crl" in app:
        return True
        
    # Check domini noti CDN / Certificate Authorities
    return any(dom in host for dom in DOMINI_WHITELIST_L7)

def pulisci_cache_scaduta():
    """Elimina dalla memoria tutte le chiavi più vecchie di CACHE_TTL_SECONDS."""
    ora_attuale = time.time()
    chiavi_da_eliminare = [
        k for k, v in execution_cache.items() 
        if ora_attuale - v["timestamp"] > CACHE_TTL_SECONDS
    ]
    for k in chiavi_da_eliminare:
        del execution_cache[k]

def mcp_cache_guard(func):
    """
    Decoratore che intercetta l'esecuzione del tool.
    Se la query è gia stata fatta, restituisce il risultato precedente.
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

def arricchisci_protocollo(proto_num: int) -> str:
    mapping = {1: "1 (ICMP)", 6: "6 (TCP)", 17: "17 (UDP)"}
    return mapping.get(proto_num, f"{proto_num} (Sconosciuto)")

def normalizza_data(data_str: str, is_end: bool = False) -> str:
    """Normalizza qualsiasi formato data (ISO con 'T', stringa breve, ecc.)

    nel formato standard MySQL 'YYYY-MM-DD HH:MM:SS'.
    """
    if not data_str:
        return data_str

    # Rimuove la 'T' inviata dall'LLM
    data_str = data_str.strip().replace("T", " ")

    # Se l'LLM invia solo 'YYYY-MM-DD' (lunghezza 10)
    if len(data_str) == 10:
        return data_str + (" 23:59:59" if is_end else " 00:00:00")

    # Tronca eventuali microsecondi o caratteri extra
    return data_str[:19]

def calcola_durata_finestra_reale(start_time: str, end_time: str) -> float:
    start_norm = normalizza_data(start_time, is_end=False)
    end_norm = normalizza_data(end_time, is_end=True)

    try:
        dt_s = datetime.datetime.fromisoformat(start_norm.replace('Z', '+00:00'))
        dt_e = datetime.datetime.fromisoformat(end_norm.replace('Z', '+00:00'))
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

# =====================================================================
# Tool MCP Implementati
# =====================================================================

def _calcola_scores_da_evidenze(
    rate_stats: dict | None,
    port_dist: dict | None,
    beacon: dict | None,
    l7: dict | None,
    conn_attempts: dict | None,
) -> dict:
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
        conn_attempts_arg: dict | None,
        port_ss_arg: dict,
        s_obj,
        web_attack_score_val: float = 0.0,
    ) -> tuple[float, list[str], bool, int]:
        conn_attempts_arg = conn_attempts_arg or {}
        note = []
        porte_gestione = getattr(s_obj, "PORTE_GESTIONE", {21, 22, 23, 3389, 5900, 2222})
        porte_web = getattr(s_obj, "PORTE_WEB_L7", {80, 443, 8080, 8443, 8000})
        porte_infra_lan = getattr(s_obj, "PORTE_INFRASTRUTTURA_LAN", {53, 88, 137, 138, 139, 389, 445, 636})

        porte_target_bruteforce = port_ss_arg.get("porte_target_bruteforce") or []
        porte_uniche_total = int(port_ss_arg.get("porte_uniche_contattate") or 0)
        sospetto_scan = port_ss_arg.get("sospetto_portscan", False)
        distribuzione_top = port_ss_arg.get("distribuzione_top") or []

        has_valid_bf_port = any(int(p) in porte_gestione for p in porte_target_bruteforce)
        tentativi_conn = conn_attempts_arg.get("tentativi_connessione") or []
        has_single_port_bf = False
        max_tentativi_bf = 0
        has_confirmed_single_target_scan = any(
            t.get("valutazione_mcp") == "SOSPETTO_PORTSCAN" for t in tentativi_conn
        )

        for t in tentativi_conn:
            tentativi = int(t.get("tentativi_totali") or 0)
            porta = int(t.get("dst_port") or 0)
            if porta in porte_gestione and tentativi >= getattr(s_obj, "BRUTEFORCE_TENTATIVI_MIN", 25):
                has_single_port_bf = True
                max_tentativi_bf = max(max_tentativi_bf, tentativi)

        scan_score = 0.0
        if porte_uniche_total >= getattr(s_obj, "SCAN_PORTE_MIN", 15) and sospetto_scan:
            if has_confirmed_single_target_scan:
                scan_score = 0.95
                note.append("Port Scan L4 rilevato su ampie fasce di porte, confermato da tentativi concentrati su un singolo target.")
            else:
                scan_score = 0.60
                note.append(
                    "Diversità di porte sopra soglia rilevata dalla distribuzione porte, ma nessuna coppia "
                    "IP mostra concentrazione su un singolo target: possibile fan-out verso molti servizi. Score depotenziato."
                )

        bruteforce_l4_confirmed = has_valid_bf_port or has_single_port_bf
        if bruteforce_l4_confirmed:
            scan_score = max(scan_score, 0.95)
            note.append("Pattern Brute Force L4 rilevato su porte di gestione (SSH/FTP/RDP).")

        sweep_porte_min = getattr(s_obj, "SWEEP_PORTE_MIN", 4)
        sweep_conc_max = getattr(s_obj, "SWEEP_CONCENTRAZIONE_MAX", 0.70)
        destinazioni_totali_uniche = int(port_ss_arg.get("destinazioni_totali_uniche") or 0)
        sweep_destinazioni_max = getattr(s_obj, "SWEEP_DESTINAZIONI_MAX", 15)

        if (
            scan_score < 0.85
            and sweep_porte_min <= porte_uniche_total < getattr(s_obj, "SCAN_PORTE_MIN", 15)
            and distribuzione_top
            and destinazioni_totali_uniche <= sweep_destinazioni_max
        ):
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
            sweep_flussi_min = getattr(s_obj, "SWEEP_FLUSSI_MIN_ASSOLUTI", 50)

            if (
                len(categorie_rilevanti) >= 2
                and concentrazione <= sweep_conc_max
                and totale_flussi_top >= sweep_flussi_min
            ):
                scan_score = max(scan_score, 0.85)
                note.append(
                    f"Rilevato sweep multi-servizio su {porte_uniche_total} porte eterogenee "
                    f"({', '.join(sorted(categorie_rilevanti))}), {totale_flussi_top} flussi totali."
                )

        if scan_score < 0.85 and web_attack_score_val >= 0.70 and not bruteforce_l4_confirmed:
            if porte_uniche_total < 20:
                scan_score = min(scan_score, 0.40)
                note.append("Portscan marginale/rumore L4 depotenziato in presenza di Web Attack L7 concentrato.")

        return scan_score, note, bruteforce_l4_confirmed, max_tentativi_bf

    def _eval_dos_scores(
        mk_arg: dict,
        l7_ss_arg: dict,
        flussi_p53: int,
        s_obj,
        is_goldeneye: bool,
        web_attack_score_val: float = 0.0,
        bruteforce_l4_confirmed: bool = False,
    ) -> tuple[float, list[str]]:
        note = []
        totale_flussi = int(mk_arg.get("totale_flussi") or 0)
        flussi_web = int(mk_arg.get("flussi_web_totali") or 0)
        destinazioni_web = int(mk_arg.get("destinazioni_web_distinte") or 0)
        concentrazione_web = (flussi_web / destinazioni_web) if destinazioni_web > 0 else 0.0
        concentrazione_dos_min = getattr(s_obj, "CONCENTRAZIONE_DOS_MIN", 25.0)

        sospetto_web_bf_locale = bool(l7_ss_arg.get("sospetto_web_bruteforce", False))
        bruteforce_confermato_qualsiasi = bruteforce_l4_confirmed or sospetto_web_bf_locale

        pps = float(mk_arg.get("pps_aggregati") or 0.0)
        burst_pps = float(mk_arg.get("burst_pps") or pps)
        effective_pps = max(pps, burst_pps)

        web_rps = float(mk_arg.get("web_rps") or 0.0)
        burst_web_rps = float(mk_arg.get("burst_web_rps") or web_rps)
        effective_web_rps = max(web_rps, burst_web_rps)

        flussi_slow = int(mk_arg.get("flussi_slowloris") or 0)
        max_tentativi_ip = int(l7_ss_arg.get("max_tentativi_per_ip") or 0)
        pacchetti_totali = int(mk_arg.get("pacchetti_totali_stimati") or 0)

        dos_pps_score = min(1.0, effective_pps / getattr(s_obj, "DOS_PPS_MIN", 3000.0)) if effective_pps >= getattr(s_obj, "DOS_PPS_MIN", 3000.0) else 0.0
        dos_l7_score = 0.0
        dos_slow_score = 0.0

        is_dns_traffic = (flussi_p53 / max(totale_flussi, 1) > 0.8) if totale_flussi > 0 else False

        if is_dns_traffic:
            if burst_pps >= 300.0 or totale_flussi >= 20000:
                dos_l7_score = 0.95
                note.append("Rilevato DNS Flood / Amplification DoS.")
        else:
            volume_elevato = (
                flussi_web >= 1000
                or max_tentativi_ip >= 1000
                or effective_web_rps >= 10.0
                or (totale_flussi < 100 and pacchetti_totali >= 5000)
                or is_goldeneye
            )

            concentrazione_ok = (
                (concentrazione_web >= concentrazione_dos_min)
                or (destinazioni_web <= 3 and flussi_web >= 1000)
                or (totale_flussi < 100 and pacchetti_totali >= 5000)
                or is_goldeneye
            )

            if volume_elevato and concentrazione_ok:
                dos_l7_score = 0.95
                if is_goldeneye:
                    note.append(
                        f"Rilevato pattern DoS L7 (GoldenEye / HTTP Flood): {max_tentativi_ip} "
                        f"connessioni/richieste concentrate su un unico target web ({flussi_web} flussi totali)."
                    )
                else:
                    note.append(
                        f"Elevata saturazione HTTP/DoI concentrata ({flussi_web} flussi web, "
                        f"{pacchetti_totali} pacchetti totali su {destinazioni_web} destinazioni): identificato DoS L7 / Volumetrico."
                    )

        slow_min = getattr(s_obj, "SLOWLORIS_FLUSSI_MIN", 50)
        if flussi_slow >= slow_min or (flussi_web >= 500 and flussi_slow >= 50):
            dos_slow_score = 0.95
            note.append("Rilevata impronta Slowloris / Slow HTTP DoS.")

        ratio_porte_effimere = float(mk_arg.get("ratio_porte_effimere") or 0.0)
        porte_sorgente_uniche = int(mk_arg.get("porte_sorgente_uniche") or 0)
        dos_effimere_score = 0.0

        pps_floor_ok = effective_pps >= getattr(s_obj, "DOS_PPS_MIN_FALLBACK", 1000.0)

        destinazioni_web_dos = int(mk_arg.get("destinazioni_web_distinte") or 0)
        dos_effimere_dest_max = getattr(s_obj, "DOS_EFFIMERE_DESTINAZIONI_MAX", 10)

        saturazione_effimere = (
            (ratio_porte_effimere >= getattr(s_obj, "RATIO_PORTE_EFFIMERE_MIN", 0.70) or porte_sorgente_uniche >= 100)
            and totale_flussi >= 150
            and not bruteforce_l4_confirmed
            and destinazioni_web_dos <= dos_effimere_dest_max 
        )

        # Se rilevata saturazione di connessioni/porte effimere, assegna lo score DoS Volumetrico
        if (
            dos_l7_score < 0.90
            and not is_dns_traffic
            and not bruteforce_confermato_qualsiasi
            and (
                saturazione_effimere
                or (pacchetti_totali >= 5000 and totale_flussi < 500 and pps_floor_ok)
            )
        ):
            dos_effimere_score = 0.95
            note.append("Rilevato pattern DoS volumetrico/esaurimento connessioni su porte effimere.")

        final_dos = max(dos_pps_score, dos_l7_score, dos_slow_score, dos_effimere_score)
        return min(final_dos, 0.95), note

    def _eval_beacon_score(beacon_arg: dict, dos_score_val: float, mk_arg: dict) -> tuple[float, list[str], tuple | None]:
        note = []
        top_candidati = beacon_arg.get("candidati_top") or []
        sintesi_beacon = beacon_arg.get("sintesi_smart") or {}

        candidati_esterni = [
            c for c in top_candidati
            if (ip := (c.get("dst_ip") or c.get("ip_dst") or c.get("ip_target") or c.get("ip") or ""))
            and not _is_private_ip(ip)
            and not (set(c.get("tags") or []) & {"WHITELISTED_SERVICE", "REPUTABLE_INFRA_WEAK_JITTER"})
        ]

        has_beacon_flag = sintesi_beacon.get("beaconing_c2_rilevato", False)
        bot_count = int(sintesi_beacon.get("bot_traffic_count") or 0)

        raw_beacon_score = 0.0
        target_beacon_res = None
        if candidati_esterni:
            max_cand_score = max([float(c.get("anomaly_score") or 0) for c in candidati_esterni], default=0.0)
            min_cv = min([float(c.get("cv") if c.get("cv") is not None else 999.0) for c in candidati_esterni], default=999.0)

            has_c2_port = any(int(c.get("dst_port") or 0) in {8080, 8443, 444, 1080} for c in candidati_esterni)
            tot_connessioni = max([int(c.get("totale_connessioni") or 0) for c in candidati_esterni], default=0)

            if (max_cand_score >= config.Soglie.ANOMALY_SCORE_CANDIDATO_MIN or min_cv <= config.Soglie.CV_BEACON_UPPER_JITTER) or (has_c2_port and tot_connessioni >= 15):
                raw_beacon_score = 0.95
                migliore = max(candidati_esterni, key=lambda c: float(c.get("anomaly_score") or 0))
                target_beacon_res = (migliore.get("dst_ip"), int(migliore.get("dst_port") or 0))
                note.append(f"Rilevato traffico di Beaconing C2/Jitter verso IP esterni (CV: {min_cv}, Connessioni: {tot_connessioni}).")
        elif has_beacon_flag or bot_count > 0:
            raw_beacon_score = 0.95
            note.append("Rilevato traffico compatibile con Botnet / Beaconing C2.")

        return raw_beacon_score, note, target_beacon_res

    # PIPELINE ESECUZIONE SCORES
    s = config.Soglie
    note_logiche = []

    mk = rate_stats.get("metriche_chiave") or {}
    l7_ss = l7.get("sintesi_smart") or {}
    port_ss = port_dist.get("sintesi_smart") or {}
    distribuzione_top = port_ss.get("distribuzione_top") or []

    flussi_p53 = sum(p.get("num_flussi", 0) for p in distribuzione_top if p.get("dst_port") == 53)

    anomalie_entropia = int(l7_ss.get("anomalie_entropia_trovate") or 0)
    anomalie_asimmetria = int(l7_ss.get("anomalie_asimmetria_trovate") or 0)
    sospetto_web_bf = l7_ss.get("sospetto_web_bruteforce", False)
    max_tentativi_ip = int(l7_ss.get("max_tentativi_per_ip") or 0)
    early_stop_exploit = l7_ss.get("early_stop_web_exploit", False)
    login_endpoint_targeted = bool(l7_ss.get("login_endpoint_targeted", False))
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
    is_web_bruteforce_active = sospetto_web_bf and not is_volumetric_dos_l7

    # Intercetta il traffico VPN prima di calcolare lo score
    app_hierarchy_str = str(l7_ss.get("app_hierarchy_top") or l7.get("app_hierarchy_top") or "")
    is_vpn_session = "FortiClient" in app_hierarchy_str or "OpenVPN" in app_hierarchy_str

    web_attack_score = 0.0
    if anomalie_entropia > 0 or early_stop_exploit:
        web_attack_score = 0.95
        note_logiche.append(f"Rilevate {anomalie_entropia} anomalie L7/HTTP ad alta entropia.")
    elif is_web_bruteforce_active:
        # SE È TRAFFICO VPN SENZA TARGET DI LOGIN, AZZERA LO SCORE
        if is_vpn_session and not login_endpoint_targeted:
            web_attack_score = 0.0
            note_logiche.append("Traffico VPN (FortiClient) identificato: concentrazione L7 fisiologica, falso positivo annullato.")
        else:
            web_attack_score = 0.95 if login_endpoint_targeted else 0.75

    scan_score, note_scan, bruteforce_l4_confirmed, max_tentativi_bf = _eval_scan_and_bruteforce(
        conn_attempts, port_ss, s, web_attack_score
    )
    note_logiche.extend(note_scan)

    dos_score, note_dos = _eval_dos_scores(
        mk, l7_ss, flussi_p53, s, is_goldeneye_pattern, web_attack_score,
        bruteforce_l4_confirmed=bruteforce_l4_confirmed,
    )
    note_logiche.extend(note_dos)

    beacon_score, note_beacon, target_beacon = _eval_beacon_score(beacon, dos_score, mk)
    note_logiche.extend(note_beacon)

    scores_dict = {
        "WEB_ATTACK_EXPLOIT": web_attack_score,
        "SCAN_BRUTEFORCE": scan_score,
        "DOS_VOLUMETRIC": dos_score,
        "BEACONING_C2": beacon_score,
    }

    max_val = max(scores_dict.values())
    vincitori = []
    conflitto_a_pari_merito = []
    override_tassativo = False

    if max_val >= 0.5:
        vincitori = [k for k, v in scores_dict.items() if v == max_val]
        if len(vincitori) == 1:
            vincitore_assoluto = vincitori[0]
            altri_valori = sorted(
                (v for k, v in scores_dict.items() if k != vincitore_assoluto),
                reverse=True,
            )
            secondo_miglior = altri_valori[0] if altri_valori else 0.0
            # margine schiacciante: nessun altro candidato, o almeno 2x sopra il secondo
            if secondo_miglior == 0.0 or (max_val / max(secondo_miglior, 0.01)) >= 2.0:
                override_tassativo = True
        else:
            vincitore_assoluto = "CONFLITTO_IRRISOLTO"
            conflitto_a_pari_merito = vincitori
    else:
        vincitore_assoluto = "BENIGN"

    return {
        "DOS_VOLUMETRIC": scores_dict["DOS_VOLUMETRIC"],
        "SCAN_BRUTEFORCE": scores_dict["SCAN_BRUTEFORCE"],
        "BEACONING_C2": scores_dict["BEACONING_C2"],
        "WEB_ATTACK_EXPLOIT": scores_dict["WEB_ATTACK_EXPLOIT"],
        "verdetto_suggerito_euristica": vincitore_assoluto,
        "conflitto_a_pari_merito": conflitto_a_pari_merito,
        "override_tassativo": override_tassativo,
        "note_logiche": note_logiche,
        "avviso_per_llm": "Questi score sono un calcolo euristico di supporto."
    }

@mcp.tool(description=prompts.DESC_COMPUTE_VERDICT_SCORES)
@mcp_cache_guard
def compute_verdict_scores(ip_target: str, start_time: str, end_time: str) -> str:
    try:
        rate_stats = _get_rate_statistics_raw(start_time, end_time, ip_target=ip_target) or {}
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
        print(f"[ERRORE] Generazione verdict scores per target {ip_target}: {e}", file=sys.stderr)
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
            select_clause = "src_ip, dst_ip, MAX(dst_port) as dst_port, COUNT(*) as tentativi_totali, 1 as porte_distinte"
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

            if porte_distinte >= getattr(s, "SCAN_PORTE_MIN", 15):
                riga["valutazione_mcp"] = "SOSPETTO_PORTSCAN"
                sospetti_count += 1
            elif porta in porte_infra_estese or porta > 32768:
                riga["valutazione_mcp"] = "TRAFFICO_ORDINARIO_LAN"
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

        # GUARDRAIL INFRASTRUTTURA REPUTATA (Prevenzione Falsi Positivi C2)
        PROVIDER_REPUTATI = {"cloudflare", "akamai", "edgecast", "aws", "google", "fastly", "amazon"}
        is_reputable_infra = bool(infra_provider) and any(
            p in infra_provider.lower() for p in PROVIDER_REPUTATI
        )
        if is_reputable_infra and cv > s.CV_BEACON_JITTER_MAX:
            tag_list.append("REPUTABLE_INFRA_WEAK_JITTER")
            return s.SCORE_DEFAULT, tag_list

        if totale_connessioni >= s.BEACON_MIN_CONNESSIONI:
            if cv <= s.CV_BEACON_JITTER_MAX:
                score = s.ANOMALY_SCORE_C2_MIN + 30
                tag_list.append("CONFIRMED_BEACONING_C2")
                return score, tag_list
            elif s.CV_BEACON_JITTER_MAX < cv <= s.CV_BEACON_UPPER_JITTER:
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
                src_ip,
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
            GROUP BY src_ip, dst_ip, dst_port
            HAVING intervalli_validi >= :min_intervals
        )
        SELECT 
            src_ip,
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

        if not is_whitelisted and not is_internal_keepalive:
            # Riconosce C2 anche con Jitter elevato (CV > 1.20) se vi sono porte C2 e alta persistenza
            is_high_volume_c2_port = (dst_port in (8080, 8443, 444, 1080) and totale_connessioni >= 15)
            
            if (
                "CONFIRMED_BEACONING_C2" in tag_list 
                or "SUSPECTED_BEACONING_JITTER" in tag_list 
                or anomaly_score >= 50 
                or cv <= config.Soglie.CV_BEACON_UPPER_JITTER
                or is_high_volume_c2_port
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

    if has_c2_candidate:
        diag_msg = "ALLERTA C2: Rilevata persistenza o cadenza di comunicazioni verso infrastruttura esterna sospetta."
    else:
        diag_msg = "Nessuna minaccia C2 rilevante."

    return {
        "sintesi_smart": {
            "beaconing_c2_rilevato": has_c2_candidate,
            "diagnosi": diag_msg
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
    def _is_vpn_or_legit_tunnel(app_hierarchy: str, hostname: str) -> bool:
        """Rileva se il flusso appartiene a un tunnel VPN o sessione TLS/SSL strutturata."""
        app_str = str(app_hierarchy or "").lower()
        host_str = str(hostname or "").lower()
        
        # Parole chiave VPN e protocolli cifrati standard
        vpn_keywords = [
            "forticlient", "openvpn", "wireguard", "cisco", 
            "ipsec", "globalprotect", "ssl", "tls", "https"
        ]
        
        if any(k in app_str or k in host_str for k in vpn_keywords):
            return True
            
        return False

    porte_web_extended = set(config.Soglie.PORTE_WEB_L7).union(
        {444, 4433}
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
                "anomalie_entropia_trovate": 0,      
                "anomalie_asimmetria_trovate": 0,    
                "flussi_web_esaminati": 0,
                "target_colpiti_count": 0,
                "target_ip_porta_bruteforce": [],
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
    anomalie_entropia_count = 0
    anomalie_asimmetria_count = 0   
    flussi_web_non_whitelisted = 0

    req_per_sorgente = defaultdict(int)
    target_per_sorgente = defaultdict(set)   # Set di tuple (dst_ip, dst_port)
    has_login_endpoint = False

    for f in flussi:
        if _is_l7_whitelisted(f.get("app_hierarchy"), f.get("ndpi_hostname")):
            continue

        flussi_web_non_whitelisted += 1
        src = f.get("src_ip")
        dst = f.get("dst_ip")
        dst_port_f = f.get("dst_port")  

        req_per_sorgente[src] += 1
        if dst:
            target_per_sorgente[src].add((dst, dst_port_f))  

        payload_ent = f.get("payload_entropy")
        # Controlla entropia elevata
        is_entropy_suspicious = (payload_ent is not None and float(payload_ent) > 0.8)

        fwd_p = f.get("fwd_packets") or 0
        bwd_p = f.get("bwd_packets") or 0
        is_volume_anomalous = (fwd_p > 100 and bwd_p == 0)

        hostname = str(f.get("ndpi_hostname") or "").lower()
        if any(pat in hostname for pat in http_login_patterns):
            has_login_endpoint = True

        if is_entropy_suspicious:
            anomalie_entropia_count += 1       
        if is_volume_anomalous:
            anomalie_asimmetria_count += 1     
            
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
    target_colpiti_bruteforce = 0
    target_ip_porta_bruteforce = []

    for src_ip, count in req_per_sorgente.items():
        distinct_targets = target_per_sorgente.get(src_ip, set())
        flussi_src = [f for f in flussi if f.get("src_ip") == src_ip]
        
        # Se almeno l'80% dei flussi ha caratteristiche VPN/TLS pulite
        flussi_vpn_count = sum(
            1 for f in flussi_src 
            if _is_vpn_or_legit_tunnel(f.get("app_hierarchy"), f.get("ndpi_hostname"))
        )
        is_prevalentemente_vpn = (
            (flussi_vpn_count / len(flussi_src)) >= 0.8
            if flussi_src else False
        )
        
        if count >= 30 and len(distinct_targets) <= 3:
            # Se è traffico VPN/TLS pulito SENZA target di login ed ENTROPIA normale -> NON è Bruteforce
            if is_prevalentemente_vpn and not has_login_endpoint and anomalie_entropia_count == 0:
                sospetto_web_bruteforce = False
            else:
                sospetto_web_bruteforce = True
                target_colpiti_bruteforce = len(distinct_targets)
                target_ip_porta_bruteforce = sorted([[ip, int(port)] for ip, port in distinct_targets if port is not None])
                break

    totale_flussi_anomali = len(richieste_sospette)
    target_colpiti = (
        len(set(f["dst_ip"] for f in richieste_sospette if f.get("dst_ip")))
        if richieste_sospette
        else target_colpiti_bruteforce   
    )

    # Early stop attivo solo se c'è reale minaccia L7
    early_stop_web_exploit = (anomalie_entropia_count > 0) or (sospetto_web_bruteforce and has_login_endpoint)

    if not sospetto_web_bruteforce:
        esito_msg = f"Rilevato traffico ordinario/VPN ({len(flussi)} flussi). Nessun attacco L7."
    else:
        esito_msg = f"RILEVATI {totale_flussi_anomali} flussi anomali HTTP/L7 su {len(flussi)} flussi Web esaminati."

    return {
        "sintesi_smart": {
            "anomalie_l7_trovate": totale_flussi_anomali,
            "anomalie_entropia_trovate": anomalie_entropia_count,      
            "anomalie_asimmetria_trovate": anomalie_asimmetria_count,   
            "flussi_web_esaminati": len(flussi),
            "sospetto_web_bruteforce": sospetto_web_bruteforce,
            "max_tentativi_per_ip": max_richieste_src,
            "target_colpiti_count": target_colpiti,
            "target_ip_porta_bruteforce": target_ip_porta_bruteforce,
            "http_req_rate": http_req_rate,
            "login_endpoint_targeted": has_login_endpoint,
            "early_stop_web_exploit": early_stop_web_exploit, 
            "esito": esito_msg,
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

    web_cond_base = f"""(
        dst_port IN ({porte_web_str}) 
        OR src_port IN ({porte_web_str}) 
        OR app_hierarchy LIKE '%HTTP%' 
        OR app_hierarchy LIKE '%SSL%'
        OR app_hierarchy LIKE '%TLS%'
        OR app_hierarchy LIKE '%Web%'
    )"""

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
        print(f"[ERRORE SQL in _get_rate_statistics_raw]: {err_sql}", file=sys.stderr)
        t_sql_puro = time.perf_counter() - t_inizio_sql

    max_pps = float(raw_stats.get("max_packet_rate") or 0.0)
    totale_flussi = int(raw_stats.get("totale_flussi") or 0)
    flussi_web = int(raw_stats.get("flussi_web_totali") or 0)
    pkts_web_totali = float(raw_stats.get("pkts_web_totali") or 0.0)
    pacchetti_per_flusso_web = round(pkts_web_totali / flussi_web, 2) if flussi_web > 0 else 0.0  
    destinazioni_web = int(raw_stats.get("destinazioni_web_distinte") or 0)
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
    dos_l7_flussi_min = getattr(s, "DOS_L7_FLUSSI_MIN", 50)
    dos_l7_rps_min = getattr(s, "DOS_L7_RPS_MIN", 10.0)
    dos_pps_min = getattr(s, "DOS_PPS_MIN", 3000.0)
    concentrazione_dos_min = getattr(s, "CONCENTRAZIONE_DOS_MIN", 25.0)

    flood_l7_concentrato = (
        flussi_web >= dos_l7_flussi_min
        and concentrazione_web >= concentrazione_dos_min
        and (web_rps >= dos_l7_rps_min or burst_web_rps >= dos_l7_rps_min)
    )

    # Rilevamento DoS Istantaneo / Multi-Sorgente a raffica
    # Cattura attacchi DoS ad alta densità di flussi o con forte asimmetria di porte effimere
    is_instantaneous_dos = (
        (max_pps >= 1000.0) or 
        (totale_flussi >= 150 and ratio_porte_effimere >= 0.85 and global_pps > 2.0)
    )

    # Guardrail Volumetrico
    min_pkts_per_dos_isolato = getattr(s, "DOS_VOLUME_MASSIVO_MIN", 10000.0) 
    flussi_high_rate_significativi = (
        flussi_high_rate >= getattr(s, "FLUSSI_HIGH_RATE_MIN", 3)
        and (pkts_totali >= min_pkts_per_dos_isolato or global_pps >= 50.0)
    )

    sospetto_volumetrico = (
        global_pps >= dos_pps_min
        or burst_pps >= dos_pps_min
        or pkts_totali >= 100000.0
        or flussi_high_rate_significativi  
        or (flussi_web >= 500 and concentrazione_web >= concentrazione_dos_min)
        or flood_l7_concentrato
        or is_instantaneous_dos
    )

    motivi_anomalia = []
    if global_pps >= dos_pps_min or burst_pps >= dos_pps_min:
        motivi_anomalia.append("burst_aggregato")
    if is_instantaneous_dos:
        motivi_anomalia.append("dos_istantaneo_o_multi_sorgente")
    if flussi_high_rate_significativi:
        motivi_anomalia.append("flussi_isolati_alto_rate")
    if (flussi_web >= 500 and concentrazione_web >= concentrazione_dos_min) or flood_l7_concentrato:
        motivi_anomalia.append("concentrazione_web_l7")

    sospetto_slowloris = flussi_slow >= getattr(s, "SLOWLORIS_FLUSSI_MIN", 50)

    if sospetto_volumetrico:
        esito_smart = (
            f"CRITICO: Rilevato DoS Volumetrico/Hulk. "
            f"Pacchetti totali: {int(pkts_totali)}, Burst PPS: {burst_pps}, Flussi Web: {flussi_web}."
        )
    elif sospetto_slowloris:
        esito_smart = f"ATTENZIONE: Rilevate {flussi_slow} sessioni persistenti lente. Candidato per DOS_VOLUMETRIC (Slowloris)."
    elif "burst_brevi_basso_volume" in motivi_anomalia:
        esito_smart = "ATTENZIONE: Rilevati picchi istantanei isolati su flussi brevi, ma il volume complessivo è scarso (traffico ordinario/scan)."
    else:
        esito_smart = "NORMALE: Volumi e frequenze pacchetti rientrano nei parametri regolari."

    return {
        "sintesi_smart": {
            "stato_anomalia": "ANOMALIA_RILEVATA" if (sospetto_volumetrico or sospetto_slowloris) else "NORMALE",
            "diagnosi_preliminare": esito_smart,
            "motivi_anomalia": motivi_anomalia,
        },
        "metriche_chiave": {
            "pps_aggregati": global_pps,
            "burst_pps": burst_pps,
            "totale_flussi": totale_flussi,
            "pacchetti_totali_stimati": int(pkts_totali),   
            "flussi_web_totali": flussi_web,
            "destinazioni_web_distinte": destinazioni_web,
            "concentrazione_flussi_per_destinazione_web": round(concentrazione_web, 2),
            "porte_sorgente_uniche": porte_sorgente_uniche,
            "ratio_porte_effimere": ratio_porte_effimere,
            "flussi_per_sec": flussi_per_sec,
            "burst_flussi_per_sec": burst_flussi_per_sec,
            "web_rps": web_rps,
            "burst_web_rps": burst_web_rps,
            "pacchetti_per_flusso_web": pacchetti_per_flusso_web,
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
        WHERE (src_ip = :ip OR dst_ip = :ip)
          AND timestamp_start BETWEEN :start_time AND :end_time
        GROUP BY dst_port
        ORDER BY num_flussi DESC;
    """)

    query_dest_totali = text("""
        SELECT COUNT(DISTINCT dst_ip) as destinazioni_totali_uniche
        FROM ndpi_flows
        WHERE (src_ip = :ip OR dst_ip = :ip)
          AND timestamp_start BETWEEN :start_time AND :end_time;
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

        result_dest = connection.execute(query_dest_totali, params)
        row_dest = result_dest.mappings().fetchone()
        destinazioni_totali_uniche = int(row_dest["destinazioni_totali_uniche"] or 0) if row_dest else 0

        t_sql_puro = time.perf_counter() - t_inizio_sql

    porte_uniche = len(distribuzione)

    # Escludiamo le porte infrastrutturali LAN standard dal conteggio dei probe
    porte_probe = [
        row["dst_port"] for row in distribuzione 
        if row["dst_port"] not in config.Soglie.PORTE_INFRASTRUTTURA_LAN 
        and (row["num_flussi"] <= 3 or (row["pacchetti_medi_per_flusso"] is not None and float(row["pacchetti_medi_per_flusso"]) <= 2.5))
    ]
    
    porte_target_bf = [
        p["dst_port"] for p in distribuzione 
        if p["num_flussi"] >= 50 and p["dst_port"] not in config.Soglie.PORTE_WEB_L7 and p["dst_port"] not in config.Soglie.PORTE_INFRASTRUTTURA_LAN
    ]

    soglia_concentrazione_scan = getattr(config.Soglie, "SCAN_DESTINAZIONI_MAX_PER_CONCENTRAZIONE", 3)
    e_concentrato_su_poche_dest = destinazioni_totali_uniche <= soglia_concentrazione_scan

    # Controllo se le porte contattate appartengono a servizi di infrastruttura LAN
    porte_infrastruttura_lan = getattr(config.Soglie, "PORTE_INFRASTRUTTURA_LAN", {53, 88, 123, 135, 137, 138, 139, 389, 445, 636, 3268, 3269, 326, 5353, 53539})
    porte_contattate_set = {row["dst_port"] for row in distribuzione}
    
    porte_infra_toccate = len(porte_contattate_set.intersection(porte_infrastruttura_lan))
    frazione_infra = porte_infra_toccate / max(porte_uniche, 1)

    e_traffico_domain_controller = (
        destinazioni_totali_uniche <= 3
        and porte_infra_toccate >= 2
        and frazione_infra >= getattr(config.Soglie, "DC_FRAZIONE_INFRA_MIN", 0.5)
    )

    sospetto_scan = (
        porte_uniche >= getattr(config.Soglie, "SCAN_PORTE_MIN", 15)
        and len(porte_probe) >= 8
        and e_concentrato_su_poche_dest
        and not e_traffico_domain_controller  # Ignora falsi positivi LAN/DC
    )
    sospetto_bruteforce = len(porte_target_bf) > 0

    return {
        "sintesi_smart": {
            "stato": "ANOMALIA_RILEVATA" if (sospetto_scan or sospetto_bruteforce) else "NORMALE",
            "porte_uniche_contattate": porte_uniche,
            "porte_probe_count": len(porte_probe),
            "destinazioni_totali_uniche": destinazioni_totali_uniche,  
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

            payload_ent_flag = int(float(flusso.get("payload_entropy") or 0.0))
            entropia_sospetta = (payload_ent_flag == 1)

            risposta_strutturata = {
                "sintesi_smart": {
                    "community_id_trovato": True,
                    "valutazione_entropia": "SOSPETTA (flag=1)" if entropia_sospetta else "NORMALE (flag=0)",
                    "note": (
                        "Payload segnalato come ad alta entropia dalla pipeline di ingestione "
                        "(possibile cifratura non standard/offuscamento)."
                        if entropia_sospetta
                        else "Nessun segnale di entropia anomala sul payload."
                    ),
                },
                "tempo_sql_reale_sec": round(t_sql_puro, 6),
                "dettaglio_flusso": flusso
            }

            return json.dumps(risposta_strutturata, indent=2, default=str)
    except Exception as e:
        return json.dumps({"status": "error", "message": f"Errore nel Drill-Down per community_id: {str(e)}"})

@mcp.tool(description=prompts.DESC_GET_FLOW_FEATURES)
@mcp_cache_guard
def get_flow_features(ip: str, start_time: str, end_time: str) -> str:
    """Estrae metriche avanzate (IAT, Entropia) dei flussi del target."""
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
                if int(f.get("payload_entropy") or 0) == 1:
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


if __name__ == "__main__":
    mcp.run(transport='stdio')

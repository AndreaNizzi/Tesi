import os
import re
import sys
import json
import datetime  
import ipaddress
from pathlib import Path
from typing import Optional, Tuple, Union, Dict, List, Any, Set
from sqlalchemy import text
from dotenv import load_dotenv

import config, prompts

load_dotenv()

# ==============================================================================
# PARSING E VALIDAZIONE DELL'INPUT
# ==============================================================================

# 1 client.py (main), 1 test_suite.py
def valida_indirizzo_ip(ip_str: str) -> bool:
    """Verifica se la stringa fornita rappresenta un indirizzo IP valido."""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

# 2 client.py (main), 2 test_suite.py
def valida_formato_timestamp(ts_str: str) -> Optional[datetime.datetime]:
    """Valida e converte le stringhe di timestamp accettando vari sottosecondi/spazi."""
    formati = [
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S"
    ]
    ts_clean = ts_str.strip()
    for fmt in formati:
        try:
            return datetime.datetime.strptime(ts_clean, fmt)
        except ValueError:
            continue
    return None

# 1 client.py (main), 1 test_suite.py
def seleziona_modello_engine():
    """Carica le variabili di ambiente e gestisce il menu di selezione del modello."""
    # Assicura il caricamento delle variabili da .env
    load_dotenv()

    while True:
        print("============================================================")
        print("CONFIGURAZIONE INIZIALE MODELLO PER BENCHMARK")
        print(
            f"1) GPT-OSS 120B (Groq / Remote)     [Context Limit: {config.Soglie.SLOWLORIS_MAX_BYTES} char/tool]"
        )
        print(
            f"2) Qwen 3.6 27B (Server Interhost)  [Context Limit: {config.Soglie.SLOWLORIS_MAX_BYTES} char/tool]"
        )
        print("3) Esci dal programma")
        print("============================================================")

        max_tool_chars = config.Soglie.SLOWLORIS_MAX_BYTES

        print("\nScegli il modello engine (default: 2): ")
        scelta = input("").strip() or "2"
        
        if scelta == "3":
            print("\nUscita dal programma.")
            sys.exit(0)

        elif scelta == "1":
            api_key = os.getenv("GROQ_API_KEY")
            if not api_key:
                print(
                    "[ERRORE]: Chiave GROQ_API_KEY non trovata nel file .env"
                )
                sys.exit(1)

            base_url = os.getenv(
                "GROQ_BASE_URL", "https://api.groq.com/openai/v1"
            )
            # Fallback aggiornato all'ID supportato da Groq
            model_name = os.getenv("GROQ_MODEL_NAME", "openai/gpt-oss-120b")

            print(
                f"\n[OK] Caricato Groq -> Modello: {model_name} | Endpoint: {base_url}"
            )
            return api_key, base_url, model_name, max_tool_chars

        elif scelta == "2":
            api_key = os.getenv("INTERHOST_API_KEY", "ntopng_mcp_test")
            base_url = os.getenv(
                "INTERHOST_BASE_URL", "https://aitest.interhost.it/v1"
            )
            model_name = os.getenv("INTERHOST_MODEL_NAME", "Qwen3.6-27B")


            if not api_key:
                print(
                    "[ERRORE]: Chiave INTERHOST_API_KEY non trovata nel file .env"
                )
                sys.exit(1)

            print(
                f"\n[OK] Caricato Interhost -> Modello: {model_name} | Endpoint: {base_url}"
            )
            return api_key, base_url, model_name, max_tool_chars

        else:
            print("\n[ERRORE]: Opzione non valida. Inserisci 1, 2 o 3.\n")

# ==============================================================================
# PERSISTENZA E FORMATTAZIONE REPORT
# ==============================================================================

# 3 test_suite.py, 1 client.py (main)
def salva_risultati_su_disco(
    ip_target: str,
    categoria: str,
    report_md: str,
    log_txt: str,
    telemetria_txt: str,
    start_time: Union[str, datetime.datetime],
    end_time: Union[str, datetime.datetime],
    cartella_sessione: Path,  # <--- NUOVO PARAMETRO
) -> Tuple[str, str]:
    """Salva i report e i log all'interno delle sottocartelle 'reports' e 'logs'

    della sessione corrente.
    """
    def formatta_ts_filename(val: Union[str, datetime.datetime]) -> str:
        """Formatta un oggetto datetime o una stringa timestamp per l'uso nei nomi dei file."""
        if isinstance(val, datetime.datetime):
            return val.strftime("%Y%m%d_%H%M%S")
        elif isinstance(val, str):
            val_clean = val.split(".")[0]
            try:
                dt = datetime.datetime.strptime(val_clean, "%Y-%m-%d %H:%M:%S")
                return dt.strftime("%Y%m%d_%H%M%S")
            except ValueError:
                return val.replace("-", "").replace(":", "").replace(" ", "_")
        return str(val)

    ts_now_fn = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    # Sottocartelle dedicate dentro la cartella di sessione
    cartella_report = cartella_sessione / "reports"
    cartella_log = cartella_sessione / "logs"

    cartella_report.mkdir(parents=True, exist_ok=True)
    cartella_log.mkdir(parents=True, exist_ok=True)

    ts_start_fn = formatta_ts_filename(start_time)
    ts_end_fn = formatta_ts_filename(end_time)
    sanitized_ip = ip_target.replace(".", "_")

    nome_base = (
        f"{sanitized_ip}_{ts_start_fn}_{ts_end_fn}_gen_{ts_now_fn}_{categoria}"
    )

    filepath_report = cartella_report / f"REPORT_{nome_base}.md"
    filepath_log = cartella_log / f"LOG_{nome_base}.txt"

    str_start_sql = (
        start_time.strftime("%Y-%m-%d %H:%M:%S")
        if isinstance(start_time, datetime.datetime)
        else str(start_time)
    )
    str_end_sql = (
        end_time.strftime("%Y-%m-%d %H:%M:%S")
        if isinstance(end_time, datetime.datetime)
        else str(end_time)
    )
    str_now_sql = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    header_md = (
        f"--- METADATI ANALISI ---\n"
        f"IP Target Analizzato: {ip_target}\n"
        f"Categoria di Analisi: {categoria}\n"
        f"Finestra Temporale: {str_start_sql} -> {str_end_sql}\n"
        f"Data Elaborazione: {str_now_sql}\n"
        f"------------------------"
    )

    contenuto_report_completo = f"{header_md}\n\n{report_md}\n\n{telemetria_txt}"

    with open(filepath_report, "w", encoding="utf-8") as f_rep:
        f_rep.write(contenuto_report_completo)

    with open(filepath_log, "w", encoding="utf-8") as f_log:
        f_log.write(log_txt)

    return str(filepath_report), str(filepath_log)


# ==============================================================================
# GROUND TRUTH ED AUDITING BENCHMARK
# ==============================================================================

# 1 test_suite.py
def controlla_ground_truth(
    ip_target: str, 
    start_time: Union[str, datetime.datetime], 
    end_time: Union[str, datetime.datetime]
) -> Dict[str, int]:
    """
    Esegue l'interrogazione diretta della tabella cic_flows senza fare JOIN con ndpi_flows, verificando la presenza dell'IP sia come sorgente che come destinazione.
    """
    if not config.engine:
        return {}
        
    query_sql = text("""
        SELECT label, COUNT(*) as conteggio
        FROM cic_flows
        WHERE (src_ip = :ip OR dst_ip = :ip)
          AND timestamp_start >= :start 
          AND timestamp_start <= :end
        GROUP BY label;
    """)
    
    risultati_db = {}
    try:
        with config.engine.connect() as connection:
            result = connection.execute(query_sql, {
                "ip": ip_target, 
                "start": str(start_time), 
                "end": str(end_time)
            })
            for riga in result.fetchall():
                risultati_db[riga[0]] = riga[1]
    except Exception as e:
        print(f"Errore nella query Ground Truth: {e}")
        
    return risultati_db

# 1 test_suite.py
def calcola_esito_classificazione(
    verdetto_llm: str,
    ground_truth_db: Dict[str, int],
    verdetto_atteso: Optional[str] = None,
) -> str:

    verdetto_upper = str(verdetto_llm).strip().upper() if verdetto_llm else ""

    MAPPING_MALEVOLI = {
        "DOS_VOLUMETRIC": {
            "DOS_VOLUMETRIC",
            "DOS",
            "DDOS",
            "ANOMALIA_VOLUMETRICA",
            "HULK",
            "GOLDENEYE",
            "SLOWLORIS",
            "SLOWHTTPTEST",
        },
        "BEACONING_C2": {
            "BEACONING_C2",
            "BEACON",
            "BOTNET",
            "C2",
            "BOT",
            "INFILTRATION",
        },
        "SCAN_BRUTEFORCE": {
            "SCAN_BRUTEFORCE",
            "PORT_SCAN",
            "PORTSCAN",
            "SCAN",
            "RECONNAISSANCE",
            "BRUTE_FORCE",
            "BRUTEFORCE",
            "BRUTE",
            "FTP-PATATOR",
            "SSH-PATATOR",
            "PASSWORD_GUESSING",
        },
        "WEB_ATTACK_EXPLOIT": {
            "WEB_ATTACK_EXPLOIT",
            "WEB_ATTACK",
            "WEB",
            "EXPLOIT",
            "SQLI",
            "XSS",
            "HEARTBLEED",
            "INJECTION",
        },
    }

    # Valutazione presenza di minacce reali nella GT del DB
    classi_gt_db = {
        str(k).encode("ascii", "ignore").decode().strip().upper(): v
        for k, v in ground_truth_db.items()
    }
    minacce_db = {
        k: v
        for k, v in classi_gt_db.items()
        if not any(b in k for b in ["BENIGN", "TRAFFICO_BENIGNO"]) and v > 0
    }
    ha_attacchi_reali = len(minacce_db) > 0

    # Gestione esplicita di "NON_IDENTIFICATO" o stringhe vuote
    if not verdetto_upper or verdetto_upper in [
        "NON_IDENTIFICATO",
        "ERRORE",
        "UNRESOLVED",
    ]:
        return "FN" if ha_attacchi_reali else "TN"

    # Estrazione categoria predetta dall'LLM
    categoria_llm = None
    if verdetto_upper in ["BENIGN", "BENIGNO", "TRAFFICO_BENIGNO"]:
        categoria_llm = "BENIGN"
    else:
        for cat_std, keywords in MAPPING_MALEVOLI.items():
            if any(kw in verdetto_upper for kw in keywords):
                categoria_llm = cat_std
                break

    if not categoria_llm:
        return "NON_PARSABILE"

    # Valutazione su Verdetto Atteso (JSON Ground Truth)
    if verdetto_atteso and str(verdetto_atteso).strip().upper() not in [
        "SCONOSCIUTO",
        "NONE",
        "",
    ]:
        atteso_upper = str(verdetto_atteso).strip().upper()
        categoria_attesa = None

        if atteso_upper in ["BENIGN", "BENIGNO", "TRAFFICO_BENIGNO"]:
            categoria_attesa = "BENIGN"
        else:
            for cat_std, keywords in MAPPING_MALEVOLI.items():
                if any(kw in atteso_upper for kw in keywords):
                    categoria_attesa = cat_std
                    break

        if categoria_attesa and categoria_llm == categoria_attesa:
            return "TN" if categoria_llm == "BENIGN" else "TP"
        elif categoria_attesa:
            if categoria_attesa == "BENIGN" and categoria_llm != "BENIGN":
                return "FP"
            elif categoria_attesa != "BENIGN" and categoria_llm == "BENIGN":
                return "FN"
            else:
                return f"FP_MISMATCH_{categoria_llm}"

    # Fallback su GT del Database SQL
    if categoria_llm == "BENIGN":
        return "TN" if not ha_attacchi_reali else "FN"
    if not ha_attacchi_reali:
        return "FP"

    keywords_llm = MAPPING_MALEVOLI.get(categoria_llm, set())
    for label_db in minacce_db.keys():
        if any(kw in label_db for kw in keywords_llm):
            return "TP"

    return f"FP_MISMATCH_{categoria_llm}"

# 1 test_suite.py
def stampa_e_salva_metriche(stats: Dict[str, int], output_dir: Path, timestamp: str, model_name: str) -> None:
    """
    Calcola le metriche del benchmark, le stampa a schermo e le salva su disco sia in formato JSON sia in TXT.
    """
    tp = stats.get("TP", 0)
    tn = stats.get("TN", 0)
    fn = stats.get("FN", 0)
    non_parsa = stats.get("NON_PARSABILE", 0)

    # Calcola i mismatch totali
    fp_mismatch_totali = sum(v for k, v in stats.items() if k.startswith("FP_MISMATCH"))
    
    # Aggrega i False Positive: i falsi allarmi puri + le minacce classificate con la categoria sbagliata
    fp = stats.get("FP", 0) + fp_mismatch_totali

    totale = tp + fp + tn + fn

    accuracy = (tp + tn) / totale if totale > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    recap_txt = (
        f"\n{'='*70}\n"
        f"MATRICE DI CONFUSIONE E METRICHE DI AUDITING RECAP\n"
        f"{'='*70}\n"
        f"            Reale: MINACCIA    Reale: BENIGNO\n"
        f"Pred: MINACCIA    TP: {tp:<12} FP: {fp:<12}\n"
        f"Pred: BENIGNO      FN: {fn:<12} TN: {tn:<12}\n"
        f"{'-'*70}\n"
        f"Scenari non parsabili / falliti: {non_parsa}\n"
        f"Totale casi validati: {totale}\n"
        f"{'-'*70}\n"
        f"Accuratezza (Accuracy): {accuracy:.2%}\n"
        f"Precisione (Precision): {precision:.2%}\n"
        f"Richiamo (Recall):      {recall:.2%}\n"
        f"F1-Score:               {f1_score:.2%}\n"
        f"{'='*70}\n"
    )
    print(recap_txt)

    summary_data = {
        "modello": model_name,
        "timestamp": timestamp,
        "matrice_confusione": {
            "TP": tp,
            "FP": fp,
            "TN": tn,
            "FN": fn,
            "FP_MISMATCH": stats.get("FP_MISMATCH", 0),
            "NON_PARSABILE": non_parsa,
            "totale_casi": totale
        },
        "metriche": {
            "accuracy": round(accuracy, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1_score, 4)
        }
    }

    base_name = f"summary_{model_name.replace(':', '_')}_{timestamp}"
    json_summary_path = output_dir / f"{base_name}.json"
    txt_summary_path = output_dir / f"{base_name}.txt"

    with open(json_summary_path, "w", encoding="utf-8") as f_json:
        json.dump(summary_data, f_json, indent=2, ensure_ascii=False)

    with open(txt_summary_path, "w", encoding="utf-8") as f_txt:
        f_txt.write(recap_txt)

    print(f"Metriche e Matrice salvate in:\n  -> {json_summary_path}\n  -> {txt_summary_path}\n")







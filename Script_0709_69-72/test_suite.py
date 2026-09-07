import asyncio
import io
import re
import json
import os
import sys
import time
import traceback
import httpx
from pathlib import Path
from datetime import datetime
from dotenv import load_dotenv
from openai import AsyncOpenAI
from mcp import StdioServerParameters

import utils
from client import esegui_analisi_mcp

load_dotenv()

class TeeStream:
    """Classe di supporto per catturare i log in una stringa e contemporaneamente stamparli su console."""
    def __init__(self, original_stream):
        self.original_stream = original_stream
        self.buffer = io.StringIO()

    def write(self, message):
        self.original_stream.write(message)
        self.buffer.write(message)

    def flush(self):
        self.original_stream.flush()

    def get_log(self):
        return self.buffer.getvalue()
        
# =====================================================================
# CORE ESECUZIONE BENCHMARK
# =====================================================================

async def run_benchmark():
    file_scenari = "test_scenarios.json"
    file_gt = "ground_truth.json"

    if not os.path.exists(file_scenari):
        print(f"File {file_scenari} non trovato.")
        return

    mappa_gt = {}
    if os.path.exists(file_gt):
        with open(file_gt, "r", encoding="utf-8") as f_gt:
            gt_data = json.load(f_gt)
            mappa_gt = {
                item["id"]: item.get("verdetto_atteso", "SCONOSCIUTO")
                for item in gt_data
                if "id" in item
            }

    api_key, base_url, model_name, max_tool_chars = (
        utils.seleziona_modello_engine()
    )
    client_openai = AsyncOpenAI(
        api_key=api_key,
        base_url=base_url,
        http_client=httpx.AsyncClient(
            timeout=httpx.Timeout(
                connect=10.0,
                read=45.0,
                write=10.0,
                pool=10.0
            )
        )
    )

    mcp_server_params = StdioServerParameters(
        command=sys.executable,
        args=["server.py"],
        env=os.environ.copy(),
        err=sys.stderr
    )

    with open(file_scenari, "r", encoding="utf-8") as f:
        scenari = json.load(f)

    risultati = []
    stats = {
        "TP": 0,
        "FP": 0,
        "TN": 0,
        "FN": 0,
        "FP_MISMATCH": 0,
        "NON_PARSABILE": 0,
    }

    ts_sessione = datetime.now().strftime("%Y%m%d_%H%M%S")
    cartella_sessione = Path("outputs") / f"SESSION_{ts_sessione}"
    cartella_sessione.mkdir(parents=True, exist_ok=True)

    model_name_safe = re.sub(r"[^\w\.-]", "_", model_name)

    print(f"\n==================================================")
    print(f"AVVIO TEST SUITE AUTOMATIZZATA CON GROUND TRUTH")
    print(f"Scenari: {len(scenari)} | Modello: {model_name} | Base URL: {base_url}")
    print(f"==================================================")

    interrotto_da_utente = False

    try:
        for idx, sc in enumerate(scenari, start=1):
            if interrotto_da_utente:
                break
            print(f"\n--- [SCENARIO {idx}/{len(scenari)}: {sc['id']}] ---")
            print(f"Target: {sc['ip_target']} | Categoria Originaria: {sc['categoria_tag']}")

            if not utils.valida_indirizzo_ip(sc["ip_target"]):
                print(f"IP target non valido ({sc['ip_target']}).")
                stats["NON_PARSABILE"] += 1
                continue

            dt_start = utils.valida_formato_timestamp(sc["start_time"])
            dt_end = utils.valida_formato_timestamp(sc["end_time"])

            if not dt_start or not dt_end:
                print(f"Errore nei timestamp per lo scenario {sc['id']}: formato non valido.")
                stats["NON_PARSABILE"] += 1
                continue

            start_time_iso = sc["start_time"].replace(" ", "T")
            end_time_iso = sc["end_time"].replace(" ", "T")

            verdetto_atteso = mappa_gt.get(
                sc["id"], sc.get("verdetto_atteso", "SCONOSCIUTO")
            )

            mappa_tag_config = {
                "web_attack_exploit": "cat_a",
                "dos_volumetric": "cat_b",
                "scan_bruteforce": "cat_c",
                "beaconing_c2": "cat_d",
                "benign": "cat_e",
            }

            tag_cat_raw = str(sc.get("categoria_tag", "")).strip().lower()
            cat_tag_config = mappa_tag_config.get(tag_cat_raw, "cat_e")

            id_upper = str(sc.get("id", "")).upper()
            for cat in ["A", "B", "C", "D", "E"]:
                if f"TEST_CAT_{cat}" in id_upper:
                    cat_tag_config = f"cat_{cat.lower()}"
                    break

            t_inizio = time.perf_counter()
            original_stdout = sys.stdout
            tee = TeeStream(original_stdout)
            sys.stdout = tee

            try:
                # Esecuzione analisi direct-LLM
                report_md, log_mcp_str, meta, verdetto_final = await esegui_analisi_mcp(
                    client=client_openai,
                    mcp_server_params=mcp_server_params,
                    ip_target=sc["ip_target"],
                    start_time=start_time_iso,
                    end_time=end_time_iso,
                    model_name=model_name,
                    categoria_tag=cat_tag_config,
                    max_tool_chars=max_tool_chars,
                )

                tempo_totale = time.perf_counter() - t_inizio
                cli_log = tee.get_log() + "\n" + log_mcp_str

                if not verdetto_final or verdetto_final in ["-", "", "NON_IDENTIFICATO"]:
                    verdetto_final = "NON_IDENTIFICATO"

                ground_truth_db = utils.controlla_ground_truth(
                    sc["ip_target"], sc["start_time"], sc["end_time"]
                )
                esito_metrica = utils.calcola_esito_classificazione(
                    verdetto_final, ground_truth_db, verdetto_atteso
                )

                if esito_metrica in ["TP", "TN", "FP", "FN", "NON_PARSABILE"]:
                    stats[esito_metrica] += 1
                elif esito_metrica.startswith("FP_MISMATCH"):
                    stats["FP_MISMATCH"] += 1
                else:
                    stats["NON_PARSABILE"] += 1

                telemetria_txt = f"--- TELEMETRIA ESECUZIONE ---\n```json\n{json.dumps(meta, indent=2)}\n```"

                utils.salva_risultati_su_disco(
                    ip_target=sc["ip_target"],
                    categoria=cat_tag_config,
                    report_md=report_md,
                    log_txt=cli_log,
                    telemetria_txt=telemetria_txt,
                    start_time=dt_start,
                    end_time=dt_end,
                    cartella_sessione=cartella_sessione,
                )

                esito = {
                    "ID": sc["id"],
                    "ip_target": sc["ip_target"],
                    "start_time": sc["start_time"],
                    "end_time": sc["end_time"],
                    "Categoria": cat_tag_config,
                    "Verdetto Atteso": verdetto_atteso,
                    "Verdetto LLM": verdetto_final,
                    "Esito Auditing": esito_metrica,
                    "Report_MD": report_md,
                    "Telemetria": meta,
                    "Ground Truth DB": ground_truth_db,
                    "Tempo Totale (s)": round(tempo_totale, 2),
                }

                print(f" -> Categoria Applicata: {cat_tag_config}")
                print(f" -> Verdetto LLM       : {verdetto_final}")
                print(f" -> Ground Truth       : {ground_truth_db}")
                print(f" -> Verdetto Atteso    : {verdetto_atteso}")
                print(f" -> Esito              : {esito_metrica}")

                risultati.append(esito)

            except (KeyboardInterrupt, asyncio.CancelledError):
                print(f"\n[AVVISO]: Interruzione rilevata durante lo scenario {sc['id']}.")
                interrotto_da_utente = True
                break

            except BaseExceptionGroup as eg:
                interruzione, _ = eg.split((KeyboardInterrupt, asyncio.CancelledError))
                if interruzione:
                    print(f"\n[AVVISO]: Interruzione CTRL+C (TaskGroup) durante lo scenario {sc['id']}.")
                    interrotto_da_utente = True
                    break

                tempo_totale = time.perf_counter() - t_inizio
                cli_log = tee.get_log() + f"\nExceptionGroup sollevato: {eg}"
                print(f"[ERRORE]: TaskGroup durante lo scenario {sc['id']}: {eg}")
                stats["NON_PARSABILE"] += 1

                utils.salva_risultati_su_disco(
                    ip_target=sc["ip_target"],
                    categoria=f"{cat_tag_config}_ERROR",
                    report_md="[ERRORE TASKGROUP DURANTE L'ESECUZIONE]",
                    log_txt=cli_log,
                    telemetria_txt="--- TELEMETRIA ESECUZIONE ---\nERRORE TASKGROUP",
                    start_time=dt_start,
                    end_time=dt_end,
                    cartella_sessione=cartella_sessione,
                )

                risultati.append({
                    "ID": sc["id"],
                    "ip_target": sc["ip_target"],
                    "start_time": sc["start_time"],
                    "end_time": sc["end_time"],
                    "Categoria": cat_tag_config,
                    "Verdetto Atteso": verdetto_atteso,
                    "Verdetto LLM": "ERRORE_TASKGROUP",
                    "Esito Auditing": "NON_PARSABILE",
                    "Report_MD": "[ERRORE TASKGROUP DURANTE L'ESECUZIONE]",
                    "Telemetria": {},
                    "Ground Truth DB": "ERRORE",
                    "Tempo Totale (s)": round(tempo_totale, 2),
                })

            except Exception as e:
                tempo_totale = time.perf_counter() - t_inizio
                cli_log = tee.get_log() + f"\nEccezione sollevata: {traceback.format_exc()}"
                print(f"[ERRORE]: durante lo scenario {sc['id']}: {e}")
                stats["NON_PARSABILE"] += 1

                utils.salva_risultati_su_disco(
                    ip_target=sc["ip_target"],
                    categoria=f"{cat_tag_config}_ERROR",
                    report_md="[ERRORE DURANTE L'ESECUZIONE]",
                    log_txt=cli_log,
                    telemetria_txt="--- TELEMETRIA ESECUZIONE ---\nERRORE",
                    start_time=dt_start,
                    end_time=dt_end,
                    cartella_sessione=cartella_sessione,
                )

                risultati.append({
                    "ID": sc["id"],
                    "ip_target": sc["ip_target"],
                    "start_time": sc["start_time"],
                    "end_time": sc["end_time"],
                    "Categoria": cat_tag_config,
                    "Verdetto Atteso": verdetto_atteso,
                    "Verdetto LLM": "ERRORE_ESECUZIONE",
                    "Esito Auditing": "NON_PARSABILE",
                    "Report_MD": f"[ERRORE DURANTE L'ESECUZIONE]: {e}",
                    "Telemetria": {},
                    "Ground Truth DB": "ERRORE",
                    "Tempo Totale (s)": round(tempo_totale, 2),
                })

            finally:
                sys.stdout = original_stdout

    finally:
        if risultati:
            suffix = "_PARZIALE" if interrotto_da_utente else ""
            output_filename = (
                cartella_sessione
                / f"benchmark_{model_name_safe}_{ts_sessione}{suffix}.json"
            )

            with open(output_filename, "w", encoding="utf-8") as f_out:
                json.dump(risultati, f_out, indent=2, ensure_ascii=False)

            print(f"\nBenchmark completato/interrotto. Dataset salvato in '{output_filename}'")
            utils.stampa_e_salva_metriche(
                stats, cartella_sessione, ts_sessione, model_name
            )

        try:
            await client_openai.close()
        except Exception:
            pass
        
if __name__ == "__main__":
    try:
        asyncio.run(run_benchmark())
    except (KeyboardInterrupt, SystemExit):
        print("\n\nBenchmark interrotto dall'utente.")
        sys.exit(0)
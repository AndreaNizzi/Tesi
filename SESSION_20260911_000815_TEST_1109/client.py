import os
import gc
import re
import sys
import json
import time
import asyncio 
import traceback
import textwrap
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional, Set
from datetime import datetime
from dotenv import load_dotenv
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from openai import AsyncOpenAI 
from openai import APIConnectionError, APITimeoutError

import utils
import config
import engine, prompts

# ==============================================================================
# ENGINE PRINCIPALE DI ANALISI MCP
# ==============================================================================

async def esegui_analisi_mcp(
    client: Any,
    mcp_server_params: Any,
    ip_target: str,
    start_time: str,
    end_time: str,
    model_name: str,
    categoria_tag: str,
    max_tool_chars: int,
    max_turns: int = config.Soglie.MAX_DRILLDOWN_TURNS,
) -> Tuple[str, str, Dict[str, Any]]:
    
    # Pulizia preventiva della memoria prima di allocare le nuove strutture dati
    gc.collect()
    config.tool_chiamati.clear()

    tempo_inizio_assoluto = time.perf_counter()
    is_gpt_oss = "gpt-oss-120b" in str(model_name).lower()

    # -------------------------------------------------------------------------
    # 1. METRICHE DI TELEMETRIA E LOGGING
    # -------------------------------------------------------------------------
    metriche_tempo = {
        "tempo_llm_sec": 0.0,
        "tempo_mcp_totale_sec": 0.0,
        "tempo_sql_reale_sec": 0.0,
        "tempo_totale_esecuzione": 0.0,
        "tempo_attesa_rate_limit_sec": 0.0,
    }

    log_lines: List[str] = []

    def log_print(messaggio: str):
        print(messaggio, flush=True)
        log_lines.append(messaggio + "\n")

    def log_only(messaggio: str):
        log_lines.append(messaggio + "\n")

    # -------------------------------------------------------------------------
    # 2. FUNZIONI DI UTILITÀ E PARSING (HELPER FUNCTIONS)
    # -------------------------------------------------------------------------
    def ottieni_params_llm(fase: str, tools: list) -> dict:
        params = {"model": model_name, "temperature": 0.0, "seed": 42}
        if fase == "ESPLORAZIONE":
            params["tools"] = tools
            params["tool_choice"] = "auto"
            params["parallel_tool_calls"] = False
        return params

    def elabora_risposta_llm(resp) -> dict:
        msg = resp.choices[0].message
        tc = []
        if hasattr(msg, "tool_calls") and msg.tool_calls:
            for t in msg.tool_calls:
                tc.append({
                    "id": t.id,
                    "type": "function",
                    "function": {
                        "name": t.function.name,
                        "arguments": t.function.arguments,
                    },
                })
        return {
            "role": "assistant",
            "content": msg.content or "",
            "tool_calls": tc,
        }

    def estrai_tempo_sql(result_mcp, testo: str) -> float:
        try:
            if hasattr(result_mcp, "meta") and result_mcp.meta:
                if "sql_time" in result_mcp.meta:
                    return float(result_mcp.meta["sql_time"])
                if "tempo_sql_reale_sec" in result_mcp.meta:
                    return float(result_mcp.meta["tempo_sql_reale_sec"])

            if testo and testo.strip().startswith("{"):
                try:
                    data = json.loads(testo)
                    if "tempo_sql_reale_sec" in data:
                        return float(data["tempo_sql_reale_sec"])
                    if "tempo_esecuzione_sql" in data:
                        return float(data["tempo_esecuzione_sql"])
                except json.JSONDecodeError:
                    pass

            m = re.search(r'["\']?tempo_sql_reale_sec["\']?\s*:\s*([\d\.]+)', testo)
            if m:
                return float(m.group(1))

            m_alt = re.search(r"tempo_esecuzione_sql:\s*([\d\.]+)", testo, re.IGNORECASE)
            if m_alt:
                return float(m_alt.group(1))
        except Exception:
            pass
        return 0.0

    def _ha_evidenza_corroborante(verdetto: str, risultati: list) -> bool:
        mappa = {
            "DOS_VOLUMETRIC": lambda r: '"pps_aggregati"' in r or '"flussi_slowloris"' in r,
            "BEACONING_C2": lambda r: '"cv"' in r and '"anomaly_score"' in r,
            "SCAN_BRUTEFORCE": lambda r: '"porte_uniche_contattate"' in r or "SOSPETTO_BRUTEFORCE" in r,
            "WEB_ATTACK_EXPLOIT": lambda r: '"anomalie_l7_trovate"' in r,
        }
        check = mappa.get(verdetto)
        return bool(check) and any(check(t["result"]) for t in risultati if isinstance(t.get("result"), str))

    # -------------------------------------------------------------------------
    # 3. ARCHITETTURA DEI PROMPT: SYSTEM VS USER (Inizializzazione Turno 1)
    # -------------------------------------------------------------------------
    
    user_prompt_iniziale = prompts.build_user_prompt_iniziale(ip_target, start_time, end_time, categoria_tag)

    system_prompt = {
        "role": "system",
        "content": prompts.SYSTEM_PROMPT_CONTENT
    }

    messages = [system_prompt, user_prompt_iniziale]

    # -------------------------------------------------------------------------
    # 4. INIZIALIZZAZIONE STATO ED ESECUZIONE LOOP INDAGINE
    # -------------------------------------------------------------------------
    turno = 0
    stato_investigazione = "ESPLORAZIONE"
    risultati_tool_raccolti: List[Dict[str, Any]] = []
    storico_chiamate_hash = set()
    verdetto_vincolante_str = "UNKNOWN" 
    report_content: Optional[str] = None

    log_print(f"=== INIZIO INDAGINE MCP PER TARGET: {ip_target} ===")

    # =========================================================================
    # FASE 1: ESPLORAZIONE MCP (OTTIMIZZATA E ROBUSTA)
    # =========================================================================

    testo_risposta = ""  # Safe initialization per scope globale del blocco

    try:
        async with stdio_client(mcp_server_params) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()

                mcp_tools = await session.list_tools()
                tools_list = getattr(mcp_tools, "tools", [])

                llm_tools_mappati = [
                    {
                        "type": "function",
                        "function": {
                            "name": t.name,
                            "description": (
                                t.description[: config.Soglie.TOOL_DESC_MAX_CHARS]
                                if t.description
                                else ""
                            ),
                            "parameters": t.inputSchema,
                        },
                    }
                    for t in tools_list
                ]

                while stato_investigazione == "ESPLORAZIONE" and turno < max_turns:
                    log_print(f"\n==================== TURNO {turno + 1}/{max_turns} [{stato_investigazione}] ====================")
                    testo_risposta = ""  # Reset a ogni turno

                    # 1. Anti-Loop Tool Repetitions
                    if engine._controlla_loop_community_id(messages):
                        log_print(" -> [ANTI-LOOP]: Rilevate chiamate consecutive a Community ID. Invio freno di sistema.")
                        messages.append({
                            "role": "user",
                            "content": (
                                "AVVISO SISTEMA: Hai gia' ispezionato sufficienti connessioni individuali via Community ID. "
                                "NON chiamare ulteriormente 'analizza_connessione_by_community_id'. "
                                "Procedi direttamente con la sintesi dei dati o emetti il VERDETTO FINALE."
                            )
                        })

                    # 2. Pruning e Compressione Contesto
                    max_recenti = (
                        config.Soglie.PRUNING_MAX_MESSAGES_GPT_OSS
                        if is_gpt_oss
                        else config.Soglie.PRUNING_MAX_MESSAGES_DEFAULT
                    )
                    messages_prunati = engine.applica_pruning_contesto(
                        messages,
                        max_messaggi_recenti=max_recenti,
                        max_chars_tool=min(
                            max_tool_chars, config.Soglie.PRUNING_TOOL_CHARS_CAP
                        ),
                    )
                    if is_gpt_oss:
                        messages_prunati = engine.comprimi_messaggi_contesto(
                            messages_prunati,
                            max_chars=config.Soglie.REPORT_CONTEXT_MAX_CHARS_GPT_OSS,
                        )

                    log_only("[PROMPT INVIATO ALL'LLM]:\n" + json.dumps(messages_prunati, indent=2, ensure_ascii=False) + "\n\n")

                    # 3. Chiamata LLM con Retry e Timeout Handling
                    llm_params = ottieni_params_llm(stato_investigazione, llm_tools_mappati)
                    response = None

                    for tentativi_llm in range(2):
                        t_llm_start = time.perf_counter()
                        try:
                            import copy
                            messages_sanitizzati = []
                            for m in messages_prunati:
                                m_copy = copy.deepcopy(m)
                                
                                if m_copy.get("content") is None:
                                    m_copy["content"] = ""
                                    
                                if m_copy.get("role") == "assistant" and "tool_calls" in m_copy:
                                    if not m_copy["tool_calls"]:
                                        m_copy.pop("tool_calls", None)

                                if m_copy.get("role") == "tool" and not m_copy.get("tool_call_id"):
                                    continue

                                messages_sanitizzati.append(m_copy)

                            response = await asyncio.wait_for(
                                client.chat.completions.create(messages=messages_sanitizzati, **llm_params),
                                timeout=120.0
                            )
                            metriche_tempo["tempo_llm_sec"] += (time.perf_counter() - t_llm_start)
                            break
                        except (asyncio.TimeoutError, APITimeoutError):
                            metriche_tempo["tempo_llm_sec"] += (time.perf_counter() - t_llm_start)
                            log_print(f" -> [TIMEOUT SERVER LLM]: Stallo al Turno {turno + 1}.")
                            await asyncio.sleep(1)
                        except APIConnectionError as e:
                            metriche_tempo["tempo_llm_sec"] += (time.perf_counter() - t_llm_start)
                            log_print(f" -> [ERRORE RETE LLM]: Connessione rifiutata o caduta: {e}")
                            await asyncio.sleep(2)
                        except Exception as e_generico:
                            log_print(f" -> [ECCEZIONE INATTESA LLM]: {type(e_generico).__name__}: {e_generico}")
                            import pprint
                            log_only(f"[PAYLOAD FALLITO]:\n{pprint.pformat(messages_prunati)}")
                            break

                    if response is None:
                        log_print("\n[ABORT SCENARIO]: Il server LLM non risponde per lo scenario attuale. Salto lo scenario.\n")
                        stato_investigazione = "ABORTED"
                        break

                    messaggio_dict = elabora_risposta_llm(response)
                    log_only("[RISPOSTA RICEVUTA DALL'LLM]:\n" + json.dumps(messaggio_dict, indent=2, ensure_ascii=False) + "\n\n")

                    if messaggio_dict.get("tool_calls") and len(messaggio_dict["tool_calls"]) > 1:
                        log_print(f" -> [AVVISO]: Rilevate {len(messaggio_dict['tool_calls'])} chiamate tool. Mantengo solo la prima.")
                        messaggio_dict["tool_calls"] = [messaggio_dict["tool_calls"][0]]

                    raw_tool_calls = messaggio_dict.get("tool_calls")
                    tool_calls = raw_tool_calls if isinstance(raw_tool_calls, list) else []
                    testo_risposta = messaggio_dict.get("content") or ""

                    # Parsing del Ragionamento LLM
                    if testo_risposta.strip():
                        thought_display = testo_risposta
                        try:
                            testo_pulito = re.sub(r"^```json\s*|\s*```$", "", testo_risposta.strip(), flags=re.MULTILINE)
                            thought_data = json.loads(testo_pulito)
                            if isinstance(thought_data, dict):
                                thought_display = thought_data.get("motivazione") or thought_data.get("note_logiche") or thought_display
                        except Exception:
                            pass

                        log_print("\n┌── [LLM THOUGHT / RAGIONAMENTO] ───────────────────────────────────────────┐")
                        log_print(f"│ {thought_display.replace(chr(10), chr(10) + '│ ')}")
                        log_print("└────────────────────────────────────────────────────────────────────────────┘\n")

                    # =========================================================================
                    # RAMO A: ESECUZIONE TOOL CALL PRESENTE
                    # =========================================================================
                    if tool_calls and isinstance(tool_calls[0], dict):
                        tc = tool_calls[0]
                        tool_id = tc.get("id")
                        nome_funzione = tc.get("function", {}).get("name")
                        raw_args = tc.get("function", {}).get("arguments", {})

                        try:
                            argomenti = json.loads(raw_args) if isinstance(raw_args, str) else (raw_args or {})
                        except json.JSONDecodeError:
                            argomenti = {}

                        if "ip_target" not in argomenti or not argomenti["ip_target"]:
                            if "ip_address" in argomenti and argomenti["ip_address"]:
                                argomenti["ip_target"] = argomenti["ip_address"]
                            elif ip_target:
                                argomenti["ip_target"] = ip_target

                        argomenti = engine._applica_auto_paginazione(nome_funzione, argomenti, storico_chiamate_hash)

                        chiamata_hash, argomenti_puliti, _ = engine.gestisci_e_calcola_hash_tool(
                            nome_funzione=nome_funzione,
                            argomenti=argomenti,
                            chiamate_effettuate=storico_chiamate_hash
                        )

                        if chiamata_hash in storico_chiamate_hash:
                            offset_val = int(argomenti_puliti.get("offset", 0) or 0)
                            limit_val = int(argomenti_puliti.get("limit", 50) or 50)
                            offset_suggerito = offset_val + limit_val

                            msg_errore = (
                                f"[ERRORE SISTEMA]: La chiamata a '{nome_funzione}' con parametri {json.dumps(argomenti_puliti)} è un DUPLICATO.\n"
                                f"Avanza la paginazione impostando 'offset'={offset_suggerito} o cambia tool."
                            )
                            log_print(f" -> [AVVISO DUPLICATO]: Tool '{nome_funzione}' bloccato per parametri duplicati.")

                            tc["function"]["arguments"] = json.dumps(argomenti_puliti)
                            messages.append({"role": "assistant", "content": testo_risposta, "tool_calls": [tc]})
                            messages.append({
                                "role": "tool",
                                "tool_call_id": tc.get("id"),
                                "name": nome_funzione,
                                "content": json.dumps({"status": "error", "message": msg_errore})
                            })
                            turno += 1
                            continue

                        if nome_funzione == "compute_verdict_scores":
                            tool_gia_eseguiti = {t["tool_name"] for t in risultati_tool_raccolti}
                            tool_base_richiesti = config.TOOL_OBBLIGATORI - {"compute_verdict_scores"}
                            mancanti_prima_dello_score = tool_base_richiesti - tool_gia_eseguiti
                            if mancanti_prima_dello_score:
                                log_print(f" -> [GATE]: 'compute_verdict_scores' rifiutato, mancano: {sorted(mancanti_prima_dello_score)}")
                                messages.append({"role": "assistant", "content": testo_risposta, "tool_calls": [tc]})
                                messages.append({
                                    "role": "tool", "tool_call_id": tool_id, "name": nome_funzione,
                                    "content": json.dumps({
                                        "status": "rejected",
                                        "message": (
                                            "compute_verdict_scores richiede prima i tool di telemetria base. "
                                            f"Mancano: {', '.join(sorted(mancanti_prima_dello_score))}. Eseguili prima."
                                        )
                                    })
                                })
                                turno += 1
                                continue

                        tc["function"]["arguments"] = json.dumps(argomenti_puliti)
                        messages.append({"role": "assistant", "content": testo_risposta, "tool_calls": [tc]})

                        t_mcp_start = time.perf_counter()
                        scansione_completa = False
                        testo_risultato_sicuro = ""

                        try:
                            log_print(f" -> [MCP TOOL]: Esecuzione '{nome_funzione}' con argomenti {json.dumps(argomenti_puliti)}")
                            mcp_result = await session.call_tool(nome_funzione, argomenti_puliti)
                            metriche_tempo["tempo_mcp_totale_sec"] += (time.perf_counter() - t_mcp_start)

                            testo_risultato = (
                                "".join([item.text for item in mcp_result.content if hasattr(item, "text")])
                                if (mcp_result and hasattr(mcp_result, "content"))
                                else "[Nessun contenuto restituito]"
                            )

                            if not any(err in testo_risultato for err in ["errore_sql", "ERRORE ESECUZIONE TOOL"]):
                                storico_chiamate_hash.add(chiamata_hash)
                                config.tool_chiamati.add(nome_funzione)
                            else:
                                log_print(f" -> [AUTO-PAGINATORE]: Errore nell'esecuzione di {nome_funzione}. Offset non registrato.")

                            if is_gpt_oss:
                                testo_risultato = engine.sanifica_risultato_tool(testo_risultato)

                            testo_risultato = engine._arricchisci_risultato_tool(testo_risultato, nome_funzione)
                            
                            testo_risultato_sicuro = engine.sintetizza_payload_tool(
                                json_str=testo_risultato, 
                                max_elementi_lista=3
                            )
                            
                            risultati_tool_raccolti.append({"tool_name": nome_funzione, "result": testo_risultato_sicuro})
                            metriche_tempo["tempo_sql_reale_sec"] += estrai_tempo_sql(mcp_result, testo_risultato_sicuro)

                            try:
                                res_payload = json.loads(testo_risultato_sicuro)
                                if isinstance(res_payload, dict):
                                    sintesi = res_payload.get("sintesi_smart", {})
                                    totale_finestra = sintesi.get("totale_flussi_nella_finestra") or res_payload.get("totale_flussi_nella_finestra") or 0
                                    off_curr = res_payload.get("pagina_offset_attuale") or 0
                                    estratte_pagina = res_payload.get("totale_anomalie_estratte_in_questa_pagina") or res_payload.get("totale_richieste_ispezionate") or 0
                                    limit_usato = int(argomenti_puliti.get("limit", 50) or 50)

                                    if totale_finestra > 0 and (off_curr + limit_usato >= totale_finestra or (off_curr > 0 and estratte_pagina == 0)):
                                        log_print(f" -> [CHECK ARRESTO]: Scansione di {nome_funzione} completata ({off_curr + estratte_pagina}/{totale_finestra}).")
                                        scansione_completa = True
                            except Exception:
                                pass
                            
                            if nome_funzione == "compute_verdict_scores":
                                try:
                                    res_json = (
                                        json.loads(testo_risultato_sicuro)
                                        if isinstance(testo_risultato_sicuro, str)
                                        else testo_risultato_sicuro
                                    )

                                    # 1. Estrazione degli score numerici
                                    CATEGORIE_ATTACCO = {"DOS_VOLUMETRIC", "SCAN_BRUTEFORCE", "BEACONING_C2", "WEB_ATTACK_EXPLOIT"}
                                    
                                    scores_validi = {
                                        k: float(v)
                                        for k, v in res_json.items()
                                        if k in CATEGORIE_ATTACCO and isinstance(v, (int, float))
                                    }

                                    # 2. Rilevamento dinamico di pareggi / top score
                                    if scores_validi:
                                        max_val = max(scores_validi.values())
                                        # Individua TUTTI i vincitori a pari merito sopra lo 0.0
                                        vincitori_top = [k for k, v in scores_validi.items() if v == max_val and max_val > 0.0]
                                        
                                        if max_val == 0.0 or not vincitori_top:
                                            verdetto = "BENIGN"
                                            score = 0.0
                                        else:
                                            verdetto = res_json.get("verdetto_suggerito_euristica") or vincitori_top[0]
                                            score = max_val
                                    else:
                                        score, verdetto = 0.0, "UNKNOWN"
                                        vincitori_top = []

                                    # 3. Isolamento degli score secondari (> 0.0 e inferiori al max_val)
                                    altri_score_attivi = {
                                        cat: val for cat, val in scores_validi.items() 
                                        if val > 0.0 and cat not in vincitori_top
                                    }
                                    
                                    # Unifica i conflitti segnalati dal JSON o rilevati dall'analisi vettoriale
                                    conflitti = res_json.get("conflitto_a_pari_merito", [])
                                    if not conflitti and len(vincitori_top) > 1:
                                        conflitti = vincitori_top

                                    corroborato = _ha_evidenza_corroborante(verdetto, risultati_tool_raccolti)

                                    # 4. Costruzione Guida Dinamica
                                    note_multi_score = ""
                                    if altri_score_attivi:
                                        dettaglio_altri = ", ".join([f"{k}: {v}" for k, v in altri_score_attivi.items()])
                                        note_multi_score = f" [ALTRE CATEGORIE MINORI: {dettaglio_altri}]."

                                    if conflitti:
                                        guida_azione = (
                                            f"[ATTENZIONE - RILEVATO MULTI-ATTACCO / PAREGGIO]: Trovato un punteggio paritario tra {conflitti} con score {max_val}.{note_multi_score} "
                                            "Non limitarti a una sola minaccia. Ispeziona i log per confermare se si tratta di un attacco combinato "
                                            "(es. Exploitation Web seguita da Beaconing C2) e documenta entrambe le componenti nel report."
                                        )
                                    elif score == 0.0:
                                        guida_azione = (
                                            "[VERIFICA RICHIESTA]: Il calcolo euristico restituisce punteggio 0.0 su tutte le categorie (BENIGN). "
                                            "Verifica se nei log L7 / HTTP precedentemente estratti vi sono anomalie non intercettate dall'euristica. "
                                            "Se confermi l'assenza di minacce, motiva il risultato ed emetti il VERDETTO FINALE 'BENIGN'."
                                        )
                                    elif score >= 0.95 and corroborato:
                                        guida_azione = (
                                            f"[EVIDENZA CORROBORATA]: L'euristica indica {verdetto} (score {score}) ed è supportata dai log grezzi.{note_multi_score} "
                                            "Se ritieni l'analisi completa, motiva le evidenze nel ragionamento finale ed emetti il VERDETTO FINALE."
                                        )
                                    else:
                                        guida_azione = (
                                            f"[ATTENZIONE - DISCREPANZA O INCOMPLETIZZA]: L'euristica suggerisce {verdetto} (score {score}),{note_multi_score} "
                                            "MA l'evidenza nei log grezzi è debole, parziale o discordante (corroborato=False). "
                                            "NON fidarti ciecamente dello score. Ispeziona ulteriormente i log DPI/HTTP o motiva criticamente il perché "
                                            "confermi o smentisci questo verdetto prima di chiudere."
                                        )

                                    log_print(f" -> [SOFT-GUIDE AGIUNTA]: Evaluated {verdetto} (score {score}) - Corroborato: {corroborato} - Pari merito: {vincitori_top} - Altri score: {altri_score_attivi}")

                                    testo_risultato_sicuro = (
                                        "=== ESITO TASSATIVO DEL TOOL COMPUTE_VERDICT_SCORES ===\n"
                                        f"{testo_risultato_sicuro}\n"
                                        "=======================================================\n"
                                        f"{guida_azione}"
                                    )

                                except Exception as e_sc:
                                    log_print(f" -> [AVVISO SHORT-CIRCUIT]: Impossibile analizzare l'output di compute_verdict_scores: {e_sc}")

                            elif engine._verifica_segnale_forte(testo_risultato_sicuro):
                                log_print(f" -> [SEGNALE FORTE]: Rilevato segnale ad alta confidenza (score >= 0.95) in '{nome_funzione}'.")
                                if "compute_verdict_scores" not in config.tool_chiamati:
                                    testo_risultato_sicuro += (
                                        "\n\n[SISTEMA - ALLERTA ALTA CONFIDENZA]: È stato rilevato un segnale di minaccia con punteggio >= 0.95.\n"
                                        "NON eseguire ulteriori ricerche o ispezioni DPI sui flussi.\n"
                                        "Esegui IMMEDIATAMENTE il tool obbligatorio 'compute_verdict_scores' ed emetti il VERDETTO FINALE."
                                    )
                                else:
                                    testo_risultato_sicuro += (
                                        "\n\n[SISTEMA - SOFT-GUIDE]: Verdetto ad alta confidenza calcolato.\n"
                                        "L'indagine è considerata CONCLUSA. Procedi direttamente ad emettere il VERDETTO FINALE nel report."
                                    )

                            if any(err in testo_risultato_sicuro.lower() for err in ["errore", "[errore tool]", "errore_sql", "exception", "failed", 'status": "error']):
                                log_print(f" -> [AVVISO FALLBACK]: Rilevato errore/warning in '{nome_funzione}'. Notifico l'LLM per continuare.")
                                testo_risultato_sicuro += (
                                    f"\n\n[AVVISO SISTEMA]: Il tool '{nome_funzione}' ha riscontrato un errore o una limitazione.\n"
                                    f"NON RIPROVARE ad eseguire '{nome_funzione}' con gli stessi parametri.\n"
                                    "IGNORA questo canale e PROSEGUI L'INDAGINE utilizzando altri tool diagnostici a disposizione."
                                )

                            if scansione_completa and not engine._verifica_segnale_forte(testo_risultato_sicuro):
                                testo_risultato_sicuro += (
                                    "\n\n[SISTEMA - SCANSIONE COMPLETATA]: Tutti i flussi della finestra temporale sono stati estratti. "
                                    "Procedi a valutare le evidenze ed emettere il VERDETTO FINALE."
                                )

                            preview_res = testo_risultato_sicuro[:180].replace("\n", " ")
                            log_print(f" -> [TOOL RESULT]: {preview_res}..." if len(testo_risultato_sicuro) > 180 else f" -> [TOOL RESULT]: {preview_res}")
                            log_only(f"[RISULTATO TOOL INTEGRALE]:\n{testo_risultato_sicuro}\n\n")

                            tag_prefix = f"[FOCUS ATTIVO: {categoria_tag}]\n" if 'categoria_tag' in locals() else ""
                            messages.append({
                                "role": "tool",
                                "tool_call_id": tool_id,
                                "name": nome_funzione,
                                "content": f"{tag_prefix}{testo_risultato_sicuro}"
                            })
                            turno += 1
                            continue

                        except (KeyboardInterrupt, asyncio.CancelledError):
                            log_print("\n[INTERRUZIONE] Interruzione durante l'esecuzione del Tool MCP.")
                            raise
                        except Exception as e_tool:
                            err_tool_msg = str(e_tool)[: config.Soglie.MAX_ERR_LOG_CHARS]
                            log_print(f" -> [ERRORE TOOL MCP]: {err_tool_msg}")
                            testo_risultato_sicuro = f"ERRORE ESECUZIONE TOOL: {err_tool_msg}.\nProva ad usare un tool alternativo."
                            
                            messages.append({
                                "role": "tool",
                                "tool_call_id": tool_id,
                                "name": nome_funzione,
                                "content": testo_risultato_sicuro
                            })
                            turno += 1
                            continue

                    # =========================================================================
                    # RAMO B: NESSUNA TOOL CALL (GESTIONE CONCLUSIONE / SOLLECITO)
                    # =========================================================================
                    if len(risultati_tool_raccolti) == 0:
                        log_print(" -> [AVVISO TURNO 1]: L'LLM non ha chiamato nessun tool. Sollecito il primo intervento...")
                        if testo_risposta.strip():
                            messages.append({"role": "assistant", "content": testo_risposta})
                        messages.append({
                            "role": "user",
                            "content": "Devi eseguire il primo tool di analisi (es. search_http_l7_anomalies o get_traffic_summary) per iniziare l'esplorazione."
                        })
                        turno += 1
                        continue

                    tool_eseguiti = {t["tool_name"] for t in risultati_tool_raccolti}
                    ha_segnale_forte = any(engine._verifica_segnale_forte(t["result"]) for t in risultati_tool_raccolti)

                    # --- MODIFICA 2: SBLOCCO FLESSIBILE TOOL MANCANTI ---
                    if "compute_verdict_scores" in tool_eseguiti:
                        tool_mancanti = set()
                    elif ha_segnale_forte:
                        tool_mancanti = {"compute_verdict_scores"} - tool_eseguiti
                    else:
                        tool_mancanti = set(config.TOOL_OBBLIGATORI) - tool_eseguiti

                    if tool_mancanti:
                        mancanti_str = ", ".join(sorted(tool_mancanti))
                        log_print(f" -> [AVVISO ANTI-BYPASS TURNO {turno + 1}]: Chiusura bloccata. Tool obbligatori mancanti: {mancanti_str}")
                        
                        if testo_risposta.strip():
                            messages.append({"role": "assistant", "content": testo_risposta})
                            
                        if tool_mancanti == {"compute_verdict_scores"}:
                            msg_sollecito = (
                                "ATTENZIONE: Hai un segnale ad alta confidenza o hai completato l'esplorazione. "
                                "Devi ora TASSATIVAMENTE eseguire il tool 'compute_verdict_scores' "
                                "per calcolare il verdetto deterministico finale prima di concludere."
                            )
                        else:
                            msg_sollecito = (
                                "ATTENZIONE: Non puoi concludere l'analisi nè emettere un verdetto. "
                                f"Devi prima completare l'ispezione eseguendo i seguenti tool obbligatori mancanti: {mancanti_str}. "
                                "Esegui immediatamente le chiamate."
                            )

                        messages.append({"role": "user", "content": msg_sollecito})
                        turno += 1
                        continue

                    verdetto_estratto = engine.estrai_verdetto_pulito(testo_risposta)
                    is_tentativo_chiusura = (verdetto_estratto == "BENIGN") or (not tool_calls)

                    ultimo_msg_utente = messages[-1]["content"] if messages and messages[-1].get("role") == "user" else ""
                    gia_avvisato_anti_fn = "ATTENZIONE - BLOCCO ANTI-FALSO NEGATIVO" in ultimo_msg_utente

                    if is_tentativo_chiusura and not gia_avvisato_anti_fn and engine._verifica_incoerenza_benign(risultati_tool_raccolti):
                        anomalie_trovate = engine._ha_rilevato_anomalie_l7_reali(risultati_tool_raccolti)
                        if anomalie_trovate:
                            log_print(f" -> [AVVISO ANTI-FN TURNO {turno + 1}]: Chiusura bloccata per presenza di anomalie L7/C2 o DoS nei dati.")
                            if testo_risposta.strip():
                                messages.append({"role": "assistant", "content": testo_risposta})
                                
                            messages.append({
                                "role": "user",
                                "content": (
                                    "ATTENZIONE - BLOCCO ANTI-FALSO NEGATIVO:\n"
                                    "Stai tentando di concludere l'analisi senza rilevare minacce, ma i tool hanno evidenziato la presenza di flussi anomali.\n"
                                    "Valuta attentamente i dati estratti prima di confermare. Se vi e' un attacco DoS, Web o Brute Force, assegna il verdetto corretto."
                                )
                            })
                            turno += 1
                            continue

                    log_print(f" -> [INFO]: Nessun ulteriore tool invocato e requisiti soddisfatti. Passo alla FASE REPORT FINALE (Verdetto: {verdetto_estratto or 'DISPONIBILE'}).")
                    stato_investigazione = "REPORT_FINALE"
                    if testo_risposta.strip():
                        messages.append({"role": "assistant", "content": testo_risposta})
                    break

                # =========================================================================
                # ESCI DAL WHILE (FINE FASE 1 - MAX TURNI RAGGIUNTO)
                # =========================================================================
                if turno >= max_turns and stato_investigazione == "ESPLORAZIONE":
                    log_print("\n -> [AVVISO MAX TURNI]: Raggiunto il limite massimo di turni. Forzatura passaggio a FASE REPORT FINALE.")
                    stato_investigazione = "REPORT_FINALE"

                    sollecitazione_finale = (
                        "Hai raggiunto il limite massimo di turni di esplorazione. "
                        "Sulla base di tutti i dati estratti finora, fornisci la tua sintesi delle evidenze ed emetti il VERDETTO FINALE."
                    )
                    messages.append({"role": "user", "content": sollecitazione_finale})

                    # --- 1. PRUNING DEL CONTESTO (Evita il Timeout LLM) ---
                    max_recenti = (
                        config.Soglie.PRUNING_MAX_MESSAGES_GPT_OSS
                        if is_gpt_oss
                        else config.Soglie.PRUNING_MAX_MESSAGES_DEFAULT
                    )
                    messages_prunati_finali = engine.applica_pruning_contesto(
                        messages,
                        max_messaggi_recenti=max_recenti,
                        max_chars_tool=min(max_tool_chars, config.Soglie.PRUNING_TOOL_CHARS_CAP),
                    )

                    # --- 2. SANIFICAZIONE AVANZATA CRONOLOGIA ---
                    tool_ids_risposti = {
                        m.get("tool_call_id") for m in messages_prunati_finali if m.get("role") == "tool" and m.get("tool_call_id")
                    }

                    messages_sanitizzati_finali = []
                    for m in messages_prunati_finali:
                        m_copy = copy.deepcopy(m)
                        
                        if m_copy.get("content") is None:
                            m_copy["content"] = ""

                        if m_copy.get("role") == "assistant":
                            tool_calls = m_copy.get("tool_calls")
                            if tool_calls:
                                t_calls_valide = [tc for tc in tool_calls if tc.get("id") in tool_ids_risposti]
                                if t_calls_valide:
                                    m_copy["tool_calls"] = t_calls_valide
                                else:
                                    m_copy.pop("tool_calls", None)
                            else:
                                m_copy.pop("tool_calls", None)

                        if m_copy.get("role") == "tool" and not m_copy.get("tool_call_id"):
                            continue

                        messages_sanitizzati_finali.append(m_copy)

                    CatchableErrors = (Exception, BaseExceptionGroup) if sys.version_info >= (3, 11) else (Exception,)

                    try:
                        llm_params_finali = ottieni_params_llm("REPORT_FINALE", [])
                        llm_params_finali.pop("tools", None)
                        llm_params_finali.pop("tool_choice", None)

                        # Timeout elevato a 60s per prevenire fallimenti su prompt lunghi
                        response_finale = await asyncio.wait_for(
                            client.chat.completions.create(messages=messages_sanitizzati_finali, **llm_params_finali),
                            timeout=60.0
                        )
                        
                        messaggio_dict = elabora_risposta_llm(response_finale)
                        testo_risposta = messaggio_dict.get("content") or ""
                        
                        # --- PARSING E STAMPA DEL THOUGHT ---
                        if testo_risposta.strip():
                            thought_display = testo_risposta
                            try:
                                testo_pulito = re.sub(r"^```json\s*|\s*```$", "", testo_risposta.strip(), flags=re.MULTILINE)
                                thought_data = json.loads(testo_pulito)
                                if isinstance(thought_data, dict):
                                    thought_display = thought_data.get("motivazione") or thought_data.get("note_logiche") or thought_display
                            except Exception:
                                pass

                            log_print("\n┌── [LLM THOUGHT / RAGIONAMENTO REPORT FINALE] ──────────────────────────────┐")
                            log_print(f"│ {thought_display.replace(chr(10), chr(10) + '│ ')}")
                            log_print("└────────────────────────────────────────────────────────────────────────────┘\n")

                            messages.append({"role": "assistant", "content": testo_risposta})

                    except CatchableErrors as e_max:
                        log_print(f" -> [ERRORE CHIAMATA MAX TURNI]: Fallimento gestito ({type(e_max).__name__}): {e_max}")
                        verdetto_fallback = engine.estrai_verdetto_euristico_da_risultati(risultati_tool_raccolti)
                        messages.append({
                            "role": "assistant", 
                            "content": f"Sintesi generata in Fallback per Max Turni / Timeout API.\nVERDETTO STIMATO: {verdetto_fallback}"
                        })

    except Exception as e_mcp:
        sub_exceptions = getattr(e_mcp, "exceptions", [e_mcp])
        err_str = " | ".join([str(ex) for ex in sub_exceptions])
        log_print(f" -> [AVVISO MCP / TASKGROUP]: Connessione MCP chiusa o interrotta ({err_str})")

    # =========================================================================
    # FASE 2: GENERAZIONE REPORT FINALE (STAGE 2 - TOOL CALLING FORZATO)
    # =========================================================================
    log_print(f" -> [DEBUG TRANSITO]: Passaggio alla Fase 2 con stato={stato_investigazione}")

    # 1. Estrazione ultimo thought dell'assistant
    ultimo_thought = ""
    for m in reversed(messages):
        if m.get("role") == "assistant" and m.get("content"):
            ultimo_thought = m["content"]
            break

    if isinstance(ultimo_thought, list):
        thought_pulito = "\n".join([str(b.get("text", "")) for b in ultimo_thought if isinstance(b, dict)])
    else:
        thought_pulito = str(ultimo_thought).strip() if ultimo_thought else "Nessuna considerazione preliminare."

    # 2. Formattazione evidenze estratte dai tool
    if risultati_tool_raccolti:
        blocchi_tool = []
        for res in risultati_tool_raccolti:
            t_name = res.get("tool_name", "UNKNOWN")
            t_res = str(res.get("result", ""))[: config.Soglie.TRONCAMENTO_TOOL_RAW_MAX]
            blocchi_tool.append(f"--- [OUTPUT TOOL: {t_name}] ---\n{t_res}")
        evidenze_tool_str = "\n\n".join(blocchi_tool)
    else:
        evidenze_tool_str = "Nessun output registrato dai tool."

    report_content = None
    verdetto_finale = None

    # Solo se siamo in stato utile procediamo con l'elaborazione del report
    if stato_investigazione in ("REPORT_FINALE", "ESPLORAZIONE"):
        log_print("\n==================== FASE FINALE: GENERAZIONE REPORT STRUTTURATO (STAGE 2) ====================")

        # A. ESTRAZIONE E VALUTAZIONE VERDETTI
        verdetto_suggerito_tool, motivo_override = engine.estrai_suggerimento_tool(risultati_tool_raccolti)
        verdetto_thought = engine.estrai_verdetto_pulito(thought_pulito)

        log_print(f" -> [ANALISI PRELIMINARE LLM THOUGHT]: '{verdetto_thought}'")
        log_print(f" -> [SUGGERIMENTO EURISTICO TOOL]: '{verdetto_suggerito_tool}' (Motivo: {motivo_override})")

        # B. DETERMINAZIONE VERDETTO VINCOLANTE STAGE 1
        verdetto_vincolante_str = None
        motivo_scelta_cli = ""
        is_fallback_tool = False

        if verdetto_thought in prompts.VERDETTI_AMMESSI:
            verdetto_vincolante_str = verdetto_thought
            motivo_scelta_cli = f"Autonomia LLM: Confermato verdetto proposto dal Thought dell'analista: '{verdetto_vincolante_str}'."
            log_print(f" -> [VERDETTO AUTONOMO LLM]: {verdetto_vincolante_str}")

        elif verdetto_suggerito_tool in prompts.VERDETTI_AMMESSI:
            verdetto_vincolante_str = verdetto_suggerito_tool
            is_fallback_tool = True
            motivo_scelta_cli = f"Thought non esplicito. Applicato fallback dal calcolo Euristico Tool: '{verdetto_vincolante_str}'."
            log_print(f" -> [FALLBACK TOOL EURISTICO]: {verdetto_vincolante_str}")
        else:
            verdetto_vincolante_str = "BENIGN"
            is_fallback_tool = True
            motivo_scelta_cli = "Nessun verdetto identificato da LLM o Tool. Forzatura di sicurezza su BENIGN."
            log_print(" ⚠️ [SAFETY FALLBACK EXTREME]: Verdetto forzato su BENIGN.")

        log_print(f"\n [VERDETTO FINALE RICHIESTO NEL JSON STAGE 2]: {verdetto_vincolante_str}\n")

        # C. LOOP DI EMISSIONE REPORT LLM CON RETRY
        stato_investigazione = "INCOMPLETE"
        storico_retry_report: List[Dict[str, Any]] = []

        for tentativo_rep in range(1, config.Soglie.MAX_RETRY_REPORT + 1):
            istruzioni_focus = prompts.FOCUS_CATEGORIE_CONTENT.get(
                categoria_tag.lower(), "ANALISI GENERICA: nessun bias iniziale."
            )
            
            prompt_corrente = textwrap.dedent(f"""
                Analisi IP Target: {ip_target} (Finestra temporale: {start_time} - {end_time})

                AMBITO INVESTIGATIVO DI ORIGINE:
                {istruzioni_focus}

                VERDETTO STABILITO IN STAGE 1: '{verdetto_vincolante_str}'
                Origine verdetto: {motivo_scelta_cli}

                REGOLE TASSATIVE PER LA DETERMINAZIONE DEL JSON FINALE:
                1. Il verdetto di Stage 1 '{verdetto_vincolante_str}' ha valore PREVALENTE.
                2. REGOLA ANTI-DECLASSAMENTO: Se lo Stage 1 ha stabilito una categoria di attacco ('WEB_ATTACK_EXPLOIT', 'DOS_VOLUMETRIC', 'SCAN_BRUTEFORCE', 'BEACONING_C2'), è SEVERAMENTE VIETATO declassare il verdetto finale a 'BENIGN'.
                3. CORREZIONI TRA CATEGORIE MALEVOLE: Puoi correggere una categoria malevole con un'altra. In questo caso, la motivazione DEVE iniziare tassativamente con "CORREZIONE RISPETTO ALLO STAGE 1:".
                4. Se confermi il verdetto dello Stage 1, il campo "verdetto" DEVE essere esattamente "{verdetto_vincolante_str}".

                EVIDENZE OGGETTIVE ESTRATTE DAI TOOL:
                {evidenze_tool_str}

                THOUGHT DELL'ANALISTA (STAGE 1):
                {thought_pulito}

                ISTRUZIONI DI FORMATTAZIONE:
                - Rispondi ESCLUSIVAMENTE con un JSON valido: {{"verdetto": "<VERDETTO>", "motivazione": "<spiegazione>"}}
                - Valori ammessi per "verdetto": {list(prompts.VERDETTI_AMMESSI)}.
            """).strip()

            soglia_chars = (
                config.Soglie.REPORT_CONTEXT_MAX_CHARS_GPT_OSS
                if is_gpt_oss
                else config.Soglie.REPORT_CONTEXT_MAX_CHARS_DEFAULT
            )
            
            base_messages_puliti = [
                m for m in engine.sanitizza_storico_per_report(messages)
                if m.get("role") in ["system", "user", "assistant"] and "tool_calls" not in m
            ]

            messaggi_report_correnti = (
                [{"role": "system", "content": prompts.SYS_INSTRUCTION_REPORT_CONTENT}]
                + base_messages_puliti
                + [{"role": "user", "content": prompt_corrente}]
                + storico_retry_report
            )

            messaggi_report_correnti = engine.comprimi_messaggi_contesto(
                messaggi_report_correnti, max_chars=soglia_chars
            )

            try:
                response = await asyncio.wait_for(
                    client.chat.completions.create(
                        model=model_name,
                        messages=messaggi_report_correnti,
                        max_tokens=512 if is_gpt_oss else 2048,
                        temperature=0.0,
                    ),
                    timeout=120.0,
                )
            except asyncio.TimeoutError:
                log_print(f" -> [TIMEOUT LLM REPORT STAGE 2]: Tentativo {tentativo_rep} fallito per timeout.")
                continue
            except Exception as e_llm:
                log_print(f" -> [ERRORE LLM REPORT STAGE 2]: {type(e_llm).__name__}: {e_llm}")
                await asyncio.sleep(2)
                continue

            contenuto_raw = response.choices[0].message.content or ""

            # --- RILEVAMENTO FORMATO TOOL-CALL VIETATO IN STAGE 2 ---
            # Alcuni modelli (es. Qwen) ricadono su una sintassi di tool-calling
            # appresa in training anche quando tools/tool_choice sono disattivati.
            # Va rifiutato esplicitamente qui, PRIMA del parsing JSON: se lo
            # lasciassimo proseguire, il fallback di prossimità in
            # estrai_verdetto_pulito potrebbe "indovinare" un verdetto sbagliato
            # in modo silenzioso, mascherando il problema di formato.
            pattern_tag_vietati = re.compile(
                r"<\s*(tool_call|function|parameter)\b", re.IGNORECASE
            )
            if pattern_tag_vietati.search(contenuto_raw):
                log_print(
                    f" -> [REJECT STAGE 2 - FORMATO]: Tentativo {tentativo_rep} ha prodotto "
                    "sintassi tool-call (<tool_call>/<function>/<parameter>) invece di JSON puro. "
                    "Forzato retry pulito."
                )
                storico_retry_report = [
                    {"role": "assistant", "content": contenuto_raw},
                    {
                        "role": "user",
                        "content": (
                            "ERRORE DI FORMATO GRAVE: hai usato tag in stile tool-call "
                            "(<tool_call>, <function=...>, <parameter=...>) che sono VIETATI in "
                            "questa fase. Rispondi ESCLUSIVAMENTE con l'oggetto JSON puro nel formato: "
                            f'{{"verdetto": "<UNO_TRA_{list(prompts.VERDETTI_AMMESSI)}>", "motivazione": "<spiegazione>"}}. '
                            "Nessun tag XML, nessuna sintassi di function-calling."
                        ),
                    },
                ]
                continue

            # A questo punto il parsing JSON procede come prima
            try:
                json_match = re.search(r"\{[\s\S]*\}", contenuto_raw)
                if json_match:
                    data_report = json.loads(json_match.group(0).strip())
                    v_estratto = str(data_report.get("verdetto", "")).strip().upper()
                    mot_estratta = str(data_report.get("motivazione", "")).strip()

                    if v_estratto in prompts.VERDETTI_AMMESSI and mot_estratta:
                        
                        is_correzione = (v_estratto != verdetto_vincolante_str)
                        ha_prefisso_corretto = mot_estratta.startswith("CORREZIONE RISPETTO ALLO STAGE 1:")

                        # REGOLA 1: Blocco Declassamento a BENIGN
                        if verdetto_vincolante_str in ("WEB_ATTACK_EXPLOIT", "DOS_VOLUMETRIC", "SCAN_BRUTEFORCE", "BEACONING_C2") and v_estratto == "BENIGN":
                            log_print(f" -> [REJECT STAGE 2]: Bloccato tentativo di declassare a BENIGN da '{verdetto_vincolante_str}'.")
                            storico_retry_report = [
                                {"role": "assistant", "content": contenuto_raw},
                                {
                                    "role": "user",
                                    "content": f"DIVIETO TASSATIVO: Il verdetto dello Stage 1 è '{verdetto_vincolante_str}'. Non declassare a 'BENIGN'."
                                }
                            ]
                            continue

                        # REGOLA 2: Se lo Stage 1 era un Fallback automatico del tool, applica il prefisso automaticamente
                        if is_correzione and not ha_prefisso_corretto and is_fallback_tool:
                            mot_estratta = f"CORREZIONE RISPETTO ALLO STAGE 1: {mot_estratta}"
                            ha_prefisso_corretto = True

                        # REGOLA 3: Se c'è una correzione autonoma dell'LLM senza il prefisso, richiedi il retry
                        if is_correzione and not ha_prefisso_corretto:
                            log_print(f" -> [REJECT STAGE 2]: Modifica verdetto da '{verdetto_vincolante_str}' a '{v_estratto}' senza prefisso obbligatorio.")
                            storico_retry_report = [
                                {"role": "assistant", "content": contenuto_raw},
                                {
                                    "role": "user",
                                    "content": (
                                        f"ERRORE DI VALIDAZIONE: Stai cambiando il verdetto da '{verdetto_vincolante_str}' a '{v_estratto}'. "
                                        f"La motivazione DEVE iniziare tassativamente con: 'CORREZIONE RISPETTO ALLO STAGE 1:'"
                                    )
                                }
                            ]
                            continue

                        # ESITO POSITIVO
                        if is_correzione:
                            log_print(f" ⚠️ [OVERRIDE STAGE 2 CONFERMATO]: Rettifica da '{verdetto_vincolante_str}' a '{v_estratto}'.")
                        else:
                            log_print(f" -> [STAGE 2]: Verdetto confermato in linea con Stage 1 ({v_estratto}).")

                        verdetto_finale = v_estratto
                        report_content = json.dumps({
                            "verdetto": verdetto_finale,
                            "motivazione": mot_estratta,
                            "ip_target": ip_target,
                            "verdetto_stage_1": verdetto_vincolante_str,
                            "is_corretto_in_stage_2": is_correzione,
                            "verdetto_suggerito_tool": verdetto_suggerito_tool
                        }, indent=2, ensure_ascii=False)
                        
                        stato_investigazione = "COMPLETED"
                        break
                    else:
                        log_print(f" -> [JSON INVALIDO STAGE 2]: Verdetto '{v_estratto}' non valido o motivazione vuota.")
            except Exception as e_json:
                log_print(f" -> [JSON ERROR STAGE 2]: {e_json}")

            # Fallback del retry se il parsing o la struttura fallisce
            storico_retry_report = [
                {"role": "assistant", "content": contenuto_raw},
                {
                    "role": "user",
                    "content": f"ERRORE DI FORMATO: Rispondi ESCLUSIVAMENTE con un JSON valido nel formato: {{\"verdetto\": \"<UNO_TRA_{list(prompts.VERDETTI_AMMESSI)}>\", \"motivazione\": \"<spiegazione>\"}}"
                }
            ]

    # =========================================================================
    # USCITA UNICA DALLA FUNZIONE
    # =========================================================================
    return {
        "stato": stato_investigazione,
        "verdetto": verdetto_finale or verdetto_vincolante_str,
        "is_fallback": stato_investigazione != "COMPLETED",
        "report": report_content,
        "metriche": metriche_tempo,
        "log_dettagliato": "\n".join(log_lines),
    }

# ==============================================================================
# MENU INTERATTIVO E FLUSSO PRINCIPALE
# ==============================================================================

async def main():
    # Inizializzazioni preventive dei dati di output
    report_md = "Analisi Interrotta o Non Completata\n"
    log_txt = "L'esecuzione è stata interrotta prima del completamento.\n"
    telemetria_txt = {"stato": "interrotto", "timestamp": datetime.now().isoformat()}

    # Inizializzazione preventiva per evitare UnboundLocalError in caso di Ctrl+C durante i menu
    cat_tag = "non_definita"
    ip_target = "0.0.0.0"
    dt_start, dt_end = None, None
    analisi_avviata = False
    cartella_sessione = None
    llm_client = None

    try:
        load_dotenv()

        mcp_server_params = StdioServerParameters(
            command=sys.executable,
            args=["server.py"],
            env=os.environ.copy()
        )

        api_key, base_url, model_name, max_tool_chars = utils.seleziona_modello_engine()

        llm_client = AsyncOpenAI(
            api_key=api_key,
            base_url=base_url
        )

        print(f"\nModello scelto: {model_name} (Endpoint: {base_url})\n")

        mappa_cat = {
            "1": ("cat_a", "Analisi Strutturale Applicativa"),
            "2": ("cat_b", "Monitoraggio Volumetrico DoS"),
            "3": ("cat_c", "Investigazione Endpoint L7 e TLS"),
            "4": ("cat_d", "Analisi Comportamentale e Beaconing"),
            "5": ("cat_e", "Analisi Forense Generica Senza Vincoli"),
        }

        while True:
            print("============================================================")
            print("Seleziona la categoria analitica da sottoporre all'LLM:")
            print("1) [CATEGORIA A] - Analisi Strutturale e Applicativa L7 (Exploit Web & Applicativi)")
            print("2) [CATEGORIA B] - Monitoraggio Volumetrico (Anomalie di Rate, Banda e DoS)")
            print("3) [CATEGORIA C] - Profiling Endpoint (Scanning, Brute Force e Slow-Rate DoS/TLS)")
            print("4) [CATEGORIA D] - Analisi Comportamentale (Beaconing C2, Botnet e DNS Tunneling)")
            print("5) [GENERICA]    - Analisi Forense Libera (Nessun vincolo di categoria)")
            print("6) Esci")
            print("============================================================")

            scelta_cat = input("\nScegli un'opzione (1-6): ").strip()

            if scelta_cat == "6":
                print("\nUscita dal programma.")
                return

            if scelta_cat in mappa_cat:
                cat_tag, cat_nome = mappa_cat[scelta_cat]
                break
            
            print(f"\n[ERRORE]: '{scelta_cat}' non è un'opzione valida! Inserisci un numero da 1 a 6.\n")

        print(f"\nCONFIGURAZIONE PARAMETRI PER SCENARIO {scelta_cat} ({cat_nome})")

        while True:
            ip_target = input("Inserisci l'IP target da analizzare: ").strip()
            if utils.valida_indirizzo_ip(ip_target):
                break
            print("[ERRORE]: Indirizzo IP non valido. Inserire un IPv4 o IPv6 corretto (es. 192.168.10.9).")

        dt_start, dt_end = None, None
        while True:
            while True:
                start_time_raw = input("Inserisci START TIME (es. YYYY-MM-DD HH:MM:SS): ").strip()
                dt_start = utils.valida_formato_timestamp(start_time_raw)
                if dt_start:
                    break
                print("[ERRORE]: Formato Data/Ora di inizio non valido. Riprova.")

            while True:
                end_time_raw = input("Inserisci END TIME (es. YYYY-MM-DD HH:MM:SS): ").strip()
                dt_end = utils.valida_formato_timestamp(end_time_raw)
                if dt_end:
                    break
                print("[ERRORE]: Formato Data/Ora di fine non valido. Riprova.")

            if dt_start >= dt_end:
                print("\n[ERRORE]: START TIME deve essere strettamente precedente a END TIME! Riprova la configurazione.\n")
                continue

            break

        start_time_iso = dt_start.strftime("%Y-%m-%d %H:%M:%S").replace(" ", "T")
        end_time_iso = dt_end.strftime("%Y-%m-%d %H:%M:%S").replace(" ", "T")

        # 1. CREAZIONE CARTELLA DI SESSIONE CON TIMESTAMP UNIVOCO
        ts_sessione = datetime.now().strftime("%Y%m%d_%H%M%S")
        cartella_sessione = Path("outputs") / f"SESSION_{ts_sessione}"
        cartella_sessione.mkdir(parents=True, exist_ok=True)

        analisi_avviata = True

        try:
            report_md, log_txt, telemetria_txt = await esegui_analisi_mcp(
                client=llm_client,
                mcp_server_params=mcp_server_params,
                ip_target=ip_target,
                start_time=start_time_iso,
                end_time=end_time_iso,
                model_name=model_name,
                categoria_tag=cat_tag,
                max_tool_chars=max_tool_chars,
                sleep_time=1.0,
            )
        except (asyncio.CancelledError, KeyboardInterrupt):
            print("\n[AVVISO]: Analisi annullata dall'utente tramite CTRL+C.")
            if isinstance(telemetria_txt, dict):
                telemetria_txt["stato"] = "annullato_da_utente"
        except Exception as e:
            print(f"\n[ERRORE DURANTE L'ESECUZIONE]: {e[:config.Soglie.BEACON_DOS_VOLUME_THRESHOLD]}")
            if isinstance(telemetria_txt, dict):
                telemetria_txt["stato"] = "errore"
                telemetria_txt["dettaglio_errore"] = str(e)
            
    except KeyboardInterrupt:
        print("\nInterruzione manuale da tastiera (Ctrl+C).")
    except Exception as e:
        err_msg = str(e)[: config.Soglie.MAX_ERR_LOG_CHARS]
        print(f"\n[ERRORE - {type(e).__name__}]: {err_msg}")
        print("\n=== TRACEBACK COMPLETO ===")
        traceback.print_exc()
        print("===========================\n")
    finally:
        if analisi_avviata and dt_start and dt_end and cartella_sessione:
            print("\n[SALVATAGGIO]: Salvataggio dei dati raccolti su disco in corso...\n")
            path_rep, path_log = utils.salva_risultati_su_disco(
                ip_target=ip_target,
                categoria=cat_tag,
                report_md=report_md,
                log_txt=log_txt,
                telemetria_txt=telemetria_txt,
                start_time=dt_start,
                end_time=dt_end,
                cartella_sessione=cartella_sessione  
            )

            print("============================================================")
            print("SALVATAGGIO FILE COMPLETATO CON SUCCESSO:")
            print(f"Report Forense (.md): {path_rep}")
            print(f"Log Investigativo (.txt): {path_log}")
            print("============================================================\n")

        if telemetria_txt and analisi_avviata:
            print("Report Telemetria:")
            if isinstance(telemetria_txt, dict):
                print(json.dumps(telemetria_txt, indent=2, ensure_ascii=False))
            else:
                print(telemetria_txt)
        if llm_client:
            try:
                await asyncio.shield(llm_client.close())
            except Exception:
                pass

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        print("\n\nProgramma terminato dall'utente.")
        sys.exit(0)
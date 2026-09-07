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
import engine

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

    # -------------------------------------------------------------------------
    # 3. ARCHITETTURA DEI PROMPT: SYSTEM VS USER (Inizializzazione Turno 1)
    # -------------------------------------------------------------------------
    
    # Recupera il blocco specifico per la categoria
    istruzioni_focus = config.FOCUS_CATEGORIE.get(
        categoria_tag.lower(), 
        "ANALISI GENERICA: Esplora i dati liberamente e determina la natura del traffico."
    )

    user_prompt_iniziale = {
        "role": "user",
        "content": (
            f"CONTESTO INDAGINE\n"
            f"- IP Target: {ip_target}\n"
            f"- Finestra Temporale: {start_time} - {end_time}\n\n"
            f"PIANO D'AZIONE SUGGERITO PER QUESTO SET DI DATI\n"
            f"{istruzioni_focus}\n\n"
            f"ISTRUZIONI DI METODO ANALITICO\n"
            f"1. Esplorazione Obbligatoria: Ispeziona in sequenza: (a) Sintesi e Volumi -> (b) Distribuzione Porte e Tentativi di Connessione -> (c) Ispezione L7 / HTTP se presenti porte 80/443 -> (d) Verifiche su Beaconing / Periodicita'.\n"
            f"2. Gestione Campione Ridotto / PortScan: Se 'get_host_port_distribution' o 'get_rate_statistics' indicano pochi flussi, NON presupporre immediatamente BENIGN. Esegui SEMPRE 'search_connection_attempts' (senza filtrare per singola porta, o verificando i SYN/connessioni fallite) per verificare se vi sono tentativi di PortScan stealth o intermittenti.\n"
            f"3. Obbligo Ispezione L7: Se rilevi traffico verso porte 80, 443 o 8080, richiama 'search_http_l7_anomalies' prima di concludere l'analisi.\n"
            f"4. Divieto di Chiusura Prematura: DEVI eseguire TUTTI i tool obbligatori prima di emettere il verdetto: {config.tool_obbligatori_str}.\n\n"
            f"Inizia l'ispezione richiamando il primo tool idoneo."
        ).strip(),
    }

    messages = [config.system_prompt, user_prompt_iniziale]

    # -------------------------------------------------------------------------
    # 4. INIZIALIZZAZIONE STATO ED ESECUZIONE LOOP INDAGINE
    # -------------------------------------------------------------------------
    turno = 0
    stato_investigazione = "ESPLORAZIONE"
    risultati_tool_raccolti: List[Dict[str, Any]] = []
    storico_chiamate_hash = set()
    report_content: Optional[str] = None

    log_print(f"=== INIZIO INDAGINE MCP PER TARGET: {ip_target} ===")

    # =========================================================================
    # FASE 1: ESPLORAZIONE MCP
    # =========================================================================

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
                            log_print(f" -> [CALL LLM]: Invio in corso (Tentativo {tentativi_llm + 1}/2)...")
                            response = await asyncio.wait_for(
                                client.chat.completions.create(messages=messages_prunati, **llm_params),
                                timeout=50.0
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
                            break

                    if response is None:
                        log_print("\n[ABORT SCENARIO]: Il server LLM non risponde per lo scenario attuale. Salto lo scenario.\n")
                        stato_investigazione = "ABORTED"
                        break

                    messaggio_dict = elabora_risposta_llm(response)
                    log_only("[RISPOSTA RICEVUTA DALL'LLM]:\n" + json.dumps(messaggio_dict, indent=2, ensure_ascii=False) + "\n\n")

                    # Limitazione a singola Tool Call
                    if messaggio_dict.get("tool_calls") and len(messaggio_dict["tool_calls"]) > 1:
                        log_print(f" -> [AVVISO]: Rilevate {len(messaggio_dict['tool_calls'])} chiamate tool. Mantengo solo la prima.")
                        messaggio_dict["tool_calls"] = [messaggio_dict["tool_calls"][0]]

                    tool_calls = messaggio_dict.get("tool_calls")
                    testo_risposta = messaggio_dict.get("content") or ""

                    if testo_risposta.strip():
                        log_print(f" -> [LLM Thought]: {testo_risposta}")

                    # =========================================================================
                    # RAMO A: L'LLM HA GENERATO UNA TOOL CALL
                    # =========================================================================
                    if tool_calls:
                        tc = tool_calls[0]
                        nome_funzione = tc.get("function", {}).get("name")
                        raw_args = tc.get("function", {}).get("arguments", {})

                        try:
                            argomenti = json.loads(raw_args) if isinstance(raw_args, str) else (raw_args or {})
                        except json.JSONDecodeError:
                            argomenti = {}

                        argomenti = engine._applica_auto_paginazione(nome_funzione, argomenti, storico_chiamate_hash)

                        chiamata_hash, argomenti_puliti, _ = engine.gestisci_e_calcola_hash_tool(
                            nome_funzione=nome_funzione,
                            argomenti=argomenti,
                            chiamate_effettuate=storico_chiamate_hash
                        )

                        # Controllo Duplicati
                        if chiamata_hash in storico_chiamate_hash:
                            offset_val = argomenti_puliti.get("offset", 0)
                            limit_val = argomenti_puliti.get("limit", 50)
                            offset_suggerito = int(offset_val) + int(limit_val)

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

                        tc["function"]["arguments"] = json.dumps(argomenti_puliti)
                        messages.append({"role": "assistant", "content": testo_risposta, "tool_calls": [tc]})

                        # Esecuzione Tool MCP
                        tool_id = tc.get("id")
                        t_mcp_start = time.perf_counter()
                        scansione_completa = False

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
                                config.tool_chiamati.add(nome_funzione)  # Aggiornamento tracciamento tool unici usati
                                
                            else:
                                log_print(f" -> [AUTO-PAGINATORE]: Errore nell'esecuzione di {nome_funzione}. Offset non registrato.")

                            if is_gpt_oss:
                                testo_risultato = engine.sanifica_risultato_tool(testo_risultato)

                            testo_risultato = engine._arricchisci_risultato_tool(testo_risultato, nome_funzione)
                            risultati_tool_raccolti.append({"tool_name": nome_funzione, "result": testo_risultato})
                            metriche_tempo["tempo_sql_reale_sec"] += estrai_tempo_sql(mcp_result, testo_risultato)

                            # Check Scansione Completata
                            try:
                                res_payload = json.loads(testo_risultato)
                                if isinstance(res_payload, dict):
                                    totale_finestra = res_payload.get("totale_flussi_nella_finestra") or 0
                                    off_curr = res_payload.get("pagina_offset_attuale") or 0
                                    estratte_pagina = res_payload.get("totale_anomalie_estratte_in_questa_pagina") or res_payload.get("totale_richieste_ispezionate") or 0
                                    limit_usato = argomenti_puliti.get("limit", 50)

                                    if totale_finestra > 0 and (off_curr + limit_usato >= totale_finestra or (off_curr > 0 and estratte_pagina == 0)):
                                        log_print(f" -> [CHECK ARRESTO]: Scansione di {nome_funzione} completata ({off_curr + estratte_pagina}/{totale_finestra}).")
                                        scansione_completa = True
                            except Exception:
                                pass

                            testo_risultato_sicuro = utils.tronca_json_sicuro(
                                testo_risultato, max_chars=config.Soglie.TRONCAMENTO_TOOL_RAW_MAX
                            )
                            
                            # Intercettazione Errori/Warning Tool
                            if any(err in testo_risultato.lower() for err in ["errore", "[errore tool]", "errore_sql", "exception", "failed", 'status": "error']):
                                log_print(f" -> [AVVISO FALLBACK]: Rilevato errore/warning in '{nome_funzione}'. Notifico l'LLM per continuare.")
                                testo_risultato_sicuro += (
                                    f"\n\n[AVVISO SISTEMA]: Il tool '{nome_funzione}' ha riscontrato un errore o una limitazione.\n"
                                    f"NON RIPROVARE ad eseguire '{nome_funzione}' con gli stessi parametri.\n"
                                    "IGNORA questo canale e PROSEGUI L'INDAGINE utilizzando altri tool diagnostici a disposizione."
                                )

                            if scansione_completa:
                                testo_risultato_sicuro += (
                                    "\n\n[SISTEMA - SCANSIONE COMPLETATA]: Tutti i flussi della finestra temporale sono stati estratti. "
                                    "Procedi a valutare le evidenze ed emettere il VERDETTO FINALE."
                                )

                            preview_res = testo_risultato[:180].replace("\n", " ")
                            log_print(f" -> [TOOL RESULT]: {preview_res}..." if len(testo_risultato) > 180 else f" -> [TOOL RESULT]: {preview_res}")
                            log_only(f"[RISULTATO TOOL INTEGRALE]:\n{testo_risultato}\n\n")

                            messages.append({
                                "role": "tool",
                                "tool_call_id": tool_id,
                                "name": nome_funzione,
                                "content": f"[FOCUS ATTIVO: {categoria_tag}]\n{testo_risultato_sicuro}"
                            })
                            turno += 1
                            continue

                        except (KeyboardInterrupt, asyncio.CancelledError):
                            log_print("\n[INTERRUZIONE] Interruzione durante l'esecuzione del Tool MCP.")
                            raise
                        except Exception as e_tool:
                            err_tool_msg = str(e_tool)[: config.Soglie.MAX_ERR_LOG_CHARS]
                            log_print(f" -> [ERRORE TOOL MCP]: {err_tool_msg}")
                            messages.append(
                                {
                                    "role": "tool",
                                    "tool_call_id": tool_id,
                                    "name": nome_funzione,
                                    "content": (
                                        f"ERRORE ESECUZIONE TOOL: {err_tool_msg}.\n"
                                        "Prova ad usare un tool alternativo."
                                    ),
                                }
                            )
                            turno += 1
                            continue

                    # =========================================================================
                    # RAMO B: L'LLM NON HA GENERATO TOOL CALL (TENTA DI CONCLUDERE)
                    # =========================================================================
                    
                    # Check Turno 1 senza tool invocati
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

                    # Nel Ramo B (L'LLM non ha generato Tool Call e vuole chiudere)
                    tool_eseguiti = {t["tool_name"] for t in risultati_tool_raccolti}
                    tool_mancanti = set(config.TOOL_OBBLIGATORI) - tool_eseguiti

                    if tool_mancanti:
                        mancanti_str = ", ".join(sorted(tool_mancanti))
                        log_print(f" -> [AVVISO ANTI-BYPASS TURNO {turno + 1}]: Chiusura bloccata. Tool obbligatori mancanti: {mancanti_str}")
                        
                        if testo_risposta.strip():
                            messages.append({"role": "assistant", "content": testo_risposta})
                            
                        # Se l'unico tool mancante è compute_verdict_scores, dia un ordine perentorio
                        if tool_mancanti == {"compute_verdict_scores"}:
                            msg_sollecito = (
                                "ATTENZIONE: Hai completato l'esplorazione dei dati. "
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

                    # Check Verdetto Falso Negativo (Anti-FN) su BENIGN
                    # --- CORREZIONE RAMO B: Anti-FN più tollerante ---
                    verdetto_estratto = utils.estrai_verdetto_pulito(testo_risposta)
                    if verdetto_estratto == "BENIGN" and engine._verifica_incoerenza_benign(risultati_tool_raccolti):
                        
                        # Verifica se sono state trovate REALI anomalie L7 o se e' solo alto volume
                        anomalie_trovate = engine._ha_rilevato_anomalie_l7_reali(risultati_tool_raccolti)
                        
                        if anomalie_trovate:
                            log_print(f" -> [AVVISO ANTI-FN TURNO {turno + 1}]: Verdetto BENIGN contestato per presenza di anomalie L7/C2.")
                            if testo_risposta.strip():
                                messages.append({"role": "assistant", "content": testo_risposta})
                                
                            messages.append({
                                "role": "user",
                                "content": (
                                    "VERIFICA RICHIESTA: Hai classificato il traffico come BENIGN, ma nei log sono state estratte anomalie applicative o di beaconing.\n"
                                    "Se le anomalie L7/C2 rappresentano un attacco confermato, valuta WEB_ATTACK_EXPLOIT o BEACONING_C2.\n"
                                    "Se invece il traffico anomalo e' trascurabile o rumore di fondo rispetto alla navigazione lecita, puoi CONFERMARE BENIGN motivandolo nel report."
                                )
                            })
                            turno += 1
                            continue

                    # Chiusura Regolare: Tutti i controlli superati
                    log_print(f" -> [INFO]: Nessun ulteriore tool invocato e requisiti soddisfatti. Passo alla FASE REPORT FINALE (Verdetto: {verdetto_estratto or 'DISPONIBILE'}).")
                    stato_investigazione = "REPORT_FINALE"
                    if testo_risposta.strip():
                        messages.append({"role": "assistant", "content": testo_risposta})
                    break

                # Fallback se si raggiunge il numero massimo di turni senza concludere
                if turno >= max_turns and stato_investigazione == "ESPLORAZIONE":
                    log_print(" -> [AVVISO MAX TURNI]: Raggiunto il limite massimo di turni. Forzo il passaggio alla fase finale.")
                    stato_investigazione = "REPORT_FINALE"

    except Exception as e_mcp:
        sub_exceptions = getattr(e_mcp, "exceptions", [e_mcp])
        err_str = " | ".join([str(ex) for ex in sub_exceptions])
        log_print(
            f" -> [AVVISO MCP / TASKGROUP]: Connessione MCP chiusa o interrotta ({err_str})"
        )

    # =========================================================================
    # FASE 2: GENERAZIONE REPORT FINALE (STAGE 2 - TOOL CALLING FORZATO)
    # =========================================================================
    log_print(
        f" -> [DEBUG TRANSITO]: Passaggio alla Fase 2 con stato={stato_investigazione}"
    )

    # Estrazione ultimo thought dell'assistant
    ultimo_thought = ""
    for m in reversed(messages):
        if m.get("role") == "assistant" and m.get("content"):
            ultimo_thought = m["content"]
            break

    thought_pulito = (
        ultimo_thought.strip()
        if ultimo_thought
        else "Nessuna considerazione preliminare."
    )

    # Formattazione evidenze estratte dai tool
    if risultati_tool_raccolti:
        blocchi_tool = []
        for res in risultati_tool_raccolti:
            t_name = res.get("tool_name", "UNKNOWN")
            t_res = str(res.get("result", ""))[
                : config.Soglie.TRONCAMENTO_TOOL_RAW_MAX
            ]
            blocchi_tool.append(f"--- [OUTPUT TOOL: {t_name}] ---\n{t_res}")
        evidenze_tool_str = "\n\n".join(blocchi_tool)
    else:
        evidenze_tool_str = "Nessun output registrato dai tool."

    report_content = ""
    verdetto_finale = None
    storico_retry_report: List[Dict[str, Any]] = []

    if stato_investigazione in ("REPORT_FINALE", "ESPLORAZIONE") and not report_content:
        log_print(
            "\n==================== FASE FINALE: GENERAZIONE REPORT STRUTTURATO (STAGE 2) ===================="
        )

        # =========================================================================
        # FIX ARCHITETTURALE: Estrazione preventiva a cascata del Verdetto Vincolante
        # =========================================================================
        verdetto_vincolante_str = None

        # 1. TENTATIVO: Parsing JSON dal tool compute_verdict_scores
        try:
            for res in risultati_tool_raccolti:
                if (
                    isinstance(res, dict)
                    and res.get("tool_name") == "compute_verdict_scores"
                ):
                    raw_out = res.get("result") or res.get("output") or "{}"
                    data_out = (
                        json.loads(raw_out) if isinstance(raw_out, str) else raw_out
                    )
                    # FIX: Cerca sia 'verdetto_suggerito' sia 'candidato_predominante'
                    verdetto_vincolante_str = data_out.get(
                        "verdetto_suggerito"
                    ) or data_out.get("candidato_predominante")
                    if verdetto_vincolante_str:
                        break
        except Exception as e_ext:
            log_print(
                f" -> [AVVISO STAGE 2]: Errore estrazione verdetto da tool: {e_ext}"
            )

        # 2. TENTATIVO (FALLBACK): Estrazione dal JSON di 'LLM Thought' (Fase 1)
        if not verdetto_vincolante_str or verdetto_vincolante_str == "INDETERMINATO":
            try:
                if ultimo_thought.startswith("{") and ultimo_thought.endswith("}"):
                    thought_json = json.loads(ultimo_thought)
                    verdetto_vincolante_str = thought_json.get("verdetto")
            except Exception:
                pass

        # 3. SAFETY NET: Se fallisce tutto o non è un valore enum valido, default su BENIGN
        valori_ammessi = [
            "DOS_VOLUMETRIC",
            "SCAN_BRUTEFORCE",
            "BEACONING_C2",
            "WEB_ATTACK_EXPLOIT",
            "BENIGN",
        ]
        if (
            not verdetto_vincolante_str
            or verdetto_vincolante_str not in valori_ammessi
        ):
            log_print(
                f" ⚠️ [AVVISO STAGE 2]: Verdetto non valido o 'INDETERMINATO' ('{verdetto_vincolante_str}'). Forzatura su BENIGN."
            )
            verdetto_vincolante_str = "BENIGN"

        log_print(
            f" -> [VERDETTO VINCOLANTE STAGE 2 IDENTIFICATO]: {verdetto_vincolante_str}"
        )

        base_messages_puliti = [
            m
            for m in engine.sanitizza_storico_per_report(messages)
            if m.get("role") in ["system", "user", "assistant"]
            and "tool_calls" not in m
        ]

        stato_investigazione = "INCOMPLETE"

        # --- LOOP DI GENERAZIONE CON TOOL CALLING FORZATO ---
        for tentativo_rep in range(1, config.Soglie.MAX_RETRY_REPORT + 1):
            prompt_corrente = textwrap.dedent(f"""
                Analisi IP Target: {ip_target} (Finestra temporale: {start_time} - {end_time})

                AMBITO INVESTIGATIVO DI ORIGINE:
                {istruzioni_focus}

                VERDETTO VINCOLANTE RIGIDO: {verdetto_vincolante_str}

                EVIDENZE OGGETTIVE ESTRATTE DAI TOOL:
                {evidenze_tool_str}

                CONSIDERAZIONI PRELIMINARI DELL'ANALISTA:
                {thought_pulito}

                ISTRUZIONI DI EMISSIONE:
                1. Rispondi ESCLUSIVAMENTE con un oggetto JSON valido con le chiavi "verdetto" e "motivazione".
                2. Il campo "verdetto" DEVE essere esattamente la stringa '{verdetto_vincolante_str}'. NON usare mai 'INDETERMINATO'.
                3. Il campo "motivazione" è OBBLIGATORIO: fornisci 1-2 frasi basate sui dati dei log (n° flussi, porte, PPS/payload) coerenti con il verdetto '{verdetto_vincolante_str}'.
            """).strip()

            messaggi_report_correnti = (
                [{"role": "system", "content": config.sys_instruction_report}]
                + base_messages_puliti
                + [{"role": "user", "content": prompt_corrente}]
                + storico_retry_report
            )

            soglia_chars = (
                config.Soglie.REPORT_CONTEXT_MAX_CHARS_GPT_OSS
                if is_gpt_oss
                else config.Soglie.REPORT_CONTEXT_MAX_CHARS_DEFAULT
            )
            messaggi_report_correnti = engine.comprimi_messaggi_contesto(
                messaggi_report_correnti, max_chars=soglia_chars
            )

            log_print(
                f" -> Generazione Report Strutturato Stage 2 (Tentativo {tentativo_rep}/{config.Soglie.MAX_RETRY_REPORT})..."
            )
            t_llm_start = time.perf_counter()

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
                log_print(
                    f" -> [TIMEOUT LLM REPORT STAGE 2]: Superati 120s al tentativo {tentativo_rep}."
                )
                storico_retry_report.append(
                    {
                        "role": "user",
                        "content": "TIMEOUT: La risposta ha impiegato troppo tempo. Genera subito il JSON del report.",
                    }
                )
                continue
            except Exception as e_report:
                log_print(
                    f" -> [ERRORE GENERAZIONE REPORT STAGE 2]: {str(e_report)}"
                )
                if is_gpt_oss:
                    await asyncio.sleep(2.0)
                continue
            finally:
                metriche_tempo["tempo_llm_sec"] += (
                    time.perf_counter() - t_llm_start
                )

            messaggio_obj = (
                elabora_risposta_llm(response)
                if hasattr(engine, "elabora_risposta_llm")
                else response.choices[0].message
            )

            raw_content = (
                messaggio_obj.get("content", "")
                if isinstance(messaggio_obj, dict)
                else getattr(messaggio_obj, "content", "")
            )

            if not raw_content:
                log_print(
                    f" -> [AVVISO STAGE 2]: Contenuto vuoto dal modello al tentativo {tentativo_rep}."
                )
                storico_retry_report.append(
                    {
                        "role": "user",
                        "content": "ERRORE: La risposta è vuota. Genera il JSON del report.",
                    }
                )
                continue

            cleaned_json_str = raw_content.strip()
            if cleaned_json_str.startswith("```"):
                lines = cleaned_json_str.splitlines()
                if lines[0].startswith("```"):
                    lines = lines[1:]
                if lines and lines[-1].startswith("```"):
                    lines = lines[:-1]
                cleaned_json_str = "\n".join(lines).strip()

            # Validazione Pydantic
            try:
                args_dict = json.loads(cleaned_json_str)

                # Sanity Overwrite: assicura che il verdetto sia conforme prima del parsing Pydantic
                if args_dict.get("verdetto") not in valori_ammessi:
                    args_dict["verdetto"] = verdetto_vincolante_str

                report_obj = config.ReportForense(**args_dict)
            except Exception as e_val:
                log_print(
                    f" -> [ERRORE VALIDAZIONE PYDANTIC] Tentativo {tentativo_rep}: {e_val}"
                )
                storico_retry_report.append(
                    {
                        "role": "user",
                        "content": (
                            f"Errore di schema JSON: {e_val}. "
                            f"Ricorda che 'verdetto' deve essere esattamente '{verdetto_vincolante_str}' "
                            f"e 'motivazione' è un campo testo obbligatorio."
                        ),
                    }
                )
                continue

            # Validation Gate: Controllo Anti-Allucinazione Porte
            testo_per_verifica = f"MOTIVAZIONE: {report_obj.motivazione}\nVERDETTO: {report_obj.verdetto}"

            porte_realmente_presenti = utils.estrai_porte_realmente_presenti(
                risultati_tool_raccolti=risultati_tool_raccolti,
                engine=engine,
                ip_target=ip_target,
            )

            is_valido, motivo_errore = engine.verifica_allucinazioni_porte(
                testo_per_verifica, porte_realmente_presenti
            )

            if not is_valido:
                log_print(
                    f" ⚠️ [VALIDATION GATE FAILED - STAGE 2]: {motivo_errore} al tentativo {tentativo_rep}."
                )
                notifica_allucinazione = (
                    f"ATTENZIONE: La motivazione menziona porte/protocolli non presenti nei log ({motivo_errore}).\n"
                    "Genera nuovamente il JSON del report basandoti unicamente ed esclusivamente sulle porte reali."
                )
                storico_retry_report.append(
                    {"role": "user", "content": notifica_allucinazione}
                )
                if len(storico_retry_report) > 4:
                    storico_retry_report = storico_retry_report[-2:]
                continue

            # Conferma e completamento
            verdetto_finale = report_obj.verdetto
            report_content = (
                f"MOTIVAZIONE: {report_obj.motivazione}\nVERDETTO: {report_obj.verdetto}"
            )
            stato_investigazione = "COMPLETATO"

            log_print(
                f" -> [REPORT STAGE 2 EMESSO CON SUCCESSO]: Verdetto = {verdetto_finale}"
            )
            break

    # Fallback di sicurezza: evita 'INDETERMINATO' anche in caso di fallimento del loop
    if not report_content:
        verdetto_fallback = (
            verdetto_vincolante_str
            if "verdetto_vincolante_str" in locals()
            and verdetto_vincolante_str in valori_ammessi
            else "BENIGN"
        )
        verdetto_finale = verdetto_fallback
        report_content = (
            f"MOTIVAZIONE: Attività di rete analizzata nella finestra temporale indicata. "
            f"Verdetto assegnato sulla base dei dati disponibili.\nVERDETTO: {verdetto_fallback}"
        )
        stato_investigazione = "COMPLETATO_FALLBACK"

    # =========================================================================
    # CONCLUSIONE E SALVATAGGIO LOGS
    # =========================================================================
    metriche_tempo["tempo_totale_esecuzione"] = (
        time.perf_counter() - tempo_inizio_assoluto
    )

    log_print("\n==================== INDAGINE CONCLUSA ====================")
    log_print(report_content)

    return (
        report_content,
        "".join(log_lines),
        metriche_tempo,
        verdetto_finale,
    )

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
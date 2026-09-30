"""
client.py — Orchestratore dell'indagine: collega l'LLM (via API OpenAI-compatible)
al server MCP (server.py) e guida il ciclo di tool-calling fino al verdetto finale.

COSA FA:
- esegui_analisi_mcp(): esegue l'intero ciclo di indagine per un singolo IP target
  (Fase 1: esplorazione con tool calling; Fase 2: generazione del report finale
  con verdetto forzato via structured output). Ritorna un dizionario con stato,
  verdetto, report, metriche di telemetria e log dettagliato.
- main(): menu interattivo a riga di comando per lanciare una singola analisi
  (alternativa a test_suite.py per test manuali/demo).

DA CHI VIENE CHIAMATO:
- test_suite.py importa esegui_analisi_mcp per il benchmark automatizzato.
- Eseguito direttamente (`python client.py`) per l'uso interattivo a menu.
"""
import os
import gc
import re
import re as _re
import sys
import json
import time
import copy
import asyncio 
import traceback
import textwrap
import ipaddress
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional
from datetime import datetime
from dotenv import load_dotenv
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from openai import AsyncOpenAI 
from openai import APIConnectionError, APITimeoutError

import utils
import config
import engine, prompts

_SUFFISSI_DOMINIO_LEGITTIMI = (".com", ".net", ".org", ".io", ".co", ".dev")

def _hostname_e_legittimo(nome: str) -> bool:
    """Un hostname/provider è 'legittimo' ai fini della deroga BENIGN solo se è
    un dominio pubblico riconoscibile o un provider cloud noto,
    non un hostname interno generico, non una stringa ambigua."""
    if not nome:
        return False
    n = nome.strip().lower()
    try:
        ipaddress.ip_address(n)
        return False  # è un IP, non un hostname
    except ValueError:
        pass
    if any(p in n for p in config.PROVIDER_REPUTATI):
        return True
    if any(n.endswith(suf) for suf in _SUFFISSI_DOMINIO_LEGITTIMI) and n.count(".") >= 1:
        return True
    return False

def _ha_score_altissimo_in_compute_verdict(risultati: list) -> bool:
    """Verifica se l'ULTIMO risultato di compute_verdict_scores riporta già
    un punteggio >= 0.95 per una categoria di attacco (soglia di STOP
    esplicitata nel system prompt). A differenza di _verifica_segnale_forte,
    funziona anche sul testo 'wrappato' con l'header ESITO TASSATIVO, perché
    cerca il pattern via regex invece di fare json.loads dell'intero blob."""
    for t in reversed(risultati):
        if t.get("tool_name") != "compute_verdict_scores":
            continue
        r = t.get("result")
        if not isinstance(r, str):
            return False
        for cat in config.CAT_ATTACCO:
            m = re.search(rf'"{cat}":\s*([\d.]+)', r)
            if m and float(m.group(1)) >= 0.95:
                return True
        return False
    return False

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
    # METRICHE DI TELEMETRIA E LOGGING
    # -------------------------------------------------------------------------
    metriche_tempo = {
        "tempo_llm_sec": 0.0,
        "tempo_mcp_totale_sec": 0.0,
        "tempo_sql_reale_sec": 0.0,
        "tempo_totale_esecuzione": 0.0,
        "tempo_attesa_rate_limit_sec": 0.0,
        "turni_esplorazione": 0,
        "tool_eseguiti": 0,
        "verdetti_ribaltati_senza_nuovo_tool": 0, 
    }

    log_lines: List[str] = []

    def log_print(messaggio: str):
        print(messaggio, flush=True)
        log_lines.append(messaggio + "\n")

    def log_only(messaggio: str):
        log_lines.append(messaggio + "\n")

    # -------------------------------------------------------------------------
    # FUNZIONI DI UTILITÀ E PARSING (HELPER FUNCTIONS)
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
        """
        Verifica che l'evidenza grezza superi REALMENTE le soglie del verdetto,
        non solo che il campo esista nel JSON.
        """
        s = config.Soglie

        def _num(pattern, testo, default=0.0):
            m = re.search(pattern, testo)
            return float(m.group(1)) if m else default

        if verdetto == "DOS_VOLUMETRIC":
            for t in risultati:
                r = t.get("result")
                if not isinstance(r, str):
                    continue
                pps = max(
                    _num(r'"pps_aggregati":\s*([\d.]+)', r),
                    _num(r'"burst_pps":\s*([\d.]+)', r),
                )
                slow = _num(r'"flussi_slowloris":\s*(\d+)', r)
                ratio = _num(r'"ratio_porte_effimere":\s*([\d.]+)', r)
                porte = _num(r'"porte_sorgente_uniche":\s*(\d+)', r)
                tot   = _num(r'"totale_flussi":\s*(\d+)', r)
                fweb  = _num(r'"flussi_web_totali":\s*(\d+)', r)
                rps   = _num(r'"web_rps":\s*([\d.]+)', r)
            
                if (
                    pps >= s.DOS_PPS_MIN_FALLBACK
                    or slow >= s.SLOWLORIS_FLUSSI_MIN
                    or ((ratio >= s.RATIO_PORTE_EFFIMERE_MIN or porte >= s.PORTE_SORGENTE_UNICHE_MIN)
                        and tot >= s.DOS_DISPERSIONE_FLUSSI_MIN)
                    or fweb >= s.DOS_L7_FLUSSI_ASSOLUTI_MIN
                    or rps >= s.DOS_L7_RPS_MIN
                ):
                    return True
            return False

        if verdetto == "SCAN_BRUTEFORCE":
            for t in risultati:
                r = t.get("result")
                if not isinstance(r, str):
                    continue
                porte = _num(r'"porte_uniche_contattate":\s*(\d+)', r)
                if porte >= s.SCAN_PORTE_MIN or "SOSPETTO_BRUTEFORCE" in r:
                    return True
            return False

        if verdetto == "BEACONING_C2":
            for t in risultati:
                r = t.get("result")
                if not isinstance(r, str):
                    continue
                score = _num(r'"anomaly_score":\s*(\d+)', r)
                if score >= s.ANOMALY_SCORE_C2_MIN:
                    return True
                if '"CONFIRMED_BEACONING_C2"' in r:
                    return True
                if re.search(r'"dst_port":\s*(8080|8443|1080|4444|5555)', r) and \
                re.search(r'"hostname":\s*"N/A"', r):
                    return True
                cv_match = re.search(r'"cv":\s*([\d.]+|null)', r)
                tot_match = re.search(r'"totale_connessioni":\s*(\d+)', r)
                porta_match = re.search(r'"dst_port":\s*(\d+)', r)
                if cv_match and tot_match and porta_match:
                    cv_val = float(cv_match.group(1))
                    tot_val = int(tot_match.group(1))
                    porta_val = int(porta_match.group(1))
                    porta_c2 = porta_val in s.PORTE_C2_SOSPETTE
                    if cv_val <= 0.05 and porta_c2 and tot_val >= 5:
                        return True
                    if cv_val <= 0.05 and tot_val >= s.BEACON_MIN_CONNESSIONI:
                        return True
            return False

        if verdetto == "WEB_ATTACK_EXPLOIT":
            for t in risultati:
                r = t.get("result")
                if not isinstance(r, str):
                    continue
                if _num(r'"anomalie_l7_trovate":\s*(\d+)', r) > 0:
                    return True
                if '"login_endpoint_targeted": true' in r:
                    return True
                if '"sospetto_web_bruteforce": true' in r:   
                    return True
            return False

        return False

    PRIORITA_DEFAULT = ["WEB_ATTACK_EXPLOIT", "SCAN_BRUTEFORCE", "DOS_VOLUMETRIC", "BEACONING_C2"]

    def _estrai_conflitto_tool(risultati: list) -> list:
        """Candidati a pari merito dal primo compute_verdict_scores (stesso criterio di
        engine.estrai_suggerimento_tool). Lista vuota se assente o non parsabile."""
        for t in risultati:
            if t.get("tool_name") != "compute_verdict_scores":
                continue
            try:
                data = json.loads(t.get("result") or "")
            except (json.JSONDecodeError, TypeError):
                return []
            return [c for c in (data.get("conflitto_a_pari_merito") or []) if c in PRIORITA_DEFAULT]
        return []

    def _evidenza_dura(risultati: list) -> Tuple[bool, str]:
        s = config.Soglie
        def _num(p, t, d=0.0):
            m = re.search(p, t)
            return float(m.group(1)) if m else d

        for t in risultati:
            r = t.get("result")
            if not isinstance(r, str):
                continue

            # Entropia: conta SOLO se ci sono più anomalie O se è confermata da altri segnali
            ent = _num(r'"anomalie_entropia_trovate":\s*(\d+)', r)
            l7 = _num(r'"anomalie_l7_trovate":\s*(\d+)', r)
            fweb = _num(r'"flussi_web_esaminati":\s*(\d+)', r)
            # Sola anomalia su centinaia di flussi NON è evidenza dura
            if l7 > 0 and (l7 >= 3 or (fweb > 0 and l7 / max(fweb, 1) > 0.02)):
                return True, f"anomalie L7 significative ({l7}/{fweb})"
            if ent > 0 and (ent >= 3 or _num(r'"login_endpoint_targeted":\s*true', r) > 0):
                return True, f"anomalie entropia significative ({ent})"

            if '"login_endpoint_targeted": true' in r:
                return True, "endpoint di login"

            if _num(r'"flussi_slowloris":\s*(\d+)', r) >= s.SLOWLORIS_FLUSSI_MIN:
                return True, "Slowloris"

            pps_val = max(_num(r'"pps_aggregati":\s*([\d.]+)', r),
              _num(r'"burst_pps":\s*([\d.]+)', r))
            if pps_val >= s.DOS_PPS_MIN: 
                return True, "PPS sopra soglia piena"
            if pps_val >= s.DOS_PPS_MIN_FALLBACK:
                dest_web = _num(r'"destinazioni_web_distinte":\s*(\d+)', r)
                fweb = _num(r'"flussi_web_totali":\s*(\d+)', r)
                if fweb > 0 and fweb / max(dest_web, 1) > 10:  # concentrazione > 10 flussi per destinazione
                    return True, "PPS sopra fallback con traffico concentrato"

            fweb_tot = _num(r'"flussi_web_totali":\s*(\d+)', r)
            rps_val = _num(r'"web_rps":\s*([\d.]+)', r)
            if rps_val >= s.DOS_L7_RPS_MIN:
                return True, "RPS web sopra soglia"
            if fweb_tot >= s.DOS_L7_FLUSSI_ASSOLUTI_MIN:
                # Volume web elevato: è evidenza dura SOLO se concentrato su poche destinazioni.
                # Se distribuito (concentrazione < 10), è browsing normale.
                dest_web = _num(r'"destinazioni_web_distinte":\s*(\d+)', r)
                if dest_web > 0 and fweb_tot / dest_web > 10:
                    return True, "volume web concentrato"

            if "SOSPETTO_BRUTEFORCE" in r or (
                "SOSPETTO_PORTSCAN" in r
                and _num(r'"porte_uniche_contattate":\s*(\d+)', r) >= s.SCAN_PORTE_MIN
            ):
                return True, "scan/bruteforce L4"

        return False, ""

    def _deroga_benign_ammessa(thought: str, risultati: list) -> Tuple[bool, str]:
        if _estrai_conflitto_tool(risultati):
            return False, "pareggio non risolto"

        candidati_c2 = []
        for t in risultati:
            r = str(t.get("result") or "")
            if '"beaconing_c2_rilevato": true' not in r:
                continue
            for m in re.finditer(
                r'"dst_ip":\s*"([^"]+)"[^}]*?"dst_port":\s*(\d+)[^}]*?'
                r'"hostname":\s*"([^"]*)"[^}]*?"infra_provider":\s*"([^"]*)"'
                r'(?:[^}]*?"tags":\s*\[([^\]]*)\])?',
                r, re.DOTALL
            ):
                tags_raw = m.group(5) or ""
                tags = [t.strip().strip('"') for t in tags_raw.split(",") if t.strip()]
                candidati_c2.append({
                    "dst_ip": m.group(1),
                    "dst_port": int(m.group(2)),
                    "hostname": m.group(3),
                    "provider": m.group(4),
                    "tags": tags,
                })

        if not candidati_c2:
            return False, "nessun candidato C2 da scartare"

        for c in candidati_c2:
            host_ok = _hostname_e_legittimo(c["hostname"])
            prov_ok = bool(c["provider"]) and c["provider"].upper() not in ("UNKNOWN", "N/A")
            
            ip_interno = ipaddress.ip_address(c["dst_ip"]).is_private if c["dst_ip"] else False
            tag_keepalive = "INTERNAL_LAN_KEEPALIVE" in (c.get("tags") or [])
            
            if not (host_ok or prov_ok or ip_interno or tag_keepalive):
                return False, (
                    f"candidato C2 {c['dst_ip']}:{c['dst_port']} "
                    f"(hostname='{c['hostname']}', provider='{c['provider']}') "
                    "non riconducibile a servizio legittimo"
                )

        provider_noti = set()
        hostname_noti = set()
        for c in candidati_c2:
            if c["hostname"] and c["hostname"].upper() != "N/A":
                hostname_noti.add(c["hostname"].lower())
            if c["provider"] and c["provider"].upper() not in ("UNKNOWN", "N/A"):
                provider_noti.add(c["provider"].lower())

        nomi = provider_noti | hostname_noti
        citati = [n for n in nomi if n in (thought or "").lower()]
        if not citati:
            return False, "hostname/provider del candidato C2 non citato nel Thought"
        return True, f"candidato C2 legittimo: {citati}"
    
    # -------------------------------------------------------------------------
    # ARCHITETTURA DEI PROMPT (Inizializzazione Turno 1)
    # -------------------------------------------------------------------------
    
    user_prompt_iniziale = prompts.build_user_prompt_iniziale(ip_target, start_time, end_time, categoria_tag)

    system_prompt = {
        "role": "system",
        "content": prompts.SYSTEM_PROMPT_CONTENT
    }

    messages = [system_prompt, user_prompt_iniziale]

    # -------------------------------------------------------------------------
    # INIZIALIZZAZIONE STATO ED ESECUZIONE LOOP INDAGINE
    # -------------------------------------------------------------------------
    turno = 0
    stato_investigazione = "ESPLORAZIONE"
    risultati_tool_raccolti: List[Dict[str, Any]] = []
    storico_chiamate_hash = set()
    verdetto_vincolante_str = "UNKNOWN" 
    report_content: Optional[str] = None
    deroga_pre_scarto_max_turni: Optional[bool] = None
    deroga_benign_accettata_nel_loop: Optional[bool] = None

    log_print(f"=== INIZIO INDAGINE MCP PER TARGET: {ip_target} ===")

    # =========================================================================
    # FASE 1: ESPLORAZIONE MCP
    # =========================================================================

    testo_risposta = "" 

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
                    metriche_tempo["turni_esplorazione"] = turno + 1
                    ultimo_verdetto_chiusura = None
                    tool_eseguito_dopo_ultimo_verdetto = True
                    testo_risposta = ""  # Reset a ogni turno

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

                    # Pruning e Compressione Contesto
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

                    # Chiamata LLM con Retry e Timeout Handling
                    llm_params = ottieni_params_llm(stato_investigazione, llm_tools_mappati)
                    response = None

                    for tentativi_llm in range(15):
                        t_llm_start = time.perf_counter()
                        try:
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
                    # CORTOCIRCUITO: VERDETTO GIÀ DICHIARATO NEL TESTO NONOSTANTE UNA TOOL_CALL
                    # =========================================================================
                    if tool_calls:
                        tool_eseguiti_correnti = {t["tool_name"] for t in risultati_tool_raccolti}
                        tutti_obbligatori_fatti = "compute_verdict_scores" in tool_eseguiti_correnti
                        ha_segnale_forte_corrente = _ha_score_altissimo_in_compute_verdict(risultati_tool_raccolti)
                        verdetto_gia_dichiarato, affidabilita_verdetto = engine._estrai_verdetto_con_confidenza(testo_risposta)

                        if (
                            tutti_obbligatori_fatti
                            and ha_segnale_forte_corrente
                            and verdetto_gia_dichiarato in prompts.VERDETTI_AMMESSI
                            and affidabilita_verdetto == "ALTA"
                        ):
                            log_print(
                                f" -> [AVVISO CORTOCIRCUITO]: L'LLM ha già dichiarato il verdetto finale "
                                f"'{verdetto_gia_dichiarato}' nel testo pur generando una tool_call "
                                f"({tool_calls[0].get('function', {}).get('name')}). Ignoro la tool_call: "
                                "i tool obbligatori sono completi e c'è già un segnale forte >= 0.95."
                            )
                            tool_calls = []
                        elif verdetto_gia_dichiarato in prompts.VERDETTI_AMMESSI and affidabilita_verdetto != "ALTA":
                            log_print(
                                f" -> [CORTOCIRCUITO RIFIUTATO]: Verdetto '{verdetto_gia_dichiarato}' rilevato "
                                f"ma con affidabilità {affidabilita_verdetto} (fallback di prossimità). "
                                "Non interrompo l'esplorazione: la tool_call viene eseguita normalmente."
                            )

                    # =========================================================================
                    # ESECUZIONE TOOL CALL PRESENTE
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

                        argomenti = engine._applica_auto_paginazione(nome_funzione, argomenti)

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
                            
                            tool_eseguito_dopo_ultimo_verdetto = True
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

                                    # Estrazione degli score numerici
                                    scores_validi = {
                                        k: float(v)
                                        for k, v in res_json.items()
                                        if k in config.CAT_ATTACCO and isinstance(v, (int, float))
                                    }

                                    # Rilevamento dinamico di pareggi / top score
                                    if scores_validi:
                                        max_val = max(scores_validi.values())
                                        # Individua TUTTI i vincitori a pari merito (sopra lo 0.0)
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

                                    # Isolamento degli score secondari (> 0.0 e inferiori al max_val)
                                    altri_score_attivi = {
                                        cat: val for cat, val in scores_validi.items() 
                                        if val > 0.0 and cat not in vincitori_top
                                    }
                                    
                                    # Unifica i conflitti segnalati dal JSON o rilevati dall'analisi 
                                    conflitti = res_json.get("conflitto_a_pari_merito", [])
                                    if not conflitti and len(vincitori_top) > 1 and verdetto not in config.CAT_ATTACCO:
                                        conflitti = vincitori_top

                                    corroborato = _ha_evidenza_corroborante(verdetto, risultati_tool_raccolti)

                                    if not corroborato and score >= 0.95:
                                        score_originale = score
                                        score = 0.70  # declassa a soglia non-tassativa
                                        log_print(
                                            f" -> [DECLASSAMENTO]: Score {score_originale} declassato a {score} "
                                            f"perché corroborato=False. Override tassativo disattivato."
                                        )
                                        res_json["override_tassativo"] = False
                                        res_json["score_declassato_da"] = score_originale
                                        testo_risultato_sicuro = json.dumps(res_json)

                                    # Costruzione Guida Dinamica
                                    note_multi_score = ""
                                    if altri_score_attivi:
                                        dettaglio_altri = ", ".join([f"{k}: {v}" for k, v in altri_score_attivi.items()])
                                        note_multi_score = f" [ALTRE CATEGORIE MINORI: {dettaglio_altri}]."

                                    if conflitti:
                                        guida_azione = (
                                            f"[ATTENZIONE - RILEVATO MULTI-ATTACCO / PAREGGIO]: Trovato un punteggio paritario tra {conflitti} con score {max_val}.{note_multi_score} "
                                            "Il tool non ha risolto il pareggio: scegli UNA sola categoria in base a PPS/RPS/flussi grezzi e motivala."
                                        )
                                    elif score == 0.0:
                                        guida_azione = (
                                            "[VERIFICA RICHIESTA]: Il calcolo euristico restituisce punteggio 0.0 su tutte le categorie (BENIGN). "
                                            "Verifica se nei log L7 / HTTP precedentemente estratti vi sono anomalie non intercettate dall'euristica. "
                                            "Se confermi l'assenza di minacce, motiva il risultato ed emetti il VERDETTO FINALE 'BENIGN'."
                                        )
                                    elif score >= 0.95 and corroborato:
                                        guida_azione = (
                                            f"[EVIDENZA CORROBORATA - VERIFICA CRITICA OBBLIGATORIA]: L'euristica "
                                            f"indica {verdetto} (score {score}) ed è supportata dai log grezzi.{note_multi_score}\n\n"
                                            "PRIMA di emettere il verdetto, esegui la VERIFICA CRITICA OBBLIGATORIA "
                                            "descritta nel system prompt:\n"
                                            "1. IDENTIFICA IL CANDIDATO PRINCIPALE: quale hostname, dst_ip, dst_port "
                                            "e numero di connessioni hanno fatto scattare lo score? Citali esplicitamente.\n"
                                            "2. VERIFICA LA NATURA DELLA DESTINAZIONE: l'hostname è riconducibile a un "
                                            "servizio legittimo (adtech, CDN, telemetria, aggiornamenti, cloud, VPN)? "
                                            "Il provider è Google, Amazon, Cloudflare, Akamai, Fastly, Microsoft, ecc.?\n"
                                            "3. VERIFICA IL CONTESTO DI RETE: quanti flussi web totali e quante "
                                            "destinazioni web distinte? Se flussi_web > 50 E destinazioni_web > 10, "
                                            "il contesto è di browsing distribuito, non di C2.\n"
                                            "4. VERIFICA LA CORROBORAZIONE DURA: il candidato ha almeno una delle "
                                            "seguenti: hostname N/A + porta non standard su IP esterno non whitelist, "
                                            "payload_entropy=1, tag CONFIRMED_BEACONING_C2 su IP non infrastrutturale, "
                                            "assenza di traffico web contestuale?\n"
                                            "5. SE HAI IDENTIFICATO UN FALSO POSITIVO: NON emettere il verdetto "
                                            "suggerito. Emetti BENIGN citando il nome del servizio, i numeri del "
                                            "contesto e il motivo per cui lo score è un falso positivo.\n\n"
                                            "NON emettere un verdetto scritto 'score alto, quindi confermo' senza "
                                            "questa analisi: la motivazione deve contenere sempre il candidato "
                                            "principale e il contesto di rete."
                                        )
                                    else:
                                        firme_depotenziate = []
                                        for t in risultati_tool_raccolti:
                                            r = str(t.get("result") or "")

                                            m_bf = re.search(
                                                r'"sospetto_web_bruteforce":\s*true', r
                                            )
                                            m_tc = re.search(
                                                r'"target_colpiti_count":\s*(\d+)', r
                                            )
                                            m_mt = re.search(
                                                r'"max_tentativi_per_ip":\s*(\d+)', r
                                            )
                                            if m_bf and m_tc and m_mt:
                                                tc_val = int(m_tc.group(1))
                                                mt_val = int(m_mt.group(1))
                                                firme_depotenziate.append(
                                                    f"sospetto_web_bruteforce=true "
                                                    f"({mt_val} richieste su {tc_val} target)"
                                                )

                                            if '"sospetto_portscan": true' in r:
                                                firme_depotenziate.append("sospetto_portscan=true")
                                            if '"sospetto_bruteforce": true' in r:
                                                firme_depotenziate.append("sospetto_bruteforce=true")

                                            m_slow = re.search(
                                                r'"flussi_slowloris_confermati":\s*(\d+)', r
                                            )
                                            if m_slow and int(m_slow.group(1)) > 0:
                                                firme_depotenziate.append(
                                                    f"flussi_slowloris_confermati={m_slow.group(1)}"
                                                )

                                        # Deduplica mantenendo l'ordine
                                        viste = set()
                                        firme_depotenziate = [
                                            f for f in firme_depotenziate
                                            if not (f in viste or viste.add(f))
                                        ]

                                        nota_firme = ""
                                        if firme_depotenziate:
                                            nota_firme = (
                                                " ATTENZIONE: sono presenti firme strutturate nei tool "
                                                f"di rilevazione ({'; '.join(firme_depotenziate)}) ma lo score "
                                                "è stato depotenziato. Se il depotenziamento deriva da "
                                                "soglie di rate/velocità tarate per traffico burst (non per "
                                                "attacchi a bassa intensità prolungata), la firma strutturata "
                                                "va rivalutata ESPLICITAMENTE nel Thought prima di emettere "
                                                "BENIGN: un rate basso su una finestra lunga non contraddice "
                                                "una concentrazione strutturale su un target singolo."
                                            )

                                        guida_azione = (
                                            f"[ATTENZIONE - DISCREPANZA O INCOMPLETIZZA]: L'euristica suggerisce {verdetto} (score {score}),{note_multi_score} "
                                            f"MA l'evidenza nei log grezzi è debole, parziale o discordante (corroborato=False).{nota_firme} "
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

                            elif nome_funzione == "detect_beaconing":
                                try:
                                    res_beacon = json.loads(testo_risultato_sicuro)
                                    candidati = res_beacon.get("candidati_top") or []
                                    candidati_c2 = [
                                        c for c in candidati
                                        if (c.get("hostname") or "N/A") == "N/A"
                                        and int(c.get("dst_port") or 0) in (8080, 8443, 444, 1080)
                                    ]
                                    if candidati_c2:
                                        c = candidati_c2[0]
                                        testo_risultato_sicuro += (
                                            f"\n\n[SISTEMA - DRILL-DOWN OBBLIGATORIO SUL CANDIDATO]: "
                                            f"Rilevato candidato C2 verso {c.get('dst_ip')}:{c.get('dst_port')} "
                                            f"con hostname N/A e {c.get('totale_connessioni')} connessioni. "
                                            f"PRIMA di confermare BEACONING_C2, esegui "
                                            f"'analizza_connessione_by_community_id' su uno dei flussi del "
                                            f"candidato per verificarne il payload. Se il payload è minimo "
                                            f"(< 1000 byte) e costante, è un heartbeat legittimo → BENIGN. "
                                            f"NON confermare C2 senza questo drill-down."
                                        )
                                except Exception:
                                    pass

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

                            risultati_tool_raccolti.append({"tool_name": nome_funzione, "result": testo_risultato_sicuro})

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
                    # NESSUNA TOOL CALL (GESTIONE CONCLUSIONE / SOLLECITO)
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

                    # SBLOCCO FLESSIBILE TOOL MANCANTI
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

                    is_tentativo_chiusura = (
                        verdetto_estratto in ("BENIGN", "NON_IDENTIFICATO")
                        or (not tool_calls and verdetto_estratto not in config.CAT_ATTACCO)
                    )

                    if (
                        ultimo_verdetto_chiusura is not None
                        and not tool_eseguito_dopo_ultimo_verdetto
                        and verdetto_estratto in prompts.VERDETTI_AMMESSI
                        and verdetto_estratto != ultimo_verdetto_chiusura
                    ):
                        metriche_tempo["verdetti_ribaltati_senza_nuovo_tool"] += 1
                        log_print(
                            f" -> [TELEMETRIA]: Verdetto ribaltato senza nuovi tool nel turno {turno + 1}: "
                            f"'{ultimo_verdetto_chiusura}' -> '{verdetto_estratto}'."
                        )

                    ultimo_verdetto_chiusura = verdetto_estratto
                    tool_eseguito_dopo_ultimo_verdetto = False

                    ultimo_msg_utente = messages[-1]["content"] if messages and messages[-1].get("role") == "user" else ""
                    gia_avvisato_anti_fn = "ATTENZIONE - BLOCCO ANTI-FALSO NEGATIVO" in ultimo_msg_utente

                    if is_tentativo_chiusura and not gia_avvisato_anti_fn and engine._verifica_incoerenza_benign(risultati_tool_raccolti):
                        deroga_ok, motivo_deroga_loop = _deroga_benign_ammessa(testo_risposta, risultati_tool_raccolti)
                        
                        if not deroga_ok:
                            thought_lower = (testo_risposta or "").lower()
                            # Verifica presenza dei 5 punti della verifica critica
                            punti_motivazione = [
                                "hostname" in thought_lower,
                                "connessioni" in thought_lower or "connessione" in thought_lower,
                                "flussi" in thought_lower or "destinazioni" in thought_lower,
                                "corroborazione" in thought_lower or "entropy" in thought_lower or "cv" in thought_lower,
                                "benign" in thought_lower,
                            ]
                            punti_presenti = sum(punti_motivazione)
                            
                            m_conn = _re.search(r'(\d+)\s*connessioni', thought_lower)
                            conn_val = int(m_conn.group(1)) if m_conn else 999
                            
                            m_cv = _re.search(r'cv[=:\s]+([\d.]+)', thought_lower)
                            cv_val = float(m_cv.group(1)) if m_cv else 999.0
                            
                            m_fweb = _re.search(r'(\d+)\s*flussi\s+web', thought_lower)
                            fweb_val = int(m_fweb.group(1)) if m_fweb else 0
                            m_dest = _re.search(r'(\d+)\s*destinazioni', thought_lower)
                            dest_val = int(m_dest.group(1)) if m_dest else 0
                            
                            deroga_strutturata = (
                                punti_presenti >= 4
                                and conn_val < config.Soglie.BEACON_MIN_CONNESSIONI 
                                and cv_val <= 0.15                                   
                                and fweb_val > 50                                   
                                and dest_val > 10
                            )
                            
                            if deroga_strutturata:
                                log_print(
                                    f" -> [DEROGA BENIGN STRUTTURATA AMMESSA NEL LOOP]: "
                                    f"LLM ha motivato con {punti_presenti}/5 punti, candidato con "
                                    f"{conn_val} connessioni (< {config.Soglie.BEACON_MIN_CONNESSIONI}), "
                                    f"CV={cv_val} (artefatto), contesto browsing ({fweb_val} flussi, "
                                    f"{dest_val} destinazioni). Chiusura NON bloccata."
                                )
                                deroga_benign_accettata_nel_loop = True
                                deroga_ok = True
                            else:
                                log_print(
                                    f" -> [DEROGA STRUTTURATA RIFIUTATA]: punti={punti_presenti}/5, "
                                    f"conn={conn_val}, cv={cv_val}, fweb={fweb_val}, dest={dest_val}"
                                )
                        
                        if deroga_ok:
                            log_print(f" -> [DEROGA BENIGN AMMESSA NEL LOOP]: {motivo_deroga_loop}. Chiusura NON bloccata.")
                        else:
                            anomalie_trovate = engine._ha_rilevato_anomalie_l7_reali(risultati_tool_raccolti)
                            if anomalie_trovate:
                                log_print(f" -> [AVVISO ANTI-FN TURNO {turno + 1}]: Chiusura bloccata per presenza di anomalie L7/C2 o DoS nei dati.")
                                if testo_risposta.strip():
                                    messages.append({"role": "assistant", "content": testo_risposta})

                                messages.append({
                                    "role": "user",
                                    "content": (
                                        "ATTENZIONE - BLOCCO ANTI-FALSO NEGATIVO:\n"
                                        "Stai tentando di concludere con BENIGN, ma i tool hanno evidenziato anomalie strutturali.\n"
                                        "Prima di cambiare verdetto: se NON hai nuove evidenze rispetto a quelle già citate nel tuo "
                                        "ragionamento precedente, NON cambiare conclusione solo per soddisfare questo avviso — "
                                        "ripeti BENIGN e spiega esplicitamente perché l'anomalia segnalata non è pertinente. "
                                        "Cambia verdetto SOLO se identifichi un dato specifico non ancora considerato."
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
                # ESCI DAL WHILE (MAX TURNI RAGGIUNTO)
                # =========================================================================
                if turno >= max_turns and stato_investigazione == "ESPLORAZIONE":
                    log_print("\n -> [AVVISO MAX TURNI]: Raggiunto il limite massimo di turni. Forzatura passaggio a FASE REPORT FINALE.")
                    stato_investigazione = "REPORT_FINALE"

                    sollecitazione_finale = (
                        "Hai raggiunto il limite massimo di turni di esplorazione. "
                        "Sulla base di tutti i dati estratti finora, fornisci la tua sintesi delle evidenze ed emetti il VERDETTO FINALE."
                    )
                    messages.append({"role": "user", "content": sollecitazione_finale})

                    # PRUNING DEL CONTESTO (Evita il Timeout LLM) 
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

                    # SANIFICAZIONE CRONOLOGIA 
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

                        # forza structured output 
                        llm_params_finali["tools"] = [prompts.TOOL_VERDETTO_FINALE_FORZATO]
                        llm_params_finali["tool_choice"] = {
                            "type": "function",
                            "function": {"name": "emetti_verdetto_finale"},
                        }
                        llm_params_finali["parallel_tool_calls"] = False

                        response_finale = await asyncio.wait_for(
                            client.chat.completions.create(messages=messages_sanitizzati_finali, **llm_params_finali),
                            timeout=120.0
                        )

                        msg_finale = response_finale.choices[0].message
                        testo_risposta = ""

                        if getattr(msg_finale, "tool_calls", None):
                            tc_finale = msg_finale.tool_calls[0]
                            try:
                                args_finali = json.loads(tc_finale.function.arguments)
                                v_forzato = str(args_finali.get("verdetto", "")).strip().upper()
                                mot_forzata = str(args_finali.get("motivazione", "")).strip()
                                if v_forzato in prompts.VERDETTI_AMMESSI and mot_forzata:
                                    testo_risposta = json.dumps(
                                        {"verdetto": v_forzato, "motivazione": mot_forzata},
                                        ensure_ascii=False,
                                    )
                                else:
                                    log_print(" -> [AVVISO]: tool_call forzata ha prodotto verdetto/motivazione non validi.")
                            except (json.JSONDecodeError, AttributeError) as e_parse:
                                log_print(f" -> [AVVISO]: Impossibile parsare arguments della tool_call forzata: {e_parse}")

                        verdetto_grezzo_max_turni = engine.estrai_verdetto_pulito(testo_risposta)
                        if verdetto_grezzo_max_turni == "BENIGN" and engine._verifica_incoerenza_benign(risultati_tool_raccolti):
                            deroga_pre_scarto_max_turni, _ = _deroga_benign_ammessa(testo_risposta, risultati_tool_raccolti)
                        else:
                            deroga_pre_scarto_max_turni = None

                        # Calcola se lo score del tool è "forte": >= 0.9 e NON declassato.
                        # Se lo score è stato declassato o è borderline, la guardia anti-FN non scatta
                        # e si accetta il BENIGN dell'LLM.
                        score_tool, stato_score = engine.estrai_score_tool(risultati_tool_raccolti)
                        score_forte = (
                            score_tool is not None
                            and score_tool >= 0.9
                            and stato_score != "declassato"
                        )

                        if (verdetto_grezzo_max_turni == "BENIGN"
                            and engine._verifica_incoerenza_benign(risultati_tool_raccolti)
                            and deroga_pre_scarto_max_turni is False
                            and score_forte
                        ):
                            log_print(
                                f" -> [ANTI-FN MAX TURNI]: Verdetto BENIGN a fine turni incoerente "
                                f"con le evidenze grezze raccolte e score tool FORTE ({score_tool}). "
                                "PRIMA di scartare il Thought, invio un'ultima richiesta di motivazione "
                                "strutturata all'LLM: se motiva la deroga con dati concreti, la accetto."
                            )

                            messaggio_richiesta_deroga = (
                                "ATTENZIONE - RICHIESTA DI MOTIVAZIONE OBBLIGATORIA (ULTIMO TENTATIVO):\n"
                                "Hai emesso BENIGN, ma lo score del tool è forte (>= 0.95). Per accettare "
                                "la tua deroga, devi rispondere a TUTTI i seguenti punti, citando dati "
                                "concreti presenti negli output dei tool. Se NON riesci a rispondere a "
                                "TUTTI i punti con dati concreti, il verdetto corretto è quello suggerito "
                                "dallo score.\n\n"
                                "1. CANDIDATO PRINCIPALE: quale hostname (o 'N/A'), dst_ip, dst_port e "
                                "numero di connessioni hanno fatto scattare lo score? Citali esplicitamente.\n"
                                "2. NATURA DELLA DESTINAZIONE: l'hostname è riconducibile a un servizio "
                                "legittimo (adtech, CDN, telemetria, aggiornamenti, cloud, VPN)? Se sì, "
                                "cita il nome del servizio. Il provider è Google, Amazon, Cloudflare, "
                                "Akamai, Fastly, Microsoft, ecc.?\n"
                                "3. CONTESTO DI RETE: quanti flussi web totali e quante destinazioni web "
                                "distinte ha l'host? Se flussi_web > 50 E destinazioni_web > 10, il "
                                "contesto è di browsing distribuito, non di C2.\n"
                                "4. CORROBORAZIONE DURA: il candidato ha almeno una delle seguenti? "
                                "(a) hostname N/A + porta non standard su IP esterno non whitelist; "
                                "(b) payload_entropy=1; (c) tag CONFIRMED_BEACONING_C2 su IP non "
                                "infrastrutturale; (d) assenza di traffico web contestuale "
                                "(destinazioni_web <= 10 E flussi_web <= 50).\n"
                                "5. CONCLUSIONE: sulla base delle risposte 1-4, spiega perché lo score "
                                "è un FALSO POSITIVO e non una minaccia reale.\n\n"
                                "Rispondi con un JSON nel formato: "
                                '{"verdetto": "<BENIGN o categoria>", "motivazione": "<risposta ai 5 punti>"}'
                            )

                            messages.append({"role": "assistant", "content": testo_risposta})
                            messages.append({"role": "user", "content": messaggio_richiesta_deroga})

                            try:
                                response_deroga = await asyncio.wait_for(
                                    client.chat.completions.create(
                                        model=model_name,
                                        messages=messages,
                                        temperature=0.0,
                                        max_tokens=1024,
                                    ),
                                    timeout=120.0,
                                )
                                contenuto_deroga = response_deroga.choices[0].message.content or ""

                                json_match = _re.search(r"\{[\s\S]*\}", contenuto_deroga)
                                if json_match:
                                    data_deroga = json.loads(json_match.group(0).strip())
                                    v_deroga = str(data_deroga.get("verdetto", "")).strip().upper()
                                    mot_deroga = str(data_deroga.get("motivazione", "")).strip()

                                    if v_deroga == "BENIGN" and mot_deroga:
                                        # Verifica che la motivazione citi i 5 punti
                                        keywords = ["hostname", "flussi", "destinazioni", "porta",
                                                    "entropy", "provider", "connessioni", "cv"]
                                        hits = sum(1 for kw in keywords if kw.lower() in mot_deroga.lower())
                                        if hits >= 3:
                                            log_print(
                                                f" -> [DEROGA BENIGN ACCETTATA]: l'LLM ha motivato la deroga "
                                                f"citando {hits}/8 keyword strutturate. Verdetto BENIGN mantenuto."
                                            )
                                            log_only(f"[DEROGA STRUTTURATA]:\n{mot_deroga}\n\n")
                                            deroga_benign_accettata_nel_loop = True
                                            testo_risposta = json.dumps(
                                                {"verdetto": "BENIGN", "motivazione": mot_deroga},
                                                ensure_ascii=False,
                                            )
                                        else:
                                            log_print(
                                                f" -> [DEROGA BENIGN RIFIUTATA]: motivazione troppo generica "
                                                f"({hits}/8 keyword). Thought scartato: Stage 2 ricadrà sul "
                                                "suggerimento euristico del tool."
                                            )
                                            log_only(f"[THOUGHT ORIGINALE SCARTATO PER INCOERENZA - MAX TURNI]:\n{testo_risposta}\n\n")
                                            testo_risposta = (
                                                "[SCARTATO DAL SISTEMA - VERDETTO BENIGN INCOERENTE CON LE "
                                                "EVIDENZE RACCOLTE]: la motivazione della deroga non cita "
                                                "abbastanza dati concreti (hostname, flussi, destinazioni, "
                                                "porta, entropy). Il verdetto sarà determinato in Stage 2 "
                                                "a partire dal suggerimento euristico del tool."
                                            )
                                    else:
                                        log_print(f" -> [DEROGA BENIGN NON EMESSA]: l'LLM ha risposto '{v_deroga}'.")
                                        testo_risposta = json.dumps(
                                            {"verdetto": v_deroga, "motivazione": mot_deroga},
                                            ensure_ascii=False,
                                        )
                                else:
                                    log_print(" -> [DEROGA BENIGN PARSING FALLITO]: nessun JSON nella risposta.")
                                    log_only(f"[THOUGHT ORIGINALE SCARTATO PER INCOERENZA - MAX TURNI]:\n{testo_risposta}\n\n")
                                    testo_risposta = (
                                        "[SCARTATO DAL SISTEMA - VERDETTO BENIGN INCOERENTE CON LE "
                                        "EVIDENZE RACCOLTE]: il sistema non ha ricevuto una motivazione "
                                        "strutturata valida. Il verdetto sarà determinato in Stage 2 a "
                                        "partire dal suggerimento euristico del tool."
                                    )
                            except Exception as e_deroga:
                                log_print(f" -> [ERRORE RICHIESTA DEROGA]: {type(e_deroga).__name__}: {e_deroga}")
                                log_only(f"[THOUGHT ORIGINALE SCARTATO PER INCOERENZA - MAX TURNI]:\n{testo_risposta}\n\n")
                                testo_risposta = (
                                    "[SCARTATO DAL SISTEMA - VERDETTO BENIGN INCOERENTE CON LE "
                                    "EVIDENZE RACCOLTE]: la richiesta di motivazione è fallita. Il "
                                    "verdetto sarà determinato in Stage 2 a partire dal suggerimento "
                                    "euristico del tool."
                                )
                        else:
                            if verdetto_grezzo_max_turni == "BENIGN" and not score_forte:
                                log_print(
                                    f" -> [ANTI-FN MAX TURNI NON ATTIVATO]: BENIGN a fine turni mantenuto. "
                                    f"Score tool debole/declassato (score={score_tool}, stato={stato_score}) "
                                    "oppure nessun conflitto forte con le evidenze. Il Thought LLM non viene scartato."
                                )

                        # Fallback residuo se il provider non supporta tool_choice forzato o la call è vuota
                        if not testo_risposta.strip():
                            testo_risposta = msg_finale.content or ""

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

        for idx_exc, sub_exc in enumerate(sub_exceptions):
            tb_str = "".join(
                traceback.format_exception(type(sub_exc), sub_exc, sub_exc.__traceback__)
            )
            log_only(f"[TRACEBACK COMPLETO SUB-EXCEPTION {idx_exc + 1}/{len(sub_exceptions)}]:\n{tb_str}")

    # =========================================================================
    # FASE 2: GENERAZIONE REPORT FINALE (TOOL CALLING FORZATO)
    # =========================================================================
    #log_print(f" -> [DEBUG TRANSITO]: Passaggio alla Fase 2 con stato={stato_investigazione}")  

    # Estrazione ultimo thought dell'assistant
    ultimo_thought = ""
    for m in reversed(messages):
        if m.get("role") == "assistant" and m.get("content"):
            ultimo_thought = m["content"]
            break

    if isinstance(ultimo_thought, list):
        thought_pulito = "\n".join([str(b.get("text", "")) for b in ultimo_thought if isinstance(b, dict)])
    else:
        thought_pulito = str(ultimo_thought).strip() if ultimo_thought else "Nessuna considerazione preliminare."

    # Formattazione evidenze estratte dai tool
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

    if stato_investigazione in ("REPORT_FINALE", "ESPLORAZIONE"):
        log_print("\n==================== FASE FINALE: GENERAZIONE REPORT STRUTTURATO (STAGE 2) ====================")

        # ESTRAZIONE E VALUTAZIONE VERDETTI
        verdetto_suggerito_tool, motivo_override = engine.estrai_suggerimento_tool(risultati_tool_raccolti)
        verdetto_thought, affidabilita_thought = engine._estrai_verdetto_con_confidenza(thought_pulito)

        log_print(f" -> [ANALISI PRELIMINARE LLM THOUGHT]: '{verdetto_thought}'")
        log_print(f" -> [SUGGERIMENTO EURISTICO TOOL]: '{verdetto_suggerito_tool}' (Motivo: {motivo_override})")

        # DETERMINAZIONE VERDETTO VINCOLANTE STAGE 1
        verdetto_vincolante_str = None
        motivo_scelta_cli = ""
        is_fallback_tool = False
        forzato_da_guardia = False

        benign_scartato = "[SCARTATO DAL SISTEMA" in thought_pulito
        benign_tentato = (verdetto_thought == "BENIGN") or benign_scartato
        conflitto_tool = _estrai_conflitto_tool(risultati_tool_raccolti)

        deroga_ok, motivo_deroga = (False, "")

        if deroga_benign_accettata_nel_loop:
            deroga_ok = True
            motivo_deroga = "deroga accettata nel loop con motivazione strutturata"
            log_print(f" -> [DEROGA BENIGN - EREDITATA DAL LOOP]: {deroga_ok}")
        elif verdetto_thought == "BENIGN" and not benign_scartato:
            deroga_ok, motivo_deroga = _deroga_benign_ammessa(thought_pulito, risultati_tool_raccolti)
            log_print(f" -> [DEROGA BENIGN]: {deroga_ok} ({motivo_deroga})")
            
            if not deroga_ok:
                thought_lower = (thought_pulito or "").lower()
                m_conn = _re.search(r'(\d+)\s*connessioni', thought_lower)
                conn_val = int(m_conn.group(1)) if m_conn else 999
                m_cv = _re.search(r'cv\s*[=:]\s*(\d+\.\d+|\d+)', thought_lower)
                cv_val = float(m_cv.group(1)) if m_cv else 999.0
                m_fweb = _re.search(r'(\d+)\s*flussi\s+web', thought_lower)
                fweb_val = int(m_fweb.group(1)) if m_fweb else 0
                m_dest = _re.search(r'(\d+)\s*destinazioni', thought_lower)
                dest_val = int(m_dest.group(1)) if m_dest else 0
                
                if (conn_val < config.Soglie.BEACON_MIN_CONNESSIONI
                    and cv_val <= 0.15
                    and fweb_val > 50
                    and dest_val > 10):
                    log_print(
                        f" -> [DEROGA BENIGN STRUTTURATA IN FASE 2]: candidato con "
                        f"{conn_val} connessioni (< {config.Soglie.BEACON_MIN_CONNESSIONI}), "
                        f"CV={cv_val}, contesto browsing ({fweb_val} flussi, {dest_val} destinazioni)."
                    )
                    deroga_ok = True
                    motivo_deroga = "deroga strutturata: candidato sotto soglia + CV artefatto + browsing distribuito"
        elif benign_scartato and deroga_pre_scarto_max_turni is not None:
            deroga_ok = deroga_pre_scarto_max_turni
            motivo_deroga = "valutazione ereditata dal ramo max-turni (pre-scarto)"
            log_print(f" -> [DEROGA BENIGN - EREDITATA DA MAX TURNI]: {deroga_ok}")

        score_tool, stato_score = engine.estrai_score_tool(risultati_tool_raccolti)

        tool_score_e_debole = (
            score_tool is None
            or score_tool < 0.9
            or stato_score == "declassato"
        )

        if (benign_tentato
            and verdetto_suggerito_tool in config.CAT_ATTACCO
            and not deroga_ok
            and not tool_score_e_debole):         
            verdetto_vincolante_str = verdetto_suggerito_tool
            is_fallback_tool = False
            motivo_scelta_cli = f"Guard FN: BENIGN in contrasto con euristica forte ({verdetto_suggerito_tool})."
            forzato_da_guardia = True
        elif benign_tentato and not deroga_ok and tool_score_e_debole:
            verdetto_vincolante_str = "BENIGN"
            is_fallback_tool = True
            motivo_scelta_cli = (
                f"Guard FN attenuata: BENIGN accettato perché lo score del tool "
                f"({score_tool}) è debole/declassato. Conflitto registrato nei log."
            )

        elif conflitto_tool and verdetto_thought not in config.CAT_ATTACCO:
            corroborati = [c for c in conflitto_tool if _ha_evidenza_corroborante(c, risultati_tool_raccolti)]
            candidati = corroborati or conflitto_tool
            verdetto_vincolante_str = min(candidati, key=PRIORITA_DEFAULT.index)
            is_fallback_tool = False   # Stage 2 non può declassare né cambiare categoria
            forzato_da_guardia = True
            motivo_scelta_cli = (
                f"Guard FN: pareggio tra {conflitto_tool} non risolto dal tool e Thought dell'analista "
                f"assente, non conclusivo o BENIGN (evidenza corroborata: {corroborati or 'nessuna'})."
            )
            log_print(f" -> [GUARD FN - CONFLITTO]: pareggio {conflitto_tool}, applico '{verdetto_vincolante_str}'.")
        
        elif verdetto_thought in prompts.VERDETTI_AMMESSI and affidabilita_thought == "ALTA":
            verdetto_vincolante_str = verdetto_thought
            motivo_scelta_cli = (
                f"Autonomia LLM: Confermato verdetto proposto dal Thought dell'analista: "
                f"'{verdetto_vincolante_str}'."
            )
            log_print(f" -> [VERDETTO AUTONOMO LLM]: {verdetto_vincolante_str}")

        elif verdetto_thought in prompts.VERDETTI_AMMESSI and affidabilita_thought == "MEDIA":
            verdetto_vincolante_str = verdetto_thought
            is_fallback_tool = True
            motivo_scelta_cli = (
                f"Fallback di prossimità (affidabilità MEDIA): il Thought dell'analista "
                f"non contiene una dichiarazione esplicita di verdetto. "
                f"Applico '{verdetto_vincolante_str}' ma Stage 2 potrà correggerlo."
            )
            log_print(f" -> [VERDETTO AUTONOMO LLM - FALLBACK]: {verdetto_vincolante_str} (affidabilità MEDIA)")

        elif verdetto_suggerito_tool in prompts.VERDETTI_AMMESSI:
            verdetto_vincolante_str = verdetto_suggerito_tool
            is_fallback_tool = True
            motivo_scelta_cli = f"Thought non esplicito. Applicato fallback dal calcolo Euristico Tool: '{verdetto_vincolante_str}'."
            log_print(f" -> [FALLBACK TOOL EURISTICO]: {verdetto_vincolante_str}")

        else:
            verdetto_vincolante_str = "BENIGN"
            is_fallback_tool = True
            motivo_scelta_cli = "Nessun verdetto identificato da LLM o Tool. Forzatura di sicurezza su BENIGN."
            if engine._ha_rilevato_anomalie_l7_reali(risultati_tool_raccolti):
                motivo_scelta_cli += (
                    " ATTENZIONE: i tool hanno rilevato anomalie strutturate (L7/L4/C2 o score >= 0.5): "
                    "non confermare BENIGN senza confutarle esplicitamente con le evidenze."
                )
                log_print(" [SAFETY FALLBACK EXTREME]: BENIGN forzato MA con anomalie strutturate nei dati (L7/L4/C2 o score >= 0.5).")
            else:
                log_print(" [SAFETY FALLBACK EXTREME]: Verdetto forzato su BENIGN.")

        log_print(f"\n [VERDETTO FINALE RICHIESTO NEL JSON STAGE 2]: {verdetto_vincolante_str}\n")

        if forzato_da_guardia:
            thought_pulito = (
                "[Thought di Stage 1 scartato: assente, non conclusivo o BENIGN in contrasto con "
                "l'euristica del tool. Motiva il verdetto imposto usando solo le EVIDENZE OGGETTIVE.]"
            )

        # LOOP DI EMISSIONE REPORT LLM CON RETRY
        stato_investigazione = "INCOMPLETE"
        storico_retry_report: List[Dict[str, Any]] = []

        for tentativo_rep in range(1, config.Soglie.MAX_RETRY_REPORT + 1):
            istruzioni_focus = prompts.FOCUS_CATEGORIE_CONTENT.get(
                categoria_tag.lower(), "ANALISI GENERICA: nessun bias iniziale."
            )

            if forzato_da_guardia:
                nota_libertà = (
                    "NOTA: il verdetto di Stage 1 sopra è stato IMPOSTO DAL SISTEMA perché il Thought "
                    "dell'analista era assente, non conclusivo o concludeva BENIGN in contrasto con "
                    "l'euristica del tool. Non puoi declassarlo a BENIGN né cambiarlo: ricopialo nel "
                    "campo 'verdetto' e motiva con le evidenze grezze."
                )
            elif is_fallback_tool:
                nota_libertà = (
                    "NOTA: il verdetto di Stage 1 sopra è un FALLBACK EURISTICO AUTOMATICO — l'LLM non ha "
                    "prodotto un giudizio esplicito valido in Stage 1. Sei libero di rivalutarlo liberamente, "
                    "incluso verso BENIGN, se le evidenze grezze non lo confermano. In tal caso, fai iniziare "
                    "la motivazione con 'REVISIONE FALLBACK EURISTICO:'."
                )
            else:
                nota_libertà = (
                    "NOTA: il verdetto di Stage 1 sopra è un giudizio esplicito dell'analista LLM. "
                    "Non puoi declassarlo a BENIGN né cambiarlo verso un'altra categoria: ricopialo nel campo 'verdetto'."
                )

            regola_2_testo = (
                "Poiché lo Stage 1 era un fallback euristico automatico (nessun giudizio esplicito "
                "valido), sei libero di declassare a 'BENIGN' se le evidenze grezze non lo confermano "
                "(vedi nota sopra)."
                if is_fallback_tool else
                "Se lo Stage 1 ha stabilito una categoria di attacco ('WEB_ATTACK_EXPLOIT', "
                "'DOS_VOLUMETRIC', 'SCAN_BRUTEFORCE', 'BEACONING_C2'), è SEVERAMENTE VIETATO "
                "declassare il verdetto finale a 'BENIGN'."
            )

            regola_3_testo = (
                "CORREZIONI TRA CATEGORIE MALEVOLE: puoi correggere una categoria malevola con un'altra "
                "SOLO se la motivazione inizia con 'CORREZIONE RISPETTO ALLO STAGE 1:' E include una sezione "
                "'NUOVE EVIDENZE:' che cita dati specifici (IP, community_id, porte, volumi) non considerati "
                "nello Stage 1. Senza nuove evidenze, il verdetto di Stage 1 va ricopiato identico."
                if is_fallback_tool else
                "NESSUNA CORREZIONE: il verdetto di Stage 1 va ricopiato identico, anche tra categorie di attacco."
            )
            
            prompt_corrente = textwrap.dedent(f"""
                Analisi IP Target: {ip_target} (Finestra temporale: {start_time} - {end_time})

                AMBITO INVESTIGATIVO DI ORIGINE:
                {istruzioni_focus}

                VERDETTO STABILITO IN STAGE 1: '{verdetto_vincolante_str}'
                Origine verdetto: {motivo_scelta_cli}

                {nota_libertà}

                REGOLE TASSATIVE PER LA DETERMINAZIONE DEL JSON FINALE:
                1. Il verdetto di Stage 1 '{verdetto_vincolante_str}' ha valore PREVALENTE.
                2. {regola_2_testo}
                3. {regola_3_testo}
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
            
            messaggi_sanitizzati, log_sanitizzazione = engine.sanitizza_storico_per_report(messages)
            for riga in log_sanitizzazione:
                log_only(f"[SANITIZZAZIONE STORICO]: {riga}")

            base_messages_puliti = [
                m for m in messaggi_sanitizzati
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

            # RILEVAMENTO FORMATO TOOL-CALL VIETATO IN STAGE 2 
            # Alcuni modelli (es. Qwen) ricadono su una sintassi di tool-calling
            # appresa in training anche quando tools/tool_choice sono disattivati.
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

            # Parsing JSON 
            try:
                json_match = re.search(r"\{[\s\S]*\}", contenuto_raw)
                if json_match:
                    data_report = json.loads(json_match.group(0).strip())
                    v_estratto = str(data_report.get("verdetto", "")).strip().upper()
                    mot_estratta = str(data_report.get("motivazione", "")).strip()

                    if v_estratto in prompts.VERDETTI_AMMESSI and mot_estratta:
                        
                        is_correzione = (v_estratto != verdetto_vincolante_str)
                        ha_prefisso_corretto = mot_estratta.startswith("CORREZIONE RISPETTO ALLO STAGE 1:")

                        # Blocco Declassamento a BENIGN 
                        if (
                            verdetto_vincolante_str in config.CAT_ATTACCO
                            and v_estratto == "BENIGN"
                            and not is_fallback_tool
                        ):
                            log_print(f" -> [REJECT STAGE 2]: Bloccato tentativo di declassare a BENIGN da '{verdetto_vincolante_str}' (giudizio Stage 1 esplicito).")
                            storico_retry_report = [
                                {"role": "assistant", "content": contenuto_raw},
                                {"role": "user", "content": f"DIVIETO TASSATIVO: Il verdetto dello Stage 1 è '{verdetto_vincolante_str}'. Non declassare a 'BENIGN'."}
                            ]
                            continue
                        elif (
                            verdetto_vincolante_str in config.CAT_ATTACCO
                            and v_estratto == "BENIGN"
                            and is_fallback_tool
                        ):
                            log_print(f" -> [ALLOW STAGE 2]: Declassamento a BENIGN accettato: Stage 1 era solo fallback euristico, non un giudizio esplicito.")
                            if not mot_estratta.startswith("REVISIONE FALLBACK EURISTICO:"):
                                mot_estratta = f"REVISIONE FALLBACK EURISTICO: {mot_estratta}"
                                ha_prefisso_corretto = True

                        elif (
                            is_correzione
                            and not is_fallback_tool
                            and verdetto_vincolante_str in config.CAT_ATTACCO
                            and v_estratto in config.CAT_ATTACCO
                        ):
                            # AMMETTI la correzione se l'LLM cita esplicitamente nuove evidenze
                            if "NUOVE EVIDENZE:" in mot_estratta:
                                log_print(
                                    f" -> [OVERRIDE STAGE 2 AMMESSO]: correzione da "
                                    f"'{verdetto_vincolante_str}' a '{v_estratto}' motivata da nuove evidenze."
                                )
                            else:
                                log_print(
                                    f" -> [REJECT STAGE 2]: Cambio categoria da '{verdetto_vincolante_str}' "
                                    f"a '{v_estratto}' senza sezione 'NUOVE EVIDENZE:' obbligatoria."
                                )
                                storico_retry_report = [
                                    {"role": "assistant", "content": contenuto_raw},
                                    {
                                        "role": "user",
                                        "content": (
                                            f"ERRORE DI VALIDAZIONE: stai cambiando il verdetto da "
                                            f"'{verdetto_vincolante_str}' a '{v_estratto}'. Per farlo DEVI citare "
                                            "esplicitamente nuove evidenze non considerate nello Stage 1, "
                                            "iniziando la motivazione con: 'NUOVE EVIDENZE:' seguita dalla/e "
                                            "prova/e specifica/che (numeri, IP, community_id) presenti negli "
                                            "output dei tool. In assenza di nuove evidenze, ricopia il verdetto "
                                            f"'{verdetto_vincolante_str}'."
                                        )
                                    }
                                ]
                                continue

                        elif (
                            verdetto_vincolante_str == "BENIGN"
                            and v_estratto in config.CAT_ATTACCO
                            and not is_fallback_tool
                        ):
                            log_print(f" -> [REJECT STAGE 2]: Bloccato tentativo di promuovere da 'BENIGN' (giudizio Stage 1 esplicito) a '{v_estratto}'.")
                            storico_retry_report = [
                                {"role": "assistant", "content": contenuto_raw},
                                {
                                    "role": "user",
                                    "content": (
                                        "DIVIETO TASSATIVO: Il verdetto dello Stage 1 è 'BENIGN' ed è un giudizio "
                                        "esplicito dell'analista, non un fallback euristico. Non puoi promuoverlo a "
                                        f"'{v_estratto}' sulla sola base dello score euristico del tool, che lo Stage 1 "
                                        "ha già esaminato e motivatamente respinto nel Thought. Ricopia esattamente "
                                        "'BENIGN' nel campo 'verdetto', a meno che tu non stia citando nell'EVIDENZE "
                                        "OGGETTIVE un elemento specifico che lo Stage 1 non aveva considerato."
                                    )
                                }
                            ]
                            continue

                        if is_correzione and not ha_prefisso_corretto and is_fallback_tool:
                            mot_estratta = f"CORREZIONE RISPETTO ALLO STAGE 1: {mot_estratta}"
                            ha_prefisso_corretto = True

                        # Questo blocco ora scatta SOLO quando is_fallback_tool è True
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

                        if is_correzione:
                            log_print(f" [OVERRIDE STAGE 2 CONFERMATO]: Rettifica da '{verdetto_vincolante_str}' a '{v_estratto}'.")
                        else:
                            log_print(f" -> [STAGE 2]: Verdetto confermato in linea con Stage 1 ({v_estratto}).")

                        verdetto_finale = v_estratto
                        report_content = json.dumps({
                            "verdetto": verdetto_finale,
                            "motivazione": mot_estratta,
                            "ip_target": ip_target,
                            "verdetto_stage_1": verdetto_vincolante_str,
                            "is_corretto_in_stage_2": is_correzione,
                            "verdetto_suggerito_tool": verdetto_suggerito_tool,
                            "verdetto_thought_llm": verdetto_thought,
                            "forzato_da_guardia": forzato_da_guardia,
                            "stage_1_e_fallback": is_fallback_tool,
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

    metriche_tempo["tempo_totale_esecuzione"] = round(
        time.perf_counter() - tempo_inizio_assoluto, 4
    )
    
    # =========================================================================
    # USCITA UNICA DALLA FUNZIONE
    # =========================================================================
    metriche_tempo["tool_eseguiti"] = len(risultati_tool_raccolti)
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
            env=os.environ.copy(),
            err=sys.stderr
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
                # Applica automaticamente lo shift di -2 minuti al datetime di inizio
                dt_start = utils.valida_formato_timestamp(start_time_raw, minuti_anticipo=2)
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

        # CREAZIONE CARTELLA DI SESSIONE CON TIMESTAMP UNIVOCO
        ts_sessione = datetime.now().strftime("%Y%m%d_%H%M%S")
        cartella_sessione = Path("outputs") / f"SESSION_{ts_sessione}"
        cartella_sessione.mkdir(parents=True, exist_ok=True)

        analisi_avviata = True

        try:
            risultato_mcp = await esegui_analisi_mcp(
                client=llm_client,
                mcp_server_params=mcp_server_params,
                ip_target=ip_target,
                start_time=start_time_iso,
                end_time=end_time_iso,
                model_name=model_name,
                categoria_tag=cat_tag,
                max_tool_chars=max_tool_chars,
            )
            report_md = risultato_mcp.get("report") or "Nessun report generato."
            log_txt = risultato_mcp.get("log_dettagliato", "")
            telemetria_txt = json.dumps(risultato_mcp.get("metriche", {}), indent=2, ensure_ascii=False)

        except (asyncio.CancelledError, KeyboardInterrupt):
            print("\n[AVVISO]: Analisi annullata dall'utente tramite CTRL+C.")
            if isinstance(telemetria_txt, dict):
                telemetria_txt["stato"] = "annullato_da_utente"
        except Exception as e:
            print(f"\n[ERRORE DURANTE L'ESECUZIONE]: {str(e)[:config.Soglie.MAX_ERR_LOG_CHARS]}")
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

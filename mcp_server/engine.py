"""
engine.py — Funzioni di supporto "senza stato" usate da esegui_analisi_mcp
per gestire il contesto della conversazione con l'LLM e per interpretare i
risultati intermedi durante l'indagine.

COSA FA:
- Gestione contesto: applica_pruning_contesto, comprimi_messaggi_contesto,
  sanitizza_storico_per_report — tengono i messaggi inviati all'LLM sotto i
  limiti di caratteri/token, troncando o rimuovendo la cronologia più vecchia.
- Deduplicazione tool call: gestisci_e_calcola_hash_tool calcola un hash
  SHA-256 deterministico su nome tool + argomenti normalizzati, per bloccare
  chiamate identiche ripetute nello stesso ciclo investigativo.
- Euristiche di controllo flusso: _verifica_segnale_forte (rileva score >= 0.95
  nei risultati tool), _verifica_incoerenza_benign (blocca chiusure premature
  su BENIGN quando i dati mostrano anomalie), _controlla_loop_community_id
  (anti-loop su drill-down ripetuti).
- Parsing del verdetto: estrai_verdetto_pulito interpreta l'output libero
  dell'LLM (JSON, tag pseudo-tool-call, dichiarazioni testuali) ed estrae il
  verdetto finale; estrai_suggerimento_tool legge lo score di
  compute_verdict_scores.

DA CHI VIENE CHIAMATO:
- Esclusivamente da client.py, dentro il loop di esegui_analisi_mcp.
"""
import copy
import re
import ast
import hashlib
import json
from typing import Any, Dict, List, Tuple

import config, prompts # prompts serve

# ==============================================================================
# Gestione e Pulizia Memoria Context
# ==============================================================================

def normalizza_parametri_tool(valore: Any) -> Any:
    """
    Pulisce ricorsivamente dizionari e liste (rimuovendo valori None e stringhe vuote)
    e converte automaticamente le stringhe numeriche nei tipi corretti (int/float).
    """
    if isinstance(valore, dict):
        # Mantiene il sorting delle chiavi per consistenza e pulisce ricorsivamente
        risultato = {}
        for k, v in sorted(valore.items()):
            valore_pulito = normalizza_parametri_tool(v)
            if valore_pulito is not None and valore_pulito != "":
                risultato[k] = valore_pulito
        return risultato

    elif isinstance(valore, list):
        return [
            item_pulito for item in valore
            if (item_pulito := normalizza_parametri_tool(item)) is not None and item_pulito != ""
        ]

    elif isinstance(valore, str):
        valore_trimmed = valore.strip()
        
        # Converte interi (es. '30' -> 30)
        if valore_trimmed.isdigit():
            return int(valore_trimmed)
        
        # Converte float (es. '0.45' -> 0.45)
        if '.' in valore_trimmed:
            try:
                return float(valore_trimmed)
            except ValueError:
                pass
                
        return valore

    return valore

def gestisci_e_calcola_hash_tool(
    nome_funzione: str, 
    argomenti: Dict[str, Any], 
    chiamate_effettuate: set
) -> Tuple[str, Dict[str, Any], bool]:
    """
    Gestisce l'auto-incremento dell'offset in caso di chiamate duplicate per i tool di ricerca
    e calcola l'hash SHA-256 deterministico.
    """
    if not isinstance(argomenti, dict):
        argomenti = {}

    argomenti_puliti = normalizza_parametri_tool(argomenti)

    def _calcola_hash(funzione: str, args: dict) -> str:
        json_canonico = json.dumps(
            {"tool": funzione, "args": args},
            sort_keys=True,
            ensure_ascii=True,
            default=str
        )
        return hashlib.sha256(json_canonico.encode('utf-8')).hexdigest()

    if nome_funzione in ["inspect_http_requests", "search_http_l7_anomalies"]:
        if "offset" not in argomenti_puliti:
            argomenti_puliti["offset"] = 0

    hash_chiamata = _calcola_hash(nome_funzione, argomenti_puliti)
    was_auto_fixed = False

    if hash_chiamata in chiamate_effettuate and nome_funzione in ["inspect_http_requests", "search_http_l7_anomalies"]:
        step_limit = int(argomenti_puliti.get("limit", getattr(config.Soglie, "AUTO_FIX_STEP_LIMIT_DEFAULT", 15)))
        while hash_chiamata in chiamate_effettuate:
            argomenti_puliti["offset"] = int(argomenti_puliti.get("offset", 0)) + step_limit
            hash_chiamata = _calcola_hash(nome_funzione, argomenti_puliti)
        was_auto_fixed = True

    return hash_chiamata, argomenti_puliti, was_auto_fixed



def applica_pruning_contesto(
    messaggi: List[Dict[str, Any]],
    max_messaggi_recenti: int = config.Soglie.PRUNING_MAX_MESSAGES_DEFAULT,
    max_chars_tool: int = config.Soglie.PRUNING_TOOL_CHARS_DEFAULT,
) -> List[Dict[str, Any]]:
    messaggi_prunati = []
    totale_messaggi = len(messaggi)

    for idx, msg in enumerate(messaggi):
        msg_copia = copy.deepcopy(msg)

        # PROTEZIONE SYSTEM PROMPT (il messaggio iniziale non si tocca mai)
        if idx == 0 or msg_copia.get("role") == "system":
            messaggi_prunati.append(msg_copia)
            continue

        if msg_copia.get("role") in ["tool", "function"] or "tool_call_id" in msg_copia:
            contenuto = msg_copia.get("content", "")

            if isinstance(contenuto, str) and len(contenuto) > max_chars_tool:
                e_vecchio = (totale_messaggi - idx) >= max_messaggi_recenti

                if e_vecchio:
                    limite_vecchi = max(
                        config.Soglie.PRUNING_LIMITE_VECCHI_MIN, max_chars_tool // 2
                    )
                    prime_righe = "\n".join(
                        contenuto.splitlines()[: config.Soglie.PRUNING_LINEE_VECCHIE_LIMIT]
                    )[:limite_vecchi]
                    msg_copia["content"] = (
                        f"{prime_righe}\n\n"
                        f"[... RISULTATO VECCHIO TRONCATO ({len(contenuto)} char orig.) ...]"
                    )
                else:
                    msg_copia["content"] = (
                        contenuto[:max_chars_tool]
                        + f"\n\n[... TRONCATO A {max_chars_tool} CHAR (su {len(contenuto)} orig.) ...]"
                    )

        messaggi_prunati.append(msg_copia)

    return messaggi_prunati

def comprimi_messaggi_contesto(
    messages: List[Dict[str, Any]],
    max_chars: int = config.Soglie.PRUNING_MAX_CHARS_DEFAULT,
    max_messaggi_recenti: int = config.Soglie.PRUNING_MAX_MESSAGES_GPT_OSS,
) -> List[Dict[str, Any]]:
    """
    Preserva rigorosamente il System Prompt e il messaggio User corrente (con Evidenze Tool).
    Tronca o rimuove la cronologia intermedia (retry e tool vecchi) per restare sotto 'max_chars'.
    """
    if not messages:
        return []

    sys_message = messages[0] if messages[0].get("role") == "system" else None
    
    # L'ultimo messaggio è il prompt di generazione corrente con le Evidenze Tool fresche
    ultimo_messaggio = messages[-1]
    
    # Estraiamo i messaggi intermedi (storico retry e base messages)
    inizio_intermedi = 1 if sys_message else 0
    intermedi = messages[inizio_intermedi:-1]

    # Prendiamo prioritariamente gli ultimi N messaggi recenti della cronologia intermedia
    intermedi_recenti = (
        intermedi[-max_messaggi_recenti:] 
        if len(intermedi) > max_messaggi_recenti 
        else intermedi
    )

    # Helper interno per calcolare la lunghezza reale del testo
    def _get_content_len(msg: Dict[str, Any]) -> int:
        c = msg.get("content", "")
        if isinstance(c, str):
            return len(c)
        elif isinstance(c, list):
            return sum(len(str(elem)) for elem in c)
        return len(str(c))

    messaggi_finali = []
    if sys_message:
        messaggi_finali.append(sys_message)
    
    chars_correnti = _get_content_len(sys_message) if sys_message else 0
    chars_ultimo = _get_content_len(ultimo_messaggio)
    
    # Budget rimanente per la cronologia dei retry
    budget_intermedio = max_chars - chars_correnti - chars_ultimo

    intermedi_accettati = []
    buffer_margine = 50  # Margine di sicurezza per la stringa di avviso troncamento

    for m in reversed(intermedi_recenti):
        content_len = _get_content_len(m)
        if budget_intermedio - content_len >= 0:
            intermedi_accettati.insert(0, m)
            budget_intermedio -= content_len
        else:
            # Se un messaggio di retry è troppo lungo, lo tronchiamo per non sforare
            m_copy = m.copy()
            content_val = m_copy.get("content")
            
            if isinstance(content_val, str) and budget_intermedio > (config.Soglie.BEACON_DOS_VOLUME_THRESHOLD):
                limite_safe = max(0, budget_intermedio - buffer_margine)
                m_copy["content"] = content_val[:limite_safe] + "\n[... Contesto intermedio compresso ...]"
                intermedi_accettati.insert(0, m_copy)
                break

    messaggi_finali.extend(intermedi_accettati)
    messaggi_finali.append(ultimo_messaggio)

    return messaggi_finali

def sanitizza_storico_per_report(
    messaggi: List[Dict[str, Any]]
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """
    Rimuove dallo storico:
    1. I messaggi di feedback temporanei.
    2. I messaggi assistant con 'tool_calls' orfani (senza i rispettivi messaggi 'tool' di risposta).
    Garantisce la conformita' con le specifiche di OpenAI/Groq API.

    Ritorna (messaggi_puliti, righe_di_log): la lista pulita e un elenco di
    stringhe descrittive delle rimozioni avvenute, da loggare a discrezione
    del chiamante (mai stampate direttamente).
    """
    messaggi_puliti = []
    righe_di_log: List[str] = []
    i = 0
    n = len(messaggi)

    while i < n:
        msg = messaggi[i]
        role = msg.get("role")
        content = msg.get("content") or ""

        if role == "user" and (
            content.startswith("[SISTEMA DEGLI ERRORI]")
            or content.startswith("SISTEMA - NOTA DI PROGRESO:")
        ):
            i += 1
            continue

        if role == "assistant" and msg.get("tool_calls"):
            tool_calls = msg.get("tool_calls", [])
            num_calls = len(tool_calls)

            j = i + 1
            risposte_trovate = 0
            while (
                j < n
                and messaggi[j].get("role") == "tool"
                and risposte_trovate < num_calls
            ):
                risposte_trovate += 1
                j += 1

            if risposte_trovate < num_calls:
                righe_di_log.append(
                    f"Rimosso messaggio assistant orfano con {num_calls} tool_calls."
                )
                i = j
                continue

            for k in range(i, j):
                messaggi_puliti.append(messaggi[k])

            i = j
            continue

        if role == "tool":
            righe_di_log.append(
                "Rimosso messaggio 'tool' isolato senza assistant precedente."
            )
            i += 1
            continue

        messaggi_puliti.append(msg)
        i += 1

    return messaggi_puliti, righe_di_log

# ==========================================
# FUNZIONI HELPER PER LOGICA D'INDAGINE
# ==========================================

def _verifica_segnale_forte(testo_risultato: str) -> bool:
    """Verifica se l'output di un tool contiene un punteggio di anomalia o verdetto >= 0.95."""
    try:
        data = json.loads(testo_risultato)
        if not isinstance(data, dict):
            return False

        verdict_scores = data.get("scores", {})
        if any(score >= 0.95 for score in verdict_scores.values() if isinstance(score, (int, float))):
            return True

        anomaly_score = data.get("anomaly_score") or data.get("max_anomaly_score") or data.get("confidence")
        if isinstance(anomaly_score, (int, float)):
            # Supporta sia scala 0.0-1.0 che 0-100
            if anomaly_score >= 0.95 and anomaly_score <= 1.0:
                return True
            if anomaly_score >= 95.0:
                return True

        verdetto_suggerito = data.get("verdetto_suggerito")
        score_dominante = data.get("score_dominante", 0)
        if verdetto_suggerito and score_dominante >= 0.95:
            return True

    except Exception:
        pass
    return False

def _verifica_incoerenza_benign(risultati_tool: list) -> bool:
    """Verifica se un verdetto BENIGN viola le evidenze di traffico raccolte."""
    max_pps = 0.0
    anomalia_strutturata = False

    for res in risultati_tool or []:
        testo = res.get("result") if isinstance(res, dict) else None
        if not isinstance(testo, str):
            continue
        try:
            data = json.loads(testo)
        except Exception:
            continue
        if not isinstance(data, dict):
            continue

        sintesi = data.get("sintesi_smart") or {}
        if isinstance(sintesi, dict):
            if sintesi.get("anomalie_l7_trovate", 0) > 0:
                anomalia_strutturata = True
            if sintesi.get("candidati_trovati", 0) > 0:
                anomalia_strutturata = True
            if sintesi.get("sospetto_web_bruteforce"):
                anomalia_strutturata = True
            if sintesi.get("sospetto_portscan") or sintesi.get("sospetto_bruteforce"):
                anomalia_strutturata = True
            if sintesi.get("beaconing_c2_rilevato"):
                anomalia_strutturata = True
            if sintesi.get("stato_anomalia") == "ANOMALIA_RILEVATA" or sintesi.get("stato") == "ANOMALIA_RILEVATA":
                anomalia_strutturata = True

        mk = data.get("metriche_chiave") or {}
        if isinstance(mk, dict):
            pps_val = float(mk.get("pps_aggregati") or mk.get("burst_pps") or 0.0)
            if pps_val > max_pps:
                max_pps = pps_val

        for categoria in ("DOS_VOLUMETRIC", "SCAN_BRUTEFORCE", "BEACONING_C2", "WEB_ATTACK_EXPLOIT"):
            valore = data.get(categoria)
            if isinstance(valore, (int, float)) and valore >= 0.5:
                anomalia_strutturata = True

    return anomalia_strutturata or (max_pps >= config.Soglie.DOS_PPS_MIN)

def _controlla_loop_community_id(messages: list) -> bool:
    """Verifica se il modello sta eseguendo chiamate ripetute a Community ID."""
    consecutive_calls = 0
    for m in reversed(messages):
        if m.get("role") == "assistant" and m.get("tool_calls"):
            t_name = m["tool_calls"][0].get("function", {}).get("name")
            if t_name == "analizza_connessione_by_community_id":
                consecutive_calls += 1
            else:
                break
        elif m.get("role") != "user":
            break
    return consecutive_calls >= 2



def _applica_auto_paginazione(nome_funzione: str, argomenti: dict) -> dict:
    """Applica un limit minimo di sicurezza per inspect_http_requests e garantisce
    che 'offset' sia sempre presente. L'avanzamento offset su chiamate duplicate
    è gestito da gestisci_e_calcola_hash_tool (hash reali), non qui."""
    if nome_funzione not in ["inspect_http_requests", "search_http_l7_anomalies"]:
        return argomenti

    if nome_funzione == "inspect_http_requests":
        argomenti["limit"] = max(int(argomenti.get("limit", 50)), 50)

    argomenti.setdefault("offset", 0)
    return argomenti

def _arricchisci_risultato_tool(testo_risultato: str, nome_funzione: str) -> str:
    """Aggiunge avvisi dinamici al contesto in base all'esito del tool."""
    try:
        res_payload = json.loads(testo_risultato)
        if not isinstance(res_payload, dict):
            return testo_risultato

        # Warning Campione Ridotto
        totale_flussi = (
            res_payload.get("sintesi_smart", {}).get("totale_flussi_reali", 0)
            if nome_funzione == "get_traffic_summary"
            else res_payload.get("totale_flussi_nella_finestra", 0)
        )
        if 0 < totale_flussi < config.Soglie.SCAN_PORTE_MIN:
            testo_risultato += (
                f"\n\n[AVVISO SISTEMA - CAMPIONE RIDOTTO]: Trovati solo {totale_flussi} flussi. "
                "NON concludere affrettatamente con 'BENIGN' se vi è il sospetto di scansioni intermittenti."
            )

        # Warning Paginazione Web
        if nome_funzione in ["inspect_http_requests", "search_http_l7_anomalies"]:
            totale_req = res_payload.get("totale_richieste_ispezionate", 0) or res_payload.get("sintesi_smart", {}).get("anomalie_l7_trovate", 0)
            if totale_req > 0 and res_payload.get("sintesi_smart", {}).get("anomalie_l7_trovate", 0) == 0:
                testo_risultato += (
                    "\n\n[AVVISO SISTEMA - ISPEZIONE WEB]: Nessuna anomalia nelle prime richieste. "
                    "Valuta di avanzare l'offset prima di escludere WEB_ATTACK_EXPLOIT."
                )
    except Exception:
        pass

    return testo_risultato

def sanifica_risultato_tool(testo: str) -> str:
    """Rimuove caratteri di controllo non stampabili che causano crash su modelli oss."""
    if not testo:
        return ""
    # Mantiene solo i caratteri stampabili standard e i newline/tab
    return re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', testo)

def sintetizza_payload_tool(json_str: str, max_elementi_lista: int = 3) -> str:
    """
    Intercetta i payload JSON dei tool e riduce le liste campionate
    mantenendo inalterate le metriche aggregate di sintesi.
    """
    try:
        data = json.loads(json_str)
        if isinstance(data, dict):
            for chiave in ["campione_flussi_recenti", "flussi_campionati", "anomalie_estratte", "requests"]:
                if chiave in data and isinstance(data[chiave], list):
                    totale_originale = len(data[chiave])
                    if totale_originale > max_elementi_lista:
                        data[chiave] = data[chiave][:max_elementi_lista]
                        data[f"nota_campionamento_{chiave}"] = (
                            f"Mostrati solo i primi {max_elementi_lista} elementi "
                            f"su un totale di {totale_originale} campioni estratti."
                        )
            return json.dumps(data, ensure_ascii=False)
    except Exception:
        pass
    return json_str



def _ha_rilevato_anomalie_l7_reali(risultati_tool_raccolti: list) -> bool:
    """
    Verifica, sui risultati grezzi già raccolti, se è presente un'anomalia
    strutturata e SPECIFICA (non solo un PPS/byte_rate sopra soglia generico)
    che giustifichi il blocco di una chiusura prematura su BENIGN: anomalie
    L7 esplicite, Web Brute Force o endpoint di login confermati, Scan/Brute
    Force L4, Beaconing C2 già confermato dal tool, Slowloris confermato, o
    uno score deterministico di compute_verdict_scores già >= 0.5 per una
    qualsiasi categoria malevola.
    """
    for res in risultati_tool_raccolti or []:
        testo = res.get("result")
        if not isinstance(testo, str):
            continue
        try:
            data = json.loads(testo)
        except Exception:
            continue
        if not isinstance(data, dict):
            continue

        sintesi = data.get("sintesi_smart") or {}

        if int(sintesi.get("anomalie_l7_trovate") or 0) > 0:
            return True
        if sintesi.get("sospetto_web_bruteforce") and int(sintesi.get("max_tentativi_per_ip") or 0) > 0:
            return True
        if sintesi.get("login_endpoint_targeted"):
            return True
        if sintesi.get("sospetto_portscan") or sintesi.get("sospetto_bruteforce"):
            return True
        if sintesi.get("beaconing_c2_rilevato"):
            return True
        if int(sintesi.get("flussi_slowloris_confermati") or 0) > 0:
            return True

        for categoria in ("DOS_VOLUMETRIC", "SCAN_BRUTEFORCE", "BEACONING_C2", "WEB_ATTACK_EXPLOIT"):
            valore = data.get(categoria)
            if isinstance(valore, (int, float)) and valore >= 0.5:
                return True

    return False


def estrai_verdetto_euristico_da_risultati(risultati_tool_raccolti: list) -> str:
    """
    Fallback ESTREMO per quando anche la chiamata LLM finale a max turni
    fallisce (timeout/errore di rete): deriva un verdetto solo dai dati
    grezzi già raccolti, senza alcun ragionamento LLM. Riusa la stessa logica
    di 'estrai_suggerimento_tool' (basata sullo score deterministico di
    compute_verdict_scores, se già eseguito); se il tool non è mai stato
    chiamato o non ha prodotto un verdetto valido, ricade sull'evidenza
    strutturale grezza già raccolta.
    """
    verdetto_tool, _ = estrai_suggerimento_tool(risultati_tool_raccolti)
    verdetti_validi = {"DOS_VOLUMETRIC", "SCAN_BRUTEFORCE", "BEACONING_C2", "WEB_ATTACK_EXPLOIT", "BENIGN"}

    if verdetto_tool in verdetti_validi:
        return verdetto_tool

    if _ha_rilevato_anomalie_l7_reali(risultati_tool_raccolti):
        return "NON_IDENTIFICATO"  # anomalia presente ma categoria non determinabile senza LLM

    return "BENIGN"

# ==============================================================================
# PARSING DEL VERDETTO DELL'LLM
# ==============================================================================

def estrai_verdetto_pulito(*args) -> str:
    """
    Estrae il verdetto espresso dall'LLM dando priorità assoluta all'ultimo blocco JSON 
    o alle dichiarazioni esplicite finali, per evitare di catturare menzioni intermedie.
    """
    # Normalizzazione e pulizia dell'input dai parametri *args
    report_md = ""
    for arg in reversed(args):
        if hasattr(arg, "choices") and arg.choices:
            report_md = arg.choices[0].message.content or ""
            break
        elif arg and isinstance(arg, str) and str(arg).strip() not in ["None", "-", ""]:
            report_md = str(arg)
            break

    if not report_md or not report_md.strip():
        return "NON_IDENTIFICATO"

    testo = report_md.strip()

    # Recupero dinamico dei verdetti ammessi
    verdetti_default = {"DOS_VOLUMETRIC", "SCAN_BRUTEFORCE", "BEACONING_C2", "WEB_ATTACK_EXPLOIT", "BENIGN"}
    
    prompts_mod = globals().get("prompts", None)
    config_mod = globals().get("config", None)
    
    verdetti_validi = set(
        getattr(prompts_mod, "VERDETTI_AMMESSI", 
        getattr(config_mod, "VERDETTI_AMMESSI", verdetti_default))
    )

    # PARSING JSON (Cerca il verdetto negli ultimi blocchi JSON validi)
    # Estrazione mirata dei blocchi ```json ... ```
    json_blocks = re.findall(r"```(?:json)?\s*([\s\S]*?)\s*```", testo)
    
    # FIX ERRORE SINTASSI (regex bilanciata per catturare qualsiasi struttura { ... })
    if not json_blocks:
        json_blocks = re.findall(r"\{[\s\S]*?\}", testo)

    for block in reversed(json_blocks):
        try:
            start_idx = block.find("{")
            end_idx = block.rfind("}")
            if start_idx != -1 and end_idx != -1:
                clean_json = block[start_idx : end_idx + 1]
                data = json.loads(clean_json)
                if isinstance(data, dict):
                    cand = str(
                        data.get("verdetto") 
                        or data.get("verdetto_finale") 
                        or data.get("verdetto_suggerito_euristica") 
                        or ""
                    ).strip().upper()
                    
                    if cand in verdetti_validi:
                        return cand
        except Exception:
            continue

    # PARSING TAG XML PSEUDO-TOOLCALL (alcuni modelli, es. Qwen, emettono
    # <function=...><parameter=verdetto>VALORE</parameter></function> come
    # testo libero anche quando tools/tool_choice sono disattivati). 
    pattern_xml_param = re.compile(
        r"<parameter[^>]*\bverdetto\b[^>]*>\s*([A-Z0-9_\-]+)\s*</parameter>",
        re.IGNORECASE,
    )
    matches_xml = list(pattern_xml_param.finditer(testo))
    if matches_xml:
        for match in reversed(matches_xml):
            cand = match.group(1).strip().upper()
            if cand in verdetti_validi:
                return cand
            
    # REGEX SU DICHIARAZIONE ESPLICITA FINALE 
    pattern = r"(?:verdetto|classificazione|conclusione)(?:\s+finale)?\s*(?:è|e'|:|=)\s*[`'\"]*([A-Z0-9_-]+)[`'\"]*"
    matches = list(re.finditer(pattern, testo, re.IGNORECASE))
    if matches:
        for match in reversed(matches):
            v_cand = match.group(1).strip().upper()
            if v_cand in verdetti_validi:
                return v_cand

    # SCANNING DI PROSSIMITÀ SUL TESTO FINALE
    testo_finale = testo[-1500:].upper()
    candidati_trovati = []

    blacklist_negazione = ["ESCLUSO", "SCARTATO", "NON È", "NON E", "NON SI TRATTA", "ESCLUDO", "IMPROBABILE"]

    for verdetto in verdetti_validi:
        for match in re.finditer(rf"\b{re.escape(verdetto)}\b", testo_finale):
            start_pos = max(0, match.start() - 40)
            contesto_precedente = testo_finale[start_pos:match.start()]
            
            # Se è preceduto da negazione, ignora questo match
            if any(neg in contesto_precedente for neg in blacklist_negazione):
                continue
                
            candidati_trovati.append((match.start(), verdetto))

    if candidati_trovati:
        candidati_trovati.sort(key=lambda x: x[0], reverse=True)
        return candidati_trovati[0][1]

    return "NON_IDENTIFICATO"

def estrai_suggerimento_tool(risultati_tool_raccolti: list) -> tuple[str, str]:
    """
    Estrae il verdetto vincente unicamente
    in base ai punteggi numerici restituite da compute_verdict_scores.
    Nessun override arbitrario basato su stringhe.
    """
    verdetto_suggerito = "NON_DISPONIBILE"
    motivo_override = "Nessun override o score valido rilevato."

    if not risultati_tool_raccolti:
        return verdetto_suggerito, motivo_override

    try:
        for res in risultati_tool_raccolti:
            if isinstance(res, dict) and res.get("tool_name") == "compute_verdict_scores":
                raw_out = res.get("result") or res.get("output") or {}

                if isinstance(raw_out, str):
                    try:
                        data_out = json.loads(raw_out)
                    except Exception:
                        data_out = ast.literal_eval(raw_out)
                else:
                    data_out = raw_out

                if isinstance(data_out, dict):
                    scores = {
                        "DOS_VOLUMETRIC": float(data_out.get("DOS_VOLUMETRIC") or 0.0),
                        "SCAN_BRUTEFORCE": float(data_out.get("SCAN_BRUTEFORCE") or 0.0),
                        "BEACONING_C2": float(data_out.get("BEACONING_C2") or 0.0),
                        "WEB_ATTACK_EXPLOIT": float(data_out.get("WEB_ATTACK_EXPLOIT") or 0.0),
                    }

                    note = data_out.get("note_logiche") or ""
                    if isinstance(note, list):
                        note = " ".join([str(x) for x in note])

                    verdetti_validi_locali = {"DOS_VOLUMETRIC", "SCAN_BRUTEFORCE", "BEACONING_C2", "WEB_ATTACK_EXPLOIT", "BENIGN"}
                    verdetto_dal_tool = str(data_out.get("verdetto_suggerito_euristica") or "").strip().upper()

                    if verdetto_dal_tool in verdetti_validi_locali:
                        verdetto_suggerito = verdetto_dal_tool
                        motivo_override = note if note else f"Verdetto dominato da {verdetto_suggerito}."
                    elif verdetto_dal_tool == "CONFLITTO_IRRISOLTO":
                        pari_merito = data_out.get("conflitto_a_pari_merito") or []
                        verdetto_suggerito = f"CONFLITTO_IRRISOLTO tra {pari_merito}"
                        motivo_override = note if note else "Conflitto a pari merito non risolvibile dalle evidenze grezze."
                    else:
                        max_kat, max_score = max(scores.items(), key=lambda x: x[1])
                        verdetto_suggerito = max_kat if max_score >= 0.5 else "BENIGN"
                        motivo_override = note if note else f"Verdetto dominato da {verdetto_suggerito}."

                break
    except Exception as e:
        motivo_override = f"Errore durante l'estrazione: {e}"

    return verdetto_suggerito, motivo_override

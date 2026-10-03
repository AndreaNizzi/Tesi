# Integrazione di Large Language Models (LLM) in sistemi di Deep Packet Inspection


Sistema di network forensics basato su LLM: un agente indaga il traffico di
un host target tramite un server MCP che espone tool di analisi (statistiche
di rate, distribuzione porte, anomalie L7, beaconing) e produce un verdetto
di classificazione tra `DOS_VOLUMETRIC`, `SCAN_BRUTEFORCE`, `BEACONING_C2`,
`WEB_ATTACK_EXPLOIT` o `BENIGN`, motivato dalle evidenze raccolte.

Il repository copre l'intero ciclo di vita del dato: dalla pipeline di
ingestion dei flussi (CIC-IDS-2017 + nDPI) fino all'analisi condotta
dall'agente LLM tramite MCP.

---

## Indice

1. [Requisiti](#requisiti)
2. [Setup](#setup)
3. [Pipeline di Ingestion Dati](#pipeline-di-ingestion-dati)
   - [Architettura del Workflow](#architettura-del-workflow)
   - [Configurazione Database](#configurazione-database)
   - [Esecuzione della Pipeline](#esecuzione-della-pipeline)
   - [Validazione e Cross-Correlazione](#validazione-e-cross-correlazione)
4. [Sistema di Analisi LLM + MCP](#sistema-di-analisi-llm--mcp)
   - [Uso: Analisi Singola](#uso-analisi-singola-interattiva)
   - [Uso: Benchmark Automatizzato](#uso-benchmark-automatizzato-con-ground-truth)
   - [Risultati di Riferimento](#risultati-di-riferimento)
5. [Struttura del Repository](#struttura-del-repository)
6. [Limiti Noti](#limiti-noti)

---

## Requisiti

- Python 3.11+
- MySQL con le tabelle:
  - `ndpi_flows` — dati di flusso arricchiti nDPI
  - `cic_flows` — ground truth di riferimento (colonne `label`, `src_ip`,
    `dst_ip`, `timestamp_start`), usata solo da `test_suite.py` per l'auditing
  - `flow_mapping` — vista allineata tra `ndpi_flows` e `cic_flows`, usata
    per l'auditing e la generazione degli scenari
- Accesso API a un modello LLM compatibile OpenAI (Groq o endpoint Interhost)
- Tool esterni per la generazione dei dati in locale: **CICFlowMeter** e
  **ndpiReader**
- Dataset **CIC-IDS-2017** scaricato e posizionato nelle cartelle di lavoro:
  [https://www.unb.ca/cic/datasets/ids-2017.html](https://www.unb.ca/cic/datasets/ids-2017.html)

*Nota: a causa delle dimensioni elevate dei file PCAP (circa 50 GB
complessivi), questi non sono inclusi nella repository e vanno scaricati
autonomamente.*

---

## Setup

1. **Clona il repository e crea un ambiente virtuale:**

   ```bash
   python -m venv venv
   source venv/bin/activate      # Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

   Le dipendenze principali sono: `openai`, `mcp`, `sqlalchemy`, `pymysql`,
   `python-dotenv`, `httpx`, `communityid`. Per i dettagli completi si
   rimanda al file `requirements.txt`.

2. **Crea un file `.env` nella root del progetto:**

   ```
   DB_PASSWORD=<password del database MySQL>

   GROQ_API_KEY=<chiave API Groq, opzionale se usi solo Interhost>
   GROQ_BASE_URL=<indirizzo Groq, opzionale se usi solo Interhost>
   GROQ_MODEL_NAME=openai/gpt-oss-120b

   INTERHOST_API_KEY=<chiave API Interhost, opzionale se usi solo Groq>
   INTERHOST_BASE_URL=<indirizzo Interhost, opzionale se usi solo Groq>
   INTERHOST_MODEL_NAME=Qwen3.8-27B
   ```

   *Nota: il nome del modello Interhost deve corrispondere a quello fornito
   dall'endpoint e configurato in `utils.seleziona_modello_engine()`.*

3. **Prepara il database e popola i dati** seguendo la sezione
   [Pipeline di Ingestion Dati](#pipeline-di-ingestion-dati).

---

## Pipeline di Ingestion Dati

Framework modulare in Python per l'estrazione, la bonifica, la correlazione
e il popolamento su MySQL dei flussi di rete estratti dal dataset pubblico
**CIC-IDS-2017**, combinando i flussi statistici ufficiali con metriche
applicative avanzate tramite Deep Packet Inspection (nDPI).

### Architettura del Workflow

```text
  [File CSV Grezzi ISCX]                     [Traffico PCAP]
            │                                       │
            ▼                                       ▼
 [ FASE 0: PRE-PROCESSING ]                     ndpiReader
 (Merge_Ufficiali.py + Preprocessing.py)            │
            │                                       │
            ▼                                       ▼
 [CSV Giornalieri Puliti]                      [JSON Lines]
            │                                       │
            ▼                                       ▼
 [ FASE 1: MERGE & LABEL ]           [ FASE 2: DPI EXTRACTION ]
 (Join_CSV.py)                       (Popola_DB_json_ndpiReader.py)
            │                                       │
            └───┬───────────────────────────────────┘
                │
                ▼
    [ FASE 3: TIME ALIGNMENT ] ──► Correzione Offset (-5h CIC / -3h nDPI)
                │
                ▼
    [ FASE 4: BULK INGESTION ] ──► Transazioni Atomiche (chunksize 20k)
                │
                ▼
    [ FASE 5: CROSS-JOIN ]     ──► flow_mapping (±5min → drift≤60s)
```

### Configurazione Database

#### 1. Inizializzazione Schema

```sql
CREATE DATABASE thesis_network;
USE thesis_network;
```

#### 2. Generazione Tabelle

Entrambe le tabelle usano come chiave primaria surrogata (`id`) di tipo
intero sequenziale per prevenire la frammentazione dei blocchi di memoria su
disco (page splitting) causata dalla casualità degli hash stringa. Il
`community_id` viene preservato come chiave di correlazione multi-istanza.

**Tabella `ndpi_flows` (dati estratti con ndpiReader):**

```sql
CREATE TABLE ndpi_flows (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    community_id VARCHAR(50) NOT NULL,
    src_ip VARCHAR(45) NOT NULL,
    dst_ip VARCHAR(45) NOT NULL,
    src_port INT UNSIGNED NOT NULL,
    dst_port INT UNSIGNED NOT NULL,
    protocol INT UNSIGNED NOT NULL,
    timestamp_start TIMESTAMP(6) NOT NULL,
    duration_ms DOUBLE NOT NULL,
    total_bytes BIGINT UNSIGNED NOT NULL,
    fwd_packets BIGINT UNSIGNED NOT NULL,
    bwd_packets BIGINT UNSIGNED NOT NULL,
    total_fwd_bytes BIGINT UNSIGNED NOT NULL,
    total_bwd_bytes BIGINT UNSIGNED NOT NULL,
    packet_rate DOUBLE NOT NULL,
    byte_rate DOUBLE NOT NULL,
    iat_flow_avg DOUBLE NOT NULL,
    iat_flow_stddev DOUBLE NOT NULL,
    tcp_flags INT NULL,                    -- bitmask intera
    ndpi_hostname VARCHAR(255) NULL,
    payload_entropy DOUBLE NULL,           -- flag binario 0/1
    app_hierarchy VARCHAR(100) NULL,
    infra_provider VARCHAR(100) NULL,
    tls_version VARCHAR(10) NULL,
    tls_cipher_suite VARCHAR(100) NULL,
    tls_ja4 VARCHAR(36) NULL,
    tls_issuer_dn VARCHAR(255) NULL,
    INDEX idx_ndpi_comm_time (community_id(50), timestamp_start),
    INDEX idx_src_ip (src_ip)
);
```

**Tabella `cic_flows` (dati CICFlowMeter + Label ufficiale):**

```sql
CREATE TABLE cic_flows (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    community_id VARCHAR(50) NOT NULL,
    src_ip VARCHAR(45) NOT NULL,
    dst_ip VARCHAR(45) NOT NULL,
    src_port INT UNSIGNED NOT NULL,
    dst_port INT UNSIGNED NOT NULL,
    protocol INT UNSIGNED NOT NULL,
    timestamp_start TIMESTAMP(6) NOT NULL,
    duration_ms DOUBLE NOT NULL,
    total_bytes BIGINT UNSIGNED NOT NULL,
    fwd_packets BIGINT UNSIGNED NOT NULL,
    bwd_packets BIGINT UNSIGNED NOT NULL,
    total_fwd_bytes BIGINT UNSIGNED NOT NULL,
    total_bwd_bytes BIGINT UNSIGNED NOT NULL,
    packet_rate DOUBLE NOT NULL,
    byte_rate DOUBLE NOT NULL,
    iat_flow_avg DOUBLE NOT NULL,
    iat_flow_stddev DOUBLE NOT NULL,
    label VARCHAR(50) NULL DEFAULT 'BENIGN',
    INDEX idx_cic_comm_time (community_id(50), timestamp_start),
    INDEX idx_label (label)
);
```

**Tabella `flow_mapping` (vista allineata ndpi ↔ cic, per auditing):**

```sql
CREATE TABLE flow_mapping (
    community_id VARCHAR(128) NOT NULL,
    ndpi_ts DATETIME(6) NOT NULL,
    cic_ts DATETIME(6) NOT NULL,
    label VARCHAR(64) NOT NULL,
    drift_sec INT NOT NULL,
    PRIMARY KEY (community_id, ndpi_ts),
    INDEX idx_fm_label_ts (label, ndpi_ts)
);
```

La query di popolamento di `flow_mapping` è riportata in Appendice B della
tesi (popolamento per giorno per evitare timeout su tabelle di grandi
dimensioni).

#### 3. Configurazione Credenziali

Le credenziali del database vengono lette dal file `.env` nella root del
progetto (vedi [Setup](#setup)). Assicurati che la variabile `DB_PASSWORD`
sia impostata correttamente.

### Esecuzione della Pipeline

Eseguire gli script rispettando l'ordine cronologico descritto per garantire
l'integrità referenziale dei dati.

#### Passo 0 — Consolidamento CSV ufficiali (Giovedì e Venerdì)

I CSV ufficiali del dataset CIC distribuiscono Giovedì e Venerdì su più file
distinti. Questo script li consolida in due file completi, usati come
riferimento per il join.

```bash
python Merge_Ufficiali.py
```

**Output:** `Thursday-Ufficiali-Completo.csv`, `Friday-Ufficiali-Completo.csv`.

#### Passo 1 — Pre-processing dei CSV ufficiali

Pulisce i file CSV originali ISCX rimuovendo le righe di header duplicate,
normalizzando gli spazi bianchi e gestendo le eccezioni matematiche
(Infinity, NaN).

```bash
python Preprocessing.py
```

**Output:** file purificati `*-Pulito-Definitivo.csv` per ogni giornata.

#### Passo 2 — Estrazione locale con CICFlowMeter

Esegui CICFlowMeter sui 5 file PCAP del dataset per ottenere i CSV locali
con le feature statistiche. Il comando esatto dipende dal modo in cui
CICFlowMeter è installato (applicazione Java, wrapper Python
`cicflowmeter`, interfaccia grafica).

Un esempio tipico con il wrapper Python è:

```bash
cicflowmeter -f Monday-WorkingHours.pcap -c Lunedi.csv
```

Ripeti il comando per ciascuno dei 5 PCAP del dataset, producendo un CSV
per giornata (`Lunedi.csv`, `Martedi.csv`, ..., `Venerdi.csv`).

*Nota: i CSV prodotti da CICFlowMeter vanno usati come primo argomento di
`Join_CSV.py` al Passo 3, mentre i CSV ufficiali puliti prodotti al Passo 1
vanno usati come secondo argomento.*

#### Passo 3 — Matching e Labeling

Calcola il Community ID bidirezionale e applica `pd.merge_asof` (tolleranza
± 60s) per associare i flussi generati in locale alle rispettive etichette
del dataset ufficiale, correggendo lo shift del formato orario pomeridiano.

```bash
python Join_CSV.py <File_CICFlowMeter_Locale.csv> <File_Ufficiale_Pulito.csv> <Output_Join_Giorno.csv>
```

**Output:** file `*-Join.csv` (es. `Lunedi-Join.csv`, `Martedi-Join.csv`),
usati dallo script di popolamento del passo successivo.

#### Passo 4 — Estrazione Metadati Avanzati (nDPI)

Elaborazione del traffico PCAP nativo tramite il motore di Deep Packet
Inspection:

```bash
./ndpiReader --cfg "tls,max_num_blocks_to_analyze,8" -i <file_cattura.pcap> -K json -k <output_ndpi.json>
```

**Output:** un file JSON Lines per ogni PCAP processato, contenente le
feature applicative L7 (SNI, TLS, entropia, provider).

Per coerenza con il comando PowerShell del Passo 6, rinomina ogni file di
output in modo che termini con `_ndpiReader.json`, ad esempio:

```bash
# Esempio per il Lunedì
mv output_ndpi.json Monday-WorkingHours_ndpiReader.json
```

Se preferisci evitare il rename manuale, salta questo passaggio e usa al
Passo 6 il comando PowerShell semplificato che prende tutti i `.json`
(vedi nota al Passo 6).

#### Passo 5 — Ingestion Massiva nel DBMS (dati CIC)

Lo script legge i file `*-Join.csv` prodotti al Passo 3 (nomi hard-coded
all'interno dello script) e li carica in `cic_flows` a blocchi di 20.000
record.

```bash
python Popola_DB_CSV_Ufficiali.py
```

*Nota: i file `Lunedi-Join.csv`, `Martedi-Join.csv`, `Mercoledi-Join.csv`,
`Giovedi-Join.csv`, `Venerdi-Join.csv` devono essere presenti nella cartella
di lavoro con questi nomi esatti.*

#### Passo 6 — Ingestion Massiva nel DBMS (dati nDPI)

Caricamento stream-based riga per riga per file JSONLines di grandi
dimensioni.

**Opzione A (consigliata) — tutti i file `.json` nella cartella:**

```powershell
Get-ChildItem *.json | ForEach-Object {
    python Popola_DB_json_ndpiReader.py $_.FullName
}
```

Questa opzione è robusta: prende tutti i file JSON nella cartella corrente
e li passa allo script. Va usata se nella cartella sono presenti **solo**
i file JSON prodotti da `ndpiReader`.

**Opzione B — solo i file con un pattern specifico:**

```powershell
Get-ChildItem *-WorkingHours_ndpiReader.json | ForEach-Object {
    python Popola_DB_json_ndpiReader.py $_.FullName
}
```

Questa opzione è utile se nella cartella ci sono **anche altri file JSON**
non pertinenti. Richiede che i file di output di `ndpiReader` siano stati
rinominati con il suffisso `_ndpiReader.json` (vedi nota al Passo 4).

*Nota: lo script `Popola_DB_json_ndpiReader.py` accetta come argomento sia
un path assoluto a un singolo file sia un pattern glob. In entrambe le
opzioni sopra, PowerShell espande già il pattern e passa un file per
iterazione.*

#### Passo 7 (opzionale) — Popolamento con traffico reale

Per il test su traffico reale (non CIC-IDS), esiste uno script dedicato che
popola `ndpi_flows` con la stessa logica del Passo 6 ma senza le correzioni
di offset pensate per il dataset CIC. È lo script usato per la validazione
su traffico reale discussa nel §7.6.6 della tesi (18 finestre da 15 minuti).

```bash
python Popola_DB_json_ndpiReader_traffico_normale.py <pattern_json>
```

**Esempio concreto:**

```bash
python Popola_DB_json_ndpiReader_traffico_normale.py "traffico_reale_*.json"
```

I file JSON di input devono essere stati prodotti da `ndpiReader` con gli
stessi flag del Passo 4. La differenza rispetto al Passo 6 è che i timestamp
non subiscono la sottrazione di 3 ore, perché il traffico reale non ha
l'offset del dataset CIC.

### Validazione e Cross-Correlazione

Il disallineamento temporale tra `cic_flows` e `ndpi_flows` è risolto dalla
tabella `flow_mapping`, popolata con la query in Appendice B della tesi
(finestra candidata ± 5 minuti, filtro `drift_sec <= 60`).

Per verificare che uno scenario contenga effettivamente il traffico d'attacco
atteso, si interroga `flow_mapping` per ottenere la distribuzione delle
label CIC nella finestra:

```sql
SELECT f.label, COUNT(*) AS cnt
FROM ndpi_flows AS n
JOIN flow_mapping AS f
  ON f.community_id = n.community_id
 AND f.ndpi_ts = n.timestamp_start
WHERE (n.src_ip = :ip OR n.dst_ip = :ip)
  AND n.timestamp_start >= :start_time
  AND n.timestamp_start < :end_time
GROUP BY f.label
ORDER BY cnt DESC;
```

Da questa distribuzione si calcolano le due metriche introdotte nel §7.3.4
della tesi:

- **Allineamento stretto**: la label dominante coincide con il verdetto atteso.
- **Contiene attacco**: il numero di flussi che mappano al verdetto atteso è
  almeno pari alla soglia della categoria.

## Sistema di Analisi LLM + MCP

Il cuore del progetto: un agente LLM che indaga un host target tramite tool
MCP esposti da `server.py`, e produce un verdetto motivato.

### Uso: Analisi Singola Interattiva

```bash
python client.py
```

Menu a schermo per scegliere categoria di indagine (A-E), IP target e
finestra temporale. Report e log vengono salvati in
`outputs/SESSION_<timestamp>/{reports,logs}/`.

### Uso: Benchmark Automatizzato con Ground Truth

```bash
python test_suite.py
```

Su Windows PowerShell si consiglia di impostare la codifica UTF-8 prima
dell'esecuzione:

```powershell
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$env:PYTHONIOENCODING="utf-8"
python test_suite.py
```

La modalità di esecuzione è controllata dalla variabile d'ambiente
`MODALITA_CATEGORIA`:

- `guidata` (default): la categoria di indagine è quella dello scenario
  (cat_a–cat_e).
- `generica`: tutte le analisi partono da `cat_e`, per misurare la capacità
  del sistema di categorizzare senza ipotesi iniziale.

Esempio su PowerShell:

```powershell
$env:MODALITA_CATEGORIA="generica"
python test_suite.py
```

Esegue tutti gli scenari definiti in `test_scenarios.json` (o in uno dei
dataset per categoria `test_scenarios_{A,B,C,D,E}.json`), confronta ogni
verdetto con `ground_truth.json` / la tabella `cic_flows`, e salva in
`outputs/SESSION_<timestamp>/`:

- un JSON con l'esito dettagliato per scenario;
- la matrice di confusione e le metriche (accuracy/precision/recall/F1).

### Risultati di Riferimento

**Test set — 193 scenari, modalità guidata, modello Qwen 3.8-27B**
(risultati riportati nella tesi, Capitolo 7):

```
            Reale: MINACCIA    Reale: BENIGNO
Pred: MINACCIA     TP: 191         FP: 1
Pred: BENIGNO      FN: 1           TN: 101

Accuracy:            98.96%
Precision:           98.90%
Recall:              98.90%
F1-Score:            98.90%
Accuratezza stretta: 98.96%
```

**Holdout set — 49 scenari, 3 run guidate, media** (tesi, §7.6.4):

```
Accuracy:            96.60%
Precision:           98.29%
Recall:              97.44%
F1-Score:            97.86%
Accuratezza stretta: 96.60%
```

*Nota: il benchmark completo della tesi conta 242 scenari (193 di test +
49 di holdout). Il test set è stato usato durante la calibrazione di soglie
e prompt, quindi le sue metriche vanno lette come accuratezza su un insieme
noto, non come misura di generalizzazione. Per la discussione completa dei
limiti si rimanda al Capitolo 7 della tesi.*

---

## Struttura del Repository

| File | Ruolo |
|---|---|
| `client.py` | Orchestratore: loop di indagine LLM + menu interattivo |
| `server.py` | Server MCP: tool di query/analisi sul DB |
| `engine.py` | Funzioni di supporto per gestione contesto e parsing verdetti |
| `prompts.py` | Tutti i testi di prompt per l'LLM (system prompt, focus per categoria, descrizioni tool) |
| `config.py` | Soglie di classificazione e connessione al DB |
| `utils.py` | Validazione input, selezione modello, persistenza, auditing |
| `test_suite.py` | Benchmark automatizzato su scenari con ground truth |

---

## Limiti Noti

Il calcolo del verdetto (`compute_verdict_scores`) è un'euristica a soglie
statiche tarate manualmente sul dataset di test disponibile: un buon
punteggio di benchmark non garantisce la stessa accuratezza su traffico di
rete reale o proveniente da reti diverse da quella usata per la generazione
degli scenari.

Il dataset di benchmark corrente conta 242 scenari (di cui 112 benigni), un
campione limitato per conclusioni statisticamente robuste. Inoltre:

- i risultati si riferiscono a un singolo modello LLM (Qwen 3.8-27B);
- il sistema presenta un non-determinismo residuo su scenari ambigui
  (verdetti diversi su esecuzioni ripetute dello stesso scenario);
- il confronto tra verdetto LLM e ground truth avviene a livello di finestra
  host/15 minuti, non di singolo flusso, per via dei diversi criteri di
  terminazione dei flussi adottati da CICFlowMeter e nDPI.

Per una discussione approfondita si rimanda al Capitolo 7 della tesi.

---

## Riferimenti

- **Repository ufficiale del progetto**: [https://github.com/AndreaNizzi/Tesi](https://github.com/AndreaNizzi/Tesi)
- **Tesi completa**: [`TesiLaTeX.pdf`](./TesiLaTeX.pdf) nella repository
- **Dataset CIC-IDS-2017**: [https://www.unb.ca/cic/datasets/ids-2017.html](https://www.unb.ca/cic/datasets/ids-2017.html)
- **nDPI** (Deep Packet Inspection): [https://github.com/ntop/nDPI](https://github.com/ntop/nDPI)
- **MCP** (Model Context Protocol): [https://modelcontextprotocol.io](https://modelcontextprotocol.io)


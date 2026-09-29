"""
genera_scenari_v2.py

Genera, a partire da cic_flows, DUE set di scenari disgiunti e un TERZO set che li
contiene entrambi, con un'unica definizione di ground truth.

  test        set di sviluppo (quello su cui itero su prompt e soglie)
  validation  holdout (da guardare solo alla fine)
  all         unione dei due (stessi id), per statistiche descrittive

Ground truth di uno slot (ip sorgente, finestra di SLOT_SECONDS):
  ATTACCO   i flussi malevoli della categoria dominante sono >= soglia della categoria
  BENIGN    nessun flusso con etichetta malevola, almeno --min-flussi-benigni flussi
            e l'IP non e' destinazione di flussi malevoli nello stesso slot 
  AMBIGUO   tutto il resto (pochi flussi malevoli sotto soglia): escluso da entrambi i set

File prodotti (stesso formato di prima):
  test_scenarios.json        ground_truth.json
  validation_scenarios.json  validation_ground_truth.json
  all_scenarios.json         all_ground_truth.json   (qui la ground truth ha anche "set")
  pool_scenari.csv           (tutti i candidati, con i conteggi di flussi)

Esempio:
  python genera_scenari_v2.py --visti old_test_scenarios.json --seed 42
"""
import argparse
import json
import os
import random
import re
from collections import Counter, defaultdict

import pandas as pd

SLOT_SECONDS = 900

MAPPA_TAG = {
    "WEB_ATTACK_EXPLOIT": "cat_a",
    "DOS_VOLUMETRIC": "cat_b",
    "SCAN_BRUTEFORCE": "cat_c",
    "BEACONING_C2": "cat_d",
    "BENIGN": "cat_e",
}

# Flussi malevoli minimi (categoria dominante) perche' uno slot sia uno scenario d'attacco.
# Sotto soglia lo slot e' "ambiguo" e non entra in nessun set.
SOGLIE_FLUSSI = {
    "WEB_ATTACK_EXPLOIT": 1,
    "BEACONING_C2": 1,
    "SCAN_BRUTEFORCE": 1,
    "DOS_VOLUMETRIC": 1,
}

MARGINE_DOMINANZA = 0.6  # la categoria dominante deve avere >= 60% dei flussi malevoli

# ---------------------------------------------------------------------------
# Regola unica: label ufficiale -> categoria
# ---------------------------------------------------------------------------
def mappa_label_a_categoria(label):
    l = str(label).upper()
    if l == "BENIGN":
        return "BENIGN"
    if any(k in l for k in ["WEB ATTACK", "XSS", "SQL INJECTION", "HEARTBLEED"]):
        return "WEB_ATTACK_EXPLOIT"
    if any(k in l for k in ["HULK", "GOLDENEYE", "SLOWLORIS", "SLOWHTTPTEST", "DDOS", "DOS"]):
        return "DOS_VOLUMETRIC"
    if any(k in l for k in ["BOT", "INFILTRATION"]):
        return "BEACONING_C2"
    if any(k in l for k in ["PORTSCAN", "PATATOR"]):
        return "SCAN_BRUTEFORCE"
    # niente default silenzioso a BENIGN: una label sconosciuta e' un errore di ingestione
    raise ValueError(f"Label sconosciuta: {label!r}")


# ---------------------------------------------------------------------------
# Accesso al DB
# ---------------------------------------------------------------------------
def crea_engine():
    from dotenv import load_dotenv
    from sqlalchemy import create_engine
    from sqlalchemy.engine import URL

    load_dotenv()
    url = URL.create(
        "mysql+pymysql",
        username=os.environ.get("DB_USER", "root"),
        password=os.environ["DB_PASSWORD"],
        host=os.environ.get("DB_HOST", "localhost"),
        database=os.environ.get("DB_NAME", "thesis_network"),
    )
    return create_engine(url)


def _slot_sql():
    s = SLOT_SECONDS
    inizio = f"FROM_UNIXTIME(FLOOR(UNIX_TIMESTAMP(timestamp_start) / {s}) * {s})"
    fine = f"FROM_UNIXTIME((FLOOR(UNIX_TIMESTAMP(timestamp_start) / {s}) + 1) * {s})"
    return inizio, fine


def carica_slot(engine, tabella_ip=None):
    """Una riga per (ip sorgente, label, slot) con il numero di flussi."""
    inizio, fine = _slot_sql()
    filtro = ""
    if tabella_ip:
        if not re.fullmatch(r"[A-Za-z0-9_]+", tabella_ip):
            raise ValueError("Nome tabella non valido")
        filtro = f"WHERE src_ip IN (SELECT DISTINCT src_ip FROM {tabella_ip})"
    query = f"""
        SELECT src_ip AS ip, label,
               {inizio} AS start_time, {fine} AS end_time,
               COUNT(*) AS n
        FROM cic_flows
        {filtro}
        GROUP BY src_ip, label, start_time, end_time
    """
    return pd.read_sql(query, con=engine)


def carica_vittime(engine):
    """(ip, slot) che sono DESTINAZIONE di almeno un flusso malevolo."""
    inizio, _ = _slot_sql()
    query = f"""
        SELECT DISTINCT dst_ip AS ip, {inizio} AS start_time
        FROM cic_flows WHERE label <> 'BENIGN'
    """
    df = pd.read_sql(query, con=engine)
    return {(str(r.ip), str(r.start_time)) for r in df.itertuples()}


def carica_visti(percorsi):
    """Slot gia' visti durante il tuning (vecchi file di scenari)."""
    visti = set()
    for p in percorsi:
        with open(p, encoding="utf-8") as f:
            for s in json.load(f):
                visti.add((s["ip_target"], str(s["start_time"])))
    return visti


# ---------------------------------------------------------------------------
# Pool di candidati 
# ---------------------------------------------------------------------------
def costruisci_pool(df, vittime, min_flussi_benigni):
    df = df.copy()
    df["cat"] = df["label"].map(mappa_label_a_categoria)
    stats = {"ambigui": Counter(), "vittime_escluse": 0, "benigni_troppo_pochi": 0}
    pool = []

    for (ip, start), g in df.groupby(["ip", "start_time"], sort=False):
        ip, start_s = str(ip), str(start)
        tot = int(g["n"].sum())
        mal = g[g["cat"] != "BENIGN"]

        if mal.empty:
            if tot < min_flussi_benigni:
                stats["benigni_troppo_pochi"] += 1
                continue
            if (ip, start_s) in vittime:
                stats["vittime_escluse"] += 1
                continue
            cat, n_mal = "BENIGN", 0
        else:
            per_cat = mal.groupby("cat")["n"].sum().sort_values(ascending=False, kind="stable")
            cat, n_mal = per_cat.index[0], int(per_cat.iloc[0])
            tot_mal = int(per_cat.sum())
            if n_mal < SOGLIE_FLUSSI[cat] or (n_mal / tot_mal) < MARGINE_DOMINANZA:
                stats["ambigui"][cat] += 1
                continue

        pool.append({
            "ip_target": ip,
            "start_time": start_s,
            "end_time": str(g["end_time"].iloc[0]),
            "categoria": cat,
            "categoria_tag": MAPPA_TAG[cat],
            "verdetto_atteso": cat,
            "flussi_totali": tot,
            "flussi_malevoli": n_mal,
        })
    return pool, stats


# ---------------------------------------------------------------------------
# Divisione in due set disgiunti, stratificata per categoria
# ---------------------------------------------------------------------------
def dividi(pool, frazione_test, rapporto_benigni, max_per_cat, visti, seed):
    rng = random.Random(seed)

    def chiave(s):
        return (s["ip_target"], s["start_time"])

    per_tag = defaultdict(list)
    for s in sorted(pool, key=chiave): 
        per_tag[s["categoria_tag"]].append(s)

    test, val = [], []
    tag_benigno = MAPPA_TAG["BENIGN"]

    # attacchi: per ogni categoria, gli slot gia' visti vanno nel set di sviluppo
    for tag in sorted(t for t in per_tag if t != tag_benigno):
        lista = per_tag[tag][:]
        rng.shuffle(lista)
        if max_per_cat and len(lista) > max_per_cat:
            lista = sorted(lista, key=lambda s: chiave(s) not in visti)[:max_per_cat]
        forzati = [s for s in lista if chiave(s) in visti]
        liberi = [s for s in lista if chiave(s) not in visti]
        n_test = max(len(forzati), round(len(lista) * frazione_test))
        prendi = n_test - len(forzati)
        test += forzati + liberi[:prendi]
        val += liberi[prendi:]

    # benigni: il pool e' enorme, quindi se ne prende un numero proporzionale agli attacchi
    benigni = per_tag.get(tag_benigno, [])[:]
    rng.shuffle(benigni)
    forzati_b = [s for s in benigni if chiave(s) in visti]
    liberi_b = [s for s in benigni if chiave(s) not in visti]
    n_test_b = max(len(forzati_b), round(len(test) * rapporto_benigni))
    prendi_t = n_test_b - len(forzati_b)
    n_val_b = round(len(val) * rapporto_benigni)
    test += forzati_b + liberi_b[:prendi_t]
    val += liberi_b[prendi_t:prendi_t + n_val_b]

    for s in test:
        s["set"] = "test"
    for s in val:
        s["set"] = "validation"
    return test, val


def assegna_id(scenari, prefisso, seed):
    rng = random.Random(seed)
    scenari = scenari[:]
    rng.shuffle(scenari)
    for i, s in enumerate(scenari, start=1):
        s["id"] = f"{prefisso}_{s['categoria_tag'].upper()}_{i:03d}"
    return scenari


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
def scrivi(scenari, f_scenari, f_gt, con_set=False):
    ingresso = [
        {k: s[k] for k in ("id", "categoria_tag", "ip_target", "start_time", "end_time")}
        for s in scenari
    ]
    gt = []
    for s in scenari:
        riga = {"id": s["id"], "verdetto_atteso": s["verdetto_atteso"]}
        if con_set:
            riga["set"] = s["set"]
        gt.append(riga)
    with open(f_scenari, "w", encoding="utf-8") as f:
        json.dump(ingresso, f, indent=2, ensure_ascii=False)
    with open(f_gt, "w", encoding="utf-8") as f:
        json.dump(gt, f, indent=2, ensure_ascii=False)


def stampa_report(pool, stats):
    df = pd.DataFrame(pool)
    print("\n=== POOL DI CANDIDATI ===")
    tab = df.groupby("categoria").agg(
        candidati=("ip_target", "size"),
        flussi_mal_min=("flussi_malevoli", "min"),
        flussi_mal_mediana=("flussi_malevoli", "median"),
    )
    tab["ambigui_esclusi"] = pd.Series(stats["ambigui"]).fillna(0).astype(int)
    print(tab.to_string())
    print(f"\nBENIGN esclusi (vittima): {stats['vittime_escluse']}")
    print(f"BENIGN esclusi (< min flussi): {stats['benigni_troppo_pochi']}")
    print(f"\nTOTALE scenari: {len(pool)}")


def main():
    ap = argparse.ArgumentParser(description="Genera set test/validation disgiunti + set unione")
    ap.add_argument("--frazione-test", type=float, default=0.5,
                    help="quota degli scenari d'attacco di ogni categoria assegnata al set test (default 0.5)")
    ap.add_argument("--rapporto-benigni", type=float, default=1.0,
                    help="scenari BENIGN per ogni scenario d'attacco, in ciascun set (default 1.0)")
    ap.add_argument("--max-per-categoria", type=int, default=0,
                    help="tetto agli scenari d'attacco per categoria prima della divisione (0 = nessuno)")
    ap.add_argument("--min-flussi-benigni", type=int, default=10,
                    help="flussi minimi in uno slot perche' sia un candidato BENIGN (default 10)")
    ap.add_argument("--visti", nargs="*", default=[],
                    help="vecchi file di scenari gia' usati per il tuning: finiscono nel set test")
    ap.add_argument("--solo-ip-da", default=None,
                    help="opzionale: considera solo gli src_ip presenti in questa tabella (es. test_dataset_750)")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--outdir", default=".")
    ap.add_argument("--sovrascrivi", action="store_true")
    args = ap.parse_args()

    file_out = {
        "scenari": ("scenarios.json", "ground_truth.json"),
        "pool": ("pool_scenari.csv",),
    }
    percorsi = [os.path.join(args.outdir, n) for v in file_out.values() for n in v]
    esistenti = [p for p in percorsi if os.path.exists(p)]
    if esistenti and not args.sovrascrivi:
        raise SystemExit(f"[!] File gia' presenti: {esistenti}. Rinominali o usa --sovrascrivi.")

    visti = carica_visti(args.visti)
    if visti:
        print(f"[i] {len(visti)} slot gia' visti: verranno esclusi dal pool.")

    engine = crea_engine()
    df = carica_slot(engine, args.solo_ip_da)
    vittime = carica_vittime(engine)

    pool, stats = costruisci_pool(df, vittime, args.min_flussi_benigni)
    # escludi gli slot gia' visti: non devono entrare in nessun set
    if visti:
        prima = len(pool)
        pool = [s for s in pool if (s["ip_target"], s["start_time"]) not in visti]
        print(f"[i] {prima - len(pool)} scenari esclusi perche' gia' visti "
            f"({len(pool)} rimasti).")
    # un unico set, niente divisione test/validation
    unico = assegna_id(pool, "SCN", args.seed)


    stampa_report(pool, stats)

    scrivi(unico,
        os.path.join(args.outdir, "scenarios.json"),
        os.path.join(args.outdir, "ground_truth.json"),
        con_set=False)
    pd.DataFrame(unico).to_csv(os.path.join(args.outdir, "pool_scenari.csv"), index=False)
    print(f"\n[✓] {len(unico)} scenari scritti in", os.path.abspath(args.outdir))


if __name__ == "__main__":
    main()

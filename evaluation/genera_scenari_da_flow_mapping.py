"""
GENERAZIONE SCENARI DI TEST PER VALIDAZIONE DEL SISTEMA
Questo script genera automaticamente una lista di "scenari di test" a partire
dai flussi di rete etichettati memorizzati nel database MySQL `thesis_network`.

Uno "scenario" è un intervallo temporale (finestra di 15 minuti) relativo a un
IP target, caratterizzato da una categoria di attacco attesa. Gli scenari
generati servono come ground-truth per valutare un sistema.

- Tabelle MySQL:
    * `flow_mapping`   : associa ogni flusso (community_id + ndpi_ts) a una label
    * `ndpi_flows`     : metadati dei flussi (IP, porte, protocollo, volumi)
    * `test_scenarios` : scenari già esistenti (da NON duplicare)
    * `report_validazione` : contiene `n_attacco` e `soglia` per
      distinguere scenari VALIDI.

OUTPUT
- `test_scenarios_generati.json` : lista degli scenari generati (id, ip, tempi)
- `ground_truth_generati.json`   : verdetto atteso per ogni scenario generato
- `report_scenari_generati.csv`  : report leggibile con statistiche per scenario

USO
$ python genera_scenari.py
"""
import json
import os
import csv
import pymysql
from datetime import datetime, timedelta
from collections import defaultdict
from dotenv import load_dotenv

load_dotenv()

DB_HOST = 'localhost'
DB_USER = 'root'
DB_PASS = os.environ.get("DB_PASSWORD")
DB_NAME = 'thesis_network'

SCENARIO_WINDOW_MIN = 15

# Soglia di flussi ATTACCO per categoria (per validità dello scenario)
SOGLIA_ATTACCO = {
    'cat_a': 3,   # Web Attack: pochi flussi HTTP
    'cat_b': 10,  # DoS: volumetrico
    'cat_c': 5,   # Scan/Bruteforce: concentrato
    'cat_d': 3,   # Beaconing C2: beacon sporadici
    'cat_e': 20,  # BENIGN
}

LABEL_TO_VERDETTO = {
    'BENIGN': 'BENIGN',
    'Bot': 'BEACONING_C2',
    'DDoS': 'DOS_VOLUMETRIC',
    'DoS Hulk': 'DOS_VOLUMETRIC',
    'DoS GoldenEye': 'DOS_VOLUMETRIC',
    'DoS slowloris': 'DOS_VOLUMETRIC',
    'DoS Slowhttptest': 'DOS_VOLUMETRIC',
    'PortScan': 'SCAN_BRUTEFORCE',
    'FTP-Patator': 'SCAN_BRUTEFORCE',
    'SSH-Patator': 'SCAN_BRUTEFORCE',
    'Web Attack – Brute Force': 'WEB_ATTACK_EXPLOIT',
    'Web Attack – XSS': 'WEB_ATTACK_EXPLOIT',
    'Web Attack – Sql Injection': 'WEB_ATTACK_EXPLOIT',
    'Web Attack Brute Force': 'WEB_ATTACK_EXPLOIT',
    'Web Attack XSS': 'WEB_ATTACK_EXPLOIT',
    'Web Attack Sql Injection': 'WEB_ATTACK_EXPLOIT',
    'Infiltration': 'WEB_ATTACK_EXPLOIT',
    'Heartbleed': 'WEB_ATTACK_EXPLOIT',
}

VERDETTO_TO_CAT = {
    'BENIGN': 'cat_e',
    'BEACONING_C2': 'cat_d',
    'DOS_VOLUMETRIC': 'cat_b',
    'SCAN_BRUTEFORCE': 'cat_c',
    'WEB_ATTACK_EXPLOIT': 'cat_a',
}


def get_finestra(dt, window_min):
    minuto = (dt.minute // window_min) * window_min
    start = dt.replace(minute=minuto, second=0, microsecond=0)
    end = start + timedelta(minutes=window_min)
    return start, end


def overlap(ip1, s1, e1, ip2, s2, e2):
    """True se i due intervalli si sovrappongono e stesso IP"""
    if ip1 != ip2:
        return False
    return not (e1 <= s2 or e2 <= s1)


def main():
    conn = pymysql.connect(
        host=DB_HOST, user=DB_USER, password=DB_PASS,
        database=DB_NAME, charset='utf8mb4', autocommit=True
    )
    cur = conn.cursor()

    print("=" * 70)
    print("GENERAZIONE SCENARI (soglia per categoria)")
    print("=" * 70)

    # -----------------------------------------------------------
    # Carica SOLO gli scenari validi per esclusione
    # -----------------------------------------------------------
    print("\n[0/5] Carico scenari validi per esclusione...")

    # Verifica se report_validazione esiste
    cur.execute("""
        SELECT COUNT(*) FROM information_schema.TABLES
        WHERE TABLE_SCHEMA = %s AND TABLE_NAME = 'report_validazione'
    """, (DB_NAME,))
    has_report = cur.fetchone()[0] > 0

    if has_report:
        cur.execute("""
            SELECT ts.id, ts.ip_target, ts.start_time, ts.end_time
            FROM test_scenarios ts
            JOIN report_validazione rv ON rv.id = ts.id
            WHERE rv.n_attacco >= rv.soglia
              AND rv.n_flussi > 0
        """)
        scenari_esistenti = cur.fetchall()
        print(f"  Scenari VALIDI (n_attacco >= soglia): {len(scenari_esistenti)}")

        cur.execute("SELECT COUNT(*) FROM test_scenarios")
        tot = cur.fetchone()[0]
        print(f"  Scenari TOTALI in DB: {tot}")
        print(f"  → Esclusione applicata solo contro i {len(scenari_esistenti)} validi")
    else:
        print(f"  [WARN] Tabella 'report_validazione' non esiste.")
        print(f"         Uso TUTTI gli scenari in test_scenarios per esclusione.")
        cur.execute("SELECT id, ip_target, start_time, end_time FROM test_scenarios")
        scenari_esistenti = cur.fetchall()
        print(f"  Scenari (da DB): {len(scenari_esistenti)}")

    esistenti_per_ip = defaultdict(list)
    for (eid, eip, es, ee) in scenari_esistenti:
        esistenti_per_ip[eip].append((eid, es, ee))

    # -----------------------------------------------------------
    # Estrai flussi da flow_mapping
    # -----------------------------------------------------------
    print("\n[1/5] Estrazione flussi da flow_mapping...")
    cur.execute("""
    SELECT
        f.label, f.ndpi_ts,
        n.src_ip, n.dst_ip, n.src_port, n.dst_port,
        n.protocol, n.total_bytes, n.fwd_packets, n.bwd_packets
    FROM flow_mapping f
    JOIN ndpi_flows n
        ON n.community_id = f.community_id
       AND n.timestamp_start = f.ndpi_ts
    ORDER BY f.ndpi_ts
    """)
    rows = cur.fetchall()
    print(f"  Estratti {len(rows)} flussi con label")

    # -----------------------------------------------------------
    # Raggruppa per (label, ip_target, finestra)
    # -----------------------------------------------------------
    print("\n[2/5] Raggruppamento in finestre temporali...")
    gruppi = defaultdict(lambda: {
        'n_flussi': 0,
        'dst_ports': set(),
        'src_ports': set(),
    })

    for (label, ndpi_ts, src_ip, dst_ip, src_port, dst_port,
         proto, tot_bytes, fwd_pkt, bwd_pkt) in rows:
        ip_target = dst_ip
        start_win, _ = get_finestra(ndpi_ts, SCENARIO_WINDOW_MIN)
        key = (label, ip_target, start_win)
        g = gruppi[key]
        g['n_flussi'] += 1
        g['dst_ports'].add(dst_port)
        g['src_ports'].add(src_port)

    print(f"  Creati {len(gruppi)} gruppi (label, ip_target, finestra)")

    # -----------------------------------------------------------
    # Genera scenari con soglia per categoria
    # -----------------------------------------------------------
    print(f"\n[3/5] Generazione scenari (soglia per categoria)...")
    scenari = []
    contatori_categoria = defaultdict(int)
    n_esclusi = 0
    n_saltati_per_soglia = 0

    chiavi_ordinate = sorted(gruppi.keys(), key=lambda k: (k[0], k[2], k[1]))

    for (label, ip_target, start_win) in chiavi_ordinate:
        g = gruppi[(label, ip_target, start_win)]

        # Determina categoria dalla label
        verdetto = LABEL_TO_VERDETTO.get(label, label)
        categoria = VERDETTO_TO_CAT.get(verdetto, 'cat_e')

        # Applica la soglia giusta per la categoria
        soglia = SOGLIA_ATTACCO.get(categoria, 3)
        if g['n_flussi'] < soglia:
            n_saltati_per_soglia += 1
            continue

        end_win = start_win + timedelta(minutes=SCENARIO_WINDOW_MIN)

        # Escludi solo se overlap con uno scenario VALIDO (stesso IP)
        gia_esiste = False
        for (eid, es, ee) in esistenti_per_ip.get(ip_target, []):
            if overlap(ip_target, start_win, end_win, ip_target, es, ee):
                gia_esiste = True
                break

        if gia_esiste:
            n_esclusi += 1
            continue

        contatori_categoria[categoria] += 1
        idx = contatori_categoria[categoria]

        scenari.append({
            'id': f"GEN_{categoria.upper()}_{idx:04d}",
            'categoria_tag': categoria,
            'ip_target': ip_target,
            'start_time': start_win.strftime('%Y-%m-%d %H:%M:%S'),
            'end_time': end_win.strftime('%Y-%m-%d %H:%M:%S'),
            'label_cic': label,
            'verdetto_atteso': verdetto,
            'n_flussi_stimati': g['n_flussi'],
            'n_porte_dst_diverse': len(g['dst_ports']),
            'soglia_applicata': soglia,
        })

    print(f"  Generati {len(scenari)} scenari NUOVI")
    print(f"  Esclusi (overlap con validi): {n_esclusi}")
    print(f"  Saltati (sotto soglia per categoria): {n_saltati_per_soglia}")

    per_cat = defaultdict(int)
    for s in scenari:
        per_cat[s['categoria_tag']] += 1
    print("\n  Distribuzione per categoria:")
    for cat in sorted(per_cat):
        print(f"    {cat}: {per_cat[cat]}  (soglia={SOGLIA_ATTACCO.get(cat, 3)})")

    per_verd = defaultdict(int)
    for s in scenari:
        per_verd[s['verdetto_atteso']] += 1
    print("\n  Distribuzione per verdetto:")
    for v in sorted(per_verd):
        print(f"    {v}: {per_verd[v]}")

    # -----------------------------------------------------------
    # Salva JSON
    # -----------------------------------------------------------
    print("\n[4/5] Salvataggio file...")

    with open('test_scenarios_generati.json', 'w', encoding='utf-8') as f:
        json.dump([{
            'id': s['id'],
            'categoria_tag': s['categoria_tag'],
            'ip_target': s['ip_target'],
            'start_time': s['start_time'],
            'end_time': s['end_time'],
        } for s in scenari], f, indent=2)
    print(f"  → test_scenarios_generati.json ({len(scenari)} scenari)")

    with open('ground_truth_generati.json', 'w', encoding='utf-8') as f:
        json.dump([{
            'id': s['id'],
            'verdetto_atteso': s['verdetto_atteso'],
            'set': 'generated',
        } for s in scenari], f, indent=2)
    print("  → ground_truth_generati.json")

    # -----------------------------------------------------------
    # Report dettagliato
    # -----------------------------------------------------------
    with open('report_scenari_generati.csv', 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['id', 'categoria', 'ip_target', 'start_time', 'end_time',
                         'label_cic', 'verdetto_atteso', 'n_flussi_stimati',
                         'n_porte_dst_diverse', 'soglia_applicata'])
        for s in scenari:
            writer.writerow([
                s['id'], s['categoria_tag'], s['ip_target'],
                s['start_time'], s['end_time'],
                s['label_cic'], s['verdetto_atteso'],
                s['n_flussi_stimati'], s['n_porte_dst_diverse'],
                s['soglia_applicata'],
            ])
    print("  → report_scenari_generati.csv")

    cur.close()
    conn.close()

    print("\n" + "=" * 70)
    print("✅ COMPLETATO")
    print("=" * 70)
    print(f"\n  Scenari generati: {len(scenari)}")
    print(f"  Esclusi (overlap con validi): {n_esclusi}")
    print(f"  Saltati (sotto soglia per categoria): {n_saltati_per_soglia}")


if __name__ == '__main__':
    main()

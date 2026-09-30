import json
import os
import csv
import pymysql
from collections import defaultdict
from dotenv import load_dotenv

load_dotenv()

DB_HOST = 'localhost'
DB_USER = 'root'
DB_PASS = os.environ.get("DB_PASSWORD")
DB_NAME = 'thesis_network'

FILES = [
    ('test_scenarios_193_test.json',      'ground_truth_193_test.json',      'test'),
    ('test_scenarios_49_validation.json', 'ground_truth_49_validation.json', 'holdout'),
]

conn = pymysql.connect(
    host=DB_HOST, user=DB_USER, password=DB_PASS,
    database=DB_NAME, charset='utf8mb4', autocommit=True
)
cur = conn.cursor()

# ------------------------------------------------------------
# Ricrea test_scenarios e ground_truth
# ------------------------------------------------------------
print("STEP 1 — Ricostruzione tabelle")

cur.execute("DROP TABLE IF EXISTS test_scenarios")
cur.execute("""
CREATE TABLE test_scenarios (
    id VARCHAR(64) PRIMARY KEY,
    categoria_tag VARCHAR(16),
    ip_target VARCHAR(64),
    start_time DATETIME,
    end_time DATETIME,
    set_name VARCHAR(32),
    INDEX idx_ts_ip (ip_target, start_time, end_time)
) ENGINE=InnoDB
""")

cur.execute("DROP TABLE IF EXISTS ground_truth")
cur.execute("""
CREATE TABLE ground_truth (
    id VARCHAR(64) PRIMARY KEY,
    verdetto_atteso VARCHAR(64)
) ENGINE=InnoDB
""")

for scen_file, gt_file, set_name in FILES:
    with open(scen_file) as f:
        scenari = json.load(f)
    with open(gt_file) as f:
        gt = {g['id']: g['verdetto_atteso'] for g in json.load(f)}

    for s in scenari:
        cur.execute("""
            INSERT IGNORE INTO test_scenarios
                (id, categoria_tag, ip_target, start_time, end_time, set_name)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (s['id'], s.get('categoria_tag'),
              s['ip_target'], s['start_time'], s['end_time'], set_name))

    for sid, verdetto in gt.items():
        cur.execute("""
            INSERT IGNORE INTO ground_truth (id, verdetto_atteso) VALUES (%s, %s)
        """, (sid, verdetto))

    print(f"  {set_name}: {len(scenari)} scenari, {len(gt)} ground truth")

cur.execute("SELECT set_name, COUNT(*) FROM test_scenarios GROUP BY set_name")
print(f"\nTotale scenari per set:")
for row in cur.fetchall():
    print(f"  {row[0]}: {row[1]}")

cur.execute("SELECT COUNT(*) FROM test_scenarios")
print(f"Totale complessivo: {cur.fetchone()[0]}")


# ============================================================
#  Verifica traffico in ndpi_flows 
# ============================================================
print("\n" + "=" * 60)
print("STEP 2 — Verifica traffico in ndpi_flows")
print("=" * 60)

# Due query separate per usare gli indici, poi unione in Python
query_dst = """
SELECT ts.id, COUNT(n.id) AS n
FROM test_scenarios ts
LEFT JOIN ndpi_flows n
    ON n.dst_ip = ts.ip_target
   AND n.timestamp_start >= ts.start_time
   AND n.timestamp_start <  ts.end_time
GROUP BY ts.id
"""
query_src = """
SELECT ts.id, COUNT(n.id) AS n
FROM test_scenarios ts
LEFT JOIN ndpi_flows n
    ON n.src_ip = ts.ip_target
   AND n.timestamp_start >= ts.start_time
   AND n.timestamp_start <  ts.end_time
GROUP BY ts.id
"""

print("  Eseguo query dst...")
cur.execute(query_dst)
dst_counts = dict(cur.fetchall())

print("  Eseguo query src...")
cur.execute(query_src)
src_counts = dict(cur.fetchall())

step2_rows = []
for sid in set(dst_counts) | set(src_counts):
    n_dst = dst_counts.get(sid, 0)
    n_src = src_counts.get(sid, 0)
    step2_rows.append((sid, n_dst, n_src, n_dst + n_src))

vuoti = [r for r in step2_rows if r[3] == 0]
con_traffico = [r for r in step2_rows if r[3] > 0]

print(f"\n  Scenari con traffico:        {len(con_traffico)}")
print(f"  Scenari VUOTI (da scartare): {len(vuoti)}")

if vuoti:
    print("\n  Scenari vuoti (primi 20):")
    for r in vuoti[:20]:
        print(f"    {r[0]:22s}  n_dst={r[1]:4d}  n_src={r[2]:4d}")

# ============================================================
# Verifica label in flow_mapping 
# ============================================================
print("\n" + "=" * 60)
print("STEP 3 — Verifica label in flow_mapping")
print("=" * 60)

# Due query separate (una per dst, una per src), poi unione in Python
query_step3_dst = """
SELECT
    ts.id,
    ts.categoria_tag,
    ts.ip_target,
    gt.verdetto_atteso,
    f.label AS label_reale,
    COUNT(*) AS n
FROM test_scenarios ts
JOIN ground_truth gt ON gt.id = ts.id
JOIN ndpi_flows n
    ON n.dst_ip = ts.ip_target
   AND n.timestamp_start >= ts.start_time
   AND n.timestamp_start <  ts.end_time
JOIN flow_mapping f
    ON f.community_id = n.community_id
   AND f.ndpi_ts = n.timestamp_start
GROUP BY ts.id, ts.categoria_tag, ts.ip_target, gt.verdetto_atteso, f.label
"""

query_step3_src = """
SELECT
    ts.id,
    ts.categoria_tag,
    ts.ip_target,
    gt.verdetto_atteso,
    f.label AS label_reale,
    COUNT(*) AS n
FROM test_scenarios ts
JOIN ground_truth gt ON gt.id = ts.id
JOIN ndpi_flows n
    ON n.src_ip = ts.ip_target
   AND n.timestamp_start >= ts.start_time
   AND n.timestamp_start <  ts.end_time
JOIN flow_mapping f
    ON f.community_id = n.community_id
   AND f.ndpi_ts = n.timestamp_start
GROUP BY ts.id, ts.categoria_tag, ts.ip_target, gt.verdetto_atteso, f.label
"""

print("  Eseguo query label (dst)...")
cur.execute(query_step3_dst)
step3_dst = cur.fetchall()

print("  Eseguo query label (src)...")
cur.execute(query_step3_src)
step3_src = cur.fetchall()

step3_rows = step3_dst + step3_src

# Raggruppa per scenario
scenari_label = defaultdict(lambda: {
    'verdetto': None, 'categoria': None,
    'ip': None, 'labels': defaultdict(int)
})
for id_, cat, ip, verdetto, label, n in step3_rows:
    s = scenari_label[id_]
    s['verdetto'] = verdetto
    s['categoria'] = cat
    s['ip'] = ip
    s['labels'][label] += n

print(f"\n  Scenari con almeno un flusso mappato: {len(scenari_label)}")

# ============================================================
# Mappa label CIC -> verdetto 
# ============================================================
print("\n" + "=" * 60)
print("STEP 4 — Mappatura label CIC → verdetto")
print("=" * 60)

LABEL_MAP = {
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
print(f"  Mappatura caricata: {len(LABEL_MAP)} label")

# ============================================================
# Report finale con purezza
# ============================================================
print("\n" + "=" * 60)
print("STEP 5 — Report finale")
print("=" * 60)

report = []
for id_, s in scenari_label.items():
    n_totali = sum(s['labels'].values())
    n_corretti = 0
    for label_reale, n in s['labels'].items():
        verdetto_reale = LABEL_MAP.get(label_reale, label_reale)
        if verdetto_reale == s['verdetto']:
            n_corretti += n
    purezza = (n_corretti * 100.0 / n_totali) if n_totali else 0
    report.append({
        'id': id_,
        'categoria': s['categoria'],
        'ip': s['ip'],
        'verdetto': s['verdetto'],
        'n_totali': n_totali,
        'n_corretti': n_corretti,
        'purezza': round(purezza, 2),
        'labels': dict(s['labels']),
    })

# Ordina per purezza crescente (i peggiori in cima)
report.sort(key=lambda r: r['purezza'])

# Conta per categoria di purezza
ottimi = [r for r in report if r['purezza'] >= 90]
buoni = [r for r in report if 80 <= r['purezza'] < 90]
scarsi = [r for r in report if 50 <= r['purezza'] < 80]
pessimi = [r for r in report if r['purezza'] < 50]

print(f"\n  ✅ Ottimi (≥90%):     {len(ottimi)}")
print(f"  🟢 Buoni (80-90%):    {len(buoni)}")
print(f"  🟡 Scarsi (50-80%):   {len(scarsi)}")
print(f"  🔴 Pessimi (<50%):    {len(pessimi)}")
print(f"  Totale scenari mappati: {len(report)}")

# ============================================================
# Salva i risultati su CSV
# ============================================================
print("\n" + "=" * 60)
print("STEP 6 — Salvataggio report")
print("=" * 60)

with open('report_validazione.csv', 'w', newline='', encoding='utf-8') as f:
    writer = csv.writer(f)
    writer.writerow(['id', 'categoria', 'ip_target', 'verdetto_atteso',
                     'n_flussi', 'n_corretti', 'purezza_pct', 'label_presenti'])
    for r in report:
        labels_str = ' | '.join(f"{k}:{v}" for k, v in r['labels'].items())
        writer.writerow([r['id'], r['categoria'], r['ip'], r['verdetto'],
                         r['n_totali'], r['n_corretti'], r['purezza'], labels_str])
print("  → report_validazione.csv")

with open('scenari_validi.csv', 'w', newline='', encoding='utf-8') as f:
    writer = csv.writer(f)
    writer.writerow(['id', 'categoria', 'ip_target', 'verdetto_atteso',
                     'n_flussi', 'purezza_pct'])
    for r in report:
        if r['purezza'] >= 80 and r['n_totali'] > 0:
            writer.writerow([r['id'], r['categoria'], r['ip'],
                             r['verdetto'], r['n_totali'], r['purezza']])
print("  → scenari_validi.csv")

with open('scenari_da_scartare.csv', 'w', newline='', encoding='utf-8') as f:
    writer = csv.writer(f)
    writer.writerow(['id', 'categoria', 'ip_target', 'verdetto_atteso',
                     'n_flussi', 'purezza_pct', 'motivo'])
    for r in report:
        motivo = None
        if r['n_totali'] == 0:
            motivo = 'nessun flusso mappato'
        elif r['purezza'] < 80:
            motivo = f"purezza {r['purezza']}% < 80%"
        if motivo:
            writer.writerow([r['id'], r['categoria'], r['ip'],
                             r['verdetto'], r['n_totali'], r['purezza'], motivo])
    for r in vuoti:
        writer.writerow([r[0], '', '', '', 0, 0, 'nessun traffico in ndpi_flows'])
print("  → scenari_da_scartare.csv")

# ============================================================
# Top 10 peggiori scenari 
# ============================================================
print("\n" + "=" * 60)
print("TOP 10 SCENARI PEGGIORI (purezza < 100%)")
print("=" * 60)
print()
print(f"{'ID':22s} {'CAT':6s} {'IP':18s} {'ATTESO':22s} {'PUR%':7s} LABELS")
print("-" * 120)
for r in report[:10]:
    labels_str = ', '.join(f"{k}={v}" for k, v in r['labels'].items())
    print(f"{r['id']:22s} {str(r['categoria']):6s} {r['ip']:18s} "
          f"{r['verdetto']:22s} {r['purezza']:7.2f} {labels_str}")

cur.close()
conn.close()
print("\n✅ Validazione completata.")

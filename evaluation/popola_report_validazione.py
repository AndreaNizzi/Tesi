import csv
import os
import pymysql
from dotenv import load_dotenv

load_dotenv()

DB_HOST = 'localhost'
DB_USER = 'root'
DB_PASS = os.environ.get("DB_PASSWORD")
DB_NAME = 'thesis_network'

CSV_FILE = 'report_validazione.csv'

# Soglia di flussi attacco per categoria (per validità dello scenario)
SOGLIA_ATTACCO = {
    'cat_a': 3,
    'cat_b': 10,
    'cat_c': 5,
    'cat_d': 3,
    'cat_e': 20,
}


def main():
    print(f"Lettura {CSV_FILE}...")
    with open(CSV_FILE, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    print(f"  {len(rows)} righe lette")

    conn = pymysql.connect(
        host=DB_HOST, user=DB_USER, password=DB_PASS,
        database=DB_NAME, charset='utf8mb4', autocommit=True
    )
    cur = conn.cursor()

    print("Creazione tabella report_validazione...")
    cur.execute("DROP TABLE IF EXISTS report_validazione")
    cur.execute("""
    CREATE TABLE report_validazione (
        id VARCHAR(64) PRIMARY KEY,
        categoria VARCHAR(16),
        ip_target VARCHAR(64),
        verdetto_atteso VARCHAR(64),
        n_flussi INT,
        n_attacco INT,
        n_altro INT,
        purezza_pct DECIMAL(5,2),
        soglia INT,
        labels_presenti TEXT,
        INDEX idx_purezza (purezza_pct),
        INDEX idx_n_attacco (n_attacco)
    ) ENGINE=InnoDB
    """)

    print("Inserimento righe...")
    inseriti = 0
    for r in rows:
        cat = r.get('categoria', 'cat_e') or 'cat_e'
        soglia = SOGLIA_ATTACCO.get(cat, 3)
        n_totali = int(r.get('n_flussi', 0) or 0)
        n_corretti = int(r.get('n_corretti', 0) or 0)
        n_altro = n_totali - n_corretti
        purezza = float(r.get('purezza_pct', 0) or 0)

        cur.execute("""
            INSERT INTO report_validazione
            (id, categoria, ip_target, verdetto_atteso, n_flussi, n_attacco,
             n_altro, purezza_pct, soglia, labels_presenti)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            r['id'],
            cat,
            r['ip_target'],
            r['verdetto_atteso'],
            n_totali,
            n_corretti,
            n_altro,
            purezza,
            soglia,
            r.get('label_presenti', '')
        ))
        inseriti += 1

    print(f"  {inseriti} righe inserite")

    cur.execute("SELECT COUNT(*) FROM report_validazione")
    print(f"  Totale righe in report_validazione: {cur.fetchone()[0]}")

    cur.execute("""
        SELECT 
            SUM(CASE WHEN n_attacco >= soglia THEN 1 ELSE 0 END) AS validi,
            SUM(CASE WHEN n_attacco < soglia THEN 1 ELSE 0 END) AS non_validi
        FROM report_validazione
    """)
    validi, non_validi = cur.fetchone()
    print(f"  Scenari validi (n_attacco >= soglia): {validi}")
    print(f"  Scenari non validi: {non_validi}")

    print("\n  Distribuzione per categoria (validi / totale):")
    cur.execute("""
        SELECT 
            categoria,
            SUM(CASE WHEN n_attacco >= soglia THEN 1 ELSE 0 END) AS validi,
            COUNT(*) AS totali
        FROM report_validazione
        GROUP BY categoria
        ORDER BY categoria
    """)
    for cat, val, tot in cur.fetchall():
        print(f"    {cat}: {val}/{tot}")

    cur.close()
    conn.close()
    print("\n✅ Fatto!")


if __name__ == '__main__':
    main()

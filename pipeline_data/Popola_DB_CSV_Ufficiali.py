import sys
import os
import pandas as pd
import numpy as np
from sqlalchemy import create_engine
from sqlalchemy import text
from dotenv import load_dotenv

load_dotenv()
# -------------------------------------------------------------
# FUNZIONE DI INSERIMENTO IN BULK 
# -------------------------------------------------------------
def insert(df, table_name, engine, chunksize=20000):
    columns = ", ".join([f"`{col}`" for col in df.columns])
    placeholders = ", ".join([f":{col}" for col in df.columns])
    query = text(f"INSERT INTO {table_name} ({columns}) VALUES ({placeholders})")
    
    with engine.begin() as connection:
        for i in range(0, len(df), chunksize):
            chunk = df.iloc[i:i + chunksize]
            data = chunk.to_dict(orient='records')
            
            for row in data:
                for key, val in row.items():
                    if isinstance(val, float) and (np.isnan(val) or np.isinf(val)):
                        row[key] = 0.0
                    elif val is pd.NaT:
                        row[key] = None
                        
            connection.execute(query, data)

def main():
    files_da_elaborare = [
        'Lunedi-Join.csv',  
        'Martedi-Join.csv',
        'Mercoledi-Join.csv',
        'Giovedi-Join.csv',
        'Venerdi-Join.csv'
    ]
    
    DB_USER = 'root'
    DB_PASS = os.environ.get("DB_PASSWORD")  
    DB_HOST = 'localhost'
    DB_NAME = 'thesis_network'

    try:
        print("Connessione al database MySQL...")
        engine = create_engine(
            f'mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_HOST}/{DB_NAME}?charset=utf8mb4'
        )
    except Exception as e:
        print(f"Errore nella creazione dell'engine SQLAlchemy: {e}")
    engine = None

    for csv_file in files_da_elaborare:
        print("\n" + "="*50)
        print(f"Caricamento database: {csv_file}")
        print("="*50)
        
        if not os.path.exists(csv_file):
            print(f"[INFO] Il file '{csv_file}' non è presente nella cartella. Lo salto.")
            continue
        
        print(f"Lettura di {csv_file}...")
        try:
            df = pd.read_csv(csv_file, low_memory=False, on_bad_lines='skip')
            df.columns = df.columns.str.strip().str.lower()
            df = df.loc[:, ~df.columns.duplicated()].copy()
        except Exception as e:
            print(f"[ERRORE] Durante la lettura di {csv_file}: {e}")
            sys.exit(1)

        mappa_colonne = {
            'community_id': 'community_id',
            'src ip': 'src_ip',        
            'dst ip': 'dst_ip',   
            'src port': 'src_port',
            'dst port': 'dst_port',
            'protocol': 'protocol',
            'ts': 'timestamp_start',       
            'duration_norm': 'duration_ms', 
            'flow byts/s': 'byte_rate', 
            'flow pkts/s': 'packet_rate',
            'flow iat mean': 'iat_flow_avg',
            'flow iat std': 'iat_flow_stddev',
            'tot fwd pkts': 'fwd_packets',
            'tot bwd pkts': 'bwd_packets',
            'totlen fwd pkts': 'total_fwd_bytes',  
            'totlen bwd pkts': 'total_bwd_bytes',
        }

        colonne_presenti = {k: v for k, v in mappa_colonne.items() if k in df.columns}
        df.rename(columns=colonne_presenti, inplace=True)
        df = df.loc[:, ~df.columns.duplicated()].copy()

        # Se ci sono colonne duplicate con lo stesso nome dopo il rename, teniamo l'ultima 
        df = df.loc[:, ~df.columns.duplicated(keep='last')].copy()

        if 'label' not in df.columns and 'label_off' not in df.columns:
            pass 

        colonne_db_target = [
            'community_id', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 
            'timestamp_start', 'duration_ms', 'total_bytes', 'fwd_packets', 
            'bwd_packets', 'total_fwd_bytes', 'total_bwd_bytes', 'packet_rate', 
            'byte_rate', 'iat_flow_avg', 'iat_flow_stddev', 'label'
        ]

        # Creiamo il DataFrame finale includendo solo le colonne target
        df_finale = df[[c for c in colonne_db_target if c in df.columns]].copy()

        # -----------------------------------------------------------------
        # CORREZIONE TIMESTAMPS
        # -----------------------------------------------------------------
        print("[INFO] Validazione e correzione dei Timestamp...")
       
        df_finale['timestamp_start'] = (
            pd.to_datetime(df_finale['timestamp_start'], errors='coerce') - pd.Timedelta(hours=5)
        )
        n_null = df_finale['timestamp_start'].isna().sum()
        if n_null:
            print(f"[WARN] {n_null} righe senza timestamp scartate")
        df_finale = df_finale[df_finale['timestamp_start'].notna()].copy()

        # Ordiniamo cronologicamente e convertiamo nel formato stringa per MySQL
        df_finale.sort_values(by='timestamp_start', inplace=True, ignore_index=True)
        df_finale['timestamp_start'] = df_finale['timestamp_start'].dt.strftime('%Y-%m-%d %H:%M:%S.%f')

        # -----------------------------------------------------------------
        # CONVERSIONI NUMERICHE 
        # -----------------------------------------------------------------
        if 'duration_ms' in df_finale.columns:
            d = pd.to_numeric(df_finale['duration_ms'], errors='coerce').fillna(0).clip(lower=0)
            df_finale['duration_ms'] = d / 1000.0          # µs di CICFlowMeter -> ms

        fwd_b = pd.to_numeric(df_finale['total_fwd_bytes'], errors='coerce').fillna(0) if 'total_fwd_bytes' in df_finale.columns else 0
        bwd_b = pd.to_numeric(df_finale['total_bwd_bytes'], errors='coerce').fillna(0) if 'total_bwd_bytes' in df_finale.columns else 0
        df_finale['total_bytes'] = (fwd_b + bwd_b).astype(int)

        for col_5t in ['src_port', 'dst_port', 'protocol', 'fwd_packets', 'bwd_packets']:
            if col_5t in df_finale.columns:
                df_finale[col_5t] = pd.to_numeric(df_finale[col_5t], errors='coerce').fillna(0).astype(int)
                df_finale.loc[df_finale[col_5t] < 0, col_5t] = 0

        colonne_numeriche_sicure = ['packet_rate', 'byte_rate', 'iat_flow_avg', 'iat_flow_stddev', 'total_fwd_bytes', 'total_bwd_bytes']
        for col_num in colonne_numeriche_sicure:
            if col_num in df_finale.columns:
                df_finale[col_num] = pd.to_numeric(df_finale[col_num], errors='coerce').fillna(0.0)
                df_finale.loc[df_finale[col_num] < 0, col_num] = 0.0

        df_finale.replace([np.inf, -np.inf], np.nan, inplace=True)
        colonne_num_finali = df_finale.select_dtypes(include=[np.number]).columns
        df_finale[colonne_num_finali] = df_finale[colonne_num_finali].fillna(0.0)

        # -----------------------------------------------------------------
        # NORMALIZZAZIONE DELLA LABEL
        # -----------------------------------------------------------------
        colonne_testo = ['community_id', 'src_ip', 'dst_ip', 'label']
        for col in colonne_testo:
            if col in df_finale.columns:
                df_finale[col] = df_finale[col].astype(str).str.strip()

        if 'label' in df_finale.columns:
            scartate = df_finale['label'].isna() | df_finale['label'].astype(str).str.strip().isin(['UNMATCHED','nan','None',''])
            print(f"[INFO] {scartate.sum()} flussi UNMATCHED scartati")
            df_finale = df_finale[~scartate].copy()

        print(f"Inizio caricamento bulk di {len(df_finale)} flussi uniti nella tabella 'cic_flows'...")
        try:
            insert(df_finale, 'cic_flows', engine, chunksize=20000)
            print(f"[INFO] {csv_file} importato con successo!")
        except Exception as e:
            print(f"[ERRORE] Durante l'importazione di {csv_file}: {e}")
        
    print("\n[INFO] Pipeline di caricamento terminata.")

if __name__ == "__main__":
    main()

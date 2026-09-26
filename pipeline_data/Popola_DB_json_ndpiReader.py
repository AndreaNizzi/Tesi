import sys
import os
import json
import glob
import pandas as pd
import numpy as np
from sqlalchemy import create_engine
from sqlalchemy import text
from datetime import datetime, timezone
from communityid import CommunityID, FlowTuple
from dotenv import load_dotenv

cid = CommunityID()

load_dotenv()
# funzione per caricare i dati a blocchi 
def insert(df, table_name, engine, chunksize=10000):
    columns = ", ".join(df.columns)
    placeholders = ", ".join([f":{col}" for col in df.columns])
    query = text(f"INSERT INTO {table_name} ({columns}) VALUES ({placeholders})")
    
    # dividiamo il dataframe in blocchi per non saturare la memoria
    with engine.begin() as connection:
        for i in range(0, len(df), chunksize):
            chunk = df.iloc[i:i + chunksize]
            data = chunk.to_dict(orient='records')
            connection.execute(query, data)

def genera_community_id(src_ip, dst_ip, src_port, dst_port, protocol):
    try:
        s_ip = str(src_ip).strip()
        d_ip = str(dst_ip).strip()
        sp = int(src_port)
        dp = int(dst_port)
        p = int(protocol)
        
        # Sfruttiamo FlowTuple per calcolare l'hash bidirezionale corretto
        flow = FlowTuple(p, s_ip, d_ip, sp, dp)
        return cid.calc(flow)
    except Exception:
        return None
def main():
    if len(sys.argv) != 2:
        print("Uso: py Popola_DB_json_ndpiReader.py <input_pattern_o_file.json>")
        sys.exit(1)

    input_pattern = sys.argv[1]
    
    # Troviamo la lista di tutti i file 
    lista_file = glob.glob(input_pattern)

    if not lista_file:
        print(f"[ERRORE] Nessun file trovato per '{input_pattern}'.")
        sys.exit(1)

    # Configurazione db
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

    for input_file in lista_file:
        print(f"Inizio elaborazione file: {input_file}")
        
        righe_flat = []

        # Lettura del file JSON Lines riga per riga
        with open(input_file, 'r') as f:
            for linea in f:
                try:
                    linea_pulita = linea.strip()
                    if not linea_pulita:
                        continue
                        
                    dati = json.loads(linea_pulita)

                    ndpi_obj = dati.get('ndpi', {})

                    contiene_entropia_sospetta = 0
                    flow_risk = ndpi_obj.get('flow_risk', {})

                    if isinstance(flow_risk, dict) and flow_risk:
                        for _, risk_info in flow_risk.items():
                            if isinstance(risk_info, dict):
                                risk_name = risk_info.get('risk', '')
                                if risk_name == 'Susp Entropy':
                                    contiene_entropia_sospetta = 1      # flag a 1 se l'entropia è anomala

                    src_ip = dati.get('src_ip')
                    dst_ip = dati.get('dest_ip') 
                    src_port = dati.get('src_port')
                    dst_port = dati.get('dst_port')
                    
                    proto_raw = str(dati.get('proto', '')).upper()
                    if 'TCP' in proto_raw:
                        protocol = 6
                    elif 'UDP' in proto_raw:
                        protocol = 17
                    elif 'ICMP' in proto_raw:
                        protocol = 1
                    else:
                        # Se è già un numero o è un protocollo strano, proviamo a convertirlo in int, altrimenti usiamo 0
                        try:
                            protocol = int(float(dati.get('proto', 0)))
                        except:
                            protocol = 0

                    # assicuriamoci che le porte siano numeri interi puliti 
                    try:
                        src_port_clean = int(float(src_port))
                    except:
                        src_port_clean = 0
                        
                    try:
                        dst_port_clean = int(float(dst_port))
                    except:
                        dst_port_clean = 0

                    # Convertiamo i timestamp in formato DATETIME ISO
                    first_seen_epoch = dati.get('first_seen')
                    if first_seen_epoch:
                        try:
                            dt_oggetto = datetime.fromtimestamp(float(first_seen_epoch), tz=timezone.utc).replace(tzinfo=None)
                        except:
                            # Se fallisce la conversione, proviamo a usare il timestamp dell'ultima riga valida
                            dt_oggetto = righe_flat[-1]['timestamp_start'] if righe_flat else None
                    else:
                        # Se manca del tutto nel JSON, eredita l'orario del flusso precedente per non rompere la timeline
                        dt_oggetto = righe_flat[-1]['timestamp_start'] if righe_flat else None

                    # Se non abbiamo proprio un punto di partenza temporale per il file, salta la riga
                    if dt_oggetto is None:
                        continue
                    
                    # Generiamo il Community ID standard
                    comm_id = genera_community_id(src_ip, dst_ip, src_port_clean, dst_port_clean, protocol)
                    if not comm_id:
                        continue

                    xfer_obj = dati.get('xfer', {})
                    if not isinstance(xfer_obj, dict): xfer_obj = {}

                    iat_obj = dati.get('iat', {})
                    if not isinstance(iat_obj, dict): iat_obj = {}

                    tls_obj = ndpi_obj.get('tls', {})
                    if not isinstance(tls_obj, dict): tls_obj = {}

                    tcp_flags_obj = dati.get('tcp_flags', {})
                    if not isinstance(tcp_flags_obj, dict): tcp_flags_obj = {}

                    # calcoliamo bitmap dei flags TCP
                    fin = 1 if tcp_flags_obj.get('fin_count', 0) > 0 else 0
                    syn = 1 if tcp_flags_obj.get('syn_count', 0) > 0 else 0
                    rst = 1 if tcp_flags_obj.get('rst_count', 0) > 0 else 0
                    psh = 1 if tcp_flags_obj.get('psh_count', 0) > 0 else 0
                    ack = 1 if tcp_flags_obj.get('ack_count', 0) > 0 else 0
                    urg = 1 if tcp_flags_obj.get('urg_count', 0) > 0 else 0
                    ece = 1 if tcp_flags_obj.get('ece_count', 0) > 0 else 0
                    cwr = 1 if tcp_flags_obj.get('cwr_count', 0) > 0 else 0
                    
                    # bitwise standard di rete
                    tcp_flags_bitmap = (fin * 1 + syn * 2 + rst * 4 + psh * 8 + ack * 16 + urg * 32 + ece * 64 + cwr * 128)

                    fwd_bytes = xfer_obj.get('src2dst_bytes', 0)
                    bwd_bytes = xfer_obj.get('dst2src_bytes', 0)
                    total_bytes = fwd_bytes + bwd_bytes

                    fwd_pkts = xfer_obj.get('src2dst_packets', 0)
                    bwd_pkts = xfer_obj.get('dst2src_packets', 0)
                    total_pkts = fwd_pkts + bwd_pkts

                    duration_sec = float(dati.get('duration', 0))   # ndpiReader: secondi 
                    duration_ms = duration_sec * 1000.0             # millisecondi
                    packet_rate = (total_pkts / duration_sec) if duration_sec > 0 else 0
                    byte_rate = (total_bytes / duration_sec) if duration_sec > 0 else 0

                    # mappiamo i dati corretti
                    flusso_mappato = {
                        'community_id': comm_id,
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'src_port': src_port_clean,
                        'dst_port': dst_port_clean,
                        'protocol': protocol,
                        'timestamp_start': dt_oggetto,
                        'duration_ms': duration_ms,
                        'total_bytes': total_bytes,
                        'fwd_packets': fwd_pkts,
                        'bwd_packets': bwd_pkts,
                        'total_fwd_bytes': fwd_bytes,
                        'total_bwd_bytes': bwd_bytes,
                        'packet_rate': packet_rate,
                        'byte_rate': byte_rate,
                        'iat_flow_avg': iat_obj.get('flow_avg', 0),
                        'iat_flow_stddev': iat_obj.get('flow_stddev', 0),
                        'tcp_flags': tcp_flags_bitmap,
                        'ndpi_hostname': ndpi_obj.get('hostname', ''),
                        'payload_entropy': contiene_entropia_sospetta,
                        'app_hierarchy': ndpi_obj.get('proto', ''),
                        'infra_provider': ndpi_obj.get('proto_by_ip', ''),
                        'tls_version': tls_obj.get('version') if isinstance(tls_obj, dict) else None,
                        'tls_cipher_suite': tls_obj.get('cipher') if isinstance(tls_obj, dict) else None,
                        'tls_ja4': tls_obj.get('ja4') if isinstance(tls_obj, dict) else None,
                        'tls_issuer_dn': tls_obj.get('issuerDN') if isinstance(tls_obj, dict) else None
                    }

                    righe_flat.append(flusso_mappato)
                    
                except Exception as e:
                    continue

        if not righe_flat:
            print(f"[ERRORE]: Nessun dato valido estratto da {input_file}. Il file potrebbe essere vuoto o corrotto. Elaborazione interrotta per sicurezza.")
            sys.exit(1)
            
        # Creiamo il DataFrame Pandas 
        df_finale = pd.DataFrame(righe_flat)
        
        print(f"Dataset pronto. Righe totali: {len(df_finale)}")

        print("Pulizia del dataset: rimozione dei valori infiniti (inf) e NaN...")
        df_finale.replace([np.inf, -np.inf], np.nan, inplace=True)
        
        colonne_numeriche = [col for col in df_finale.select_dtypes(include=[np.number]).columns if col != 'payload_entropy']
        df_finale[colonne_numeriche] = df_finale[colonne_numeriche].fillna(0)
        colonne_testo = df_finale.select_dtypes(include=['object', 'string']).columns
        df_finale[colonne_testo] = df_finale[colonne_testo].fillna(np.nan).replace({np.nan: None})

        df_finale['payload_entropy'] = pd.to_numeric(df_finale['payload_entropy'], errors='coerce').fillna(0).astype('int64')
        
        # Asicuriamoci che Pandas tratti la colonna come datetime nativo ISO 8601
        df_finale['timestamp_start'] = pd.to_datetime(df_finale['timestamp_start'], errors='coerce')
        df_finale['timestamp_start'] = df_finale['timestamp_start'].dt.tz_localize(None) 

        print("[INFO] Allineamento temporale: Sottrazione di 3 ore per allineamento con cic_flows...")

        # Sottraiamo 3 ore per passare da UTC (orario nativo pcap) a EDT (orario locale dataset)
        df_finale['timestamp_start'] = df_finale['timestamp_start'] - pd.to_timedelta('3 hours')

        # Convertiamo nel formato stringa definitivo per MySQL TIMESTAMP(6)
        df_finale['timestamp_start'] = df_finale['timestamp_start'].dt.strftime('%Y-%m-%d %H:%M:%S.%f')

        print(f"Inizio caricamento bulk di {len(df_finale)} flussi nella tabella 'ndpi_flows'...")
        try:
            insert(df_finale, 'ndpi_flows', engine, chunksize=20000)
            print("Db popolato con successo!")
        except Exception as e:
            print(f"[ERRORE]: Durante l'importazione dei dati di {input_file}: {e}")
            sys.exit(1)

if __name__ == "__main__":
    main()

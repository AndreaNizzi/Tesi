import pandas as pd
import numpy as np
import os

# Mappa di tutti i file del dataset divisi per giorno
dataset_mappa = {
    'Lunedi': ['Monday-WorkingHours.pcap_ISCX.csv'],
    'Martedi': ['Tuesday-WorkingHours.pcap_ISCX.csv'],
    'Mercoledi': ['Wednesday-workingHours.pcap_ISCX.csv'],
    'Giovedi': [
        'Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv',
        'Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv'
    ],
    'Venerdi': [
        'Friday-WorkingHours-Morning.pcap_ISCX.csv',
        'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv',
        'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv'
    ]
}

def pipeline_pulizia_giornaliera(nome_giorno, lista_file):
    print(f"=== Elaborazione: {nome_giorno} ===")
    
    # Carichiamo e concateniamo dei file del giorno
    df_list = []
    for file in lista_file:
        if os.path.exists(file):
            df_list.append(pd.read_csv(file, encoding='cp1252', low_memory=False))
        else:
            print(f"File non trovato: {file}")
            return None
            
    df = pd.concat(df_list, ignore_index=True)
    righe_iniziali = len(df)
    
    # Puliamo i nomi delle colonne dagli spazi bianchi
    df.columns = df.columns.str.strip()
    
    # Rimuoviamo righe che ripetono l'header (il problema del Giovedì)
    df = df[df['Destination IP'] != 'Destination IP']
    
    # Convertiamo in numeri le colonne critiche (gestiamo stringhe 'Infinity' o spazi)
    colonne_critiche = ['Flow Bytes/s', 'Flow Packets/s']
    for col in colonne_critiche:
        df[col] = pd.to_numeric(df[col], errors='coerce')
    
    # Sostituiamo gli infiniti con NaN
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    
    # Rimuoviamo tutte le righe che contengono NaN nelle colonne numeriche o righe vuote
    df.dropna(how='all', inplace=True)
    df.dropna(subset=colonne_critiche, inplace=True)
    
    righe_finali = len(df)
    print(f"Righe Iniziali: {righe_iniziali} | Righe Finali: {righe_finali}")
    print(f"Rimossi {righe_iniziali - righe_finali} flussi non validi o corrotti.")
    
    # Salviamo il file di giornata pulito
    output_filename = f"{nome_giorno}-Pulito-Definitivo.csv"
    df.to_csv(output_filename, index=False, encoding='utf-8')
    print(f"Salvato: {output_filename}\n")

# Eseguiamo la pipeline su tutti i giorni configurati
for giorno, files in dataset_mappa.items():
    pipeline_pulizia_giornaliera(giorno, files)

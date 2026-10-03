import pandas as pd
import numpy as np

def pulisci_e_salva(lista_file, nome_output):
    print(f"--- Elaborazione {nome_output} ---")
    
    # Carichiamo e concateniamo i file
    df_list = [pd.read_csv(f, encoding='cp1252', low_memory=False) for f in lista_file]
    df = pd.concat(df_list, ignore_index=True)
    print(f"Righe pre-pulizia: {len(df)}")
    
    # Puliamo i nomi delle colonne da spazi bianchi
    df.columns = df.columns.str.strip()
    
    # Rimuoviamo righe che ripetono l'header
    df = df[df['Destination IP'] != 'Destination IP']
    
    # Rimuoviamo righe completamente vuote
    df.dropna(how='all', inplace=True)
    
    # Sostituiamo stringhe come 'Infinity' o spazi vuoti con NaN 
    df.replace(['Infinity', 'inf', 'NaN', ' '], np.nan, inplace=True)
    
    print(f"Righe post-pulizia: {len(df)}")
    
    # Salviamo il risultato
    df.to_csv(nome_output, index=False, encoding='utf-8')
    print(f"File {nome_output} generato con successo!\n")

# Eseguiamo per il Giovedì
files_giovedi = [
    'Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv',
    'Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv'
]
pulisci_e_salva(files_giovedi, 'Thursday-Ufficiali-Completo.csv')

# Eseguiamo per il Venerdì
files_venerdi = [
    'Friday-WorkingHours-Morning.pcap_ISCX.csv',
    'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv',
    'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv'
]
pulisci_e_salva(files_venerdi, 'Friday-Ufficiali-Completo.csv')

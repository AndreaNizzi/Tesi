
import sys
import pandas as pd
import numpy as np
from ipaddress import ip_address
import communityid

CID = communityid.CommunityID()

# ---------------------------
# COMMUNITY ID
# ---------------------------
def calc_community_id(sip, dip, sport, dport, proto):
    try:
        src_ip = ip_address(str(sip).strip())
        dst_ip = ip_address(str(dip).strip())
        proto_num = int(str(proto).strip())

        s = int(str(sport).strip())
        d = int(str(dport).strip())

        if proto_num == 6:
            tpl = communityid.FlowTuple.make_tcp(src_ip, dst_ip, s, d)
        elif proto_num == 17:
            tpl = communityid.FlowTuple.make_udp(src_ip, dst_ip, s, d)
        elif proto_num == 1:
            tpl = communityid.FlowTuple.make_icmp(src_ip, dst_ip, s, d)
        elif proto_num == 58:
            tpl = communityid.FlowTuple.make_icmp6(src_ip, dst_ip, s, d)
        else:
            return "error"

        return CID.calc(tpl)
    except Exception:
        return "error"


# ---------------------------
# COL DETECTION
# ---------------------------
def auto_detect_columns(columns):
    cols = {}
    for c in columns:
        cl = str(c).lower().strip()
        if 'id' in cl and ('src' in cl or 'dst' in cl or 'flow' in cl):
            continue
        
        if ('src' in cl or 'source' in cl) and 'ip' in cl:
            cols['src'] = c
        elif ('dst' in cl or 'dest' in cl) and 'ip' in cl:
            cols['dst'] = c
        elif ('src' in cl or 'source' in cl) and 'port' in cl:
            cols['sp'] = c
        elif ('dst' in cl or 'dest' in cl) and 'port' in cl:
            cols['dp'] = c
        elif 'protocol' in cl or cl == 'proto':
            cols['pr'] = c
        elif 'timestamp' in cl:
            cols['ts'] = c
    return cols


# ---------------------------
# PROTOCOL + PORTS
# ---------------------------
def normalize_proto(series):
    proto_map = {"TCP": "6", "UDP": "17", "ICMP": "1", "ICMPV6": "58"}
    s = series.astype(str).str.strip().str.upper().replace(proto_map)
    return pd.to_numeric(s, errors="coerce").astype("Int64").astype(str)


def prepare_ports(df, sp_col, dp_col):
    df["s_port"] = pd.to_numeric(df[sp_col], errors="coerce").astype("Int64").astype(str)
    df["d_port"] = pd.to_numeric(df[dp_col], errors="coerce").astype("Int64").astype(str)
    return df


def build_community_ids(df, cols):
    df["Community_ID"] = [
        calc_community_id(sip, dip, sp, dp, pr)
        for sip, dip, sp, dp, pr in zip(
            df[cols["src"]],
            df[cols["dst"]],
            df["s_port"],
            df["d_port"],
            df["proto_clean"]
        )
    ]
    return df


# ---------------------------
# TIMESTAMP PARSING
# ---------------------------
def robust_timestamp_parsing(series):
    s = series.astype(str).str.strip().str.replace(r'\s+', ' ', regex=True)
    res = pd.to_datetime(pd.Series(np.nan, index=series.index))
    
    mask_pm = s.str.contains('AM|PM|am|pm', na=False)
    if mask_pm.any():
        res.loc[mask_pm] = pd.to_datetime(s.loc[mask_pm], format='%d/%m/%Y %I:%M:%S %p', errors='coerce')
        still_na = res.isna() & mask_pm
        if still_na.any():
            res.loc[still_na] = pd.to_datetime(s.loc[still_na], format='%d/%m/%Y %I:%M %p', errors='coerce')

    mask_24h = ~mask_pm
    if mask_24h.any():
        res.loc[mask_24h] = pd.to_datetime(s.loc[mask_24h], format='%d/%m/%Y %H:%M:%S', errors='coerce')
        still_na_24h = res.isna() & mask_24h
        if still_na_24h.any():
            res.loc[still_na_24h] = pd.to_datetime(s.loc[still_na_24h], format='%d/%m/%Y %H:%M', errors='coerce')

    if res.isna().any():
        res = res.fillna(pd.to_datetime(s, errors='coerce', format='mixed', dayfirst=True))

    return res

def read_uff(path):
    try:
        return pd.read_csv(path, encoding="utf-8", low_memory=False)
    except UnicodeDecodeError:
        return pd.read_csv(path, encoding="cp1252", low_memory=False)
    
# ---------------------------
# MAIN
# ---------------------------
def main():
    if len(sys.argv) != 4:
        print("Uso: python join_CSV.py <pcap_miei.csv> <definitivo_uff.csv> <out.csv>")
        sys.exit(1)

    path_miei, path_off, path_out = sys.argv[1:]

    print("[INFO] Caricamento dati...")
    df_miei = pd.read_csv(path_miei, low_memory=False)
    df_uff = read_uff(path_off)

    df_miei.columns = df_miei.columns.str.strip()
    df_uff.columns = df_uff.columns.str.strip()

    miei_cols = auto_detect_columns(df_miei.columns)
    off_cols = auto_detect_columns(df_uff.columns)

    required = ['src', 'dst', 'sp', 'dp', 'pr', 'ts']
    for r in required:
        if r not in miei_cols or r not in off_cols:
            print(f"[ERROR] Colonna mancante nel mapping: {r}")
            sys.exit(1)

    df_miei.replace([np.inf, -np.inf], np.nan, inplace=True)
    df_uff.replace([np.inf, -np.inf], np.nan, inplace=True)

    df_miei["proto_clean"] = normalize_proto(df_miei[miei_cols["pr"]])
    df_uff["proto_clean"] = normalize_proto(df_uff[off_cols["pr"]])

    df_miei = prepare_ports(df_miei, miei_cols["sp"], miei_cols["dp"])
    df_uff = prepare_ports(df_uff, off_cols["sp"], off_cols["dp"])

    print("[INFO] Parsing dei timestamp...")
    df_miei["ts"] = robust_timestamp_parsing(df_miei[miei_cols["ts"]])
    df_uff["ts"] = robust_timestamp_parsing(df_uff[off_cols["ts"]])

    df_miei = df_miei[df_miei["ts"].notna()].copy()
    df_uff = df_uff[df_uff["ts"].notna()].copy()

    print("[INFO] Generazione Community ID...")
    df_miei = build_community_ids(df_miei, miei_cols)
    df_uff = build_community_ids(df_uff, off_cols)

    df_miei = df_miei[df_miei["Community_ID"].ne("error")].copy()
    df_uff = df_uff[df_uff["Community_ID"].ne("error")].copy()
    df_miei["flow_key"] = df_miei["Community_ID"] + "|" + df_miei[miei_cols["src"]].astype(str).str.strip()
    df_uff["flow_key"] = df_uff["Community_ID"] + "|" + df_uff[off_cols["src"]].astype(str).str.strip()

    common = set(df_miei["Community_ID"]) & set(df_uff["Community_ID"])
    print(f"[INFO] Community ID unici in comune: {len(common)}")

    if len(common) == 0:
        print("[ERROR] Nessun Community ID comune trovato.")
        sys.exit(1)

    # -----------------------
    # TIME ALIGNMENT
    # -----------------------
    print("[INFO] Sincronizzazione del fuso orario (-5 ore dal PCAP)...")

    # Portiamo indietro di 5 ore l'orario di df_miei per ottenere l'orario lavorativo reale (9 AM - 5 PM)
    delta_fuso = pd.Timedelta(hours=5)
    
    df_miei["ts_match"] = df_miei["ts"] - delta_fuso
    
    # Per il file definitivo (df_uff), normalizziamo i pomeriggio 
    mask_pomeriggio_uff = df_uff["ts"].dt.hour < 8
    if mask_pomeriggio_uff.any():
        df_uff.loc[mask_pomeriggio_uff, "ts"] = df_uff.loc[mask_pomeriggio_uff, "ts"] + pd.Timedelta(hours=12)
    
    df_uff["ts_match"] = df_uff["ts"]
    # I timestamp ufficiali (Mar-Ven) sono troncati al minuto: allineiamo entrambi sul minuto
    df_miei["ts_key"] = df_miei["ts_match"].dt.floor("min")
    df_uff["ts_key"] = df_uff["ts_match"].dt.floor("min")

    # -----------------------
    # DURATION EXTRACTION
    # -----------------------
    duration_col_off = next((c for c in df_uff.columns if "duration" in c.lower()), None)
    duration_col_miei = next((c for c in df_miei.columns if "duration" in c.lower()), None)

    df_miei["duration_norm"] = pd.to_numeric(df_miei[duration_col_miei], errors="coerce")
    df_uff["duration_norm"] = pd.to_numeric(df_uff[duration_col_off], errors="coerce")

    # -----------------------
    # MERGE FINAL
    # -----------------------
    print("[INFO] Allineamento temporale...")
    df_miei["ts_key"] = pd.to_datetime(df_miei["ts_key"], errors="coerce").dt.as_unit("ns")
    df_uff["ts_key"] = pd.to_datetime(df_uff["ts_key"], errors="coerce").dt.as_unit("ns")

    df_miei = df_miei.sort_values("ts_key").copy()
    df_uff = df_uff.sort_values("ts_key").copy()

    label_col_off = next((c for c in df_uff.columns if "label" in c.lower() or "class" in c.lower()), "Label")

    print("[INFO] Accoppiamento dei flussi...")
    df_final = pd.merge_asof(
        df_miei,
        df_uff[["flow_key", "ts_key", "duration_norm", label_col_off]],
        on="ts_key",
        by="flow_key",
        direction="nearest",
        tolerance=pd.Timedelta(minutes=1),
        suffixes=('', '_off')
    )

    # -------------------------------------------------------------
    # SOVRASCRIVIAMO LA COLONNA TIMESTAMP ORIGINALE
    # -------------------------------------------------------------
    
    df_final[miei_cols["ts"]] = pd.to_datetime(df_final["ts_match"]).dt.strftime('%d/%m/%Y %I:%M:%S %p')
    
    # Rimuoviamo la colonna di servizio temporanea
    df_final.drop(columns=["Orario_Reale_AM_PM"], errors="ignore", inplace=True)

    final_label_col = f"{label_col_off}_off" if f"{label_col_off}_off" in df_final.columns else label_col_off

    matched = df_final[final_label_col].notna().mean()
    print(f"[INFO] Tasso di match: {matched:.1%}")
    if matched < 0.95:
        print("[WARN] Match basso: controlla shift orario e formato timestamp")

    df_final["Label"] = df_final[final_label_col].fillna("UNMATCHED").astype(str)

    print("[INFO] Salvataggio dei dati...")
    df_final.to_csv(path_out, index=False)

    print(f"\n[SUCCESS] TOTALE RECORD GENERATI: {len(df_final)}")
    print("\nDISTRIBUZIONE DELLE ETICHETTE:")
    print(df_final["Label"].value_counts(dropna=False).head(20))


if __name__ == "__main__":
    main()

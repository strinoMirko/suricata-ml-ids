import json
import pandas as pd
import numpy as np
from datetime import datetime
from sklearn.preprocessing import LabelEncoder, MinMaxScaler
from sklearn.ensemble import IsolationForest
import joblib
import os
import ipaddress

INPUT_FILE = "featuresFromEve.json"

records = [json.loads(line) for line in open(INPUT_FILE, encoding="utf-8")]
df = pd.DataFrame(records)


def normalize_proto_value(v):
    if isinstance(v, list) and len(v) > 0:
        v = v[0]
    if v is None:
        return ""
    return str(v).strip().lower()

def detect_protocol(row):
    proto = normalize_proto_value(row.get("proto", ""))
    app_proto = normalize_proto_value(row.get("app_proto", ""))
    if "icmp" in proto or "icmp" in app_proto:
        return "ICMP"
    elif "http" in proto or "http" in app_proto:
        return "HTTP"
    elif "udp" in proto or app_proto in ["dhcp", "dns", "ntp"]:
        return "UDP"
    else:
        return "TCP"

def to_seconds(t):
    try:
        dt = datetime.fromisoformat(t.replace("Z", "+00:00"))
        return dt.hour * 3600 + dt.minute * 60 + dt.second
    except Exception:
        return np.nan

df["traffic_type"] = df.apply(detect_protocol, axis=1)

print("\nIdentified types:")
print(df["traffic_type"].value_counts(dropna=False).to_string())

base_features = [
    "dest_port", "proto", "ip_v", "signature_id", "app_proto",
    "direction", "pkts_toserver", "pkts_toclient",
    "bytes_toserver", "bytes_toclient", "url", "http_user_agent",
    "http_content_type", "http_method", "protocol", "status", "size"
]

num_cols = ["dest_port", "signature_id", "pkts_toserver", "pkts_toclient",
            "bytes_toserver", "bytes_toclient", "size", "timestamp_sec"]

cat_cols = ["proto", "ip_v", "app_proto", "direction",
            "url", "http_user_agent", "http_content_type",
            "http_method", "protocol", "status"]


def train_model(df_group, group_name):
    print(f"\n Train Model for: {group_name} (n={len(df_group)})")

    if len(df_group) < 10:
        print(f"Low entries: ({len(df_group)}) – skip {group_name}.")
        return

    df_group = df_group.copy()

    # fill missing column
    for col in base_features:
        if col not in df_group.columns:
            df_group[col] = None

    for col in df_group.columns:
        df_group[col] = df_group[col].apply(lambda x: x[0] if isinstance(x, list) else x)

    # new features
    if "src_ip" in df_group.columns:
        df_group["src_ip_num"] = df_group["src_ip"].apply(
            lambda x: int(ipaddress.ip_address(x)) if pd.notna(x) else 0
        )
        if "src_ip_num" not in base_features:
            base_features.append("src_ip_num")

    if "timestamp" in df_group.columns:
        df_group["timestamp_sec"] = df_group["timestamp"].apply(to_seconds).fillna(0)
        if "timestamp_sec" not in base_features:
            base_features.append("timestamp_sec")

    for col in num_cols:
        if col in df_group.columns:
            df_group[col] = pd.to_numeric(df_group[col], errors="coerce").fillna(0)

    encoders = {}
    for col in cat_cols:
        df_group[col] = df_group[col].fillna("unknown").astype(str)
        enc = LabelEncoder()
        df_group[col] = enc.fit_transform(df_group[col])
        encoders[col] = enc

    for col in ["dest_port", "signature_id"]:
        if col in df_group.columns:
            df_group[col] = pd.to_numeric(df_group[col], errors="coerce").fillna(0)

    X = df_group[base_features].fillna(0)


    scaler = MinMaxScaler()
    X_scaled = scaler.fit_transform(X)

    iso = IsolationForest(
        n_estimators=200,
        contamination=0.009,
        random_state=42,
        n_jobs=-1
    )
    iso.fit(X_scaled)

    os.makedirs("models", exist_ok=True)

    known_signatures = df_group["signature_id"].unique().tolist()
    print('[%s]' % ', '.join(map(str, known_signatures)))
    joblib.dump(known_signatures, f"models/known_signatures_{group_name}.pkl")
    joblib.dump(iso, f"models/isoforest_{group_name}.pkl")
    joblib.dump(scaler, f"models/scaler_{group_name}.pkl")
    joblib.dump(encoders, f"models/encoders_{group_name}.pkl")
    joblib.dump(base_features, f"models/features_{group_name}.pkl")

    print(f"Model: '{group_name}' saved ({len(X)} Samples)")


for group_name, group_df in df.groupby("traffic_type"):
    train_model(group_df, group_name)

print("\n Training completed.")

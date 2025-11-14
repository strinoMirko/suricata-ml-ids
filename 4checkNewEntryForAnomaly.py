import json
import pandas as pd
import joblib
import numpy as np
from datetime import datetime
import os
from sklearn.preprocessing import MinMaxScaler, LabelEncoder
import sys
import matplotlib.pyplot as plt

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
    #iso to seconds
    try:
        dt = datetime.fromisoformat(t.replace("Z", "+00:00"))
        return dt.hour * 3600 + dt.minute * 60 + dt.second
    except Exception:
        return np.nan

MODEL_DIR = "/home/suricata/Downloads/isolationForest/eve30-10_8-15/models"
MODELS = {}
for proto in ["TCP", "UDP", "HTTP", "ICMP"]:
    postfix = f"{proto}"
    model_path = os.path.join(MODEL_DIR, f"isoforest_{postfix}.pkl")
    scaler_path = os.path.join(MODEL_DIR, f"scaler_{postfix}.pkl")
    enc_path = os.path.join(MODEL_DIR, f"encoders_{postfix}.pkl")
    feat_path = os.path.join(MODEL_DIR, f"features_{postfix}.pkl")
    sig_path = os.path.join(MODEL_DIR, f"known_signatures_{postfix}.pkl")

    if all(os.path.exists(p) for p in [model_path, scaler_path, enc_path, feat_path]):
        model = joblib.load(model_path)
        scaler = joblib.load(scaler_path)
        encoders = joblib.load(enc_path)
        features = joblib.load(feat_path)

        known_signatures = []
        if os.path.exists(sig_path):
            raw_sigs = joblib.load(sig_path)
            # converts signatures to int
            try:
                known_signatures = [int(x) for x in raw_sigs if x is not None]
                known_signatures = [x for x in known_signatures if x > 0]
            except Exception:
                # Fallback
                known_signatures = []
                for x in raw_sigs:
                    try:
                        ix = int(x)
                        if ix > 0:
                            known_signatures.append(ix)
                    except Exception:
                        continue

        MODELS[proto] = {
            "model": model,
            "scaler": scaler,
            "encoders": encoders,
            "features": features,
            "known_signatures": known_signatures,
        }
        print(f"Model loaded for {proto} ({len(known_signatures)} known signatures).")
    else:
        print(f"No Model found for {proto} – skip.")


input_file = sys.argv[1]  
records = [json.loads(line) for line in open(input_file, encoding="utf-8")]
df = pd.DataFrame(records)


df["traffic_type"] = df.apply(detect_protocol, axis=1)

print("\nFound following traffic_types:")
print(df["traffic_type"].value_counts(dropna=False).to_string())

all_anomalies = []

for proto, group in df.groupby("traffic_type"):
    if proto not in MODELS:
        print(f"No model found for {proto} , skip entry.")
        continue

    model_info = MODELS[proto]
    model = model_info["model"]
    scaler = model_info["scaler"]
    encoders = model_info["encoders"]
    features = model_info["features"].copy() 
    known_sigs = model_info.get("known_signatures", [])

    for col in group.columns:
        group[col] = group[col].apply(lambda x: x[0] if isinstance(x, list) else x)

    for col in features:
        if col not in group.columns:
            group[col] = None

    if "timestamp" in group.columns:
        group["timestamp_sec"] = group["timestamp"].apply(to_seconds).fillna(0)
        if "timestamp_sec" not in features:
            features.append("timestamp_sec")

    num_cols = [
        "dest_port", "signature_id", "pkts_toserver", "pkts_toclient",
        "bytes_toserver", "bytes_toclient", "size", "timestamp_sec"
    ]
    for col in num_cols:
        if col in group.columns:
            group[col] = pd.to_numeric(group[col], errors="coerce").fillna(0)

    if "signature_id" in group.columns:
        group["signature_id"] = group["signature_id"].fillna(0).astype(int)

    group["is_new_signature"] = ~group["signature_id"].isin(known_sigs)

    for col, enc in encoders.items():
        if col in group.columns:
            group[col] = group[col].fillna("unknown").astype(str)
            if "unknown" not in enc.classes_:
                enc.classes_ = np.append(enc.classes_, "unknown")

            group[col] = group[col].apply(lambda x: x if x in enc.classes_ else "unknown")
            group[col] = enc.transform(group[col])
        else:
            group[col] = 0

    X = group.reindex(columns=features).fillna(0)
    try:
        X_scaled = scaler.transform(X)
    except Exception as e:
        print(f"Failed to scale for {proto}: {e}")
        X_scaled = np.zeros((len(X), len(features)))

    try:
        group["anomaly_score"] = model.decision_function(X_scaled)
        group["is_anomaly"] = model.predict(X_scaled)
    except Exception as e:
        print(f"Error predicting {proto}: {e}")
        group["anomaly_score"] = 0
        group["is_anomaly"] = 1

    group.loc[group["is_new_signature"], "is_anomaly"] = -1
    group.loc[group["is_new_signature"], "anomaly_score"] = -999  

    anomalies = group[group["is_anomaly"] == -1].copy()
    anomalies["model_used"] = proto
    all_anomalies.append(anomalies)

    new_sigs = group.loc[group["is_new_signature"], "signature_id"].unique()
    if len(new_sigs) > 0:
        print(f"Found {len(new_sigs)} new signatures in {proto}-Traffic: {new_sigs[:5]}{'...' if len(new_sigs)>5 else ''}")

    print(f"{len(anomalies)} anomalies found in {proto}-model")


    df_corr = group.copy()
    numeric_df = df_corr.select_dtypes(include=[np.number])

    if "anomaly_score" in numeric_df.columns:
        corrs = numeric_df.corr(numeric_only=True)["anomaly_score"].abs().sort_values(ascending=False)
        print(f"\nTop features in {proto}-model:")
        print(corrs.head(10))

    if not anomalies.empty:
        try:
            X_unscaled = pd.DataFrame(scaler.inverse_transform(X_scaled), columns=features)
            feature_means = X_unscaled.mean(axis=0)
            diff = abs(X_unscaled - feature_means)
            diff_mean = diff.mean(axis=0)
            top_features = pd.Series(diff_mean, index=features).sort_values(ascending=False).head(5)

            print(f"\nThese features have the most difference in model: {proto}:")
            print(top_features)
        except Exception:
            pass


if all_anomalies:
    result_df = pd.concat(all_anomalies, ignore_index=True)
    output_file = "detected_anomalies.json"
    result_df.to_json(output_file, orient="records", indent=2, force_ascii=False)
    print(f"\n{len(result_df)} anomalies found in total and saved in '{output_file}'.")
else:
    print("\nNo anomalies found.")

#Extracts specified features
import json
import sys
from datetime import datetime, timedelta


def process_entry(entry, history, window=timedelta(seconds=60)):
    id_ = entry.get("signature_id")[0]
    ts_str = entry.get("timestamp")[0]
    ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))

    if not (id_ and ts):
        return None  

    history.setdefault(id_, [])
    history[id_] = [t for t in history[id_] if ts - t <= window]

    history[id_].append(ts)

    entry["timestamp"] = ts.strftime("%H:%M:%S")
    entry["count_last_60s"] = len(history[id_])
    return entry

def find_nodes(obj, keys):
    found = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in keys:
                found.setdefault(k, []).append(v)
            found.update(find_nodes(v, keys))
    elif isinstance(obj, list):
        for item in obj:
            found.update(find_nodes(item, keys))
    return found

def main():
    results = []
    counter = 0
    history = {}
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        for line in f:
            data = json.loads(line)
            nodes = find_nodes(
                data,
                keys=[
                    "timestamp", "src_ip", "dest_port", "proto", "ip_v",
                    "signature_id", "app_proto", "direction", "pkts_toserver", "pkts_toclient", "bytes_toserver", "bytes_toclient",
                    "url", "http_user_agent", "http_content_type", "http_method", "protocol", "status", "size"
                ]
            )
            processed = process_entry(nodes, history)
            if processed:
                results.append(processed)

    for r in results:
        print(json.dumps(r))

if __name__ == "__main__":
    main()
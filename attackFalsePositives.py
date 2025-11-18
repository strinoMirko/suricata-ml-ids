#!/usr/bin/env python3

import argparse
import concurrent.futures
import csv
import ipaddress
import os
import random
import string
import threading
import time
from datetime import datetime, timezone
from typing import Dict, List
import psycopg2
import requests

BASELINE_TEXTS = [
    "Eine Datei kann mit dem Befehl chmod +x ausführbar gemacht werden",
    "Ein Script lässt sich durch die Tags <script> und </script> ausführen",
    "Ea sdässt asd rd\x00char",
    "email@@example..com",
    "Diese Nachricht enthält Sonderzeichen: äöü ß €"
]

IP_CLIENT_POOL = [
    "192.168.0.200",
    "192.168.0.205",
    "192.168.0.206",
    "192.168.0.207",
    "192.168.0.208",
    "192.168.0.209",
    "192.168.0.210",
    "192.168.0.211",
    
]

DEFAULT_TIMEOUT = 12.0

def long_string(n: int) -> str:
    return ''.join(random.choices(string.ascii_letters + string.digits, k=n))

def build_headers(session_id: int, extra: Dict = None, long_header: bool = False) -> Dict[str, str]:
    headers = {
        "User-Agent": random.choice([ #Agent Variation
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "curl/7.79.1",
            "python-requests/2.x",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
        ]),
        "Accept": "*/*",
        "X-Client-Id": f"client-{session_id}"

    }
    if long_header and random.random() < 0.5:
        headers["X-Test-Long"] = long_string(random.randint(2000, 20000))
    if extra:
        headers.update(extra)
    return headers


def do_simple_get(base_url: str, payload_text: str, headers: Dict, timeout: float):
    print("Gewöhnlicher Get... mit " + payload_text)
    params = {"q": payload_text[:400]}
    url = f"{base_url}/probe/sqli"
    r = requests.get(url, params=params, headers=headers, timeout=timeout)
    return r.status_code, url, params

def do_xss_probe(base_url: str, payload: str, headers: Dict, timeout: float):
    print("XSS Ähnlicher Aufruf...mit " + payload)
    url = f"{base_url}/probe/xss"
    data = {"note": f"Feedback: {payload}"}
    r = requests.get(url, data=data, headers=headers, timeout=timeout)
    return r.status_code, url, data

def do_long_header(base_url: str, headers: Dict, timeout: float):
    print("Aufruf mit langem Header...")
    url = f"{base_url}/headers/long?size=20000"
    r = requests.get(url, headers=headers, timeout=timeout)
    return r.status_code, url, None

def do_file_upload(base_url: str, file_path: str, headers: Dict, timeout: float):
    print("Lade Datei Hoch...")
    url = f"{base_url}/upload"
    with open(file_path, "rb") as f:
        files = {"file": (os.path.basename(file_path), f, "application/octet-stream")}
        r = requests.post(url, files=files, headers=headers, timeout=timeout)
    return r.status_code, url, {"file": os.path.basename(file_path)}

def do_ping(host: str):
    print("Starte ping...")
    response = os.system("ping -c 3 "+ host + " > nul")

def do_connection_db(hostip: str):
    print("Verbinde zu db...")
    connection = psycopg2.connect(database="appdb", user="meinuser", password="password", host=hostip, port=5432)
    connection.close()


PATTERNS = {
    "simple_get": do_simple_get,
    "xss_probe": do_xss_probe,
    "long_header": do_long_header,
    "file_upload": do_file_upload,
    "ping": do_ping,
    "connection_db": do_connection_db
}



def random_bin_file(path: str, size_bytes: int):
    with open(path, "wb") as f:
        f.write(os.urandom(size_bytes))

def run_session(base_url: str, session_idx: int, args) -> List[Dict]:
    rng = random.Random(session_idx ^ int(time.time()))
    results = []


    time.sleep(rng.uniform(0, args.session_start_jitter))

    req_count = rng.randint(1, 5)
    created_files = []

    for i in range(req_count):

        intra = rng.uniform(args.min_delay, args.max_delay)
        time.sleep(intra)

        pattern = rng.choice(list(PATTERNS.keys()))
        headers = build_headers(session_idx, long_header=(pattern == "long_header" and rng.random() < 0.6))

        try:
            if pattern == "simple_get":
                payload = rng.choice(BASELINE_TEXTS)
                status, url, meta = do_simple_get(base_url, payload, headers, DEFAULT_TIMEOUT)

            elif pattern == "xss_probe":
                payload = rng.choice(BASELINE_TEXTS)
                status, url, meta = do_xss_probe(base_url, payload, headers, DEFAULT_TIMEOUT)

            elif pattern == "long_header":
                status, url, meta = do_long_header(base_url, headers, DEFAULT_TIMEOUT)

            elif pattern == "file_upload":
                size_kb = rng.choice([1, 8, 32, 128])
                path = f"/tmp/random_{session_idx}_{i}.bin"
                random_bin_file(path, size_kb * 1024)
                created_files.append(path)
                status, url, meta = do_file_upload(base_url, path, headers, DEFAULT_TIMEOUT)
            elif pattern == "ping":
            	do_ping(args.host)
            elif pattern == "connection_db":
            	do_connection_db(args.host)
            else:
                status, url, meta = (0, "unknown", None)

            results.append({
                "session_id": session_idx,
                "pattern": pattern,
                "status": status,
                "url": url,
                "meta": str(meta),
                "client_ip_header": headers.get("X-Forwarded-For"),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
        except Exception as e:
            results.append({
                "session_id": session_idx,
                "pattern": pattern,
                "status": "error",
                "url": url if 'url' in locals() else "unknown",
                "meta": f"exception:{e}",
                "client_ip_header": headers.get("X-Forwarded-For"),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

    for fpath in created_files:
        try:
            os.remove(fpath)
        except Exception:
            pass

    return results


def run_loop(base_url: str, args):
    fieldnames = ["session_id", "pattern", "status", "url", "meta", "client_ip_header", "timestamp"]

    session_counter = 0
    start_time = time.time()

    try:
        iteration = 0
        while True:
            if args.iterations and iteration >= args.iterations:
                break
            if args.duration and (time.time() - start_time) > args.duration:
                break

            batch_size = args.batch_size

            batch_size = max(1, int(random.gauss(batch_size, batch_size * 0.25)))


            with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as exe:
                futures = []
                for b in range(batch_size):
                    fut = exe.submit(run_session, base_url, session_counter, args)
                    futures.append(fut)
                    session_counter += 1

                for fut in concurrent.futures.as_completed(futures):
                    rows = fut.result()
                    changeToRandomIp()


            iteration += 1
            

            gap = random.uniform(args.min_batch_gap, args.max_batch_gap)
            gap *= random.uniform(0.75, 1.5)
            if iteration % max(1, args.status_interval) == 0:
                print(f"[{datetime.now().isoformat()}] Iteration {iteration}, sessions_sent={session_counter}, next_gap={gap:.1f}s")
            time.sleep(gap)

            if not args.loop and not args.iterations and not args.duration:
                break

    except KeyboardInterrupt:
        print("Abbruch...")
    finally:
        print(f"Fertig. Gesamte Sessions: {session_counter}.")

def changeToRandomIp():
    os.system("sudo ifconfig eth0 down")
    newIp = random.choice(IP_CLIENT_POOL)
    print("changing to client with ip: " + newIp)
    os.system("sudo ifconfig eth0 " + newIp)
    os.system("sudo ifconfig eth0 up")
    

def parse_args():
    p = argparse.ArgumentParser(description="Generate realistic looking traffic in batches/loop.")
    p.add_argument("--host", required=True)
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--use_tls", action="store_true")
    p.add_argument("--batch_size", type=int, default=10, help="Sessions per batch")
    p.add_argument("--workers", type=int, default=20, help="Thread pool size for parallel sessions")
    p.add_argument("--min_delay", type=float, default=0.5, help="Min intra-session delay in seconds")
    p.add_argument("--max_delay", type=float, default=30.0, help="Max intra-session delay in seconds")
    p.add_argument("--session_start_jitter", type=float, default=2.0, help="Pre-session jitter seconds")
    p.add_argument("--min_batch_gap", type=float, default=1.0, help="Min gap between batches in seconds")
    p.add_argument("--max_batch_gap", type=float, default=120.0, help="Max gap between batches in seconds")
    p.add_argument("--status_interval", type=int, default=1, help="How often to print status (in iterations)")
    p.add_argument("--loop", action="store_true", help="Run forever until interrupted")
    p.add_argument("--iterations", type=int, default=0, help="Number of batches to run (0 = not used)")
    p.add_argument("--duration", type=float, default=0.0, help="Total run duration in seconds (0 = not used)")
    return p.parse_args()

def main():
    args = parse_args()
    scheme = "https" if args.use_tls else "http"
    base_url = f"{scheme}://{args.host}:{args.port}"

    if args.iterations <= 0:
        args.iterations = None
    if args.duration <= 0:
        args.duration = None

    print(f"Starte Traffic-Loop -> target={base_url}, batch_size={args.batch_size}, loop={args.loop}, duration={args.duration}, iterations={args.iterations}")
    run_loop(base_url, args)

if __name__ == "__main__":
    main()


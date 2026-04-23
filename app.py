"""CT Listener — écoute le flux Certificate Transparency en continu
et enregistre les nouveaux NDD par jour + par TLD.

Sert une API HTTP pour que les scanners locaux (EmailScraper, Belgique Scanner…)
récupèrent la liste des NDD captés quand ils en ont besoin.

Source du flux : CertStream (https://certstream.calidog.io/)
Format messages : JSON {data: {leaf_cert: {all_domains: [...]}, ...}, message_type: "certificate_update"}
"""
import os
import json
import gzip
import time
import socket
import threading
import signal
import sys
from datetime import datetime, timedelta, timezone
from collections import defaultdict, deque

import websocket  # websocket-client
from flask import Flask, request, Response, jsonify

# ── Config ────────────────────────────────────────────────────────────────────
DATA_DIR = os.environ.get("DATA_DIR", "/data")
os.makedirs(DATA_DIR, exist_ok=True)

# TLDs filtrés. Séparés par virgule dans la variable d'env.
# Par défaut : pays européens utiles + les TLD principaux.
TLDS_RAW = os.environ.get("TLDS", ".fr,.be,.ch,.eu,.de,.nl,.es,.it,.uk,.com,.net,.org,.io,.shop,.online,.xyz")
TLDS = tuple(t.strip().lower() for t in TLDS_RAW.split(",") if t.strip())

# Token d'accès simple (optionnel — les données CT sont publiques de toute façon)
ACCESS_TOKEN = os.environ.get("ACCESS_TOKEN", "").strip()

# Limites de rétention
RETENTION_DAYS = int(os.environ.get("RETENTION_DAYS", "30"))

# Endpoint CertStream compatible. Par défaut : notre ct-server Railway interne.
# On peut override avec la variable d'env CT_WSS si on veut un autre provider.
CT_WSS = os.environ.get("CT_WSS", "ws://ct-server.railway.internal:8080/full-stream")

PORT = int(os.environ.get("PORT", "8080"))

# ── État partagé ──────────────────────────────────────────────────────────────
class State:
    def __init__(self):
        self.started_at = datetime.now(timezone.utc)
        self.total_certs = 0            # nb de certificats reçus depuis démarrage
        self.total_domains = 0          # nb de domaines captés (toutes sources)
        self.total_matched = 0          # nb de domaines qui matchent nos TLDs
        self.unique_today = set()       # dédup par jour (reset à minuit UTC)
        self.today_tag = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        self.per_tld_today = defaultdict(int)
        self.last_message_at = None
        self.ws_connected = False
        self.recent = deque(maxlen=200)  # 200 derniers domaines captés (pour debug)
        self.lock = threading.Lock()

STATE = State()

# ── Fichiers ──────────────────────────────────────────────────────────────────
def file_for_date(day_tag: str) -> str:
    return os.path.join(DATA_DIR, f"ct_{day_tag}.txt")

def append_domain(day_tag: str, domain: str):
    """Append un domaine dans le fichier du jour (un par ligne)."""
    try:
        with open(file_for_date(day_tag), "a", encoding="utf-8") as f:
            f.write(domain + "\n")
    except Exception as e:
        print(f"[WARN] append fail: {e}", flush=True)

def maybe_roll_day():
    """Reset les sets de dédup et logs quand on change de jour (UTC)."""
    now_tag = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    if now_tag != STATE.today_tag:
        with STATE.lock:
            old = STATE.today_tag
            STATE.today_tag = now_tag
            STATE.unique_today = set()
            STATE.per_tld_today = defaultdict(int)
        print(f"[ROLL] Nouveau jour : {old} -> {now_tag}", flush=True)

def cleanup_old_files():
    """Supprime les fichiers ct_YYYY-MM-DD.txt plus vieux que RETENTION_DAYS."""
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=RETENTION_DAYS)
    removed = 0
    try:
        for name in os.listdir(DATA_DIR):
            if not name.startswith("ct_") or not name.endswith(".txt"):
                continue
            tag = name[3:-4]  # strip "ct_" and ".txt"
            try:
                d = datetime.strptime(tag, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            except Exception:
                continue
            if d < cutoff:
                os.remove(os.path.join(DATA_DIR, name))
                removed += 1
        if removed:
            print(f"[CLEANUP] {removed} fichiers > {RETENTION_DAYS}j supprimes", flush=True)
    except Exception as e:
        print(f"[WARN] cleanup: {e}", flush=True)

# ── Filtrage domaines ─────────────────────────────────────────────────────────
def should_keep(domain: str) -> bool:
    """Filtre : correspond à un TLD surveillé + pas un wildcard + pas un sous-domaine generique."""
    d = domain.lower()
    if d.startswith("*."):
        return False
    # Garde tout ce qui matche le suffixe d'un TLD configuré
    return any(d.endswith(tld) for tld in TLDS)

def tld_of(domain: str) -> str:
    d = domain.lower()
    # Approx : prend le dernier segment (.com, .fr) ou .co.uk si présent
    if d.endswith(".co.uk"): return ".co.uk"
    parts = d.rsplit(".", 1)
    return "." + parts[-1] if len(parts) > 1 else ""

# ── WebSocket ─────────────────────────────────────────────────────────────────
def on_message(ws, raw):
    try:
        m = json.loads(raw)
    except Exception:
        return
    if m.get("message_type") != "certificate_update":
        return
    data = (m.get("data") or {}).get("leaf_cert") or {}
    all_domains = data.get("all_domains") or []
    if not all_domains:
        return

    STATE.total_certs += 1
    STATE.last_message_at = datetime.now(timezone.utc)
    maybe_roll_day()

    for dom in all_domains:
        STATE.total_domains += 1
        if not should_keep(dom):
            continue
        key = dom.lower()
        # Dedup journalier en RAM
        with STATE.lock:
            if key in STATE.unique_today:
                continue
            STATE.unique_today.add(key)
            STATE.per_tld_today[tld_of(key)] += 1
            STATE.recent.append(key)
        STATE.total_matched += 1
        append_domain(STATE.today_tag, key)

def on_error(ws, error):
    print(f"[WS ERROR] {error}", flush=True)
    STATE.ws_connected = False

def on_close(ws, code, reason):
    print(f"[WS CLOSE] code={code} reason={reason}", flush=True)
    STATE.ws_connected = False

def on_open(ws):
    print(f"[WS OPEN] Connected to CertStream (TLDs={TLDS})", flush=True)
    STATE.ws_connected = True

def run_ws_forever():
    """Boucle infinie : reconnecte en cas de déconnexion."""
    backoff = 1
    while True:
        try:
            ws = websocket.WebSocketApp(
                CT_WSS,
                on_open=on_open,
                on_message=on_message,
                on_error=on_error,
                on_close=on_close,
            )
            ws.run_forever(ping_interval=30, ping_timeout=10)
        except Exception as e:
            print(f"[WS LOOP] exception: {e}", flush=True)
        STATE.ws_connected = False
        # Reconnexion avec backoff exponentiel (max 60s)
        print(f"[WS] Reconnexion dans {backoff}s", flush=True)
        time.sleep(backoff)
        backoff = min(60, backoff * 2)

def run_cleanup_loop():
    """Cleanup des fichiers anciens, toutes les heures."""
    while True:
        try:
            cleanup_old_files()
        except Exception as e:
            print(f"[CLEANUP] err: {e}", flush=True)
        time.sleep(3600)

# ── API HTTP ──────────────────────────────────────────────────────────────────
app = Flask(__name__)

def check_auth():
    if not ACCESS_TOKEN:
        return True  # public
    tok = request.headers.get("Authorization", "").replace("Bearer ", "").strip() \
          or request.args.get("token", "").strip()
    return tok == ACCESS_TOKEN

def load_domains_for_date(day_tag: str) -> list:
    p = file_for_date(day_tag)
    if not os.path.exists(p):
        return []
    with open(p, "r", encoding="utf-8") as f:
        return sorted({l.strip().lower() for l in f if l.strip()})

def filter_by_tld(domains: list, tld: str | None) -> list:
    if not tld:
        return domains
    t = tld.lower()
    if not t.startswith("."):
        t = "." + t
    return [d for d in domains if d.endswith(t)]

@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "ws_connected": STATE.ws_connected,
        "uptime_minutes": round((datetime.now(timezone.utc) - STATE.started_at).total_seconds() / 60, 1),
        "last_message_at": STATE.last_message_at.isoformat() if STATE.last_message_at else None,
    })

@app.route("/stats")
def stats():
    if not check_auth():
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({
        "ws_connected": STATE.ws_connected,
        "started_at": STATE.started_at.isoformat(),
        "today": STATE.today_tag,
        "total_certs": STATE.total_certs,
        "total_domains_seen": STATE.total_domains,
        "total_matched": STATE.total_matched,
        "unique_today": len(STATE.unique_today),
        "per_tld_today": dict(STATE.per_tld_today),
        "tlds_watched": list(TLDS),
    })

@app.route("/recent")
def recent():
    if not check_auth():
        return jsonify({"error": "unauthorized"}), 401
    n = int(request.args.get("n", 50))
    return jsonify({"recent": list(STATE.recent)[-n:]})

@app.route("/today")
def today():
    if not check_auth():
        return jsonify({"error": "unauthorized"}), 401
    tld = request.args.get("tld")
    day = STATE.today_tag
    domains = load_domains_for_date(day)
    domains = filter_by_tld(domains, tld)
    if request.args.get("format", "txt") == "json":
        return jsonify({"date": day, "count": len(domains), "domains": domains})
    return Response("\n".join(domains) + "\n", mimetype="text/plain")

@app.route("/date/<day>")
def by_date(day):
    if not check_auth():
        return jsonify({"error": "unauthorized"}), 401
    try:
        datetime.strptime(day, "%Y-%m-%d")
    except Exception:
        return jsonify({"error": "bad date format YYYY-MM-DD"}), 400
    tld = request.args.get("tld")
    domains = load_domains_for_date(day)
    domains = filter_by_tld(domains, tld)
    if request.args.get("format", "txt") == "json":
        return jsonify({"date": day, "count": len(domains), "domains": domains})
    return Response("\n".join(domains) + "\n", mimetype="text/plain")

@app.route("/days")
def days():
    if not check_auth():
        return jsonify({"error": "unauthorized"}), 401
    out = []
    try:
        for name in sorted(os.listdir(DATA_DIR)):
            if name.startswith("ct_") and name.endswith(".txt"):
                tag = name[3:-4]
                path = os.path.join(DATA_DIR, name)
                try:
                    with open(path, encoding="utf-8") as f:
                        n = sum(1 for _ in f)
                except Exception:
                    n = 0
                out.append({"date": tag, "lines": n})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"days": out})

@app.route("/")
def index():
    return Response(
        "CT Listener — running\n"
        "Endpoints:\n"
        "  GET /health                         (public)\n"
        "  GET /stats                          (token si configuré)\n"
        "  GET /recent?n=50\n"
        "  GET /today?tld=.be&format=json\n"
        "  GET /date/2026-04-23?tld=.fr\n"
        "  GET /days\n",
        mimetype="text/plain")

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    print(f"[BOOT] DATA_DIR={DATA_DIR}  TLDS={TLDS}  PORT={PORT}  retention={RETENTION_DAYS}d", flush=True)
    # WebSocket CertStream dans un thread
    t_ws = threading.Thread(target=run_ws_forever, daemon=True)
    t_ws.start()
    # Cleanup dans un autre thread
    t_cl = threading.Thread(target=run_cleanup_loop, daemon=True)
    t_cl.start()
    # Flask dans le thread principal
    app.run(host="0.0.0.0", port=PORT, debug=False, threaded=True)

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
log_watcher.py
==============
Watches a raw Cowrie JSONL log file for new entries, aggregates them into
sessions, and POSTs completed sessions to the AI analysis API server.

Usage:
    python3 log_watcher.py --log /path/to/cowrie.json [--api http://localhost:5000/analyze] [--output results.jsonl]

How it works:
    1. Tails the raw log file (like `tail -f`) using inotify / polling.
    2. Groups events by session ID.
    3. A session is considered "complete" when a `cowrie.session.closed` event
       arrives OR after a configurable idle timeout (default 60 s).
    4. The completed session JSON is POSTed to api_server.py /analyze.
    5. The AI response (persona + summary) is merged with session metadata and
       written to an output JSONL file AND printed to stdout.
"""

import argparse
import json
import os
import sys
import time
import threading
import requests
from datetime import datetime, timezone
from collections import defaultdict

# ── Config ──────────────────────────────────────────────────────────────────
DEFAULT_API_URL   = "http://localhost:5000/analyze"
DEFAULT_OUTPUT    = "analysis_results.jsonl"
SESSION_IDLE_TTL  = 60          # seconds of silence before flushing a session
POLL_INTERVAL     = 0.5         # seconds between file-read polls
# ────────────────────────────────────────────────────────────────────────────


# ── Session store ────────────────────────────────────────────────────────────
class SessionStore:
    """Accumulates raw Cowrie events, keyed by session UUID."""

    def __init__(self):
        self.sessions: dict[str, dict] = defaultdict(lambda: {
            "events": [],
            "source_ip": "Unknown",
            "start_time": None,
            "end_time": None,
            "last_seen": 0.0,
        })
        self.lock = threading.Lock()

    def ingest(self, raw: dict) -> str | None:
        """
        Add a raw event to the appropriate session bucket.
        Returns the session_id if the session is now closed, else None.
        """
        session_id = raw.get("session")
        if not session_id:
            return None

        event_id  = raw.get("eventid", "")
        timestamp = raw.get("timestamp", datetime.now(timezone.utc).isoformat())
        src_ip    = raw.get("src_ip", "Unknown")

        # Build a normalised timeline event
        tl_event = {"action": event_id}

        if "login.success" in event_id or "login.failed" in event_id:
            tl_event["username"] = raw.get("username", "")
            tl_event["password"] = raw.get("password", "")
            tl_event["status"]   = "Success" if "success" in event_id else "Failed"

        elif "command.input" in event_id:
            tl_event["command"] = raw.get("input", raw.get("message", ""))

        elif "file_download" in event_id or "download" in event_id:
            tl_event["url"] = raw.get("url", raw.get("outfile", "Unknown URL"))

        with self.lock:
            sess = self.sessions[session_id]
            sess["source_ip"]  = src_ip
            sess["last_seen"]  = time.monotonic()

            if sess["start_time"] is None or timestamp < sess["start_time"]:
                sess["start_time"] = timestamp
            if sess["end_time"] is None or timestamp > sess["end_time"]:
                sess["end_time"] = timestamp

            sess["events"].append(tl_event)

            # Signal completion on session.closed
            if "session.closed" in event_id:
                return session_id

        return None

    def pop_session(self, session_id: str) -> dict | None:
        with self.lock:
            return self.sessions.pop(session_id, None)

    def flush_idle(self, ttl: float) -> list[str]:
        """Return session IDs that have been idle longer than `ttl` seconds."""
        now = time.monotonic()
        with self.lock:
            idle = [
                sid for sid, s in self.sessions.items()
                if (now - s["last_seen"]) > ttl
            ]
        return idle


def build_session_payload(session_id: str, sess: dict) -> dict:
    """Convert the internal session dict into the api_server.py payload format."""
    events = sess["events"]
    return {
        "session_id":   session_id,
        "source_ip":    sess["source_ip"],
        "start_time":   sess["start_time"]  or datetime.now(timezone.utc).isoformat(),
        "end_time":     sess["end_time"]    or datetime.now(timezone.utc).isoformat(),
        "total_events": len(events),
        "timeline":     events,
    }


# ── API caller ───────────────────────────────────────────────────────────────
def call_api(payload: dict, api_url: str) -> dict:
    """POST session payload to api_server.py, return AI result dict."""
    try:
        resp = requests.post(api_url, json=payload, timeout=120)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.ConnectionError:
        return {
            "persona": "Error",
            "summary": f"Could not connect to AI API at {api_url}. Is api_server.py running?"
        }
    except Exception as e:
        return {"persona": "Error", "summary": str(e)}


# ── Output writer ────────────────────────────────────────────────────────────
def write_result(result: dict, output_path: str):
    """Append a result line to the JSONL output file."""
    with open(output_path, "a") as f:
        f.write(json.dumps(result) + "\n")
    print(f"\n{'='*60}")
    print(f"[+] Session : {result.get('session_id')}")
    print(f"[+] IP      : {result.get('source_ip')}")
    print(f"[+] Persona : {result.get('persona')}")
    print(f"[+] Summary : {result.get('summary')}")
    print(f"{'='*60}\n")


# ── Session processor ─────────────────────────────────────────────────────────
def process_session(session_id: str, store: SessionStore,
                    api_url: str, output_path: str):
    """Pop a session, call the API, and write the result."""
    sess = store.pop_session(session_id)
    if not sess:
        return

    payload = build_session_payload(session_id, sess)
    print(f"\n[*] Flushing session {session_id} ({len(sess['events'])} events) → AI API …")

    ai = call_api(payload, api_url)

    result = {
        "session_id":   session_id,
        "source_ip":    sess["source_ip"],
        "start_time":   sess["start_time"],
        "end_time":     sess["end_time"],
        "total_events": len(sess["events"]),
        "persona":      ai.get("persona", "Unknown"),
        "summary":      ai.get("summary", ""),
    }
    write_result(result, output_path)


# ── Idle session reaper ───────────────────────────────────────────────────────
def idle_reaper(store: SessionStore, api_url: str,
                output_path: str, ttl: float):
    """Background thread that flushes sessions idle for longer than `ttl`."""
    while True:
        time.sleep(ttl / 2)
        for sid in store.flush_idle(ttl):
            print(f"[~] Idle timeout: flushing session {sid}")
            process_session(sid, store, api_url, output_path)


# ── Log tailer ────────────────────────────────────────────────────────────────
def tail_log(log_path: str, store: SessionStore,
             api_url: str, output_path: str):
    """
    Continuously read new lines appended to `log_path`.
    Works even if the file doesn't exist yet (waits for creation).
    """
    print(f"[*] Watching log file : {log_path}")
    print(f"[*] Posting to API    : {api_url}")
    print(f"[*] Writing results   : {output_path}\n")

    # Wait for file to appear
    while not os.path.exists(log_path):
        print(f"[~] Waiting for log file to appear at {log_path} …")
        time.sleep(2)

    with open(log_path, "r") as f:
        # Seek to end so we only process NEW lines (skip historical backlog)
        # Remove the next line if you want to process the entire existing file:
        f.seek(0, os.SEEK_END)
        print("[*] Tailing from current end of file. New events will be processed.\n")
        print("    (Delete the f.seek() line in tail_log() to replay existing logs.)\n")

        while True:
            line = f.readline()
            if not line:
                time.sleep(POLL_INTERVAL)
                continue

            line = line.strip()
            if not line:
                continue

            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                print(f"[!] Skipping non-JSON line: {line[:80]}")
                continue

            closed_id = store.ingest(raw)
            if closed_id:
                process_session(closed_id, store, api_url, output_path)


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Cowrie log watcher → session aggregator → AI analyser"
    )
    parser.add_argument(
        "--log", required=True,
        help="Path to the raw Cowrie JSONL log file (e.g. cowrie.json)"
    )
    parser.add_argument(
        "--api", default=DEFAULT_API_URL,
        help=f"URL of the AI analysis endpoint (default: {DEFAULT_API_URL})"
    )
    parser.add_argument(
        "--output", default=DEFAULT_OUTPUT,
        help=f"Output JSONL file for analysis results (default: {DEFAULT_OUTPUT})"
    )
    parser.add_argument(
        "--replay", action="store_true",
        help="Replay the entire existing log file instead of tailing from end"
    )
    parser.add_argument(
        "--idle-ttl", type=float, default=SESSION_IDLE_TTL,
        help=f"Seconds of inactivity before flushing an open session (default: {SESSION_IDLE_TTL})"
    )
    args = parser.parse_args()

    store = SessionStore()

    # Start idle session reaper in background
    reaper = threading.Thread(
        target=idle_reaper,
        args=(store, args.api, args.output, args.idle_ttl),
        daemon=True
    )
    reaper.start()

    # If --replay, rewind to start of file
    if args.replay:
        # Monkey-patch tail_log to seek to beginning
        global _REPLAY
        _REPLAY = True

    try:
        if getattr(args, 'replay', False):
            # Replay mode: process whole file then continue tailing
            print("[*] REPLAY MODE: processing existing log entries first …\n")
            with open(args.log, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        raw = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    closed_id = store.ingest(raw)
                    if closed_id:
                        process_session(closed_id, store, args.api, args.output)
            # Flush any still-open sessions from replay
            for sid in list(store.sessions.keys()):
                process_session(sid, store, args.api, args.output)
            print("[*] Replay complete. Now tailing for new entries …\n")

        tail_log(args.log, store, args.api, args.output)

    except KeyboardInterrupt:
        print("\n[*] Interrupted. Flushing open sessions …")
        for sid in list(store.sessions.keys()):
            process_session(sid, store, args.api, args.output)
        print("[*] Done.")
        sys.exit(0)


if __name__ == "__main__":
    main()

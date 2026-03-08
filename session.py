import json
import time
import os

# --- CONFIGURATION ---
RAW_LOG_FILE = "cowrie.json"
LIVE_EVENTS_FILE = "live_events.json"               # Task 1: Instant raw stream for GeoIP map
COMPLETED_SESSIONS_FILE = "completed_sessions.json" # Task 2: Fully mapped sessions for the dashboard UI

# Dictionary to hold active sessions in RAM until they close
active_sessions = {}

def process_raw_line(line):
    """Parses a single raw line, routes it for GeoIP, and buffers the session."""
    try:
        log = json.loads(line.strip())
    except json.JSONDecodeError:
        return

    # ==========================================
    # TASK 1: INSTANT ROUTING (For GeoIP Mapping)
    # ==========================================
    # Immediately dump the raw log into the live events file.
    # Your frontend map can poll this file (or you can link a WebSocket here later).
    with open(LIVE_EVENTS_FILE, "a") as f:
        f.write(line.strip() + "\n")


    # ==========================================
    # TASK 2: SESSION BUFFERING
    # ==========================================
    session_id = log.get("session")
    if not session_id:
        return # Skip logs without a session ID

    event_id = log.get("eventid", "")
    timestamp = log.get("timestamp")

    # Initialize the session if it's the first time we are seeing this ID
    if session_id not in active_sessions:
        active_sessions[session_id] = {
            "session_id": session_id,
            "source_ip": log.get("src_ip", "Unknown"),
            "start_time": timestamp,
            "end_time": timestamp,
            "total_events": 0,
            "timeline": []
        }

    # Update session metrics
    session = active_sessions[session_id]
    session["end_time"] = timestamp
    session["total_events"] += 1

    # Map the raw event to our clean timeline format
    clean_event = {
        "timestamp": timestamp,
        "action": event_id
    }

    if "login" in event_id:
        clean_event["username"] = log.get("username", "")
        clean_event["password"] = log.get("password", "")
        clean_event["status"] = "Success" if "success" in event_id else "Failed"
    elif "command.input" in event_id:
        clean_event["command"] = log.get("input", "")
    elif "file_download" in event_id:
        clean_event["url"] = log.get("url", "")

    session["timeline"].append(clean_event)

    # THE TRIGGER: If the session closes, move it from RAM to the completed file
    if event_id == "cowrie.session.closed":
        print(f"\n[*] Session {session_id} from {session['source_ip']} closed! Saving to {COMPLETED_SESSIONS_FILE}...")
        save_completed_session(session_id)


def save_completed_session(session_id):
    """Pops the session from memory and appends it to the final JSON file."""
    session_data = active_sessions.pop(session_id, None)
    if not session_data:
        return

    # Append to the mapped log file for the dashboard UI to read
    with open(COMPLETED_SESSIONS_FILE, "a") as f:
        f.write(json.dumps(session_data) + "\n")


def tail_logs():
    """Silently watches the live Cowrie log for new lines being appended."""
    if not os.path.exists(RAW_LOG_FILE):
        open(RAW_LOG_FILE, 'a').close() 
            
    print(f"[-] Tailing {RAW_LOG_FILE} waiting for new attacks...")
    
    with open(RAW_LOG_FILE, "r") as f:
        # Seek to the end of the file so we only process NEW logs
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1) # Wait a split second if no new lines exist
                continue
            process_raw_line(line)

if __name__ == "__main__":
    tail_logs()

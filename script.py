import json
import re
import requests
import time
import os

# --- CONFIGURATION ---
OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "llama3.1"
RAW_COWRIE_LOG = "demo.json"    # The live log Cowrie writes to
PROCESSED_LOG = "attacks.log"     # The NDJSON file your dashboard will read from
MITRE_DB_FILE = "mitre_attack_data.json"

# --- 1. LOAD MITRE DATABASE ---
try:
    with open(MITRE_DB_FILE, 'r') as f:
        MITRE_DB = json.load(f)
    print(f"[+] Loaded MITRE Database successfully. ({len(MITRE_DB)} Tactics found)")
except FileNotFoundError:
    print(f"[-] Error: Could not find {MITRE_DB_FILE}. MITRE mapping will be empty.")
    MITRE_DB = []

# --- 2. TIER 2: LOW-LATENCY REGEX SIGNATURES ---
# Maps fast regex patterns to exact Tactic and Technique names in your JSON
SIGNATURE_RULES = {
    r"wget\s+http|curl\s+": {"tactic": "Command and Control", "technique": "Ingress Tool Transfer"}, 
    r"chmod\s+\+x": {"tactic": "Defense Evasion", "technique": "File and Directory Permissions Modification"},
    r"cat\s+/etc/shadow|cat\s+/etc/passwd": {"tactic": "Credential Access", "technique": "OS Credential Dumping"},
    r"whoami|id": {"tactic": "Discovery", "technique": "Account Discovery"},
    r"uname|/proc/uptime|/proc/cpuinfo": {"tactic": "Discovery", "technique": "System Information Discovery"},
    r"rm\s+-rf|history\s+-c": {"tactic": "Defense Evasion", "technique": "Indicator Removal"}
}

def get_mitre_mitigations(tactic_name, technique_name):
    """Scans the loaded mitre_attack_data.json for matching mitigations."""
    for tactic in MITRE_DB:
        if tactic.get("tactic") == tactic_name:
            for tech in tactic.get("techniques", []):
                # Using lower() to ensure case-insensitive matching
                if technique_name.lower() in tech.get("technique", "").lower():
                    return tech.get("mitigations", [])
    return []

def map_input_to_ttp(event_id, command_input):
    """Tiered mapping for Zero-Latency MITRE tagging."""
    tactic, technique = "Unknown", "Unknown"
    
    # Tier 1: Event ID Mapping
    if "login.failed" in event_id or "login.success" in event_id:
        tactic, technique = "Credential Access", "Brute Force"
    elif "file_download" in event_id:
        tactic, technique = "Command and Control", "Ingress Tool Transfer"
    
    # Tier 2: Command Regex Mapping
    elif command_input and "command.input" in event_id:
        for pattern, ttp in SIGNATURE_RULES.items():
            if re.search(pattern, command_input, re.IGNORECASE):
                tactic, technique = ttp["tactic"], ttp["technique"]
                break
                
    # If no mapping was found, return an empty dictionary
    if tactic == "Unknown":
        return {}
        
    # Fetch mitigations from your JSON file based on the matched TTP
    mitigations = get_mitre_mitigations(tactic, technique)
    
    return {
        "tactic": tactic,
        "techniques": [
            {
                "technique": technique,
                "mitigations": mitigations
            }
        ]
    }

def ask_ollama(prompt):
    """Sends the context to Llama 3.1."""
    payload = {"model": MODEL, "prompt": prompt, "stream": False}
    try:
        response = requests.post(OLLAMA_URL, json=payload)
        response.raise_for_status()
        return response.json().get("response", "")
    except Exception as e:
        print(f"[-] Ollama Error: {e}")
        return '{"persona": "Cant decide", "summary": "AI offline or unreachable."}'

def process_log_line(line):
    """Parses raw Cowrie log, enriches with AI & MITRE, and formats perfectly."""
    try:
        raw_event = json.loads(line.strip())
    except json.JSONDecodeError:
        return

    event_id = raw_event.get("eventid", "")
    
    # Skip events we don't care about to save processing time
    if "cowrie.command.input" not in event_id and "cowrie.login" not in event_id:
        return

    cmd = raw_event.get("input")  # Will be None if it's a login event
    user = raw_event.get("username") or raw_event.get("user")
    password = raw_event.get("password")
    src_ip = raw_event.get("src_ip", "Unknown")

    print(f"\n[*] Processing attack from {src_ip}...")

    # 1. MAP TO MITRE (Zero Latency)
    mitre_data = map_input_to_ttp(event_id, cmd)

    # 2. ASK AI FOR SUMMARY & PERSONA
    narrative = f"Action: {event_id}\nInput: {cmd}\nUser: {user} / Pass: {password}"
    
    prompt = f"""You are an expert SOC Analyst. Analyze this single attacker action:
{narrative}

Task 1: Determine if the attacker is a "Human", "Bot", or "Cant decide". 
(Hint: Bots often use automated/chained scripts, wget, or massive repetitive patterns. Humans use manual exploration like whoami, ls, or make typos).

Task 2: Write a 1-2 sentence technical summary of the goal.

Output ONLY valid JSON matching this exact format. No markdown, no backticks, no explanations.
{{
  "persona": "Bot", 
  "summary": "Technical summary here"
}}"""
    
    raw_ai = ask_ollama(prompt)
    
    # Clean up formatting just in case Llama hallucinates markdown blocks
    clean_ai = raw_ai.replace("```json", "").replace("```", "").strip()
    
    try:
        ai_data = json.loads(clean_ai)
    except json.JSONDecodeError:
        ai_data = {"persona": "Cant decide", "summary": f"Raw AI Output: {clean_ai}"}

    # 3. BUILD THE FINAL TARGET FORMAT (Exactly as you requested)
    # Ensure the event ID has "event." prepended if Cowrie didn't add it
    formatted_event_id = event_id if event_id.startswith("event.") else f"event.{event_id}"

    final_payload = {
        "time stamp": raw_event.get("timestamp"),
        "src ip": src_ip,
        "event id": formatted_event_id,
        "session id": raw_event.get("session"),
        "input": cmd,
        "user": user,
        "password": password,
        "response": mitre_data,
        "ai_response": {
            "summary": ai_data.get("summary", ""),
            "persona": ai_data.get("persona", "Cant decide")
        }
    }

    # 4. APPEND TO ATTACKS.LOG AS NDJSON
    with open(PROCESSED_LOG, "a") as f:
        f.write(json.dumps(final_payload) + "\n")
        
    print(f"[+] Successfully wrote to {PROCESSED_LOG} | Persona: {ai_data.get('persona')}")

def tail_cowrie_logs():
    """Tails the live Cowrie log and processes new entries in real-time."""
    if not os.path.exists(RAW_COWRIE_LOG):
        print(f"[-] Waiting for {RAW_COWRIE_LOG} to be created...")
        # Create a blank file just so the script doesn't crash while waiting for the first attack
        open(RAW_COWRIE_LOG, 'a').close()
            
    print(f"[-] Tailing {RAW_COWRIE_LOG} and writing to {PROCESSED_LOG}...")
    
    with open(RAW_COWRIE_LOG, "r") as f:
        # Seek to the end of the file so we only analyze NEW attacks 
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1) # Ultra-fast polling
                continue
            process_log_line(line)

if __name__ == "__main__":
    tail_cowrie_logs()

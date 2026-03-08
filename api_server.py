from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import requests

# Initialize the Flask App
app = Flask(__name__)
CORS(app) 

# Ollama Setup
OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "llama3.1"

def ask_ollama(prompt):
    payload = {
        "model": MODEL,
        "prompt": prompt,
        "stream": False
    }
    try:
        response = requests.post(OLLAMA_URL, json=payload)
        response.raise_for_status()
        return response.json().get("response", "No response received.")
    except Exception as e:
        return f"Error connecting to local Ollama: {e}"

# The API Endpoint
@app.route('/analyze', methods=['POST'])
def analyze_endpoint():
    """This endpoint expects a full Session JSON object."""
    session_data = request.json
    if not session_data:
        return jsonify({"error": "No JSON payload provided"}), 400

    sess_id = session_data.get("session_id", "Unknown ID")
    src_ip = session_data.get("source_ip", "Unknown IP")
    timeline = session_data.get("timeline", [])
    
    # FIX 1: Indentation corrected here
    start_time = session_data.get("start_time", "Unknown")
    end_time = session_data.get("end_time", "Unknown")
    total_events = session_data.get("total_events", 0)

    # Build a chronological story for the AI, including time!
    narrative = f"Session ID: {sess_id}\nSource IP: {src_ip}\nSession Start: {start_time}\nSession End: {end_time}\nTotal Events: {total_events}\nTimeline:\n"
    
    for event in timeline:
        action = event.get("action", "")
        
        if "login" in action:
            narrative += f"- Login {event.get('status', 'Attempt')}: {event.get('username', 'N/A')} / {event.get('password', 'N/A')}\n"
        elif "command.input" in action:
            narrative += f"- Executed Command: '{event.get('command', '')}'\n"
        elif "file_download" in action:
            narrative += f"- Downloaded File from: {event.get('url', 'Unknown URL')}\n"

    if narrative.endswith("Timeline:\n"):
        narrative += "- No significant commands or login attempts recorded."

    # THE AGGRESSIVE SESSION PROMPT
    # FIX 2: Removed the trailing extra triple quotes at the bottom
    prompt = f"""
    You are an expert SOC Analyst analyzing a complete honeypot session timeline.
    
    Event Details:
    {narrative}

    Task 1: Classify the attacker into EXACTLY ONE of these Personas:
    - Automated Bot (Machine speed, rapid brute-forcing, instant execution of wget/curl scripts)
    - Script Kiddie (Human speed, basic noisy commands like 'whoami', 'ls', manual exploration, simple login attempts)
    - Advanced Threat (Stealthy, complex encoded payloads, clearing logs, privilege escalation)

    Task 2: Write a highly descriptive, 2-3 sentence technical summary of the ENTIRE session. You MUST analyze the flow: mention the speed of the attack (based on start/end times), the exact sequence of actions (e.g., "The attacker connected, attempted X failed logins, executed Y"), and their ultimate objective.

    OUTPUT RULE: You must output ONLY valid JSON. Do not include markdown backticks (```json). Do not explain.
    Format exactly like this:
    {{
      "persona": "Persona Name",
      "summary": "Your highly descriptive session summary here"
    }}
    """

    print(f"\n[*] Analyzing complete session {sess_id} from {src_ip}...")
    
    raw_ai_response = ask_ollama(prompt)
    
    # Clean up the AI output just in case it hallucinates markdown backticks
    clean_response = raw_ai_response.replace("```json", "").replace("```", "").strip()
    
    try:
        # Convert the AI's string back into a real JSON dictionary
        ai_data = json.loads(clean_response)
        print(f"[+] AI Classification: {ai_data.get('persona')}")
    except json.JSONDecodeError:
        print("[-] AI output formatting failed. Falling back to raw text.")
        ai_data = {
            "persona": "Unknown",
            "summary": clean_response
        }
    
    # Send the dual-data back to the dashboard!
    return jsonify(ai_data)

if __name__ == '__main__':
    print("[-] AI API Server starting...")
    app.run(host='0.0.0.0', port=5000)

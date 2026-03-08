import json
import requests

# Set your Ollama endpoint and model
OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "llama3.1"

def ask_ollama(prompt):
    """Sends the crafted prompt to the local Ollama model."""
    print("\n[*] Sending to Llama 3.1 for analysis...")
    payload = {
        "model": MODEL,
        "prompt": prompt,
        "stream": False
    }
    
    try:
        response = requests.post(OLLAMA_URL, json=payload)
        response.raise_for_status() # Check for HTTP errors
        return response.json().get("response", "No response received.")
    except requests.exceptions.RequestException as e:
        return f"Error connecting to Ollama: {e}"

def parse_and_analyze(json_input):
    """Parses the specific Cowrie JSON format and builds the AI prompt."""
    try:
        event = json.loads(json_input)
    except json.JSONDecodeError:
        print("[-] Error: Invalid JSON format. Please try again.")
        return

    # Extract common fields
    event_id = event.get("event id", "")
    src_ip = event.get("src ip", "Unknown IP")
    timestamp = event.get("time stamp", "Unknown Time")
    
    # 1. Build the narrative based on the event type
    narrative = f"Timestamp: {timestamp}\nSource IP: {src_ip}\n"
    
    if "login" in event_id.lower():
        user = event.get("user", "None")
        password = event.get("password", "None")
        narrative += f"Action: Attacker attempted to log in.\nCredentials Used: Username '{user}' / Password '{password}'\n"
    elif "input" in event_id.lower():
        cmd = event.get("input", "None")
        narrative += f"Action: Attacker executed a terminal command.\nCommand Typed: '{cmd}'\n"
    else:
        narrative += f"Action: Unknown event type ({event_id})\n"

    # 2. Add the MITRE ATT&CK context from the 'response' block
    mitre_data = event.get("response", {})
    if mitre_data:
        tactic = mitre_data.get("tactic", "Unknown Tactic")
        narrative += f"\nMITRE ATT&CK Mapping:\n- Tactic: {tactic}\n"
        
        # Extract techniques and mitigations if they exist
        techniques = mitre_data.get("techniques", [])
        for tech in techniques:
            for mitigation in tech.get("mitigations", []):
                narrative += f"- Recommended Mitigation: {mitigation.get('name', 'N/A')} ({mitigation.get('id', 'N/A')})\n"

    # 3. Construct the strict System Prompt for Llama 3.1
    prompt = f"""
    You are an expert SOC Analyst. Analyze this single honeypot event:
    
    {narrative}
    
    Task: 1. Write a concise, 2-3 sentence explanation of exactly what the attacker is trying to achieve. Do not use conversational filler. Be direct and technical.
	  2. analyse the log and tell whether the log is executed by a human or a bot.
    """

    # 4. Get the result
    analysis = ask_ollama(prompt)
    
    print("\n====== Llama 3.1 Analysis ======")
    print(analysis.strip())
    print("================================\n")


if __name__ == "__main__":
    print("[-] Interactive SOC AI Debugger Started.")
    print("[-] Make sure Ollama is running in the background.")
    
    while True:
        print("\nPaste your JSON event below (or type 'exit' to quit):")
        
        # Read multi-line input from the terminal until an empty line is entered
        lines = []
        while True:
            line = input()
            if line.strip() == "exit":
                exit()
            if line == "":
                break
            lines.append(line)
            
        user_json = "\n".join(lines)
        
        if user_json.strip():
            parse_and_analyze(user_json)

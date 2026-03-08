import time
import sys

# Change this to whatever your input file is named
INPUT_FILE = "demo.json" 
TARGET_FILE = "cowrie.json"

def play_logs(delay=1.0):
    print(f"[*] Starting Hackathon Demo Sequence...")
    print(f"[*] Streaming {INPUT_FILE} into {TARGET_FILE} at {delay}s intervals.\n")
    
    try:
        with open(INPUT_FILE, 'r') as infile, open(TARGET_FILE, 'a') as outfile:
            for line in infile:
                if line.strip():
                    # Write the line and force the OS to save it instantly
                    outfile.write(line)
                    outfile.flush() 
                    
                    # Print a preview so you know it's working
                    print(f"[+] Sent -> {line.strip()[:65]}...")
                    
                    # Pause before sending the next line to make the UI look real
                    time.sleep(delay)
                    
        print("\n[*] Demo playback complete!")
    except FileNotFoundError:
        print(f"[-] Error: Make sure {INPUT_FILE} is in the same folder!")

if __name__ == "__main__":
    # You can change 1.0 to 0.5 to make it type faster!
    play_logs(delay=1.0)
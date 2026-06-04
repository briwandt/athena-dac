import subprocess
import sys
import time
import re
import os

WORKSPACE_DIR = r"c:\Users\user\Documents\AntiGravity\detection engineering"
URL_FILE = os.path.join(WORKSPACE_DIR, "public_url.txt")

cmd = [
    "ssh",
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=NUL",
    "-o", "ServerAliveInterval=15",
    "-o", "ServerAliveCountMax=3",
    "-R", "80:localhost:8501",
    "nokey@localhost.run"
]

def run_tunnel():
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Starting Localhost.run tunnel...")
    sys.stdout.flush()
    
    # Start the process
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    
    # Read stdout in real-time
    url_found = False
    try:
        for line in iter(process.stdout.readline, ''):
            sys.stdout.write(line)
            sys.stdout.flush()
            
            # Look for the .lhr.life HTTPS URL
            match = re.search(r'https://[a-zA-Z0-9.-]+\.lhr\.life', line)
            if match:
                url = match.group(0)
                url_found = True
                print(f"\n[+] ACTIVE PUBLIC URL: {url}\n")
                sys.stdout.flush()
                
                # Write to the workspace file
                with open(URL_FILE, "w", encoding="utf-8") as f:
                    f.write(url + "\n")
                    
        # If loop exits, process has closed
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] SSH connection closed.")
        sys.stdout.flush()
    except Exception as e:
        print(f"Error in tunnel execution: {e}")
        sys.stdout.flush()
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            
    return url_found

def main():
    while True:
        try:
            run_tunnel()
        except Exception as e:
            print(f"Error in daemon loop: {e}")
            sys.stdout.flush()
            
        print("Sleeping 5 seconds before reconnecting...")
        sys.stdout.flush()
        time.sleep(5)

if __name__ == "__main__":
    main()

import subprocess
import sys
import os

# Define the command
cmd = [
    "ssh",
    "-o", "StrictHostKeyChecking=no",
    "-p", "443",
    "-R", "80:localhost:8501",
    "loop@a.pinggy.io"
]

print("Launching SSH tunnel...")
sys.stdout.flush()

# Start process
process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)

# Read output in real-time
try:
    for line in iter(process.stdout.readline, ''):
        sys.stdout.write(line)
        sys.stdout.flush()
        
        # Check if the line contains the generated pinggy URL
        if "pinggy.link" in line:
            url = line.strip()
            print(f"\n[+] Captured Public URL: {url}\n")
            sys.stdout.flush()
            # Save it to a file
            with open("public_url.txt", "w", encoding="utf-8") as f:
                f.write(url + "\n")
except Exception as e:
    print(f"Error reading stdout: {e}")
    sys.stdout.flush()
finally:
    process.terminate()

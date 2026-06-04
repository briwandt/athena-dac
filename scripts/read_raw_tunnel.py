import subprocess
import sys
import time

cmd = [
    "ssh",
    "-o", "StrictHostKeyChecking=no",
    "-p", "443",
    "-R", "80:localhost:8501",
    "loop@a.pinggy.io"
]

print("Launching diag tunnel...")
process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

# Read raw characters in a loop for 10 seconds
start_time = time.time()
output_chars = []

# Set non-blocking or just read character by character
# On Windows, we can read char by char:
try:
    while time.time() - start_time < 15:
        char = process.stdout.read(1)
        if not char:
            break
        output_chars.append(char)
        # Flush to a local file immediately
        with open("diag_output.txt", "a", encoding="utf-8") as f:
            f.write(char)
except Exception as e:
    with open("diag_output.txt", "a", encoding="utf-8") as f:
        f.write(f"\nError: {e}\n")
finally:
    process.terminate()
    print("Diag tunnel terminated.")
